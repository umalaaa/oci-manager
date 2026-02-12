use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime};

use anyhow::{bail, Result};
use axum::body::Body;
use axum::extract::{Path, Query, State};
use axum::http::header::AUTHORIZATION;
use axum::http::{Request, StatusCode};
use axum::middleware::{self, Next};
use axum::response::{Html, IntoResponse, Redirect};
use axum::routing::{delete, get, post};
use axum::{Json, Router};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;
use tracing::{info, warn};

use crate::config::{NotificationConfig, OciConfig, Preset, ProfileDefaults};
use crate::logic::{resolve_create_payload, CreateInput};
use crate::models::{AvailabilityDomain, InstanceSummary, Shape, SubnetSummary};
use crate::notify::{notify_success, NotifySource};
use crate::oci::OciClient;
use crate::telegram_bind;

#[derive(Clone, Serialize)]
#[allow(dead_code)]
enum TaskStatus {
    Pending,
    Running,
    Success(String),
    Failed(String),
    Retrying(String),
    Cancelled,
}

#[derive(Clone)]
struct Task {
    id: String,
    target_profile: String,
    description: String,
    status: TaskStatus,
    created_at: u64,
    retry_count: u32,
    last_error: Option<String>,
    next_retry_at: Option<u64>,
    cancelled: Arc<AtomicBool>,
}

impl Serialize for Task {
    fn serialize<S: serde::Serializer>(
        &self,
        serializer: S,
    ) -> std::result::Result<S::Ok, S::Error> {
        use serde::ser::SerializeStruct;
        let mut s = serializer.serialize_struct("Task", 10)?;
        s.serialize_field("id", &self.id)?;
        s.serialize_field("target_profile", &self.target_profile)?;
        s.serialize_field("description", &self.description)?;
        s.serialize_field("status", &self.status)?;
        s.serialize_field("created_at", &self.created_at)?;
        s.serialize_field("retry_count", &self.retry_count)?;
        s.serialize_field("last_error", &self.last_error)?;
        s.serialize_field("next_retry_at", &self.next_retry_at)?;
        s.serialize_field("cancelled", &self.cancelled.load(Ordering::Relaxed))?;
        s.end()
    }
}

#[derive(Clone)]
pub struct AppState {
    profiles: Arc<HashMap<String, ProfileState>>,
    default_profile: String,
    admin_key: Option<String>,
    presets: Arc<Vec<Preset>>,
    tasks: Arc<Mutex<Vec<Task>>>,
}

#[derive(Clone)]
struct ProfileState {
    client: Arc<OciClient>,
    defaults: ProfileDefaults,
}

#[derive(Clone)]
struct TelegramBotState {
    app: AppState,
    token: String,
    bind_state: Arc<Mutex<telegram_bind::TelegramBindState>>,
    chat_profiles: Arc<Mutex<HashMap<i64, String>>>,
    chat_compartments: Arc<Mutex<HashMap<i64, ChatCompartment>>>,
    chat_availability_domains: Arc<Mutex<HashMap<i64, Vec<String>>>>,
    chat_shapes: Arc<Mutex<HashMap<i64, String>>>,
    chat_shape_ocpus: Arc<Mutex<HashMap<i64, f64>>>,
    chat_shape_memory: Arc<Mutex<HashMap<i64, f64>>>,
    shape_cache: Arc<Mutex<HashMap<i64, Vec<Shape>>>>,
    chat_root_login: Arc<Mutex<HashMap<i64, bool>>>,
    chat_use_ssh_key: Arc<Mutex<HashMap<i64, bool>>>,
    chat_boot_volume_gbs: Arc<Mutex<HashMap<i64, u64>>>,
    chat_boot_volume_vpus: Arc<Mutex<HashMap<i64, u64>>>,
    chat_instance_cache: Arc<Mutex<HashMap<i64, InstanceListCache>>>,
    compartment_cache: Arc<Mutex<HashMap<i64, Vec<CompartmentItem>>>>,
    last_actions: Arc<Mutex<HashMap<i64, LastAction>>>,
}

#[derive(Clone)]
struct LastAction {
    key: String,
    at: Instant,
}

#[derive(Clone)]
struct ChatCompartment {
    id: String,
    name: String,
    from_config_default: bool,
}

#[derive(Clone)]
struct InstanceListCache {
    profile_key: String,
    items: Vec<InstanceSummary>,
}
pub async fn serve(
    config: OciConfig,
    default_profile: String,
    admin_key: Option<String>,
    host: String,
    port: u16,
) -> Result<()> {
    let global_notify = NotificationConfig::from_props(&config.global_props)?;
    let mut profiles = HashMap::new();
    for (name, profile) in config.profiles.into_iter() {
        let client = OciClient::new(profile.clone())?;
        let key = name.to_uppercase();
        profiles.insert(
            key.clone(),
            ProfileState {
                client: Arc::new(client),
                defaults: profile.defaults.clone(),
            },
        );
    }
    let default_profile = default_profile.to_uppercase();
    if !profiles.is_empty() && !profiles.contains_key(&default_profile) {
        // Only bail if we have profiles but the requested default isn't among them
        bail!("Default profile '{}' not found", default_profile);
    }

    let state = AppState {
        profiles: Arc::new(profiles),
        default_profile,
        admin_key,
        presets: Arc::new(config.presets),
        tasks: Arc::new(Mutex::new(Vec::new())),
    };

    start_telegram_bot_if_configured(state.clone(), &global_notify);

    let app = Router::new()
        .route("/", get(index))
        .route("/login", get(login_page))
        .route("/admin", get(admin_page))
        .route("/api/profiles", get(list_profiles))
        .route("/api/presets", get(list_presets))
        .route("/api/defaults", get(get_defaults))
        .route("/api/ssh-keys", get(list_ssh_keys))
        .route("/api/instances", get(list_instances).post(create_instance))
        .route("/api/instances/:id", delete(terminate_instance))
        .route("/api/instances/:id/reboot", post(reboot_instance))
        .route("/api/subnets", get(list_subnets))
        .route("/api/compartments", get(list_compartments))
        .route("/api/availability", get(availability))
        .route(
            "/api/tasks",
            get(list_tasks).post(queue_instance).delete(clear_tasks),
        )
        .route("/api/tasks/:id", delete(delete_task))
        .layer(middleware::from_fn_with_state(
            state.clone(),
            auth_middleware,
        ))
        .with_state(state);

    let address = format!("{}:{}", host, port);
    info!("Web UI running at http://{}", address);
    let listener = tokio::net::TcpListener::bind(&address).await?;
    axum::serve(listener, app).await?;
    Ok(())
}

async fn index() -> impl IntoResponse {
    Redirect::to("/login")
}

async fn login_page() -> impl IntoResponse {
    Html(include_str!("../static/login.html"))
}

async fn admin_page() -> impl IntoResponse {
    Html(include_str!("../static/index.html"))
}

async fn auth_middleware(
    State(state): State<AppState>,
    request: Request<Body>,
    next: Next,
) -> impl IntoResponse {
    let Some(admin_key) = &state.admin_key else {
        return next.run(request).await.into_response();
    };

    let path = request.uri().path();
    // Allow index and static assets (if any)
    if path == "/" || path == "/login" {
        return next.run(request).await.into_response();
    }

    // Check Headers (x-admin-key or Authorization)
    if let Some(value) = request.headers().get("x-admin-key") {
        if let Ok(value) = value.to_str() {
            if value == admin_key {
                return next.run(request).await.into_response();
            }
        }
    }

    if let Some(value) = request.headers().get(AUTHORIZATION) {
        if let Ok(value) = value.to_str() {
            if let Some(token) = value.strip_prefix("Bearer ") {
                if token == admin_key {
                    return next.run(request).await.into_response();
                }
            }
        }
    }

    // Check Cookie
    if let Some(cookie_header) = request.headers().get("cookie") {
        if let Ok(cookies) = cookie_header.to_str() {
            for cookie in cookies.split(';') {
                if let Some((name, value)) = cookie.trim().split_once('=') {
                    if name == "admin_key" && value == admin_key {
                        return next.run(request).await.into_response();
                    }
                }
            }
        }
    }

    // Return 401 for API, Redirect for Page
    if path == "/admin" {
        return Redirect::to("/login").into_response();
    }

    (StatusCode::UNAUTHORIZED, "Unauthorized").into_response()
}

impl AppState {
    fn select_profile(&self, name: Option<&str>) -> Result<&ProfileState, (StatusCode, String)> {
        let key = name
            .map(|value| value.trim().to_uppercase())
            .filter(|value| !value.is_empty())
            .unwrap_or_else(|| self.default_profile.clone());
        self.profiles.get(&key).ok_or_else(|| {
            (
                StatusCode::BAD_REQUEST,
                format!("Profile '{}' not found", key),
            )
        })
    }
}

#[derive(Debug, Serialize)]
struct ProfilesResponse {
    default: String,
    profiles: Vec<String>,
}

async fn list_profiles(State(state): State<AppState>) -> Json<ProfilesResponse> {
    let mut profiles = state.profiles.keys().cloned().collect::<Vec<_>>();
    profiles.sort();
    Json(ProfilesResponse {
        default: state.default_profile.clone(),
        profiles,
    })
}

async fn list_presets(State(state): State<AppState>) -> Json<Vec<Preset>> {
    Json(state.presets.as_ref().clone())
}

async fn get_defaults(
    State(state): State<AppState>,
    Query(query): Query<ProfileQuery>,
) -> Result<Json<ProfileDefaults>, (StatusCode, String)> {
    let profile = state.select_profile(query.profile.as_deref())?;
    Ok(Json(profile.defaults.clone()))
}

#[derive(Debug, Serialize)]
struct SshKeyInfo {
    name: String,
}

async fn list_ssh_keys() -> Json<Vec<SshKeyInfo>> {
    let mut keys = Vec::new();
    if let Some(home) = dirs::home_dir() {
        let ssh_dir = home.join(".ssh");
        if let Ok(entries) = std::fs::read_dir(&ssh_dir) {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.extension().and_then(|ext| ext.to_str()) == Some("pub") {
                    let name = path
                        .file_name()
                        .and_then(|value| value.to_str())
                        .unwrap_or("key.pub")
                        .to_string();
                    keys.push(SshKeyInfo { name });
                }
            }
        }
    }
    keys.sort_by(|a, b| a.name.cmp(&b.name));
    Json(keys)
}

#[derive(Debug, Deserialize)]
struct InstanceQuery {
    profile: Option<String>,
    compartment: Option<String>,
}

async fn list_instances(
    State(state): State<AppState>,
    Query(query): Query<InstanceQuery>,
) -> Result<Json<Vec<InstanceSummary>>, (StatusCode, String)> {
    let profile = state.select_profile(query.profile.as_deref())?;
    let compartment = query
        .compartment
        .or_else(|| profile.defaults.compartment.clone())
        .ok_or_else(|| (StatusCode::BAD_REQUEST, "Missing compartment".to_string()))?;
    let instances = profile
        .client
        .list_instances(&compartment)
        .await
        .map_err(internal_error)?;
    Ok(Json(instances))
}

async fn list_subnets(
    State(state): State<AppState>,
    Query(query): Query<InstanceQuery>,
) -> Result<Json<Vec<SubnetSummary>>, (StatusCode, String)> {
    let profile = state.select_profile(query.profile.as_deref())?;
    let compartment = query
        .compartment
        .or_else(|| profile.defaults.compartment.clone())
        .ok_or_else(|| (StatusCode::BAD_REQUEST, "Missing compartment".to_string()))?;
    let subnets = profile
        .client
        .list_subnets(&compartment)
        .await
        .map_err(internal_error)?;
    Ok(Json(subnets))
}

#[derive(Debug, Serialize, Clone)]
struct CompartmentItem {
    id: String,
    name: String,
}

async fn list_compartments(
    State(state): State<AppState>,
    Query(query): Query<ProfileQuery>,
) -> Result<Json<Vec<CompartmentItem>>, (StatusCode, String)> {
    let profile = state.select_profile(query.profile.as_deref())?;
    let mut items = vec![CompartmentItem {
        id: profile.client.tenancy().to_string(),
        name: "(root tenancy)".to_string(),
    }];
    let compartments = profile
        .client
        .list_compartments()
        .await
        .map_err(internal_error)?;
    for c in compartments {
        if c.lifecycle_state.as_deref() == Some("ACTIVE") {
            items.push(CompartmentItem {
                id: c.id,
                name: c.name,
            });
        }
    }
    Ok(Json(items))
}

#[derive(Debug, Deserialize)]
struct CreateRequest {
    profile: Option<String>,
    compartment: Option<String>,
    subnet: Option<String>,
    shape: Option<String>,
    ocpus: Option<f64>,
    #[serde(rename = "memoryInGBs", alias = "memory_in_gbs")]
    memory_in_gbs: Option<f64>,
    #[serde(rename = "bootVolumeSizeInGBs", alias = "boot_volume_size_gbs")]
    boot_volume_size_gbs: Option<u64>,
    #[serde(rename = "bootVolumeVpusPerGB", alias = "boot_volume_vpus_per_gb")]
    boot_volume_vpus_per_gb: Option<u64>,
    availability_domain: Option<String>,
    image: Option<String>,
    image_os: Option<String>,
    image_version: Option<String>,
    display_name: Option<String>,
    ssh_key: Option<String>,
    #[serde(rename = "useSshKey", alias = "use_ssh_key")]
    use_ssh_key: Option<bool>,
    #[serde(rename = "rootLogin", alias = "root_login")]
    root_login: Option<bool>,
}

async fn create_instance(
    State(state): State<AppState>,
    Json(payload): Json<CreateRequest>,
) -> Result<Json<InstanceSummary>, (StatusCode, String)> {
    let profile = state.select_profile(payload.profile.as_deref())?;
    let input = CreateInput {
        profile: payload.profile.clone(),
        compartment: payload.compartment,
        subnet: payload.subnet,
        shape: payload.shape,
        ocpus: payload.ocpus,
        memory_in_gbs: payload.memory_in_gbs,
        boot_volume_size_gbs: payload.boot_volume_size_gbs,
        boot_volume_vpus_per_gb: payload.boot_volume_vpus_per_gb,
        availability_domain: payload.availability_domain,
        image: payload.image,
        image_os: payload.image_os,
        image_version: payload.image_version,
        display_name: payload.display_name,
        ssh_key: payload.ssh_key,
        use_ssh_key: payload.use_ssh_key,
        root_login: payload.root_login,
        retry_interval_secs: None,
    };
    ensure_login_method(&input, Some(&profile.defaults))
        .map_err(|err| (StatusCode::BAD_REQUEST, err))?;
    let resolved = resolve_create_payload(&profile.client, &profile.defaults, input, false)
        .await
        .map_err(internal_error)?;
    let instance = profile
        .client
        .create_instance(resolved.payload)
        .await
        .map_err(internal_error)?;
    notify_success(
        &profile.client.profile,
        &instance,
        NotifySource::Web,
        resolved.root_password.as_deref(),
    )
    .await;
    Ok(Json(instance))
}

#[derive(Debug, Deserialize)]
struct ProfileQuery {
    profile: Option<String>,
}

#[derive(Debug, Deserialize)]
struct RebootRequest {
    hard: Option<bool>,
}

async fn reboot_instance(
    State(state): State<AppState>,
    Path(id): Path<String>,
    Query(query): Query<ProfileQuery>,
    Json(payload): Json<RebootRequest>,
) -> Result<StatusCode, (StatusCode, String)> {
    let hard = payload.hard.unwrap_or(false);
    let profile = state.select_profile(query.profile.as_deref())?;
    profile
        .client
        .reboot_instance(&id, hard)
        .await
        .map_err(internal_error)?;
    Ok(StatusCode::NO_CONTENT)
}

async fn terminate_instance(
    State(state): State<AppState>,
    Path(id): Path<String>,
    Query(query): Query<ProfileQuery>,
) -> Result<StatusCode, (StatusCode, String)> {
    let profile = state.select_profile(query.profile.as_deref())?;
    profile
        .client
        .terminate_instance(&id)
        .await
        .map_err(internal_error)?;
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Debug, Deserialize)]
struct AvailabilityQuery {
    profile: Option<String>,
    compartment: Option<String>,
    availability_domain: Option<String>,
}

#[derive(Debug, Serialize)]
struct AvailabilityResponse {
    availability_domains: Vec<AvailabilityDomain>,
    shapes: Option<Vec<Shape>>,
}

async fn availability(
    State(state): State<AppState>,
    Query(query): Query<AvailabilityQuery>,
) -> Result<Json<AvailabilityResponse>, (StatusCode, String)> {
    let profile = state.select_profile(query.profile.as_deref())?;
    let compartment = query
        .compartment
        .or_else(|| profile.defaults.compartment.clone())
        .ok_or_else(|| (StatusCode::BAD_REQUEST, "Missing compartment".to_string()))?;
    let ads = profile
        .client
        .availability_domains(&compartment)
        .await
        .map_err(internal_error)?;
    let shapes = if let Some(ad) = query
        .availability_domain
        .or_else(|| profile.defaults.availability_domain.clone())
    {
        Some(
            profile
                .client
                .list_shapes(&compartment, &ad)
                .await
                .map_err(internal_error)?,
        )
    } else {
        None
    };
    Ok(Json(AvailabilityResponse {
        availability_domains: ads,
        shapes,
    }))
}

fn internal_error(err: anyhow::Error) -> (StatusCode, String) {
    (StatusCode::INTERNAL_SERVER_ERROR, err.to_string())
}

async fn list_tasks(State(state): State<AppState>) -> impl IntoResponse {
    let tasks = state.tasks.lock().unwrap();
    Json(tasks.clone())
}

async fn queue_instance(
    State(state): State<AppState>,
    Json(input): Json<CreateInput>,
) -> impl IntoResponse {
    let id = enqueue_task(&state, input);
    Json(serde_json::json!({ "taskId": id }))
}

async fn delete_task(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<StatusCode, (StatusCode, String)> {
    remove_task(&state, &id)
        .map(|_| StatusCode::NO_CONTENT)
        .map_err(|err| (StatusCode::NOT_FOUND, err))
}

async fn clear_tasks(State(state): State<AppState>) -> impl IntoResponse {
    clear_tasks_internal(&state);
    StatusCode::NO_CONTENT
}

fn remove_task(state: &AppState, id: &str) -> Result<(), String> {
    let mut tasks = state.tasks.lock().unwrap();
    if let Some(pos) = tasks.iter().position(|t| t.id == id) {
        let task = &tasks[pos];
        task.cancelled.store(true, Ordering::Relaxed);
        tasks.remove(pos);
        Ok(())
    } else {
        Err(format!("Task '{}' not found", id))
    }
}

fn clear_tasks_internal(state: &AppState) {
    let mut tasks = state.tasks.lock().unwrap();
    tasks.retain(|t| {
        let active = matches!(
            t.status,
            TaskStatus::Pending | TaskStatus::Running | TaskStatus::Retrying(_)
        );
        active && !t.cancelled.load(Ordering::Relaxed)
    });
}

fn enqueue_task(state: &AppState, input: CreateInput) -> String {
    let id = format!(
        "task-{}",
        SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_micros()
    );
    let target = input
        .profile
        .clone()
        .unwrap_or(state.default_profile.clone());
    let ad_info = input.availability_domain.as_deref().unwrap_or("auto");
    let desc = format!(
        "Create {} ({}, {})",
        input.display_name.clone().unwrap_or("instance".into()),
        target,
        ad_info
    );
    let cancelled = Arc::new(AtomicBool::new(false));

    let task = Task {
        id: id.clone(),
        target_profile: target,
        description: desc,
        status: TaskStatus::Pending,
        created_at: SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_secs(),
        retry_count: 0,
        last_error: None,
        next_retry_at: None,
        cancelled: cancelled.clone(),
    };

    {
        let mut tasks = state.tasks.lock().unwrap();
        tasks.push(task);
    }

    let state_clone = state.clone();
    let task_id = id.clone();
    let input_clone = input.clone();

    tokio::spawn(async move {
        let mut attempts = 0;
        let retry_interval: u64 = input_clone.retry_interval_secs.unwrap_or(60).max(10);
        loop {
            if cancelled.load(Ordering::Relaxed) {
                update_task_status(
                    &state_clone,
                    &task_id,
                    TaskStatus::Cancelled,
                    attempts,
                    None,
                    None,
                );
                break;
            }
            attempts += 1;
            update_task_status(
                &state_clone,
                &task_id,
                TaskStatus::Running,
                attempts,
                None,
                None,
            );

            match execute_creation(&state_clone, input_clone.clone()).await {
                Ok(inst) => {
                    update_task_status(
                        &state_clone,
                        &task_id,
                        TaskStatus::Success(format!("Created: {}", inst.display_name)),
                        attempts,
                        None,
                        None,
                    );
                    break;
                }
                Err(e) => {
                    let mut err_msg = e.to_string();
                    if err_msg.contains("Out of host capacity") {
                        err_msg = "Out of host capacity".to_string();
                    } else if err_msg.contains("LimitExceeded") {
                        err_msg = "Limit Exceeded".to_string();
                    }
                    if err_msg.contains("Missing compartment")
                        || err_msg.contains("缺少 compartment")
                        || err_msg.contains("Missing subnet")
                        || err_msg.contains("No available subnet")
                    {
                        update_task_status(
                            &state_clone,
                            &task_id,
                            TaskStatus::Failed(err_msg.clone()),
                            attempts,
                            Some(err_msg),
                            None,
                        );
                        break;
                    }
                    let now_secs = SystemTime::now()
                        .duration_since(SystemTime::UNIX_EPOCH)
                        .unwrap()
                        .as_secs();
                    let next_at = now_secs + retry_interval;
                    update_task_status(
                        &state_clone,
                        &task_id,
                        TaskStatus::Retrying(err_msg.clone()),
                        attempts,
                        Some(err_msg),
                        Some(next_at),
                    );
                    for _ in 0..retry_interval {
                        if cancelled.load(Ordering::Relaxed) {
                            update_task_status(
                                &state_clone,
                                &task_id,
                                TaskStatus::Cancelled,
                                attempts,
                                None,
                                None,
                            );
                            return;
                        }
                        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
                    }
                }
            }
        }
    });

    id
}

fn update_task_status(
    state: &AppState,
    id: &str,
    status: TaskStatus,
    count: u32,
    last_error: Option<String>,
    next_retry_at: Option<u64>,
) {
    let mut tasks = state.tasks.lock().unwrap();
    if let Some(task) = tasks.iter_mut().find(|t| t.id == id) {
        task.status = status;
        task.retry_count = count;
        if last_error.is_some() {
            task.last_error = last_error;
        }
        task.next_retry_at = next_retry_at;
    }
}

async fn execute_creation(state: &AppState, input: CreateInput) -> Result<InstanceSummary> {
    let target_profile_name = input
        .profile
        .as_deref()
        .unwrap_or(&state.default_profile)
        .to_uppercase();
    let Some(profile_state) = state.profiles.get(&target_profile_name) else {
        bail!("Profile '{}' not found", target_profile_name);
    };

    let payload =
        resolve_create_payload(&profile_state.client, &profile_state.defaults, input, false)
            .await?;
    let instance = profile_state
        .client
        .create_instance(payload.payload)
        .await?;
    notify_success(
        &profile_state.client.profile,
        &instance,
        NotifySource::Task,
        payload.root_password.as_deref(),
    )
    .await;
    Ok(instance)
}

fn start_telegram_bot_if_configured(state: AppState, notify: &NotificationConfig) {
    let Some(token) = notify.telegram_bot_token.clone() else {
        return;
    };
    let bind_state = telegram_bind::load_state();
    let bot_state = TelegramBotState {
        app: state,
        token,
        bind_state: Arc::new(Mutex::new(bind_state)),
        chat_profiles: Arc::new(Mutex::new(HashMap::new())),
        chat_compartments: Arc::new(Mutex::new(HashMap::new())),
        chat_availability_domains: Arc::new(Mutex::new(HashMap::new())),
        chat_shapes: Arc::new(Mutex::new(HashMap::new())),
        chat_shape_ocpus: Arc::new(Mutex::new(HashMap::new())),
        chat_shape_memory: Arc::new(Mutex::new(HashMap::new())),
        shape_cache: Arc::new(Mutex::new(HashMap::new())),
        chat_root_login: Arc::new(Mutex::new(HashMap::new())),
        chat_use_ssh_key: Arc::new(Mutex::new(HashMap::new())),
        chat_boot_volume_gbs: Arc::new(Mutex::new(HashMap::new())),
        chat_boot_volume_vpus: Arc::new(Mutex::new(HashMap::new())),
        chat_instance_cache: Arc::new(Mutex::new(HashMap::new())),
        compartment_cache: Arc::new(Mutex::new(HashMap::new())),
        last_actions: Arc::new(Mutex::new(HashMap::new())),
    };
    tokio::spawn(async move {
        telegram_poll_loop(bot_state).await;
    });
}

#[derive(Debug, Deserialize)]
struct TelegramUpdateResponse {
    ok: bool,
    result: Vec<TelegramUpdate>,
}

#[derive(Debug, Deserialize)]
struct TelegramUpdate {
    update_id: i64,
    message: Option<TelegramMessage>,
    callback_query: Option<TelegramCallbackQuery>,
}

#[derive(Debug, Deserialize)]
struct TelegramMessage {
    message_id: Option<i64>,
    chat: TelegramChat,
    text: Option<String>,
}

#[derive(Debug, Deserialize)]
struct TelegramChat {
    id: i64,
}

#[derive(Debug, Deserialize)]
struct TelegramUser {
    id: i64,
}

#[derive(Debug, Deserialize)]
struct TelegramCallbackQuery {
    id: String,
    from: TelegramUser,
    message: Option<TelegramMessage>,
    data: Option<String>,
}

#[derive(Debug, Serialize)]
struct TelegramUpdateQuery {
    timeout: u64,
    offset: i64,
    allowed_updates: Option<String>,
}

enum BotReply {
    Text(String),
    Inline {
        text: String,
        keyboard: serde_json::Value,
    },
    Reply {
        text: String,
        keyboard: serde_json::Value,
    },
}

async fn telegram_poll_loop(state: TelegramBotState) {
    let client = Client::new();
    let mut offset: i64 = 0;
    loop {
        match fetch_updates(&client, &state.token, offset).await {
            Ok(updates) => {
                for update in updates {
                    offset = update.update_id + 1;
                    let state_clone = state.clone();
                    let client_clone = client.clone();
                    tokio::spawn(async move {
                        handle_telegram_update(&state_clone, &client_clone, update).await;
                    });
                }
            }
            Err(err) => {
                warn!("Telegram polling failed: {}", err);
                tokio::time::sleep(std::time::Duration::from_secs(5)).await;
            }
        }
    }
}

async fn fetch_updates(client: &Client, token: &str, offset: i64) -> Result<Vec<TelegramUpdate>> {
    let url = format!("https://api.telegram.org/bot{}/getUpdates", token);
    let allowed_updates = serde_json::to_string(&vec!["message", "callback_query"]).ok();
    let query = TelegramUpdateQuery {
        timeout: 5,
        offset,
        allowed_updates,
    };
    let response = client.get(url).query(&query).send().await?;
    if !response.status().is_success() {
        let status = response.status();
        let body = response.text().await.unwrap_or_default();
        return Err(anyhow::anyhow!(
            "telegram getUpdates error {}: {}",
            status,
            body
        ));
    }
    let payload = response.json::<TelegramUpdateResponse>().await?;
    if !payload.ok {
        return Err(anyhow::anyhow!("telegram getUpdates returned ok=false"));
    }
    Ok(payload.result)
}

async fn handle_telegram_update(state: &TelegramBotState, client: &Client, update: TelegramUpdate) {
    if let Some(callback) = update.callback_query {
        handle_telegram_callback(state, client, callback).await;
    }
    if let Some(message) = update.message {
        handle_telegram_message(state, client, message).await;
    }
}

async fn handle_telegram_message(
    state: &TelegramBotState,
    client: &Client,
    message: TelegramMessage,
) {
    let Some(text) = message.text else {
        return;
    };
    let Some((command, args)) = parse_command(&text) else {
        return;
    };
    let chat_id = message.chat.id;

    let is_blocked = {
        let bind_state = state.bind_state.lock().unwrap();
        telegram_bind::is_blocked(&bind_state, chat_id)
    };
    if is_blocked {
        let _ = send_bot_message(client, &state.token, chat_id, "已被拉黑。").await;
        return;
    }

    let response = match command.as_str() {
        "start" => {
            if is_authorized(state, chat_id) {
                Ok(BotReply::Inline {
                    text: format!(
                        "已就绪（当前 Profile: {}）。点击下方菜单操作，输入 /help 查看指令。",
                        get_chat_profile(state, chat_id)
                    ),
                    keyboard: main_inline_menu(),
                })
            } else {
                Ok(BotReply::Reply {
                    text: "请先绑定：/bind <admin_key>".to_string(),
                    keyboard: bind_keyboard(),
                })
            }
        }
        "help" => {
            if is_authorized(state, chat_id) {
                Ok(BotReply::Inline {
                    text: help_text(),
                    keyboard: main_inline_menu(),
                })
            } else {
                Ok(BotReply::Reply {
                    text: "请先绑定：/bind <admin_key>".to_string(),
                    keyboard: bind_keyboard(),
                })
            }
        }
        "menu" => {
            if is_authorized(state, chat_id) {
                Ok(BotReply::Inline {
                    text: menu_text(state, chat_id),
                    keyboard: main_inline_menu(),
                })
            } else {
                Ok(BotReply::Reply {
                    text: "请先绑定：/bind <admin_key>".to_string(),
                    keyboard: bind_keyboard(),
                })
            }
        }
        "bind" => match handle_bind_command(state, chat_id, &args) {
            Ok(text) => Ok(BotReply::Inline {
                text,
                keyboard: main_inline_menu(),
            }),
            Err(text) => Ok(BotReply::Reply {
                text,
                keyboard: bind_keyboard(),
            }),
        },
        _ => {
            if !is_authorized(state, chat_id) {
                let (count, blocked) = {
                    let mut bind_state = state.bind_state.lock().unwrap();
                    telegram_bind::record_failure(&mut bind_state, chat_id).unwrap_or((3, true))
                };
                if blocked {
                    Ok(BotReply::Text("未授权，已被拉黑。".to_string()))
                } else {
                    Ok(BotReply::Reply {
                        text: format!("未授权，第 {}/3 次。请先 /bind <admin_key>。", count),
                        keyboard: bind_keyboard(),
                    })
                }
            } else {
                handle_authed_command(state, chat_id, &command, &args).await
            }
        }
    };

    let reply = match response {
        Ok(value) => value,
        Err(value) => BotReply::Text(value),
    };
    if let Err(err) = send_bot_reply(client, &state.token, chat_id, reply).await {
        warn!("Telegram sendBotReply failed: {}", err);
    }
}

async fn handle_telegram_callback(
    state: &TelegramBotState,
    client: &Client,
    callback: TelegramCallbackQuery,
) {
    let chat_id = callback
        .message
        .as_ref()
        .map(|msg| msg.chat.id)
        .unwrap_or(callback.from.id);
    let data = callback.data.unwrap_or_default();
    let message_id = callback.message.as_ref().and_then(|msg| msg.message_id);

    let is_blocked = {
        let bind_state = state.bind_state.lock().unwrap();
        telegram_bind::is_blocked(&bind_state, chat_id)
    };
    if is_blocked {
        if let Err(err) =
            answer_callback_query(client, &state.token, &callback.id, Some("已被拉黑。")).await
        {
            warn!("Telegram answerCallbackQuery failed: {}", err);
        }
        return;
    }

    if let Some(text) = check_telegram_callback_throttle(state, chat_id, &data) {
        if let Err(err) =
            answer_callback_query(client, &state.token, &callback.id, Some(text)).await
        {
            warn!("Telegram answerCallbackQuery failed: {}", err);
        }
        return;
    }

    let reply = if !is_authorized(state, chat_id) {
        let (count, blocked) = {
            let mut bind_state = state.bind_state.lock().unwrap();
            telegram_bind::record_failure(&mut bind_state, chat_id).unwrap_or((3, true))
        };
        if blocked {
            BotReply::Text("未授权，已被拉黑。".to_string())
        } else {
            BotReply::Reply {
                text: format!("未授权，第 {}/3 次。请先 /bind <admin_key>。", count),
                keyboard: bind_keyboard(),
            }
        }
    } else {
        let reply = match data.as_str() {
            "menu" => BotReply::Inline {
                text: menu_text(state, chat_id),
                keyboard: main_inline_menu(),
            },
            "help" => BotReply::Inline {
                text: help_text(),
                keyboard: main_inline_menu(),
            },
            "profiles" => {
                if state.app.profiles.is_empty() {
                    BotReply::Inline {
                        text: no_profile_text(),
                        keyboard: main_inline_menu(),
                    }
                } else {
                    let mut profiles = state.app.profiles.keys().cloned().collect::<Vec<_>>();
                    profiles.sort();
                    BotReply::Inline {
                        text: "选择 Profile：".to_string(),
                        keyboard: profiles_inline_menu(&profiles),
                    }
                }
            }
            "compartments" => match handle_compartments_menu(state, chat_id).await {
                Ok(reply) => reply,
                Err(err) => BotReply::Inline {
                    text: err,
                    keyboard: main_inline_menu(),
                },
            },
            value if value.starts_with("profile_set:") => {
                let name = value.trim_start_matches("profile_set:");
                let key = name.trim().to_uppercase();
                if !state.app.profiles.contains_key(&key) {
                    BotReply::Text(format!("Profile '{}' 不存在。", key))
                } else {
                    let mut profiles = state.chat_profiles.lock().unwrap();
                    profiles.insert(chat_id, key.clone());
                    clear_chat_selections(state, chat_id);
                    BotReply::Inline {
                        text: format!(
                            "Profile 已切换为 {}（分区=自动(根分区)，可用区已清空）。",
                            key
                        ),
                        keyboard: main_inline_menu(),
                    }
                }
            }
            value if value.starts_with("compartment_pick:") => {
                let idx = value.trim_start_matches("compartment_pick:");
                match handle_compartment_pick(state, chat_id, idx) {
                    Ok(reply) => reply,
                    Err(err) => BotReply::Inline {
                        text: err,
                        keyboard: main_inline_menu(),
                    },
                }
            }
            "compartment_default" => match handle_compartment_default(state, chat_id).await {
                Ok(reply) => reply,
                Err(err) => BotReply::Inline {
                    text: err,
                    keyboard: main_inline_menu(),
                },
            },
            "compartment_clear" => {
                state.chat_compartments.lock().unwrap().remove(&chat_id);
                clear_chat_after_compartment_change(state, chat_id);
                BotReply::Inline {
                    text: "分区已切换为自动(根分区)。".to_string(),
                    keyboard: main_inline_menu(),
                }
            }
            "presets" => {
                let presets = state.app.presets.as_ref();
                BotReply::Inline {
                    text: "选择 Preset：".to_string(),
                    keyboard: presets_inline_menu(presets),
                }
            }
            value if value.starts_with("preset_create:") => {
                let idx = value.trim_start_matches("preset_create:");
                let reply = preset_action(state, chat_id, idx, true).await;
                match reply {
                    Ok(result) => result,
                    Err(err) => BotReply::Text(err),
                }
            }
            value if value.starts_with("preset_queue:") => {
                let idx = value.trim_start_matches("preset_queue:");
                let reply = preset_action(state, chat_id, idx, true).await;
                match reply {
                    Ok(result) => result,
                    Err(err) => BotReply::Text(err),
                }
            }
            "instances" => match handle_instances_menu(state, chat_id).await {
                Ok(reply) => reply,
                Err(err) => BotReply::Inline {
                    text: err,
                    keyboard: main_inline_menu(),
                },
            },
            value if value.starts_with("instance_pick:") => {
                let idx = value.trim_start_matches("instance_pick:");
                match handle_instance_pick(state, chat_id, idx) {
                    Ok(reply) => reply,
                    Err(err) => BotReply::Inline {
                        text: err,
                        keyboard: main_inline_menu(),
                    },
                }
            }
            value if value.starts_with("instance_reboot_hard:") => {
                let idx = value.trim_start_matches("instance_reboot_hard:");
                match handle_instance_reboot(state, chat_id, idx, true).await {
                    Ok(reply) => reply,
                    Err(err) => BotReply::Inline {
                        text: err,
                        keyboard: main_inline_menu(),
                    },
                }
            }
            value if value.starts_with("instance_reboot:") => {
                let idx = value.trim_start_matches("instance_reboot:");
                match handle_instance_reboot(state, chat_id, idx, false).await {
                    Ok(reply) => reply,
                    Err(err) => BotReply::Inline {
                        text: err,
                        keyboard: main_inline_menu(),
                    },
                }
            }
            value if value.starts_with("instance_terminate:") => {
                let idx = value.trim_start_matches("instance_terminate:");
                match get_instance_from_cache(state, chat_id, idx) {
                    Ok((_list, instance, index)) => BotReply::Inline {
                        text: format!(
                            "{}\n\n⚠️ 确认删除该实例？",
                            format_instance_detail(&instance)
                        ),
                        keyboard: instance_confirm_menu(index),
                    },
                    Err(err) => BotReply::Inline {
                        text: err,
                        keyboard: main_inline_menu(),
                    },
                }
            }
            value if value.starts_with("instance_terminate_confirm:") => {
                let idx = value.trim_start_matches("instance_terminate_confirm:");
                match handle_instance_terminate_confirm(state, chat_id, idx).await {
                    Ok(reply) => reply,
                    Err(err) => BotReply::Inline {
                        text: err,
                        keyboard: main_inline_menu(),
                    },
                }
            }
            "availability" => match handle_availability_menu(state, chat_id).await {
                Ok(reply) => reply,
                Err(err) => BotReply::Inline {
                    text: err,
                    keyboard: main_inline_menu(),
                },
            },
            "boot_volume" => match handle_boot_volume_menu(state, chat_id) {
                Ok(reply) => reply,
                Err(err) => BotReply::Inline {
                    text: err,
                    keyboard: main_inline_menu(),
                },
            },
            "shapes" => match handle_shapes_menu(state, chat_id).await {
                Ok(reply) => reply,
                Err(err) => BotReply::Inline {
                    text: err,
                    keyboard: main_inline_menu(),
                },
            },
            value if value.starts_with("boot_set:") => {
                let raw = value.trim_start_matches("boot_set:");
                match raw.parse::<u64>() {
                    Ok(size) => {
                        state
                            .chat_boot_volume_gbs
                            .lock()
                            .unwrap()
                            .insert(chat_id, size);
                        BotReply::Inline {
                            text: format!("硬盘大小已设置为 {} GB。", size),
                            keyboard: main_inline_menu(),
                        }
                    }
                    Err(_) => BotReply::Inline {
                        text: "硬盘大小无效。".to_string(),
                        keyboard: main_inline_menu(),
                    },
                }
            }
            "boot_clear" => {
                state.chat_boot_volume_gbs.lock().unwrap().remove(&chat_id);
                BotReply::Inline {
                    text: "硬盘已恢复默认(自动)。".to_string(),
                    keyboard: main_inline_menu(),
                }
            }
            "boot_perf" => match handle_boot_perf_menu(state, chat_id) {
                Ok(reply) => reply,
                Err(err) => BotReply::Inline {
                    text: err,
                    keyboard: main_inline_menu(),
                },
            },
            value if value.starts_with("bvpus_set:") => {
                let raw = value.trim_start_matches("bvpus_set:");
                match raw.parse::<u64>() {
                    Ok(vpus) => {
                        state
                            .chat_boot_volume_vpus
                            .lock()
                            .unwrap()
                            .insert(chat_id, vpus);
                        BotReply::Inline {
                            text: format!("引导卷性能已设置为 {} VPUs/GB。", vpus),
                            keyboard: main_inline_menu(),
                        }
                    }
                    Err(_) => BotReply::Inline {
                        text: "性能值无效。".to_string(),
                        keyboard: main_inline_menu(),
                    },
                }
            }
            "bvpus_clear" => {
                state.chat_boot_volume_vpus.lock().unwrap().remove(&chat_id);
                BotReply::Inline {
                    text: "引导卷性能已恢复默认。".to_string(),
                    keyboard: main_inline_menu(),
                }
            }
            value if value.starts_with("shapes_page:") => {
                let raw = value.trim_start_matches("shapes_page:");
                match raw.parse::<usize>() {
                    Ok(page) => match handle_shapes_menu_page(state, chat_id, page).await {
                        Ok(reply) => reply,
                        Err(err) => BotReply::Inline {
                            text: err,
                            keyboard: main_inline_menu(),
                        },
                    },
                    Err(_) => BotReply::Inline {
                        text: "机型页码无效。".to_string(),
                        keyboard: main_inline_menu(),
                    },
                }
            }
            value if value.starts_with("shape_set:") => {
                let name = value.trim_start_matches("shape_set:");
                if name.is_empty() {
                    BotReply::Inline {
                        text: "机型无效。".to_string(),
                        keyboard: main_inline_menu(),
                    }
                } else {
                    state
                        .chat_shapes
                        .lock()
                        .unwrap()
                        .insert(chat_id, name.to_string());
                    state.chat_shape_ocpus.lock().unwrap().remove(&chat_id);
                    state.chat_shape_memory.lock().unwrap().remove(&chat_id);
                    let is_flex = shape_from_cache(state, chat_id, name)
                        .map(|shape| is_flex_shape(&shape))
                        .unwrap_or_else(|| name.to_uppercase().contains(".FLEX"));
                    if is_flex {
                        match handle_shape_ocpu_menu(state, chat_id, 0) {
                            Ok(reply) => reply,
                            Err(err) => BotReply::Inline {
                                text: format!("机型已选择：{}。\n{}", name, err),
                                keyboard: main_inline_menu(),
                            },
                        }
                    } else {
                        match handle_boot_volume_menu_with_back(
                            state,
                            chat_id,
                            Some("shapes"),
                            Some(format!("机型已选择：{}。", name)),
                        ) {
                            Ok(reply) => reply,
                            Err(err) => BotReply::Inline {
                                text: format!("机型已选择：{}。\n{}", name, err),
                                keyboard: main_inline_menu(),
                            },
                        }
                    }
                }
            }
            value if value.starts_with("shape_ocpu:") => {
                let raw = value.trim_start_matches("shape_ocpu:");
                match raw.parse::<u32>() {
                    Ok(value) => {
                        state
                            .chat_shape_ocpus
                            .lock()
                            .unwrap()
                            .insert(chat_id, value as f64);
                        state.chat_shape_memory.lock().unwrap().remove(&chat_id);
                        match handle_shape_memory_menu(state, chat_id, 0) {
                            Ok(reply) => reply,
                            Err(err) => BotReply::Inline {
                                text: format!("OCPU 已选择：{}。\n{}", value, err),
                                keyboard: main_inline_menu(),
                            },
                        }
                    }
                    Err(_) => BotReply::Inline {
                        text: "OCPU 选项无效。".to_string(),
                        keyboard: main_inline_menu(),
                    },
                }
            }
            value if value.starts_with("shape_mem:") => {
                let raw = value.trim_start_matches("shape_mem:");
                match raw.parse::<u32>() {
                    Ok(value) => {
                        state
                            .chat_shape_memory
                            .lock()
                            .unwrap()
                            .insert(chat_id, value as f64);
                        let summary = format_shape_selection(state, chat_id);
                        match handle_boot_volume_menu_with_back(
                            state,
                            chat_id,
                            Some("shape_mem_page:0"),
                            Some(format!("内存已选择：{} GB。\n当前机型：{}", value, summary)),
                        ) {
                            Ok(reply) => reply,
                            Err(err) => BotReply::Inline {
                                text: format!("内存已选择：{} GB。\n{}", value, err),
                                keyboard: main_inline_menu(),
                            },
                        }
                    }
                    Err(_) => BotReply::Inline {
                        text: "内存选项无效。".to_string(),
                        keyboard: main_inline_menu(),
                    },
                }
            }
            value if value.starts_with("shape_ocpu_page:") => {
                let raw = value.trim_start_matches("shape_ocpu_page:");
                match raw.parse::<usize>() {
                    Ok(page) => match handle_shape_ocpu_menu(state, chat_id, page) {
                        Ok(reply) => reply,
                        Err(err) => BotReply::Inline {
                            text: err,
                            keyboard: main_inline_menu(),
                        },
                    },
                    Err(_) => BotReply::Inline {
                        text: "OCPU 页码无效。".to_string(),
                        keyboard: main_inline_menu(),
                    },
                }
            }
            value if value.starts_with("shape_mem_page:") => {
                let raw = value.trim_start_matches("shape_mem_page:");
                match raw.parse::<usize>() {
                    Ok(page) => match handle_shape_memory_menu(state, chat_id, page) {
                        Ok(reply) => reply,
                        Err(err) => {
                            if err.contains("OCPU") {
                                match handle_shape_ocpu_menu(state, chat_id, 0) {
                                    Ok(reply) => reply,
                                    Err(err) => BotReply::Inline {
                                        text: err,
                                        keyboard: main_inline_menu(),
                                    },
                                }
                            } else {
                                BotReply::Inline {
                                    text: err,
                                    keyboard: main_inline_menu(),
                                }
                            }
                        }
                    },
                    Err(_) => BotReply::Inline {
                        text: "内存页码无效。".to_string(),
                        keyboard: main_inline_menu(),
                    },
                }
            }
            "shape_flex_auto" => {
                state.chat_shape_ocpus.lock().unwrap().remove(&chat_id);
                state.chat_shape_memory.lock().unwrap().remove(&chat_id);
                BotReply::Inline {
                    text: "CPU/内存已恢复自动选择。".to_string(),
                    keyboard: main_inline_menu(),
                }
            }
            "shape_clear" => {
                state.chat_shapes.lock().unwrap().remove(&chat_id);
                state.chat_shape_ocpus.lock().unwrap().remove(&chat_id);
                state.chat_shape_memory.lock().unwrap().remove(&chat_id);
                BotReply::Inline {
                    text: "机型已恢复自动选择。".to_string(),
                    keyboard: main_inline_menu(),
                }
            }
            value if value.starts_with("ad_set:") => {
                let name = value.trim_start_matches("ad_set:");
                if name.is_empty() {
                    BotReply::Inline {
                        text: "可用区无效。".to_string(),
                        keyboard: main_inline_menu(),
                    }
                } else {
                    let mut notice = {
                        let mut list_map = state.chat_availability_domains.lock().unwrap();
                        let list = list_map.entry(chat_id).or_default();
                        let mut action = "已加入";
                        if let Some(pos) = list.iter().position(|item| item == name) {
                            list.remove(pos);
                            action = "已移除";
                        } else {
                            list.push(name.to_string());
                        }
                        if list.is_empty() {
                            format!("{}可用区：{}，已恢复自动选择。", action, name)
                        } else {
                            format!("{}可用区：{}。", action, name)
                        }
                    };
                    state.chat_shapes.lock().unwrap().remove(&chat_id);
                    state.chat_shape_ocpus.lock().unwrap().remove(&chat_id);
                    state.chat_shape_memory.lock().unwrap().remove(&chat_id);
                    state.shape_cache.lock().unwrap().remove(&chat_id);
                    notice.push_str("\n可用区已变更，机型已清空。");
                    match handle_availability_menu(state, chat_id).await {
                        Ok(BotReply::Inline { text, keyboard }) => BotReply::Inline {
                            text: format!("{}\n{}", notice, text),
                            keyboard,
                        },
                        Ok(other) => other,
                        Err(err) => BotReply::Inline {
                            text: err,
                            keyboard: main_inline_menu(),
                        },
                    }
                }
            }
            "ad_clear" => {
                state
                    .chat_availability_domains
                    .lock()
                    .unwrap()
                    .remove(&chat_id);
                state.chat_shapes.lock().unwrap().remove(&chat_id);
                state.chat_shape_ocpus.lock().unwrap().remove(&chat_id);
                state.chat_shape_memory.lock().unwrap().remove(&chat_id);
                state.shape_cache.lock().unwrap().remove(&chat_id);
                match handle_availability_menu(state, chat_id).await {
                    Ok(BotReply::Inline { text, keyboard }) => BotReply::Inline {
                        text: format!("可用区已恢复自动选择，机型已清空。\n{}", text),
                        keyboard,
                    },
                    Ok(other) => other,
                    Err(err) => BotReply::Inline {
                        text: err,
                        keyboard: main_inline_menu(),
                    },
                }
            }
            "tasks" => match handle_tasks_command(state, chat_id, &[]) {
                Ok(result) => wrap_text_reply_with_menu(result),
                Err(err) => BotReply::Inline {
                    text: err,
                    keyboard: main_inline_menu(),
                },
            },
            "tasks_clear" => {
                clear_tasks_internal(&state.app);
                BotReply::Inline {
                    text: "任务已清理。".to_string(),
                    keyboard: main_inline_menu(),
                }
            }
            "root_toggle" => {
                let enabled = {
                    let mut map = state.chat_root_login.lock().unwrap();
                    let entry = map.entry(chat_id).or_insert(false);
                    *entry = !*entry;
                    *entry
                };
                let text = if enabled {
                    "Root 登录已开启，将生成随机密码并发送通知。".to_string()
                } else {
                    "Root 登录已关闭。".to_string()
                };
                BotReply::Inline {
                    text,
                    keyboard: main_inline_menu(),
                }
            }
            "ssh_toggle" => {
                let enabled = {
                    let mut map = state.chat_use_ssh_key.lock().unwrap();
                    let entry = map.entry(chat_id).or_insert(true);
                    *entry = !*entry;
                    *entry
                };
                let text = if enabled {
                    "SSH 公钥已开启。".to_string()
                } else {
                    "SSH 公钥已关闭。".to_string()
                };
                BotReply::Inline {
                    text,
                    keyboard: main_inline_menu(),
                }
            }
            value if value.starts_with("task_stop:") => {
                let id = value.trim_start_matches("task_stop:");
                let reply =
                    handle_task_command(state, chat_id, &["stop".to_string(), id.to_string()]);
                match reply {
                    Ok(text) => BotReply::Inline {
                        text,
                        keyboard: main_inline_menu(),
                    },
                    Err(err) => BotReply::Inline {
                        text: err,
                        keyboard: main_inline_menu(),
                    },
                }
            }
            "bind" => BotReply::Reply {
                text: "请发送：/bind <admin_key>".to_string(),
                keyboard: bind_keyboard(),
            },
            _ => BotReply::Text("未知操作。".to_string()),
        };
        wrap_text_reply_with_menu(reply)
    };

    if let Err(err) = answer_callback_query(client, &state.token, &callback.id, None).await {
        warn!("Telegram answerCallbackQuery failed: {}", err);
    }
    if let Err(err) =
        send_bot_reply_for_callback(client, &state.token, chat_id, message_id, reply).await
    {
        warn!("Telegram sendBotReply failed: {}", err);
    }
}

fn menu_text(state: &TelegramBotState, chat_id: i64) -> String {
    let profile = get_chat_profile(state, chat_id);
    let compartment =
        get_chat_compartment_label(state, chat_id).unwrap_or("自动(根分区)".to_string());
    let ad = get_chat_availability_label(state, chat_id);
    let shape = format_shape_selection(state, chat_id);
    let root_login = match get_chat_root_login(state, chat_id) {
        Some(true) => "开启",
        Some(false) => "关闭",
        None => "关闭",
    };
    let use_ssh_key = match get_chat_use_ssh_key(state, chat_id) {
        Some(true) => "开启",
        Some(false) => "关闭",
        None => "开启",
    };
    let boot = match get_chat_boot_volume_gbs(state, chat_id) {
        Some(size) => format!("{} GB", size),
        None => "默认".to_string(),
    };
    let boot_perf = match get_chat_boot_volume_vpus(state, chat_id) {
        Some(vpus) => format!("{}VPUs", vpus),
        None => "默认".to_string(),
    };
    format!(
        "菜单已加载（Profile: {}，分区: {}，可用区: {}，机型: {}，硬盘: {}，性能: {}，Root 登录: {}，SSH 公钥: {}）。点击按钮操作。",
        profile, compartment, ad, shape, boot, boot_perf, root_login, use_ssh_key
    )
}

fn wrap_text_reply_with_menu(reply: BotReply) -> BotReply {
    match reply {
        BotReply::Text(text) => BotReply::Inline {
            text,
            keyboard: main_inline_menu(),
        },
        other => other,
    }
}

fn check_telegram_callback_throttle(
    state: &TelegramBotState,
    chat_id: i64,
    data: &str,
) -> Option<&'static str> {
    let mut actions = state.last_actions.lock().unwrap();
    let now = Instant::now();
    if let Some(last) = actions.get(&chat_id) {
        let elapsed = now.duration_since(last.at);
        if elapsed < Duration::from_millis(350) {
            return Some("操作太快，请稍后再试。");
        }
        if last.key == data && elapsed < Duration::from_secs(2) {
            return Some("已收到，请勿重复点击。");
        }
    }
    actions.insert(
        chat_id,
        LastAction {
            key: data.to_string(),
            at: now,
        },
    );
    None
}

fn parse_command(text: &str) -> Option<(String, Vec<String>)> {
    let trimmed = text.trim();
    if !trimmed.starts_with('/') {
        return None;
    }
    let mut parts = trimmed.split_whitespace();
    let raw = parts.next()?.trim_start_matches('/');
    let cmd = raw.split('@').next().unwrap_or(raw).to_lowercase();
    let args = parts.map(|item| item.to_string()).collect::<Vec<_>>();
    Some((cmd, args))
}

fn help_text() -> String {
    [
        "快捷菜单已加载（建议用按钮，机型内含硬盘选择）。",
        "常用指令：",
        "/bind <admin_key>",
        "/menu | /help",
        "/profile | /profile list | /profile set <NAME>",
        "/compartment",
        "/boot | /boot_volume",
        "/shape",
        "/presets",
        "/instances [profile=NAME] [compartment=OCID]",
        "/availability [profile=NAME] [compartment=OCID] [availability_domain=AD]",
        "/create key=value ...（Telegram 中等同后台执行）",
        "/queue key=value ...",
        "/tasks | /tasks clear",
        "/task stop <TASK_ID>",
        "",
        "Create/Queue 参数：",
        "compartment, subnet, shape, ocpus, memory_gbs, boot_volume_gbs,",
        "availability_domain, image, image_os, image_version, display_name,",
        "ssh_key, use_ssh_key, root_login, retry_interval_secs, profile, preset",
    ]
    .join("\n")
}

fn bind_keyboard() -> serde_json::Value {
    serde_json::json!({
        "keyboard": [[{ "text": "/bind" }]],
        "resize_keyboard": true,
        "one_time_keyboard": false
    })
}

fn main_inline_menu() -> serde_json::Value {
    serde_json::json!({
        "inline_keyboard": [
            [{ "text": "配置", "callback_data": "profiles" }, { "text": "分区", "callback_data": "compartments" }],
            [{ "text": "预设", "callback_data": "presets" }, { "text": "机型", "callback_data": "shapes" }],
            [{ "text": "可用区", "callback_data": "availability" }, { "text": "硬盘", "callback_data": "boot_volume" }],
            [{ "text": "实例", "callback_data": "instances" }, { "text": "任务", "callback_data": "tasks" }],
            [{ "text": "Root 登录", "callback_data": "root_toggle" }, { "text": "SSH 公钥", "callback_data": "ssh_toggle" }],
            [{ "text": "帮助", "callback_data": "help" }]
        ]
    })
}

fn profiles_inline_menu(profiles: &[String]) -> serde_json::Value {
    let mut rows = Vec::new();
    for name in profiles.iter().take(12) {
        rows.push(vec![serde_json::json!({
            "text": name,
            "callback_data": format!("profile_set:{}", name)
        })]);
    }
    rows.push(vec![
        serde_json::json!({ "text": "返回菜单", "callback_data": "menu" }),
    ]);
    serde_json::json!({ "inline_keyboard": rows })
}

fn compartments_inline_menu(
    items: &[CompartmentItem],
    selected_id: Option<&str>,
    has_config_default: bool,
) -> serde_json::Value {
    let mut rows = Vec::new();
    for (idx, item) in items.iter().take(10).enumerate() {
        let is_selected = selected_id.map(|id| id == item.id).unwrap_or(false);
        let label = if is_selected {
            format!("✅ {}", item.name)
        } else {
            item.name.clone()
        };
        rows.push(vec![serde_json::json!({
            "text": label,
            "callback_data": format!("compartment_pick:{}", idx)
        })]);
    }
    let mut tail = Vec::new();
    if has_config_default {
        tail.push(serde_json::json!({
            "text": "使用配置默认",
            "callback_data": "compartment_default"
        }));
    } else {
        tail.push(serde_json::json!({
            "text": "配置默认(未设置)",
            "callback_data": "compartment_default"
        }));
    }
    tail.push(serde_json::json!({
        "text": "自动(根分区)",
        "callback_data": "compartment_clear"
    }));
    tail.push(serde_json::json!({ "text": "返回菜单", "callback_data": "menu" }));
    rows.push(tail);
    serde_json::json!({ "inline_keyboard": rows })
}

fn presets_inline_menu(presets: &[Preset]) -> serde_json::Value {
    let mut rows = Vec::new();
    for (idx, preset) in presets.iter().take(10).enumerate() {
        rows.push(vec![serde_json::json!({
            "text": format!("✅ 后台执行 {}", preset.name),
            "callback_data": format!("preset_queue:{}", idx)
        })]);
    }
    rows.push(vec![
        serde_json::json!({ "text": "返回菜单", "callback_data": "menu" }),
    ]);
    serde_json::json!({ "inline_keyboard": rows })
}

fn availability_inline_menu(ads: &[AvailabilityDomain], selected: &[String]) -> serde_json::Value {
    let mut rows = Vec::new();
    for ad in ads.iter().take(10) {
        let is_selected = selected.iter().any(|item| item == &ad.name);
        let label = if is_selected {
            format!("✅ {}", ad.name)
        } else {
            ad.name.clone()
        };
        rows.push(vec![serde_json::json!({
            "text": label,
            "callback_data": format!("ad_set:{}", ad.name)
        })]);
    }
    rows.push(vec![
        serde_json::json!({ "text": "自动选择", "callback_data": "ad_clear" }),
        serde_json::json!({ "text": "返回菜单", "callback_data": "menu" }),
    ]);
    serde_json::json!({ "inline_keyboard": rows })
}

const SHAPE_PAGE_SIZE: usize = 12;

fn shapes_inline_menu(shapes: &[Shape], selected: Option<&str>, page: usize) -> serde_json::Value {
    let total_pages = shapes.len().div_ceil(SHAPE_PAGE_SIZE);
    let page = page.min(total_pages.saturating_sub(1));
    let start = page * SHAPE_PAGE_SIZE;
    let end = (start + SHAPE_PAGE_SIZE).min(shapes.len());
    let mut rows = Vec::new();
    for shape in shapes.iter().skip(start).take(end - start) {
        let is_selected = selected.map(|v| v == shape.shape).unwrap_or(false);
        let label = if is_selected {
            format!("✅ {}", shape.shape)
        } else {
            shape.shape.clone()
        };
        rows.push(vec![serde_json::json!({
            "text": label,
            "callback_data": format!("shape_set:{}", shape.shape)
        })]);
    }
    if total_pages > 1 {
        let mut nav = Vec::new();
        if page > 0 {
            nav.push(serde_json::json!({
                "text": "◀️",
                "callback_data": format!("shapes_page:{}", page - 1)
            }));
        }
        if page + 1 < total_pages {
            nav.push(serde_json::json!({
                "text": "▶️",
                "callback_data": format!("shapes_page:{}", page + 1)
            }));
        }
        if !nav.is_empty() {
            rows.push(nav);
        }
    }
    rows.push(vec![
        serde_json::json!({ "text": "清除机型", "callback_data": "shape_clear" }),
        serde_json::json!({ "text": "返回菜单", "callback_data": "menu" }),
    ]);
    serde_json::json!({ "inline_keyboard": rows })
}

const FLEX_PAGE_SIZE: usize = 12;

fn shape_from_cache(state: &TelegramBotState, chat_id: i64, name: &str) -> Option<Shape> {
    let cache = state.shape_cache.lock().unwrap();
    cache
        .get(&chat_id)
        .and_then(|items| items.iter().find(|shape| shape.shape == name).cloned())
}

fn is_flex_shape(shape: &Shape) -> bool {
    shape
        .is_flexible
        .unwrap_or_else(|| shape.shape.to_uppercase().contains(".FLEX"))
}

fn ocpu_values(shape: &Shape) -> Option<Vec<u32>> {
    if let Some(opts) = shape.ocpu_options.as_ref() {
        let min = opts.min?.round() as i64;
        let max = opts.max?.round() as i64;
        if min <= 0 || max < min {
            return None;
        }
        return Some((min..=max).map(|v| v as u32).collect());
    }
    shape.ocpus.map(|value| vec![value.round().max(1.0) as u32])
}

fn memory_range(shape: &Shape, ocpus: f64) -> Option<(u32, u32)> {
    let opts = shape.memory_options.as_ref()?;
    let mut min = opts.min_in_gbs;
    let mut max = opts.max_in_gbs;
    if let Some(value) = opts.min_per_ocpu_in_gbs {
        let calc = value * ocpus;
        min = Some(min.map(|v| v.max(calc)).unwrap_or(calc));
    }
    if let Some(value) = opts.max_per_ocpu_in_gbs {
        let calc = value * ocpus;
        max = Some(max.map(|v| v.min(calc)).unwrap_or(calc));
    }
    let min = min?.round() as i64;
    let max = max?.round() as i64;
    if min <= 0 || max < min {
        return None;
    }
    Some((min as u32, max as u32))
}

fn memory_values(shape: &Shape, ocpus: f64) -> Option<Vec<u32>> {
    if let Some((min, max)) = memory_range(shape, ocpus) {
        let span = max.saturating_sub(min);
        let step = if span > 512 {
            8
        } else if span > 128 {
            4
        } else {
            1
        };
        let mut values = Vec::new();
        let mut current = min;
        while current <= max {
            values.push(current);
            current = current.saturating_add(step);
            if current == 0 {
                break;
            }
        }
        return Some(values);
    }
    shape
        .memory_in_gbs
        .map(|value| vec![value.round().max(1.0) as u32])
}

fn paginate_values(values: &[u32], page: usize) -> (Vec<u32>, usize) {
    if values.is_empty() {
        return (Vec::new(), 0);
    }
    let total_pages = values.len().div_ceil(FLEX_PAGE_SIZE);
    let page = page.min(total_pages.saturating_sub(1));
    let start = page * FLEX_PAGE_SIZE;
    let end = (start + FLEX_PAGE_SIZE).min(values.len());
    (values[start..end].to_vec(), total_pages)
}

fn ocpu_inline_menu(
    values: &[u32],
    selected: Option<u32>,
    page: usize,
    total_pages: usize,
) -> serde_json::Value {
    let mut rows = Vec::new();
    for chunk in values.chunks(3) {
        let mut row = Vec::new();
        for value in chunk {
            let label = if selected == Some(*value) {
                format!("✅ {} OCPU", value)
            } else {
                format!("{} OCPU", value)
            };
            row.push(serde_json::json!({
                "text": label,
                "callback_data": format!("shape_ocpu:{}", value)
            }));
        }
        rows.push(row);
    }
    if total_pages > 1 {
        let mut nav = Vec::new();
        if page > 0 {
            nav.push(serde_json::json!({
                "text": "◀️",
                "callback_data": format!("shape_ocpu_page:{}", page - 1)
            }));
        }
        if page + 1 < total_pages {
            nav.push(serde_json::json!({
                "text": "▶️",
                "callback_data": format!("shape_ocpu_page:{}", page + 1)
            }));
        }
        if !nav.is_empty() {
            rows.push(nav);
        }
    }
    rows.push(vec![
        serde_json::json!({ "text": "自动 CPU/内存", "callback_data": "shape_flex_auto" }),
        serde_json::json!({ "text": "返回机型", "callback_data": "shapes" }),
    ]);
    rows.push(vec![
        serde_json::json!({ "text": "返回菜单", "callback_data": "menu" }),
    ]);
    serde_json::json!({ "inline_keyboard": rows })
}

fn memory_inline_menu(
    values: &[u32],
    selected: Option<u32>,
    page: usize,
    total_pages: usize,
) -> serde_json::Value {
    let mut rows = Vec::new();
    for chunk in values.chunks(3) {
        let mut row = Vec::new();
        for value in chunk {
            let label = if selected == Some(*value) {
                format!("✅ {} GB", value)
            } else {
                format!("{} GB", value)
            };
            row.push(serde_json::json!({
                "text": label,
                "callback_data": format!("shape_mem:{}", value)
            }));
        }
        rows.push(row);
    }
    if total_pages > 1 {
        let mut nav = Vec::new();
        if page > 0 {
            nav.push(serde_json::json!({
                "text": "◀️",
                "callback_data": format!("shape_mem_page:{}", page - 1)
            }));
        }
        if page + 1 < total_pages {
            nav.push(serde_json::json!({
                "text": "▶️",
                "callback_data": format!("shape_mem_page:{}", page + 1)
            }));
        }
        if !nav.is_empty() {
            rows.push(nav);
        }
    }
    rows.push(vec![
        serde_json::json!({ "text": "返回 CPU", "callback_data": "shape_ocpu_page:0" }),
        serde_json::json!({ "text": "返回机型", "callback_data": "shapes" }),
    ]);
    rows.push(vec![
        serde_json::json!({ "text": "自动 CPU/内存", "callback_data": "shape_flex_auto" }),
        serde_json::json!({ "text": "返回菜单", "callback_data": "menu" }),
    ]);
    serde_json::json!({ "inline_keyboard": rows })
}

fn instances_inline_menu(instances: &[InstanceSummary]) -> serde_json::Value {
    let mut rows = Vec::new();
    for (idx, inst) in instances.iter().take(10).enumerate() {
        rows.push(vec![serde_json::json!({
            "text": format_instance_label(inst),
            "callback_data": format!("instance_pick:{}", idx)
        })]);
    }
    rows.push(vec![
        serde_json::json!({ "text": "刷新列表", "callback_data": "instances" }),
        serde_json::json!({ "text": "返回菜单", "callback_data": "menu" }),
    ]);
    serde_json::json!({ "inline_keyboard": rows })
}

fn instance_actions_menu(idx: usize) -> serde_json::Value {
    serde_json::json!({
        "inline_keyboard": [
            [
                { "text": "重启", "callback_data": format!("instance_reboot:{}", idx) },
                { "text": "强制重启", "callback_data": format!("instance_reboot_hard:{}", idx) }
            ],
            [
                { "text": "删除实例", "callback_data": format!("instance_terminate:{}", idx) }
            ],
            [
                { "text": "返回实例", "callback_data": "instances" },
                { "text": "返回菜单", "callback_data": "menu" }
            ]
        ]
    })
}

fn instance_confirm_menu(idx: usize) -> serde_json::Value {
    serde_json::json!({
        "inline_keyboard": [
            [
                { "text": "⚠️ 确认删除", "callback_data": format!("instance_terminate_confirm:{}", idx) },
                { "text": "取消", "callback_data": format!("instance_pick:{}", idx) }
            ],
            [
                { "text": "返回实例", "callback_data": "instances" }
            ]
        ]
    })
}

fn instance_footer_menu() -> serde_json::Value {
    serde_json::json!({
        "inline_keyboard": [
            [
                { "text": "返回实例", "callback_data": "instances" },
                { "text": "返回菜单", "callback_data": "menu" }
            ]
        ]
    })
}

fn format_instance_label(instance: &InstanceSummary) -> String {
    let name = shorten_text(&instance.display_name, 18);
    let state = shorten_text(&instance.lifecycle_state, 10);
    format!("{} | {}", name, state)
}

fn format_instance_detail(instance: &InstanceSummary) -> String {
    format!(
        "实例：{}\n状态：{}\n形状：{}\n可用区：{}\nID：{}",
        instance.display_name,
        instance.lifecycle_state,
        instance.shape,
        instance.availability_domain,
        short_ocid(&instance.id)
    )
}

fn shorten_text(value: &str, max: usize) -> String {
    let chars: Vec<char> = value.chars().collect();
    if chars.len() <= max {
        return value.to_string();
    }
    let mut result: String = chars.into_iter().take(max - 1).collect();
    result.push('…');
    result
}

fn tasks_inline_menu(tasks: &[Task]) -> serde_json::Value {
    let mut rows = Vec::new();
    for task in tasks.iter().take(10) {
        rows.push(vec![serde_json::json!({
            "text": format!("停止 {}", task.id),
            "callback_data": format!("task_stop:{}", task.id)
        })]);
    }
    rows.push(vec![
        serde_json::json!({ "text": "清理任务", "callback_data": "tasks_clear" }),
        serde_json::json!({ "text": "返回菜单", "callback_data": "menu" }),
    ]);
    serde_json::json!({ "inline_keyboard": rows })
}

fn boot_volume_inline_menu(selected: Option<u64>, back: Option<&str>) -> serde_json::Value {
    let options = [50_u64, 100, 150, 200, 300, 500, 1024];
    let mut rows = Vec::new();
    for chunk in options.chunks(3) {
        let mut row = Vec::new();
        for size in chunk {
            let label = if selected == Some(*size) {
                format!("✅ {} GB", size)
            } else {
                format!("{} GB", size)
            };
            row.push(serde_json::json!({
                "text": label,
                "callback_data": format!("boot_set:{}", size)
            }));
        }
        rows.push(row);
    }
    let mut tail = Vec::new();
    tail.push(serde_json::json!({ "text": "默认(自动)", "callback_data": "boot_clear" }));
    tail.push(serde_json::json!({ "text": "性能(VPUs)", "callback_data": "boot_perf" }));
    if let Some(back) = back {
        tail.push(serde_json::json!({ "text": "返回机型", "callback_data": back }));
    }
    tail.push(serde_json::json!({ "text": "返回菜单", "callback_data": "menu" }));
    rows.push(tail);
    serde_json::json!({ "inline_keyboard": rows })
}

fn boot_perf_inline_menu(selected: Option<u64>) -> serde_json::Value {
    let options: &[(u64, &str)] = &[
        (10, "均衡(10)"),
        (20, "较高(20)"),
        (30, "超高30"),
        (40, "超高40"),
        (60, "超高60"),
        (80, "超高80"),
        (120, "超高120"),
    ];
    let mut rows = Vec::new();
    for chunk in options.chunks(3) {
        let mut row = Vec::new();
        for (vpus, label) in chunk {
            let text = if selected == Some(*vpus) {
                format!("✅ {}", label)
            } else {
                label.to_string()
            };
            row.push(serde_json::json!({
                "text": text,
                "callback_data": format!("bvpus_set:{}", vpus)
            }));
        }
        rows.push(row);
    }
    rows.push(vec![
        serde_json::json!({ "text": "默认(自动)", "callback_data": "bvpus_clear" }),
        serde_json::json!({ "text": "返回菜单", "callback_data": "menu" }),
    ]);
    serde_json::json!({ "inline_keyboard": rows })
}

fn handle_boot_perf_menu(state: &TelegramBotState, chat_id: i64) -> Result<BotReply, String> {
    let current = get_chat_boot_volume_vpus(state, chat_id)
        .map(|v| format!("{} VPUs/GB", v))
        .unwrap_or_else(|| "默认".to_string());
    Ok(BotReply::Inline {
        text: format!(
            "选择引导卷性能（当前: {}）\n10=均衡 20=较高 30-120=超高性能",
            current
        ),
        keyboard: boot_perf_inline_menu(get_chat_boot_volume_vpus(state, chat_id)),
    })
}

fn is_authorized(state: &TelegramBotState, chat_id: i64) -> bool {
    let bind_state = state.bind_state.lock().unwrap();
    bind_state.chat_id == Some(chat_id)
}

fn handle_bind_command(
    state: &TelegramBotState,
    chat_id: i64,
    args: &[String],
) -> Result<String, String> {
    let Some(admin_key) = state.app.admin_key.clone() else {
        return Err("未配置 admin_key。".to_string());
    };
    let provided = args.first().map(|v| v.trim()).unwrap_or("");
    if provided.is_empty() {
        return Err("用法：/bind <admin_key>".to_string());
    }
    if provided != admin_key {
        let (count, blocked) = {
            let mut bind_state = state.bind_state.lock().unwrap();
            telegram_bind::record_failure(&mut bind_state, chat_id).unwrap_or((3, true))
        };
        if blocked {
            return Ok("未授权，失败 3 次已拉黑。".to_string());
        }
        return Ok(format!("未授权，第 {}/3 次。", count));
    }

    let mut bind_state = state.bind_state.lock().unwrap();
    if let Err(err) = telegram_bind::set_chat_id(&mut bind_state, chat_id) {
        return Err(format!("绑定失败：{}", err));
    }
    Ok("绑定成功，本聊天已授权。".to_string())
}

async fn handle_authed_command(
    state: &TelegramBotState,
    chat_id: i64,
    command: &str,
    args: &[String],
) -> Result<BotReply, String> {
    match command {
        "profile" => handle_profile_command(state, chat_id, args),
        "compartment" | "compartments" => handle_compartments_menu(state, chat_id).await,
        "boot" | "boot_volume" => handle_boot_volume_menu(state, chat_id),
        "shape" | "shapes" => handle_shapes_menu(state, chat_id).await,
        "presets" => handle_presets_command(state),
        "instances" => {
            if args.is_empty() {
                handle_instances_menu(state, chat_id).await
            } else {
                handle_instances_command(state, chat_id, args)
                    .await
                    .map(BotReply::Text)
            }
        }
        "availability" => handle_availability_menu(state, chat_id).await,
        "create" => handle_create_command(state, chat_id, args)
            .await
            .map(BotReply::Text),
        "queue" => handle_queue_command(state, chat_id, args).map(BotReply::Text),
        "tasks" => handle_tasks_command(state, chat_id, args),
        "task" => handle_task_command(state, chat_id, args).map(BotReply::Text),
        _ => Err("未知命令。请用 /help。".to_string()),
    }
}

fn handle_profile_command(
    state: &TelegramBotState,
    chat_id: i64,
    args: &[String],
) -> Result<BotReply, String> {
    if state.app.profiles.is_empty() {
        return Ok(BotReply::Inline {
            text: no_profile_text(),
            keyboard: main_inline_menu(),
        });
    }
    if args.is_empty() {
        let current = get_chat_profile(state, chat_id);
        return Ok(BotReply::Text(format!("当前 Profile：{}", current)));
    }
    if args[0].eq_ignore_ascii_case("list") {
        let mut profiles = state.app.profiles.keys().cloned().collect::<Vec<_>>();
        profiles.sort();
        return Ok(BotReply::Inline {
            text: "选择 Profile：".to_string(),
            keyboard: profiles_inline_menu(&profiles),
        });
    }
    if args[0].eq_ignore_ascii_case("set") {
        let Some(name) = args.get(1) else {
            return Err("用法：/profile set <NAME>".to_string());
        };
        let key = name.trim().to_uppercase();
        if !state.app.profiles.contains_key(&key) {
            return Err(format!("Profile '{}' 不存在。", key));
        }
        let mut profiles = state.chat_profiles.lock().unwrap();
        profiles.insert(chat_id, key.clone());
        clear_chat_selections(state, chat_id);
        return Ok(BotReply::Text(format!(
            "Profile 已切换为 {}（分区=自动(根分区)，可用区已清空）。",
            key
        )));
    }
    Err("用法：/profile list | /profile set <NAME> | /profile".to_string())
}

fn handle_presets_command(state: &TelegramBotState) -> Result<BotReply, String> {
    let presets = state.app.presets.as_ref();
    if presets.is_empty() {
        return Ok(BotReply::Text("暂无 Preset。".to_string()));
    }
    Ok(BotReply::Inline {
        text: "选择 Preset：".to_string(),
        keyboard: presets_inline_menu(presets),
    })
}

async fn handle_compartments_menu(
    state: &TelegramBotState,
    chat_id: i64,
) -> Result<BotReply, String> {
    ensure_profiles_available(state)?;
    let profile_key = resolve_profile_key(state, chat_id, None);
    let Some(profile_state) = state.app.profiles.get(&profile_key) else {
        return Err(format!("Profile '{}' 不存在。", profile_key));
    };
    let mut items = vec![CompartmentItem {
        id: profile_state.client.tenancy().to_string(),
        name: "(root tenancy)".to_string(),
    }];
    let compartments = profile_state
        .client
        .list_compartments()
        .await
        .map_err(|err| err.to_string())?;
    for c in compartments {
        if c.lifecycle_state.as_deref() == Some("ACTIVE") {
            items.push(CompartmentItem {
                id: c.id,
                name: c.name,
            });
        }
    }
    if items.is_empty() {
        return Ok(BotReply::Inline {
            text: "暂无分区。".to_string(),
            keyboard: main_inline_menu(),
        });
    }
    state
        .compartment_cache
        .lock()
        .unwrap()
        .insert(chat_id, items.clone());
    let current = get_chat_compartment_label(state, chat_id).unwrap_or("自动(根分区)".to_string());
    let mut text = format!("选择分区（当前: {}）", current);
    if items.len() > 10 {
        text.push_str("\n仅显示前 10 个分区。");
    }
    let selected_id = get_chat_compartment(state, chat_id).map(|c| c.id);
    let has_config_default = profile_state.defaults.compartment.is_some();
    Ok(BotReply::Inline {
        text,
        keyboard: compartments_inline_menu(&items, selected_id.as_deref(), has_config_default),
    })
}

fn handle_compartment_pick(
    state: &TelegramBotState,
    chat_id: i64,
    idx_str: &str,
) -> Result<BotReply, String> {
    let idx = idx_str
        .parse::<usize>()
        .map_err(|_| "分区索引无效。".to_string())?;
    let cache = state.compartment_cache.lock().unwrap();
    let Some(items) = cache.get(&chat_id) else {
        return Err("分区列表已过期，请重新打开分区。".to_string());
    };
    let Some(item) = items.get(idx) else {
        return Err("分区索引无效。请重新打开分区。".to_string());
    };
    state.chat_compartments.lock().unwrap().insert(
        chat_id,
        ChatCompartment {
            id: item.id.clone(),
            name: item.name.clone(),
            from_config_default: false,
        },
    );
    clear_chat_after_compartment_change(state, chat_id);
    Ok(BotReply::Inline {
        text: format!("分区已选择：{}。", item.name),
        keyboard: main_inline_menu(),
    })
}

async fn handle_compartment_default(
    state: &TelegramBotState,
    chat_id: i64,
) -> Result<BotReply, String> {
    ensure_profiles_available(state)?;
    let profile_key = resolve_profile_key(state, chat_id, None);
    let Some(profile_state) = state.app.profiles.get(&profile_key) else {
        return Err(format!("Profile '{}' 不存在。", profile_key));
    };
    let Some(default_id) = profile_state.defaults.compartment.clone() else {
        return Err("当前 Profile 未配置 compartment。".to_string());
    };
    let cached_items = state
        .compartment_cache
        .lock()
        .unwrap()
        .get(&chat_id)
        .cloned();
    let mut name = cached_items
        .as_ref()
        .and_then(|items| items.iter().find(|item| item.id == default_id))
        .map(|item| item.name.clone());
    if name.is_none() {
        let mut items = vec![CompartmentItem {
            id: profile_state.client.tenancy().to_string(),
            name: "(root tenancy)".to_string(),
        }];
        let compartments = profile_state
            .client
            .list_compartments()
            .await
            .map_err(|err| err.to_string())?;
        for c in compartments {
            if c.lifecycle_state.as_deref() == Some("ACTIVE") {
                items.push(CompartmentItem {
                    id: c.id,
                    name: c.name,
                });
            }
        }
        name = items
            .iter()
            .find(|item| item.id == default_id)
            .map(|item| item.name.clone());
        state
            .compartment_cache
            .lock()
            .unwrap()
            .insert(chat_id, items);
    }
    let label = name.unwrap_or_else(|| short_ocid(&default_id));
    state.chat_compartments.lock().unwrap().insert(
        chat_id,
        ChatCompartment {
            id: default_id,
            name: label.clone(),
            from_config_default: true,
        },
    );
    clear_chat_after_compartment_change(state, chat_id);
    Ok(BotReply::Inline {
        text: format!("分区已切换为配置默认：{}。", label),
        keyboard: main_inline_menu(),
    })
}

async fn handle_availability_menu(
    state: &TelegramBotState,
    chat_id: i64,
) -> Result<BotReply, String> {
    ensure_profiles_available(state)?;
    let profile_key = resolve_profile_key(state, chat_id, None);
    let Some(profile_state) = state.app.profiles.get(&profile_key) else {
        return Err(format!("Profile '{}' 不存在。", profile_key));
    };
    let compartment = resolve_compartment_for_chat(state, chat_id, &HashMap::new(), profile_state)?;
    let ads = profile_state
        .client
        .availability_domains(&compartment)
        .await
        .map_err(|err| err.to_string())?;
    if ads.is_empty() {
        return Ok(BotReply::Inline {
            text: "暂无可用区。".to_string(),
            keyboard: main_inline_menu(),
        });
    }
    let current = get_chat_availability_label(state, chat_id);
    let mut text = format!("选择可用区（当前: {}）\n可多选，点击可选/取消。", current);
    if ads.len() > 10 {
        text.push_str("\n仅显示前 10 个可用区。");
    }
    let selected = get_chat_availability_list(state, chat_id);
    Ok(BotReply::Inline {
        text,
        keyboard: availability_inline_menu(&ads, &selected),
    })
}

async fn handle_shapes_menu(state: &TelegramBotState, chat_id: i64) -> Result<BotReply, String> {
    handle_shapes_menu_page(state, chat_id, 0).await
}

async fn handle_shapes_menu_page(
    state: &TelegramBotState,
    chat_id: i64,
    page: usize,
) -> Result<BotReply, String> {
    ensure_profiles_available(state)?;
    let profile_key = resolve_profile_key(state, chat_id, None);
    let Some(profile_state) = state.app.profiles.get(&profile_key) else {
        return Err(format!("Profile '{}' 不存在。", profile_key));
    };
    let compartment = resolve_compartment_for_chat(state, chat_id, &HashMap::new(), profile_state)?;
    let selected_ads = get_chat_availability_list(state, chat_id);
    let mut note = None;
    let ad = if let Some(ad) = selected_ads.first() {
        if selected_ads.len() > 1 {
            note = Some("当前可用区多选，机型列表基于第一个可用区。".to_string());
        }
        ad.clone()
    } else if let Some(ad) = profile_state.defaults.availability_domain.clone() {
        ad
    } else {
        let ads = profile_state
            .client
            .availability_domains(&compartment)
            .await
            .map_err(|err| err.to_string())?;
        ads.first()
            .map(|item| item.name.clone())
            .ok_or_else(|| "没有可用区可用于查询机型。".to_string())?
    };
    let cached_shapes = state.shape_cache.lock().unwrap().get(&chat_id).cloned();
    let mut shapes = if let Some(cached) = cached_shapes {
        cached
    } else {
        profile_state
            .client
            .list_shapes(&compartment, &ad)
            .await
            .map_err(|err| err.to_string())?
    };
    if shapes.is_empty() {
        return Ok(BotReply::Inline {
            text: "暂无机型。".to_string(),
            keyboard: main_inline_menu(),
        });
    }
    shapes.sort_by(|a, b| a.shape.cmp(&b.shape));
    state
        .shape_cache
        .lock()
        .unwrap()
        .insert(chat_id, shapes.clone());
    let current = format_shape_selection(state, chat_id);
    let mut text = format!("选择机型（当前: {}，基于 {}）", current, ad);
    if let Some(note) = note {
        text.push('\n');
        text.push_str(&note);
    }
    let total_pages = shapes.len().div_ceil(SHAPE_PAGE_SIZE);
    if total_pages > 1 {
        text.push_str(&format!("\n页码: {}/{}", page + 1, total_pages));
    }
    let selected = get_chat_shape_label(state, chat_id);
    Ok(BotReply::Inline {
        text,
        keyboard: shapes_inline_menu(&shapes, selected.as_deref(), page),
    })
}

fn handle_boot_volume_menu(state: &TelegramBotState, chat_id: i64) -> Result<BotReply, String> {
    handle_boot_volume_menu_with_back(state, chat_id, None, None)
}

fn handle_boot_volume_menu_with_back(
    state: &TelegramBotState,
    chat_id: i64,
    back: Option<&str>,
    prefix: Option<String>,
) -> Result<BotReply, String> {
    let current = get_chat_boot_volume_gbs(state, chat_id)
        .map(|size| format!("{} GB", size))
        .unwrap_or_else(|| "默认(自动)".to_string());
    let mut text = format!("选择硬盘大小（当前: {}）", current);
    if let Some(prefix) = prefix {
        text = format!("{}\n{}", prefix, text);
    }
    Ok(BotReply::Inline {
        text,
        keyboard: boot_volume_inline_menu(get_chat_boot_volume_gbs(state, chat_id), back),
    })
}

fn handle_shape_ocpu_menu(
    state: &TelegramBotState,
    chat_id: i64,
    page: usize,
) -> Result<BotReply, String> {
    let Some(shape_name) = get_chat_shape_label(state, chat_id) else {
        return Err("请先选择机型。".to_string());
    };
    let Some(shape) = shape_from_cache(state, chat_id, &shape_name) else {
        return Err("机型列表已过期，请重新打开机型菜单。".to_string());
    };
    if !is_flex_shape(&shape) {
        return Err("该机型不是 Flex，无需选择 OCPU。".to_string());
    }
    let values = ocpu_values(&shape).ok_or_else(|| "该机型未提供 OCPU 选项。".to_string())?;
    let (page_values, total_pages) = paginate_values(&values, page);
    let selected = get_chat_shape_ocpus(state, chat_id).map(|v| v.round() as u32);
    let mut text = format!("选择 OCPU（机型: {}）", shape_name);
    if total_pages > 1 {
        text.push_str(&format!("\n页码: {}/{}", page + 1, total_pages));
    }
    Ok(BotReply::Inline {
        text,
        keyboard: ocpu_inline_menu(&page_values, selected, page, total_pages),
    })
}

fn handle_shape_memory_menu(
    state: &TelegramBotState,
    chat_id: i64,
    page: usize,
) -> Result<BotReply, String> {
    let Some(shape_name) = get_chat_shape_label(state, chat_id) else {
        return Err("请先选择机型。".to_string());
    };
    let Some(shape) = shape_from_cache(state, chat_id, &shape_name) else {
        return Err("机型列表已过期，请重新打开机型菜单。".to_string());
    };
    if !is_flex_shape(&shape) {
        return Err("该机型不是 Flex，无需选择内存。".to_string());
    }
    let ocpus =
        get_chat_shape_ocpus(state, chat_id).ok_or_else(|| "请先选择 OCPU。".to_string())?;
    let values =
        memory_values(&shape, ocpus).ok_or_else(|| "该机型未提供内存选项。".to_string())?;
    let (page_values, total_pages) = paginate_values(&values, page);
    let selected = get_chat_shape_memory(state, chat_id).map(|v| v.round() as u32);
    let mut text = format!("选择内存（机型: {}，OCPU: {}）", shape_name, ocpus);
    if total_pages > 1 {
        text.push_str(&format!("\n页码: {}/{}", page + 1, total_pages));
    }
    Ok(BotReply::Inline {
        text,
        keyboard: memory_inline_menu(&page_values, selected, page, total_pages),
    })
}

async fn handle_instances_menu(state: &TelegramBotState, chat_id: i64) -> Result<BotReply, String> {
    ensure_profiles_available(state)?;
    let profile_key = resolve_profile_key(state, chat_id, None);
    let Some(profile_state) = state.app.profiles.get(&profile_key) else {
        return Err(format!("Profile '{}' 不存在。", profile_key));
    };
    let compartment = resolve_compartment_for_chat(state, chat_id, &HashMap::new(), profile_state)?;
    let mut instances = profile_state
        .client
        .list_instances(&compartment)
        .await
        .map_err(|err| err.to_string())?;
    if instances.is_empty() {
        return Ok(BotReply::Inline {
            text: "暂无实例。".to_string(),
            keyboard: main_inline_menu(),
        });
    }
    instances.sort_by(|a, b| a.display_name.cmp(&b.display_name));
    state.chat_instance_cache.lock().unwrap().insert(
        chat_id,
        InstanceListCache {
            profile_key: profile_key.clone(),
            items: instances.clone(),
        },
    );
    let mut text = format!("选择实例（共 {} 个，显示前 10 个）", instances.len());
    if let Some(label) = get_chat_compartment_label(state, chat_id) {
        text.push_str(&format!("\n当前分区：{}", label));
    } else {
        text.push_str("\n当前分区：自动");
    }
    Ok(BotReply::Inline {
        text,
        keyboard: instances_inline_menu(&instances),
    })
}

fn get_instance_from_cache(
    state: &TelegramBotState,
    chat_id: i64,
    idx_str: &str,
) -> Result<(InstanceListCache, InstanceSummary, usize), String> {
    let idx = idx_str
        .parse::<usize>()
        .map_err(|_| "实例索引无效。".to_string())?;
    let cache = state.chat_instance_cache.lock().unwrap();
    let Some(list) = cache.get(&chat_id) else {
        return Err("实例列表已过期，请重新打开实例。".to_string());
    };
    let Some(instance) = list.items.get(idx).cloned() else {
        return Err("实例索引无效，请重新打开实例。".to_string());
    };
    Ok((list.clone(), instance, idx))
}

fn handle_instance_pick(
    state: &TelegramBotState,
    chat_id: i64,
    idx_str: &str,
) -> Result<BotReply, String> {
    let (_list, instance, idx) = get_instance_from_cache(state, chat_id, idx_str)?;
    Ok(BotReply::Inline {
        text: format_instance_detail(&instance),
        keyboard: instance_actions_menu(idx),
    })
}

async fn handle_instance_reboot(
    state: &TelegramBotState,
    chat_id: i64,
    idx_str: &str,
    hard: bool,
) -> Result<BotReply, String> {
    let (list, instance, idx) = get_instance_from_cache(state, chat_id, idx_str)?;
    let Some(profile_state) = state.app.profiles.get(&list.profile_key) else {
        return Err(format!("Profile '{}' 不存在。", list.profile_key));
    };
    profile_state
        .client
        .reboot_instance(&instance.id, hard)
        .await
        .map_err(|err| err.to_string())?;
    let tip = if hard {
        "已发起强制重启"
    } else {
        "已发起重启"
    };
    Ok(BotReply::Inline {
        text: format!("{}：{}。", tip, instance.display_name),
        keyboard: instance_actions_menu(idx),
    })
}

async fn handle_instance_terminate_confirm(
    state: &TelegramBotState,
    chat_id: i64,
    idx_str: &str,
) -> Result<BotReply, String> {
    let (list, instance, _idx) = get_instance_from_cache(state, chat_id, idx_str)?;
    let Some(profile_state) = state.app.profiles.get(&list.profile_key) else {
        return Err(format!("Profile '{}' 不存在。", list.profile_key));
    };
    profile_state
        .client
        .terminate_instance(&instance.id)
        .await
        .map_err(|err| err.to_string())?;
    Ok(BotReply::Inline {
        text: format!("已提交删除：{}。", instance.display_name),
        keyboard: instance_footer_menu(),
    })
}

async fn handle_instances_command(
    state: &TelegramBotState,
    chat_id: i64,
    args: &[String],
) -> Result<String, String> {
    ensure_profiles_available(state)?;
    let params = parse_kv_args(args)?;
    let profile_key = resolve_profile_key(state, chat_id, params.get("profile"));
    let Some(profile_state) = state.app.profiles.get(&profile_key) else {
        return Err(format!("Profile '{}' 不存在。", profile_key));
    };
    let compartment = resolve_compartment_for_chat(state, chat_id, &params, profile_state)?;
    let instances = profile_state
        .client
        .list_instances(&compartment)
        .await
        .map_err(|err| err.to_string())?;
    if instances.is_empty() {
        return Ok("暂无实例。".to_string());
    }
    let mut lines = Vec::new();
    for (idx, inst) in instances.iter().enumerate() {
        if idx >= 20 {
            lines.push("...truncated...".to_string());
            break;
        }
        lines.push(format!(
            "{} | {} | {} | {}",
            inst.id, inst.display_name, inst.lifecycle_state, inst.shape
        ));
    }
    Ok(lines.join("\n"))
}

async fn handle_create_command(
    state: &TelegramBotState,
    chat_id: i64,
    args: &[String],
) -> Result<String, String> {
    handle_queue_command(state, chat_id, args)
}

fn handle_queue_command(
    state: &TelegramBotState,
    chat_id: i64,
    args: &[String],
) -> Result<String, String> {
    ensure_profiles_available(state)?;
    let mut params = parse_kv_args(args)?;
    let preset_name = params.remove("preset");
    let profile_key = resolve_profile_key(state, chat_id, params.get("profile"));
    let Some(profile_state) = state.app.profiles.get(&profile_key) else {
        return Err(format!("Profile '{}' 不存在。", profile_key));
    };
    let mut input = build_create_input(&params, Some(profile_key.clone()))?;
    if let Some(name) = preset_name {
        apply_preset_by_name(state, &profile_key, &mut input, &name)?;
    }
    apply_chat_defaults(state, chat_id, &mut input);
    if input.compartment.is_none() {
        input.compartment = Some(profile_state.client.tenancy().to_string());
    }
    let inputs = expand_inputs_with_availability(state, chat_id, input);
    let mut lines = Vec::new();
    for input in inputs {
        ensure_login_method(&input, Some(&profile_state.defaults))?;
        let ad = input
            .availability_domain
            .clone()
            .unwrap_or_else(|| "auto".to_string());
        let id = enqueue_task(&state.app, input);
        lines.push(format!("{} | {}", id, ad));
    }
    if lines.len() > 1 {
        Ok(format!(
            "已加入后台队列（{} 个）：\n{}",
            lines.len(),
            lines.join("\n")
        ))
    } else {
        Ok(format!("已加入后台队列：{}", lines.join("\n")))
    }
}

fn handle_tasks_command(
    state: &TelegramBotState,
    _chat_id: i64,
    args: &[String],
) -> Result<BotReply, String> {
    if args.first().map(|v| v.as_str()) == Some("clear") {
        clear_tasks_internal(&state.app);
        return Ok(BotReply::Text("任务已清理。".to_string()));
    }
    let tasks = state.app.tasks.lock().unwrap();
    if tasks.is_empty() {
        return Ok(BotReply::Text("暂无任务。".to_string()));
    }
    let mut lines = Vec::new();
    for (idx, task) in tasks.iter().enumerate() {
        if idx >= 20 {
            lines.push("...truncated...".to_string());
            break;
        }
        lines.push(format!(
            "{} | {} | {}",
            task.id,
            task.description,
            task_status_label(&task.status)
        ));
    }
    Ok(BotReply::Inline {
        text: lines.join("\n"),
        keyboard: tasks_inline_menu(&tasks),
    })
}

fn handle_task_command(
    state: &TelegramBotState,
    _chat_id: i64,
    args: &[String],
) -> Result<String, String> {
    if args.first().map(|v| v.as_str()) != Some("stop") {
        return Err("用法：/task stop <TASK_ID>".to_string());
    }
    let Some(task_id) = args.get(1) else {
        return Err("用法：/task stop <TASK_ID>".to_string());
    };
    remove_task(&state.app, task_id)
        .map(|_| format!("任务 {} 已停止。", task_id))
        .map_err(|err| err.to_string())
}

fn task_status_label(status: &TaskStatus) -> String {
    match status {
        TaskStatus::Pending => "pending".to_string(),
        TaskStatus::Running => "running".to_string(),
        TaskStatus::Success(msg) => format!("success ({})", msg),
        TaskStatus::Failed(msg) => format!("failed ({})", msg),
        TaskStatus::Retrying(msg) => format!("retrying ({})", msg),
        TaskStatus::Cancelled => "cancelled".to_string(),
    }
}

fn get_chat_profile(state: &TelegramBotState, chat_id: i64) -> String {
    if state.app.profiles.is_empty() {
        return "未配置".to_string();
    }
    let profiles = state.chat_profiles.lock().unwrap();
    if let Some(key) = profiles.get(&chat_id).cloned() {
        if state.app.profiles.contains_key(&key) {
            return key;
        }
    }
    if state.app.profiles.contains_key(&state.app.default_profile) {
        return state.app.default_profile.clone();
    }
    state
        .app
        .profiles
        .keys()
        .cloned()
        .min()
        .unwrap_or_else(|| "未配置".to_string())
}

fn get_chat_compartment(state: &TelegramBotState, chat_id: i64) -> Option<ChatCompartment> {
    let compartments = state.chat_compartments.lock().unwrap();
    compartments.get(&chat_id).cloned()
}

fn get_chat_compartment_label(state: &TelegramBotState, chat_id: i64) -> Option<String> {
    let compartment = get_chat_compartment(state, chat_id)?;
    let name = compartment.name.trim();
    let base = if !name.is_empty() {
        name.to_string()
    } else {
        short_ocid(&compartment.id)
    };
    if compartment.from_config_default {
        Some(format!("配置默认({})", base))
    } else {
        Some(format!("手动({})", base))
    }
}

fn get_chat_shape_label(state: &TelegramBotState, chat_id: i64) -> Option<String> {
    let shapes = state.chat_shapes.lock().unwrap();
    shapes.get(&chat_id).cloned()
}

fn get_chat_shape_ocpus(state: &TelegramBotState, chat_id: i64) -> Option<f64> {
    let values = state.chat_shape_ocpus.lock().unwrap();
    values.get(&chat_id).cloned()
}

fn get_chat_shape_memory(state: &TelegramBotState, chat_id: i64) -> Option<f64> {
    let values = state.chat_shape_memory.lock().unwrap();
    values.get(&chat_id).cloned()
}

fn get_chat_root_login(state: &TelegramBotState, chat_id: i64) -> Option<bool> {
    let values = state.chat_root_login.lock().unwrap();
    values.get(&chat_id).cloned()
}

fn get_chat_use_ssh_key(state: &TelegramBotState, chat_id: i64) -> Option<bool> {
    let values = state.chat_use_ssh_key.lock().unwrap();
    values.get(&chat_id).cloned()
}

fn get_chat_boot_volume_gbs(state: &TelegramBotState, chat_id: i64) -> Option<u64> {
    let values = state.chat_boot_volume_gbs.lock().unwrap();
    values.get(&chat_id).cloned()
}

fn get_chat_boot_volume_vpus(state: &TelegramBotState, chat_id: i64) -> Option<u64> {
    let values = state.chat_boot_volume_vpus.lock().unwrap();
    values.get(&chat_id).cloned()
}

fn format_shape_selection(state: &TelegramBotState, chat_id: i64) -> String {
    let Some(shape) = get_chat_shape_label(state, chat_id) else {
        return "自动".to_string();
    };
    let ocpus = get_chat_shape_ocpus(state, chat_id);
    let memory = get_chat_shape_memory(state, chat_id);
    match (ocpus, memory) {
        (Some(cpu), Some(mem)) => format!("{} ({} OCPU / {} GB)", shape, cpu, mem),
        (Some(cpu), None) => format!("{} ({} OCPU / 内存未选)", shape, cpu),
        (None, Some(mem)) => format!("{} (CPU 未选 / {} GB)", shape, mem),
        (None, None) => shape,
    }
}

fn get_chat_availability_list(state: &TelegramBotState, chat_id: i64) -> Vec<String> {
    let ads = state.chat_availability_domains.lock().unwrap();
    ads.get(&chat_id).cloned().unwrap_or_default()
}

fn get_chat_availability_label(state: &TelegramBotState, chat_id: i64) -> String {
    let ads = get_chat_availability_list(state, chat_id);
    if ads.is_empty() {
        return "自动".to_string();
    }
    if ads.len() <= 2 {
        return ads.join("、");
    }
    format!("{}、{} 等", ads[0], ads[1])
}

fn clear_chat_selections(state: &TelegramBotState, chat_id: i64) {
    state.chat_compartments.lock().unwrap().remove(&chat_id);
    state
        .chat_availability_domains
        .lock()
        .unwrap()
        .remove(&chat_id);
    state.chat_shapes.lock().unwrap().remove(&chat_id);
    state.chat_shape_ocpus.lock().unwrap().remove(&chat_id);
    state.chat_shape_memory.lock().unwrap().remove(&chat_id);
    state.shape_cache.lock().unwrap().remove(&chat_id);
    state.chat_instance_cache.lock().unwrap().remove(&chat_id);
    state.compartment_cache.lock().unwrap().remove(&chat_id);
}

fn clear_chat_after_compartment_change(state: &TelegramBotState, chat_id: i64) {
    state
        .chat_availability_domains
        .lock()
        .unwrap()
        .remove(&chat_id);
    state.chat_shapes.lock().unwrap().remove(&chat_id);
    state.chat_shape_ocpus.lock().unwrap().remove(&chat_id);
    state.chat_shape_memory.lock().unwrap().remove(&chat_id);
    state.shape_cache.lock().unwrap().remove(&chat_id);
    state.chat_instance_cache.lock().unwrap().remove(&chat_id);
}

fn resolve_profile_key(
    state: &TelegramBotState,
    chat_id: i64,
    override_name: Option<&String>,
) -> String {
    if let Some(name) = override_name {
        return name.trim().to_uppercase();
    }
    get_chat_profile(state, chat_id)
}

fn no_profile_text() -> String {
    "未配置任何 Profile。请在 config 中添加 [profile:NAME] 并重启服务。".to_string()
}

fn ensure_profiles_available(state: &TelegramBotState) -> Result<(), String> {
    if state.app.profiles.is_empty() {
        Err(no_profile_text())
    } else {
        Ok(())
    }
}

fn short_ocid(value: &str) -> String {
    let trimmed = value.trim();
    if trimmed.len() <= 12 {
        return trimmed.to_string();
    }
    let start = &trimmed[..6];
    let end = &trimmed[trimmed.len() - 4..];
    format!("{}...{}", start, end)
}

fn parse_kv_args(args: &[String]) -> Result<HashMap<String, String>, String> {
    let mut map = HashMap::new();
    for arg in args {
        let Some((key, value)) = arg.split_once('=') else {
            return Err(format!("Invalid arg '{}', expected key=value", arg));
        };
        map.insert(key.trim().to_lowercase(), value.trim().to_string());
    }
    Ok(map)
}

fn parse_f64(value: &str, key: &str) -> Result<f64, String> {
    value
        .parse::<f64>()
        .map_err(|_| format!("Invalid number for {}", key))
}

fn parse_u64(value: &str, key: &str) -> Result<u64, String> {
    value
        .parse::<u64>()
        .map_err(|_| format!("Invalid number for {}", key))
}

fn parse_bool(value: &str, key: &str) -> Result<bool, String> {
    match value.trim().to_lowercase().as_str() {
        "true" | "1" | "yes" | "on" => Ok(true),
        "false" | "0" | "no" | "off" => Ok(false),
        _ => Err(format!("Invalid boolean for {}", key)),
    }
}

fn build_create_input(
    params: &HashMap<String, String>,
    profile: Option<String>,
) -> Result<CreateInput, String> {
    let ocpus = params
        .get("ocpus")
        .map(|value| parse_f64(value, "ocpus"))
        .transpose()?;
    let memory_in_gbs = params
        .get("memory_gbs")
        .or_else(|| params.get("memory_in_gbs"))
        .map(|value| parse_f64(value, "memory_gbs"))
        .transpose()?;
    let boot_volume_size_gbs = params
        .get("boot_volume_gbs")
        .or_else(|| params.get("boot_volume_size_gbs"))
        .map(|value| parse_u64(value, "boot_volume_gbs"))
        .transpose()?;
    let boot_volume_vpus_per_gb = params
        .get("boot_volume_vpus")
        .or_else(|| params.get("boot_volume_vpus_per_gb"))
        .map(|value| parse_u64(value, "boot_volume_vpus"))
        .transpose()?;
    let retry_interval_secs = params
        .get("retry_interval_secs")
        .map(|value| parse_u64(value, "retry_interval_secs"))
        .transpose()?;
    let root_login = params
        .get("root_login")
        .or_else(|| params.get("root"))
        .map(|value| parse_bool(value, "root_login"))
        .transpose()?;
    let use_ssh_key = params
        .get("use_ssh_key")
        .or_else(|| params.get("use_ssh"))
        .map(|value| parse_bool(value, "use_ssh_key"))
        .transpose()?;

    Ok(CreateInput {
        profile,
        compartment: params.get("compartment").cloned(),
        subnet: params.get("subnet").cloned(),
        shape: params.get("shape").cloned(),
        ocpus,
        memory_in_gbs,
        boot_volume_size_gbs,
        boot_volume_vpus_per_gb,
        availability_domain: params.get("availability_domain").cloned(),
        image: params.get("image").cloned(),
        image_os: params.get("image_os").cloned(),
        image_version: params.get("image_version").cloned(),
        display_name: params.get("display_name").cloned(),
        ssh_key: params.get("ssh_key").cloned(),
        use_ssh_key,
        root_login,
        retry_interval_secs,
    })
}

fn apply_chat_defaults(state: &TelegramBotState, chat_id: i64, input: &mut CreateInput) {
    if input.compartment.is_none() {
        if let Some(compartment) = get_chat_compartment(state, chat_id) {
            input.compartment = Some(compartment.id);
        }
    }
    if input.shape.is_none() {
        if let Some(shape) = get_chat_shape_label(state, chat_id) {
            input.shape = Some(shape);
        }
    }
    if input.boot_volume_size_gbs.is_none() {
        if let Some(size) = get_chat_boot_volume_gbs(state, chat_id) {
            input.boot_volume_size_gbs = Some(size);
        }
    }
    if input.boot_volume_vpus_per_gb.is_none() {
        if let Some(vpus) = get_chat_boot_volume_vpus(state, chat_id) {
            input.boot_volume_vpus_per_gb = Some(vpus);
        }
    }
    if input.ocpus.is_none() {
        if let Some(ocpus) = get_chat_shape_ocpus(state, chat_id) {
            input.ocpus = Some(ocpus);
        }
    }
    if input.memory_in_gbs.is_none() {
        if let Some(memory) = get_chat_shape_memory(state, chat_id) {
            input.memory_in_gbs = Some(memory);
        }
    }
    if input.use_ssh_key.is_none() {
        if let Some(value) = get_chat_use_ssh_key(state, chat_id) {
            input.use_ssh_key = Some(value);
        }
    }
    if input.root_login.is_none() {
        if let Some(value) = get_chat_root_login(state, chat_id) {
            input.root_login = Some(value);
        }
    }
    if input.use_ssh_key == Some(false) {
        input.ssh_key = None;
    }
}

fn ensure_login_method(
    input: &CreateInput,
    defaults: Option<&ProfileDefaults>,
) -> Result<(), String> {
    let ssh_enabled = input.use_ssh_key.unwrap_or(true);
    let has_root = input
        .root_login
        .or_else(|| defaults.and_then(|item| item.root_login))
        .unwrap_or(false);
    if ssh_enabled || has_root {
        Ok(())
    } else {
        Err("至少选择一种登录方式：SSH 公钥或 Root 登录。".to_string())
    }
}

fn expand_inputs_with_availability(
    state: &TelegramBotState,
    chat_id: i64,
    mut input: CreateInput,
) -> Vec<CreateInput> {
    if input.availability_domain.is_some() {
        return vec![input];
    }
    let selected = get_chat_availability_list(state, chat_id);
    if selected.is_empty() {
        return vec![input];
    }
    if selected.len() == 1 {
        input.availability_domain = Some(selected[0].clone());
        return vec![input];
    }
    selected
        .into_iter()
        .map(|ad| {
            let mut cloned = input.clone();
            cloned.availability_domain = Some(ad);
            cloned
        })
        .collect()
}

fn resolve_compartment_for_chat(
    state: &TelegramBotState,
    chat_id: i64,
    params: &HashMap<String, String>,
    profile_state: &ProfileState,
) -> Result<String, String> {
    if let Some(compartment) = params.get("compartment") {
        return Ok(compartment.clone());
    }
    if let Some(compartment) = get_chat_compartment(state, chat_id) {
        return Ok(compartment.id);
    }
    Ok(profile_state.client.tenancy().to_string())
}

fn apply_preset_by_name(
    state: &TelegramBotState,
    profile_key: &str,
    input: &mut CreateInput,
    preset_name: &str,
) -> Result<(), String> {
    let preset = state
        .app
        .presets
        .iter()
        .find(|preset| preset.name.eq_ignore_ascii_case(preset_name))
        .cloned()
        .ok_or_else(|| format!("Preset '{}' 不存在。", preset_name))?;
    apply_preset_to_input(profile_key, input, &preset);
    Ok(())
}

fn apply_preset_to_input(profile_key: &str, input: &mut CreateInput, preset: &Preset) {
    if input.compartment.is_none() {
        input.compartment = preset.compartment.clone();
    }
    if input.subnet.is_none() {
        input.subnet = preset.subnet.clone();
    }
    if input.shape.is_none() {
        input.shape = preset.shape.clone();
    }
    if input.availability_domain.is_none() {
        input.availability_domain = preset.availability_domain.clone();
    }
    if input.image.is_none() {
        input.image = preset.image.clone();
    }
    if input.image_os.is_none() {
        input.image_os = preset.image_os.clone();
    }
    if input.image_version.is_none() {
        input.image_version = preset.image_version.clone();
    }
    if input.ssh_key.is_none() {
        input.ssh_key = preset.ssh_public_key.clone();
    }
    if input.boot_volume_size_gbs.is_none() {
        input.boot_volume_size_gbs = preset.boot_volume_size_gbs;
    }
    if input.boot_volume_vpus_per_gb.is_none() {
        input.boot_volume_vpus_per_gb = preset.boot_volume_vpus_per_gb;
    }
    if input.ocpus.is_none() {
        input.ocpus = preset.ocpus;
    }
    if input.memory_in_gbs.is_none() {
        input.memory_in_gbs = preset.memory_in_gbs;
    }
    if input.root_login.is_none() {
        input.root_login = preset.root_login;
    }
    if input.display_name.is_none() {
        if let Some(prefix) = preset.display_name_prefix.as_ref() {
            input.display_name = Some(generate_display_name(prefix, profile_key));
        }
    }
}

fn generate_display_name(prefix: &str, profile_key: &str) -> String {
    let timestamp = OffsetDateTime::now_utc()
        .format(&Rfc3339)
        .unwrap_or_else(|_| "now".to_string());
    format!("{}-{}-{}", prefix, profile_key, timestamp.replace(':', ""))
}

async fn preset_action(
    state: &TelegramBotState,
    chat_id: i64,
    idx_str: &str,
    _queue: bool,
) -> Result<BotReply, String> {
    ensure_profiles_available(state)?;
    let idx = idx_str
        .parse::<usize>()
        .map_err(|_| "Preset 索引无效。".to_string())?;
    let preset = state
        .app
        .presets
        .get(idx)
        .cloned()
        .ok_or_else(|| "Preset 不存在。".to_string())?;
    let profile_key = resolve_profile_key(state, chat_id, None);
    let Some(profile_state) = state.app.profiles.get(&profile_key) else {
        return Err(format!("Profile '{}' 不存在。", profile_key));
    };
    let mut input = build_create_input(&HashMap::new(), Some(profile_key.clone()))?;
    apply_preset_to_input(&profile_key, &mut input, &preset);
    apply_chat_defaults(state, chat_id, &mut input);
    if input.compartment.is_none() {
        input.compartment = Some(profile_state.client.tenancy().to_string());
    }
    let inputs = expand_inputs_with_availability(state, chat_id, input);
    let mut lines = Vec::new();
    for input in inputs {
        ensure_login_method(&input, Some(&profile_state.defaults))?;
        let ad = input
            .availability_domain
            .clone()
            .unwrap_or_else(|| "auto".to_string());
        let id = enqueue_task(&state.app, input);
        lines.push(format!("{} | {}", id, ad));
    }
    let header = if lines.len() > 1 {
        format!(
            "已加入后台队列（{} 个，Preset {}）：",
            lines.len(),
            preset.name
        )
    } else {
        format!("已加入后台队列（Preset {}）：", preset.name)
    };
    Ok(BotReply::Inline {
        text: format!("{}\n{}", header, lines.join("\n")),
        keyboard: main_inline_menu(),
    })
}

async fn send_bot_reply(client: &Client, token: &str, chat_id: i64, reply: BotReply) -> Result<()> {
    match reply {
        BotReply::Text(text) => send_bot_message(client, token, chat_id, &text).await,
        BotReply::Inline { text, keyboard } => {
            send_bot_message_with_markup(client, token, chat_id, &text, Some(keyboard)).await
        }
        BotReply::Reply { text, keyboard } => {
            send_bot_message_with_markup(client, token, chat_id, &text, Some(keyboard)).await
        }
    }
}

async fn send_bot_reply_for_callback(
    client: &Client,
    token: &str,
    chat_id: i64,
    message_id: Option<i64>,
    reply: BotReply,
) -> Result<()> {
    match reply {
        BotReply::Inline { text, keyboard } => {
            if let Some(message_id) = message_id {
                if edit_bot_message_with_markup(
                    client,
                    token,
                    chat_id,
                    message_id,
                    &text,
                    Some(keyboard.clone()),
                )
                .await
                .is_ok()
                {
                    return Ok(());
                }
            }
            send_bot_message_with_markup(client, token, chat_id, &text, Some(keyboard)).await
        }
        BotReply::Text(text) => {
            if let Some(message_id) = message_id {
                if edit_bot_message_with_markup(client, token, chat_id, message_id, &text, None)
                    .await
                    .is_ok()
                {
                    return Ok(());
                }
            }
            send_bot_message(client, token, chat_id, &text).await
        }
        BotReply::Reply { text, keyboard } => {
            send_bot_message_with_markup(client, token, chat_id, &text, Some(keyboard)).await
        }
    }
}

async fn send_bot_message(client: &Client, token: &str, chat_id: i64, text: &str) -> Result<()> {
    send_bot_message_with_markup(client, token, chat_id, text, None).await
}

async fn send_bot_message_with_markup(
    client: &Client,
    token: &str,
    chat_id: i64,
    text: &str,
    reply_markup: Option<serde_json::Value>,
) -> Result<()> {
    let url = format!("https://api.telegram.org/bot{}/sendMessage", token);
    let mut payload = serde_json::json!({
        "chat_id": chat_id,
        "text": text,
        "disable_web_page_preview": true,
    });
    if let Some(markup) = reply_markup {
        payload["reply_markup"] = markup;
    }
    let response = client.post(url).json(&payload).send().await?;
    if response.status().is_success() {
        Ok(())
    } else {
        let status = response.status();
        let body = response.text().await.unwrap_or_default();
        Err(anyhow::anyhow!(
            "telegram sendMessage error {}: {}",
            status,
            body
        ))
    }
}

async fn edit_bot_message_with_markup(
    client: &Client,
    token: &str,
    chat_id: i64,
    message_id: i64,
    text: &str,
    reply_markup: Option<serde_json::Value>,
) -> Result<()> {
    let url = format!("https://api.telegram.org/bot{}/editMessageText", token);
    let mut payload = serde_json::json!({
        "chat_id": chat_id,
        "message_id": message_id,
        "text": text,
        "disable_web_page_preview": true,
    });
    if let Some(markup) = reply_markup {
        payload["reply_markup"] = markup;
    }
    let response = client.post(url).json(&payload).send().await?;
    if response.status().is_success() {
        return Ok(());
    }
    let status = response.status();
    let body = response.text().await.unwrap_or_default();
    if body.contains("message is not modified") {
        return Ok(());
    }
    Err(anyhow::anyhow!(
        "telegram editMessageText error {}: {}",
        status,
        body
    ))
}

async fn answer_callback_query(
    client: &Client,
    token: &str,
    callback_id: &str,
    text: Option<&str>,
) -> Result<()> {
    let url = format!("https://api.telegram.org/bot{}/answerCallbackQuery", token);
    let mut payload = serde_json::json!({ "callback_query_id": callback_id });
    if let Some(text) = text {
        payload["text"] = serde_json::json!(text);
    }
    let response = client.post(url).json(&payload).send().await?;
    if response.status().is_success() {
        Ok(())
    } else {
        let status = response.status();
        let body = response.text().await.unwrap_or_default();
        Err(anyhow::anyhow!(
            "telegram answerCallbackQuery error {}: {}",
            status,
            body
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_kv_args_requires_key_value() {
        let args = vec!["compartment".to_string()];
        assert!(parse_kv_args(&args).is_err());
    }

    #[test]
    fn build_create_input_parses_numbers() {
        let mut params = HashMap::new();
        params.insert("ocpus".to_string(), "2".to_string());
        params.insert("memory_gbs".to_string(), "8".to_string());
        let input = build_create_input(&params, Some("DEFAULT".to_string())).expect("input");
        assert_eq!(input.ocpus, Some(2.0));
        assert_eq!(input.memory_in_gbs, Some(8.0));
    }
}
