use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::SystemTime;

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

#[derive(Debug, Serialize)]
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
    availability_domain: Option<String>,
    image: Option<String>,
    image_os: Option<String>,
    image_version: Option<String>,
    display_name: Option<String>,
    ssh_key: Option<String>,
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
        availability_domain: payload.availability_domain,
        image: payload.image,
        image_os: payload.image_os,
        image_version: payload.image_version,
        display_name: payload.display_name,
        ssh_key: payload.ssh_key,
        retry_interval_secs: None,
    };
    let resolved = resolve_create_payload(&profile.client, &profile.defaults, input, false)
        .await
        .map_err(internal_error)?;
    let instance = profile
        .client
        .create_instance(resolved.payload)
        .await
        .map_err(internal_error)?;
    notify_success(&profile.client.profile, &instance, NotifySource::Web).await;
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
    notify_success(&profile_state.client.profile, &instance, NotifySource::Task).await;
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
    let query = TelegramUpdateQuery { timeout: 5, offset };
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
        "start" | "help" => {
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
                    text: "菜单已加载，点击按钮操作。".to_string(),
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
    let _ = send_bot_reply(client, &state.token, chat_id, reply).await;
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

    let is_blocked = {
        let bind_state = state.bind_state.lock().unwrap();
        telegram_bind::is_blocked(&bind_state, chat_id)
    };
    if is_blocked {
        let _ = answer_callback_query(client, &state.token, &callback.id, Some("已被拉黑。")).await;
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
        match data.as_str() {
            "menu" => BotReply::Inline {
                text: "菜单已加载，点击按钮操作。".to_string(),
                keyboard: main_inline_menu(),
            },
            "help" => BotReply::Inline {
                text: help_text(),
                keyboard: main_inline_menu(),
            },
            "profiles" => {
                let mut profiles = state.app.profiles.keys().cloned().collect::<Vec<_>>();
                profiles.sort();
                BotReply::Inline {
                    text: "选择 Profile：".to_string(),
                    keyboard: profiles_inline_menu(&profiles),
                }
            }
            value if value.starts_with("profile_set:") => {
                let name = value.trim_start_matches("profile_set:");
                let key = name.trim().to_uppercase();
                if !state.app.profiles.contains_key(&key) {
                    BotReply::Text(format!("Profile '{}' 不存在。", key))
                } else {
                    let mut profiles = state.chat_profiles.lock().unwrap();
                    profiles.insert(chat_id, key.clone());
                    BotReply::Inline {
                        text: format!("Profile 已切换为 {}。", key),
                        keyboard: main_inline_menu(),
                    }
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
                let reply = preset_action(state, chat_id, idx, false).await;
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
            "instances" => match handle_instances_command(state, chat_id, &[]).await {
                Ok(text) => BotReply::Text(text),
                Err(err) => BotReply::Text(err),
            },
            "availability" => match handle_availability_command(state, chat_id, &[]).await {
                Ok(text) => BotReply::Text(text),
                Err(err) => BotReply::Text(err),
            },
            "tasks" => match handle_tasks_command(state, chat_id, &[]) {
                Ok(result) => result,
                Err(err) => BotReply::Text(err),
            },
            "tasks_clear" => match handle_tasks_command(state, chat_id, &["clear".to_string()]) {
                Ok(result) => result,
                Err(err) => BotReply::Text(err),
            },
            value if value.starts_with("task_stop:") => {
                let id = value.trim_start_matches("task_stop:");
                let reply =
                    handle_task_command(state, chat_id, &["stop".to_string(), id.to_string()]);
                match reply {
                    Ok(text) => BotReply::Text(text),
                    Err(err) => BotReply::Text(err),
                }
            }
            "bind" => BotReply::Reply {
                text: "请发送：/bind <admin_key>".to_string(),
                keyboard: bind_keyboard(),
            },
            _ => BotReply::Text("未知操作。".to_string()),
        }
    };

    let _ = answer_callback_query(client, &state.token, &callback.id, None).await;
    let _ = send_bot_reply(client, &state.token, chat_id, reply).await;
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
        "快捷菜单已加载（建议用按钮）。",
        "常用指令：",
        "/bind <admin_key>",
        "/menu | /help",
        "/profile | /profile list | /profile set <NAME>",
        "/presets",
        "/instances [profile=NAME] [compartment=OCID]",
        "/availability [profile=NAME] [compartment=OCID] [availability_domain=AD]",
        "/create key=value ...",
        "/queue key=value ...",
        "/tasks | /tasks clear",
        "/task stop <TASK_ID>",
        "",
        "Create/Queue 参数：",
        "compartment, subnet, shape, ocpus, memory_gbs, boot_volume_gbs,",
        "availability_domain, image, image_os, image_version, display_name,",
        "ssh_key, retry_interval_secs, profile, preset",
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
            [{ "text": "配置", "callback_data": "profiles" }, { "text": "预设", "callback_data": "presets" }],
            [{ "text": "实例", "callback_data": "instances" }, { "text": "可用区", "callback_data": "availability" }],
            [{ "text": "任务", "callback_data": "tasks" }, { "text": "帮助", "callback_data": "help" }]
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

fn presets_inline_menu(presets: &[Preset]) -> serde_json::Value {
    let mut rows = Vec::new();
    for (idx, preset) in presets.iter().take(10).enumerate() {
        rows.push(vec![
            serde_json::json!({
                "text": format!("✅ 创建 {}", preset.name),
                "callback_data": format!("preset_create:{}", idx)
            }),
            serde_json::json!({
                "text": format!("🕒 排队 {}", preset.name),
                "callback_data": format!("preset_queue:{}", idx)
            }),
        ]);
    }
    rows.push(vec![
        serde_json::json!({ "text": "返回菜单", "callback_data": "menu" }),
    ]);
    serde_json::json!({ "inline_keyboard": rows })
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
        return Err("Admin key is not configured.".to_string());
    };
    let provided = args.first().map(|v| v.trim()).unwrap_or("");
    if provided.is_empty() {
        return Err("Usage: /bind <admin_key>".to_string());
    }
    if provided != admin_key {
        let (count, blocked) = {
            let mut bind_state = state.bind_state.lock().unwrap();
            telegram_bind::record_failure(&mut bind_state, chat_id).unwrap_or((3, true))
        };
        if blocked {
            return Ok("Unauthorized. You are blocked after 3 failures.".to_string());
        }
        return Ok(format!("Unauthorized. Attempt {}/3.", count));
    }

    let mut bind_state = state.bind_state.lock().unwrap();
    if let Err(err) = telegram_bind::set_chat_id(&mut bind_state, chat_id) {
        return Err(format!("Bind failed: {}", err));
    }
    Ok("Bind success. This chat is now authorized.".to_string())
}

async fn handle_authed_command(
    state: &TelegramBotState,
    chat_id: i64,
    command: &str,
    args: &[String],
) -> Result<BotReply, String> {
    match command {
        "profile" => handle_profile_command(state, chat_id, args),
        "presets" => handle_presets_command(state),
        "instances" => handle_instances_command(state, chat_id, args)
            .await
            .map(BotReply::Text),
        "availability" => handle_availability_command(state, chat_id, args)
            .await
            .map(BotReply::Text),
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
        return Ok(BotReply::Text(format!("Profile 已切换为 {}。", key)));
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

async fn handle_instances_command(
    state: &TelegramBotState,
    chat_id: i64,
    args: &[String],
) -> Result<String, String> {
    let params = parse_kv_args(args)?;
    let profile_key = resolve_profile_key(state, chat_id, params.get("profile"));
    let Some(profile_state) = state.app.profiles.get(&profile_key) else {
        return Err(format!("Profile '{}' 不存在。", profile_key));
    };
    let compartment = params
        .get("compartment")
        .cloned()
        .or_else(|| profile_state.defaults.compartment.clone())
        .ok_or_else(|| "缺少 compartment".to_string())?;
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

async fn handle_availability_command(
    state: &TelegramBotState,
    chat_id: i64,
    args: &[String],
) -> Result<String, String> {
    let params = parse_kv_args(args)?;
    let profile_key = resolve_profile_key(state, chat_id, params.get("profile"));
    let Some(profile_state) = state.app.profiles.get(&profile_key) else {
        return Err(format!("Profile '{}' 不存在。", profile_key));
    };
    let compartment = params
        .get("compartment")
        .cloned()
        .or_else(|| profile_state.defaults.compartment.clone())
        .ok_or_else(|| "缺少 compartment".to_string())?;
    let ads = profile_state
        .client
        .availability_domains(&compartment)
        .await
        .map_err(|err| err.to_string())?;
    let mut lines = vec!["Availability Domains:".to_string()];
    for ad in &ads {
        lines.push(format!("{} ({})", ad.name, ad.id));
    }
    if let Some(ad) = params
        .get("availability_domain")
        .cloned()
        .or_else(|| profile_state.defaults.availability_domain.clone())
    {
        let shapes = profile_state
            .client
            .list_shapes(&compartment, &ad)
            .await
            .map_err(|err| err.to_string())?;
        lines.push(format!("Shapes in {}:", ad));
        for (idx, shape) in shapes.iter().enumerate() {
            if idx >= 20 {
                lines.push("...truncated...".to_string());
                break;
            }
            let ocpus = shape.ocpus.unwrap_or_default();
            let mem = shape.memory_in_gbs.unwrap_or_default();
            lines.push(format!("{} - {} OCPUs / {} GB", shape.shape, ocpus, mem));
        }
    }
    Ok(lines.join("\n"))
}

async fn handle_create_command(
    state: &TelegramBotState,
    chat_id: i64,
    args: &[String],
) -> Result<String, String> {
    let mut params = parse_kv_args(args)?;
    let preset_name = params.remove("preset");
    let profile_key = resolve_profile_key(state, chat_id, params.get("profile"));
    let mut input = build_create_input(&params, Some(profile_key.clone()))?;
    if let Some(name) = preset_name {
        apply_preset_by_name(state, &profile_key, &mut input, &name)?;
    }
    let instance = execute_creation(&state.app, input)
        .await
        .map_err(|err| err.to_string())?;
    Ok(format!(
        "已创建实例：{} ({})",
        instance.display_name, instance.id
    ))
}

fn handle_queue_command(
    state: &TelegramBotState,
    chat_id: i64,
    args: &[String],
) -> Result<String, String> {
    let mut params = parse_kv_args(args)?;
    let preset_name = params.remove("preset");
    let profile_key = resolve_profile_key(state, chat_id, params.get("profile"));
    let mut input = build_create_input(&params, Some(profile_key.clone()))?;
    if let Some(name) = preset_name {
        apply_preset_by_name(state, &profile_key, &mut input, &name)?;
    }
    let id = enqueue_task(&state.app, input);
    Ok(format!("任务已排队：{}", id))
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
    let profiles = state.chat_profiles.lock().unwrap();
    profiles
        .get(&chat_id)
        .cloned()
        .unwrap_or_else(|| state.app.default_profile.clone())
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
    let retry_interval_secs = params
        .get("retry_interval_secs")
        .map(|value| parse_u64(value, "retry_interval_secs"))
        .transpose()?;

    Ok(CreateInput {
        profile,
        compartment: params.get("compartment").cloned(),
        subnet: params.get("subnet").cloned(),
        shape: params.get("shape").cloned(),
        ocpus,
        memory_in_gbs,
        boot_volume_size_gbs,
        availability_domain: params.get("availability_domain").cloned(),
        image: params.get("image").cloned(),
        image_os: params.get("image_os").cloned(),
        image_version: params.get("image_version").cloned(),
        display_name: params.get("display_name").cloned(),
        ssh_key: params.get("ssh_key").cloned(),
        retry_interval_secs,
    })
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
    if input.ocpus.is_none() {
        input.ocpus = preset.ocpus;
    }
    if input.memory_in_gbs.is_none() {
        input.memory_in_gbs = preset.memory_in_gbs;
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
    queue: bool,
) -> Result<BotReply, String> {
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
    let mut input = build_create_input(&HashMap::new(), Some(profile_key.clone()))?;
    apply_preset_to_input(&profile_key, &mut input, &preset);
    if queue {
        let id = enqueue_task(&state.app, input);
        Ok(BotReply::Inline {
            text: format!("已排队：{}（Preset {}）", id, preset.name),
            keyboard: main_inline_menu(),
        })
    } else {
        let instance = execute_creation(&state.app, input)
            .await
            .map_err(|err| err.to_string())?;
        Ok(BotReply::Inline {
            text: format!(
                "已创建：{} ({})（Preset {}）",
                instance.display_name, instance.id, preset.name
            ),
            keyboard: main_inline_menu(),
        })
    }
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
