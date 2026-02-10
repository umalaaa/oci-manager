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
use serde::{Deserialize, Serialize};
use tracing::info;

use crate::config::{OciConfig, Preset, ProfileDefaults};
use crate::logic::{resolve_create_payload, CreateInput};
use crate::models::{AvailabilityDomain, InstanceSummary, Shape, SubnetSummary};
use crate::oci::OciClient;

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

pub async fn serve(
    config: OciConfig,
    default_profile: String,
    admin_key: Option<String>,
    host: String,
    port: u16,
) -> Result<()> {
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
    if !profiles.contains_key(&default_profile) {
        bail!("Default profile '{}' not found", default_profile);
    }

    let state = AppState {
        profiles: Arc::new(profiles),
        default_profile,
        admin_key,
        presets: Arc::new(config.presets),
        tasks: Arc::new(Mutex::new(Vec::new())),
    };

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

// ... (other imports remain, but I need to make sure I don't duplicate or miss them if I replace a block)
// I better replace functions carefully.

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
    if path == "/login" || path == "/" {
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
    };
    let resolved = resolve_create_payload(&profile.client, &profile.defaults, input, false)
        .await
        .map_err(internal_error)?;
    let instance = profile
        .client
        .create_instance(resolved.payload)
        .await
        .map_err(internal_error)?;
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
        tasks.push(task.clone());
    }

    let state_clone = state.clone();
    let task_id = id.clone();
    let input_clone = input.clone();

    tokio::spawn(async move {
        let mut attempts = 0;
        let retry_interval: u64 = 60;
        loop {
            // Check cancellation before each attempt
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
                    // Sleep in 1s increments so cancellation is responsive
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

    Json(serde_json::json!({ "taskId": id }))
}

async fn delete_task(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<StatusCode, (StatusCode, String)> {
    let mut tasks = state.tasks.lock().unwrap();
    if let Some(pos) = tasks.iter().position(|t| t.id == id) {
        let task = &tasks[pos];
        task.cancelled.store(true, Ordering::Relaxed);
        tasks.remove(pos);
        Ok(StatusCode::NO_CONTENT)
    } else {
        Err((StatusCode::NOT_FOUND, format!("Task '{}' not found", id)))
    }
}

async fn clear_tasks(State(state): State<AppState>) -> impl IntoResponse {
    let mut tasks = state.tasks.lock().unwrap();
    tasks.retain(|t| {
        let active = matches!(
            t.status,
            TaskStatus::Pending | TaskStatus::Running | TaskStatus::Retrying(_)
        );
        active && !t.cancelled.load(Ordering::Relaxed)
    });
    StatusCode::NO_CONTENT
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
    Ok(instance)
}
