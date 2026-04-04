use crate::{
    domain::user::{AvatarUploadResponse, CreateUserRequest},
    error::AppError,
    service::ServiceFactory,
    state::AppState,
};
use axum::{
    extract::{Multipart, Path, State},
    http::{header, HeaderMap, HeaderValue},
    response::IntoResponse,
    routing::{get, post},
    Json, Router,
};
use image::{DynamicImage, GenericImageView, ImageFormat};
use std::path::PathBuf;

const MAX_AVATAR_UPLOAD_BYTES: usize = 5 * 1024 * 1024;
const MAX_AVATAR_DIMENSION: u32 = 128;
const WEBP_QUALITY: f32 = 75.0;

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/users", post(create_user))
        .route("/users/{id}", get(get_user))
        .route("/users/me/avatar", post(upload_avatar))
    .route("/media/avatars/{user_id}/avatar.webp", get(get_avatar))
}

async fn create_user(
    State(state): State<AppState>,
    Json(payload): Json<CreateUserRequest>,
) -> Result<Json<crate::domain::user::User>, AppError> {
    let service = ServiceFactory::new(state).user();
    let user = service.create_user(payload).await?;
    Ok(Json(user))
}

async fn get_user(
    State(state): State<AppState>,
    Path(id): Path<i64>,
) -> Result<Json<crate::domain::user::User>, AppError> {
    let service = ServiceFactory::new(state).user();
    let user = service.get_user(id).await?;
    Ok(Json(user))
}

async fn upload_avatar(
    headers: HeaderMap,
    State(state): State<AppState>,
    mut multipart: Multipart,
) -> Result<Json<AvatarUploadResponse>, AppError> {
    let auth_service = ServiceFactory::new(state.clone()).auth();
    let current_user = auth_service.me(&headers).await?;

    let mut upload_bytes: Option<Vec<u8>> = None;

    while let Some(field) = multipart
        .next_field()
        .await
        .map_err(|_| AppError::BadRequest("invalid multipart payload".to_string()))?
    {
        let field_name = field.name().unwrap_or_default();
        if field_name != "file" {
            continue;
        }

        let bytes = field
            .bytes()
            .await
            .map_err(|_| AppError::BadRequest("failed to read uploaded file".to_string()))?;
        upload_bytes = Some(bytes.to_vec());
        break;
    }

    let upload_bytes = upload_bytes
        .ok_or_else(|| AppError::BadRequest("multipart field 'file' is required".to_string()))?;

    if upload_bytes.len() > MAX_AVATAR_UPLOAD_BYTES {
        return Err(AppError::Validation(
            "image exceeds 5MB upload limit".to_string(),
        ));
    }

    let guessed = image::guess_format(&upload_bytes)
        .map_err(|_| AppError::Validation("file must be a valid JPG or PNG image".to_string()))?;

    if guessed != ImageFormat::Jpeg && guessed != ImageFormat::Png {
        return Err(AppError::Validation(
            "only JPG and PNG uploads are allowed".to_string(),
        ));
    }

    let decoded = image::load_from_memory_with_format(&upload_bytes, guessed)
        .map_err(|_| AppError::Validation("failed to decode image".to_string()))?;
    let optimized = resize_avatar(decoded);
    let (width, height) = optimized.dimensions();
    let webp_bytes = encode_webp(&optimized)?;

    let avatar_file_path = avatar_file_path(&state.avatar_storage_dir, current_user.id);
    if let Some(parent) = avatar_file_path.parent() {
        tokio::fs::create_dir_all(parent)
            .await
            .map_err(|_| AppError::BadRequest("failed to prepare avatar storage".to_string()))?;
    }

    let tmp_file = avatar_file_path.with_extension("webp.tmp");
    tokio::fs::write(&tmp_file, &webp_bytes)
        .await
        .map_err(|_| AppError::BadRequest("failed to persist avatar".to_string()))?;
    tokio::fs::rename(&tmp_file, &avatar_file_path)
        .await
        .map_err(|_| AppError::BadRequest("failed to finalize avatar file".to_string()))?;

    let avatar_url = format!("/api/v1/media/avatars/{}/avatar.webp", current_user.id);
    let user_service = ServiceFactory::new(state).user();
    user_service
        .update_avatar_url(current_user.id, &avatar_url)
        .await?;

    Ok(Json(AvatarUploadResponse {
        avatar_url,
        width,
        height,
        size_bytes: webp_bytes.len(),
        format: "image/webp",
    }))
}

async fn get_avatar(
    State(state): State<AppState>,
    Path(user_id): Path<i64>,
) -> Result<impl IntoResponse, AppError> {
    let file_path = avatar_file_path(&state.avatar_storage_dir, user_id);
    let bytes = tokio::fs::read(file_path)
        .await
        .map_err(|_| AppError::NotFound)?;

    Ok((
        [
            (header::CONTENT_TYPE, HeaderValue::from_static("image/webp")),
            (header::CACHE_CONTROL, HeaderValue::from_static("no-store")),
        ],
        bytes,
    ))
}

fn resize_avatar(input: DynamicImage) -> DynamicImage {
    let (width, height) = input.dimensions();
    if width <= MAX_AVATAR_DIMENSION && height <= MAX_AVATAR_DIMENSION {
        return input;
    }

    input.resize(
        MAX_AVATAR_DIMENSION,
        MAX_AVATAR_DIMENSION,
        image::imageops::FilterType::Lanczos3,
    )
}

fn encode_webp(image: &DynamicImage) -> Result<Vec<u8>, AppError> {
    let encoder = webp::Encoder::from_image(image)
        .map_err(|_| AppError::BadRequest("invalid image data".to_string()))?;
    let encoded = encoder.encode(WEBP_QUALITY);
    Ok(encoded.to_vec())
}

fn avatar_file_path(storage_root: &str, user_id: i64) -> PathBuf {
    PathBuf::from(storage_root)
        .join(user_id.to_string())
        .join("avatar.webp")
}
