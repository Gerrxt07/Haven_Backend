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
use chrono::Utc;
use image::{DynamicImage, GenericImageView, ImageFormat};
use std::path::PathBuf;
use std::process::Command;
use tracing::{info, warn};

const MAX_AVATAR_UPLOAD_BYTES: usize = 5 * 1024 * 1024;
const MAX_AVATAR_DIMENSION: u32 = 128;
const WEBP_QUALITY: f32 = 75.0;

struct ProcessedAvatar {
    webp_bytes: Vec<u8>,
    width: u32,
    height: u32,
}

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

    info!(
        event = "avatar.upload.start",
        user_id = current_user.id,
        "avatar upload started"
    );

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
        warn!(
            event = "avatar.upload.rejected_size",
            user_id = current_user.id,
            bytes = upload_bytes.len(),
            max_bytes = MAX_AVATAR_UPLOAD_BYTES,
            "avatar upload rejected due to size"
        );
        return Err(AppError::Validation(
            "image exceeds 5MB upload limit".to_string(),
        ));
    }

    let guessed = image::guess_format(&upload_bytes)
        .map_err(|_| AppError::Validation("file must be a valid JPG or PNG image".to_string()))?;

    info!(
        event = "avatar.upload.detected_format",
        user_id = current_user.id,
        format = ?guessed,
        bytes = upload_bytes.len(),
        "avatar upload format detected"
    );

    if guessed != ImageFormat::Jpeg && guessed != ImageFormat::Png {
        warn!(
            event = "avatar.upload.rejected_format",
            user_id = current_user.id,
            format = ?guessed,
            "avatar upload rejected due to unsupported image format"
        );
        return Err(AppError::Validation(
            "only JPG and PNG uploads are allowed".to_string(),
        ));
    }

    let processed =
        tokio::task::spawn_blocking(move || process_avatar_image(upload_bytes, guessed))
            .await
            .map_err(|_| AppError::BadRequest("avatar processing task failed".to_string()))?
            .map_err(AppError::Validation)?;

    let ProcessedAvatar {
        webp_bytes,
        width,
        height,
    } = processed;

    info!(
        event = "avatar.upload.optimized",
        user_id = current_user.id,
        width,
        height,
        webp_bytes = webp_bytes.len(),
        "avatar upload image optimized and encoded"
    );

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

    let avatar_url = format!(
        "/api/v1/media/avatars/{}/avatar.webp?v={}",
        current_user.id,
        Utc::now().timestamp_millis()
    );
    let user_service = ServiceFactory::new(state).user();
    user_service
        .update_avatar_url(current_user.id, &avatar_url)
        .await?;

    info!(
        event = "avatar.upload.success",
        user_id = current_user.id,
        width,
        height,
        size_bytes = webp_bytes.len(),
        avatar_url = %avatar_url,
        "avatar upload completed"
    );

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
    info!(
        event = "avatar.download.request",
        user_id,
        file_path = %file_path.display(),
        "avatar download requested"
    );
    let bytes = tokio::fs::read(file_path).await.map_err(|_| {
        warn!(
            event = "avatar.download.not_found",
            user_id, "avatar download failed: file not found"
        );
        AppError::NotFound
    })?;

    info!(
        event = "avatar.download.success",
        user_id,
        size_bytes = bytes.len(),
        "avatar download succeeded"
    );

    Ok((
        [
            (header::CONTENT_TYPE, HeaderValue::from_static("image/webp")),
            (
                header::CACHE_CONTROL,
                HeaderValue::from_static("public, max-age=31536000, immutable"),
            ),
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

fn process_avatar_image(
    upload_bytes: Vec<u8>,
    guessed: ImageFormat,
) -> Result<ProcessedAvatar, String> {
    if let Ok(processed) = process_avatar_image_vips(&upload_bytes, guessed) {
        return Ok(processed);
    }

    let decoded = image::load_from_memory_with_format(&upload_bytes, guessed)
        .map_err(|_| "failed to decode image".to_string())?;
    let optimized = resize_avatar(decoded);
    let (width, height) = optimized.dimensions();
    let webp_bytes = encode_webp(&optimized).map_err(|_| "failed to encode image".to_string())?;

    Ok(ProcessedAvatar {
        webp_bytes,
        width,
        height,
    })
}

fn process_avatar_image_vips(
    upload_bytes: &[u8],
    guessed: ImageFormat,
) -> Result<ProcessedAvatar, String> {
    let temp_dir = tempfile::tempdir().map_err(|_| "failed to create temp dir".to_string())?;
    let input_ext = match guessed {
        ImageFormat::Png => "png",
        ImageFormat::Jpeg => "jpg",
        _ => return Err("unsupported image format".to_string()),
    };

    let input_path = temp_dir.path().join(format!("input.{input_ext}"));
    let output_path = temp_dir.path().join("output.webp");

    std::fs::write(&input_path, upload_bytes)
        .map_err(|_| "failed to write temp input".to_string())?;

    let output_spec = format!("{}[Q={}]", output_path.display(), WEBP_QUALITY.round());
    let status = Command::new("vipsthumbnail")
        .arg(&input_path)
        .arg("--size")
        .arg(format!("{}x{}", MAX_AVATAR_DIMENSION, MAX_AVATAR_DIMENSION))
        .arg("-o")
        .arg(output_spec)
        .status()
        .map_err(|_| "failed to start vipsthumbnail".to_string())?;

    if !status.success() {
        return Err("vipsthumbnail failed".to_string());
    }

    let webp_bytes = std::fs::read(&output_path)
        .map_err(|_| "failed to read vipsthumbnail output".to_string())?;
    let output_image = image::load_from_memory_with_format(&webp_bytes, ImageFormat::WebP)
        .map_err(|_| "failed to decode vipsthumbnail output".to_string())?;
    let (width, height) = output_image.dimensions();

    Ok(ProcessedAvatar {
        webp_bytes,
        width,
        height,
    })
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
