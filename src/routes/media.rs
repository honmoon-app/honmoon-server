use axum::{
    body::Body,
    extract::{Multipart, Path, State},
    http::{HeaderMap, StatusCode, header},
    response::IntoResponse,
    Json,
};
use serde::Serialize;
use tokio::io::AsyncWriteExt;
use tokio_util::io::ReaderStream;
use tracing::{debug, error, info};
use uuid::Uuid;

use super::auth::ErrorResponse;
use crate::{auth, AppState};

// ========== Response types ==========

#[derive(Debug, Serialize)]
pub struct UploadMediaResponse {
    pub media_id: String,
    pub size_bytes: i64,
    pub created_at: i64,
}

#[derive(Debug, Serialize)]
pub struct MediaUsageResponse {
    pub used_bytes: i64,
    pub quota_bytes: i64,
    pub used_percent: f64,
}

// ========== Endpoints ==========

/// POST /api/v1/media/upload — Upload an encrypted media file
///
/// Requires JWT Authorization header. Accepts multipart/form-data with:
/// - `file`: the encrypted blob (required)
/// - `original_name`: original filename (optional)
/// - `checksum`: SHA-256 hash for integrity (optional)
pub async fn upload_media(
    headers: HeaderMap,
    State(state): State<AppState>,
    mut multipart: Multipart,
) -> impl IntoResponse {
    // Authenticate
    let claims = match auth::extract_household_claims_from_header(&headers, &state.config.jwt_secret) {
        Ok(c) => c,
        Err(resp) => return resp.into_response(),
    };

    let household_id = &claims.household_id;
    let member_id = &claims.member_id;

    // Check quota before accepting upload
    let quota_bytes = state.config.media_quota_bytes();
    let usage = match state.db.get_household_usage(household_id, quota_bytes).await {
        Ok(u) => u,
        Err(e) => {
            error!("Failed to check storage quota for household {}: {}", household_id, e);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: "Failed to check storage quota".to_string(),
                    code: "QUOTA_CHECK_FAILED".to_string(),
                }),
            ).into_response();
        }
    };

    if usage.used_bytes >= usage.quota_bytes {
        return (
            StatusCode::PAYLOAD_TOO_LARGE,
            Json(ErrorResponse {
                error: "Storage quota exceeded".to_string(),
                code: "QUOTA_EXCEEDED".to_string(),
            }),
        ).into_response();
    }

    // Parse multipart fields
    let media_id = Uuid::new_v4().to_string();
    let mut original_name: Option<String> = None;
    let mut checksum: Option<String> = None;
    let mut file_saved = false;
    let mut file_size: i64 = 0;
    let max_size = state.config.max_upload_bytes() as i64;

    // Create directory
    let dir = format!("{}/{}", state.config.media_dir, household_id);
    if let Err(e) = tokio::fs::create_dir_all(&dir).await {
        error!("Failed to create media directory {}: {}", dir, e);
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: "Failed to prepare storage".to_string(),
                code: "STORAGE_ERROR".to_string(),
            }),
        ).into_response();
    }

    let file_path = format!("{}/{}", dir, media_id);

    while let Ok(Some(field)) = multipart.next_field().await {
        let field_name = field.name().unwrap_or("").to_string();

        match field_name.as_str() {
            "file" => {
                // Stream file to disk
                let mut file = match tokio::fs::File::create(&file_path).await {
                    Ok(f) => f,
                    Err(e) => {
                        error!("Failed to create media file {}: {}", file_path, e);
                        return (
                            StatusCode::INTERNAL_SERVER_ERROR,
                            Json(ErrorResponse {
                                error: "Failed to write file".to_string(),
                                code: "STORAGE_ERROR".to_string(),
                            }),
                        ).into_response();
                    }
                };

                // Read and write in chunks
                let bytes = match field.bytes().await {
                    Ok(b) => b,
                    Err(e) => {
                        error!("Failed to read upload data: {}", e);
                        let _ = tokio::fs::remove_file(&file_path).await;
                        return (
                            StatusCode::BAD_REQUEST,
                            Json(ErrorResponse {
                                error: "Failed to read upload data".to_string(),
                                code: "UPLOAD_ERROR".to_string(),
                            }),
                        ).into_response();
                    }
                };

                file_size = bytes.len() as i64;

                // Check size limit
                if file_size > max_size {
                    let _ = tokio::fs::remove_file(&file_path).await;
                    return (
                        StatusCode::PAYLOAD_TOO_LARGE,
                        Json(ErrorResponse {
                            error: format!("File too large (max {}MB)", state.config.max_upload_size_mb),
                            code: "FILE_TOO_LARGE".to_string(),
                        }),
                    ).into_response();
                }

                // Check if upload would exceed quota
                if usage.used_bytes + file_size > usage.quota_bytes {
                    let _ = tokio::fs::remove_file(&file_path).await;
                    return (
                        StatusCode::PAYLOAD_TOO_LARGE,
                        Json(ErrorResponse {
                            error: "Upload would exceed storage quota".to_string(),
                            code: "QUOTA_EXCEEDED".to_string(),
                        }),
                    ).into_response();
                }

                if let Err(e) = file.write_all(&bytes).await {
                    error!("Failed to write media file: {}", e);
                    let _ = tokio::fs::remove_file(&file_path).await;
                    return (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        Json(ErrorResponse {
                            error: "Failed to write file".to_string(),
                            code: "STORAGE_ERROR".to_string(),
                        }),
                    ).into_response();
                }

                file_saved = true;
            }
            "original_name" => {
                if let Ok(text) = field.text().await {
                    // Limit filename length
                    original_name = Some(text.chars().take(255).collect());
                }
            }
            "checksum" => {
                if let Ok(text) = field.text().await {
                    checksum = Some(text.chars().take(128).collect());
                }
            }
            _ => {} // Ignore unknown fields
        }
    }

    if !file_saved || file_size == 0 {
        let _ = tokio::fs::remove_file(&file_path).await;
        return (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "No file provided in upload".to_string(),
                code: "MISSING_FILE".to_string(),
            }),
        ).into_response();
    }

    // Photos are the bulk of what a household moves, so the media endpoints
    // are counted alongside the relay. Global totals only — see src/traffic.rs.
    state.traffic.record_in(file_size as usize);

    // Store metadata in DB
    if let Err(e) = state.db.insert_media_file(
        &media_id,
        household_id,
        member_id,
        original_name.as_deref(),
        file_size,
        checksum.as_deref(),
    ).await {
        error!("Failed to store media metadata for {}: {}", media_id, e);
        let _ = tokio::fs::remove_file(&file_path).await;
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: "Failed to store file metadata".to_string(),
                code: "STORAGE_ERROR".to_string(),
            }),
        ).into_response();
    }

    // Update quota
    if let Err(e) = state.db.update_household_usage(household_id, file_size).await {
        error!("Failed to update quota for household {}: {}", household_id, e);
        // Non-fatal — file is stored, quota just might be slightly off
    }

    let now = chrono::Utc::now().timestamp();
    info!("Media uploaded: {} ({} bytes) for household {}", media_id, file_size, household_id);

    (
        StatusCode::CREATED,
        Json(UploadMediaResponse {
            media_id,
            size_bytes: file_size,
            created_at: now,
        }),
    ).into_response()
}

/// GET /api/v1/media/:id — Download a media file
///
/// Requires JWT Authorization header. Streams the encrypted file bytes.
pub async fn download_media(
    headers: HeaderMap,
    State(state): State<AppState>,
    Path(media_id): Path<String>,
) -> impl IntoResponse {
    // Authenticate
    let claims = match auth::extract_household_claims_from_header(&headers, &state.config.jwt_secret) {
        Ok(c) => c,
        Err(resp) => return resp.into_response(),
    };

    // Get file metadata
    let file_info = match state.db.get_media_file(&media_id).await {
        Ok(Some(info)) => info,
        Ok(None) => {
            return (
                StatusCode::NOT_FOUND,
                Json(ErrorResponse {
                    error: "Media file not found".to_string(),
                    code: "NOT_FOUND".to_string(),
                }),
            ).into_response();
        }
        Err(e) => {
            error!("Failed to get media file {}: {}", media_id, e);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: "Failed to retrieve file info".to_string(),
                    code: "STORAGE_ERROR".to_string(),
                }),
            ).into_response();
        }
    };

    // Verify household ownership
    if file_info.household_id != claims.household_id {
        return (
            StatusCode::FORBIDDEN,
            Json(ErrorResponse {
                error: "Access denied".to_string(),
                code: "FORBIDDEN".to_string(),
            }),
        ).into_response();
    }

    // Open and stream file
    let file_path = format!("{}/{}/{}", state.config.media_dir, file_info.household_id, media_id);
    let file = match tokio::fs::File::open(&file_path).await {
        Ok(f) => f,
        Err(e) => {
            error!("Failed to open media file {}: {}", file_path, e);
            return (
                StatusCode::NOT_FOUND,
                Json(ErrorResponse {
                    error: "Media file not found on disk".to_string(),
                    code: "FILE_MISSING".to_string(),
                }),
            ).into_response();
        }
    };

    debug!("Streaming media file {} ({} bytes)", media_id, file_info.size_bytes);
    state.traffic.record_out(file_info.size_bytes as usize);

    let stream = ReaderStream::new(file);
    let body = Body::from_stream(stream);

    let mut headers = HeaderMap::new();
    headers.insert(header::CONTENT_TYPE, "application/octet-stream".parse().unwrap());
    headers.insert(header::CONTENT_LENGTH, file_info.size_bytes.to_string().parse().unwrap());
    // Never let a browser sniff/inline a stored blob as HTML/JS on this origin
    // (defense-in-depth stored-XSS guard, audit 2026-07-07).
    headers.insert(header::CONTENT_DISPOSITION, "attachment".parse().unwrap());
    headers.insert("x-content-type-options", "nosniff".parse().unwrap());

    (StatusCode::OK, headers, body).into_response()
}

/// DELETE /api/v1/media/:id — Delete a media file
///
/// Requires JWT Authorization header. Only the owning household can delete.
pub async fn delete_media(
    headers: HeaderMap,
    State(state): State<AppState>,
    Path(media_id): Path<String>,
) -> impl IntoResponse {
    // Authenticate
    let claims = match auth::extract_household_claims_from_header(&headers, &state.config.jwt_secret) {
        Ok(c) => c,
        Err(resp) => return resp.into_response(),
    };

    // Get file info and verify ownership
    let file_info = match state.db.get_media_file(&media_id).await {
        Ok(Some(info)) => info,
        Ok(None) => {
            return (
                StatusCode::NOT_FOUND,
                Json(ErrorResponse {
                    error: "Media file not found".to_string(),
                    code: "NOT_FOUND".to_string(),
                }),
            ).into_response();
        }
        Err(e) => {
            error!("Failed to get media file {}: {}", media_id, e);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: "Failed to retrieve file info".to_string(),
                    code: "STORAGE_ERROR".to_string(),
                }),
            ).into_response();
        }
    };

    if file_info.household_id != claims.household_id {
        return (
            StatusCode::FORBIDDEN,
            Json(ErrorResponse {
                error: "Access denied".to_string(),
                code: "FORBIDDEN".to_string(),
            }),
        ).into_response();
    }

    // Delete from DB
    let size_bytes = file_info.size_bytes;
    if let Err(e) = state.db.delete_media_file(&media_id).await {
        error!("Failed to delete media record {}: {}", media_id, e);
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: "Failed to delete file record".to_string(),
                code: "STORAGE_ERROR".to_string(),
            }),
        ).into_response();
    }

    // Delete from filesystem
    let file_path = format!("{}/{}/{}", state.config.media_dir, file_info.household_id, media_id);
    if let Err(e) = tokio::fs::remove_file(&file_path).await {
        error!("Failed to delete media file from disk {}: {}", file_path, e);
        // Non-fatal — DB record already deleted
    }

    // Update quota
    if let Err(e) = state.db.update_household_usage(&file_info.household_id, -size_bytes).await {
        error!("Failed to update quota after delete: {}", e);
    }

    info!("Media deleted: {} ({} bytes) from household {}", media_id, size_bytes, file_info.household_id);
    StatusCode::OK.into_response()
}

/// GET /api/v1/media/usage — Get storage usage for the authenticated household
///
/// Requires JWT Authorization header.
pub async fn get_usage(
    headers: HeaderMap,
    State(state): State<AppState>,
) -> impl IntoResponse {
    // Authenticate
    let claims = match auth::extract_household_claims_from_header(&headers, &state.config.jwt_secret) {
        Ok(c) => c,
        Err(resp) => return resp.into_response(),
    };

    let quota_bytes = state.config.media_quota_bytes();
    match state.db.get_household_usage(&claims.household_id, quota_bytes).await {
        Ok(usage) => {
            let used_percent = if usage.quota_bytes > 0 {
                (usage.used_bytes as f64 / usage.quota_bytes as f64) * 100.0
            } else {
                0.0
            };

            (
                StatusCode::OK,
                Json(MediaUsageResponse {
                    used_bytes: usage.used_bytes,
                    quota_bytes: usage.quota_bytes,
                    used_percent,
                }),
            ).into_response()
        }
        Err(e) => {
            error!("Failed to get usage for household {}: {}", claims.household_id, e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: "Failed to get storage usage".to_string(),
                    code: "USAGE_CHECK_FAILED".to_string(),
                }),
            ).into_response()
        }
    }
}
