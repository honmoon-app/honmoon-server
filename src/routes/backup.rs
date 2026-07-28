use axum::{
    body::Body,
    extract::{Multipart, Path, Query, State},
    http::{HeaderMap, StatusCode, header},
    response::IntoResponse,
    Json,
};
use serde::{Deserialize, Serialize};
use tokio::io::AsyncWriteExt;
use tokio_util::io::ReaderStream;
use tracing::{debug, error, info};
use uuid::Uuid;

use super::auth::ErrorResponse;
use crate::{auth, AppState};

// ========== Request / Response types ==========

#[derive(Debug, Deserialize)]
pub struct ListBackupsParams {
    pub household_id: String,
}

#[derive(Debug, Serialize)]
pub struct UploadBackupResponse {
    pub backup_id: String,
    pub created_at: i64,
}

#[derive(Debug, Serialize)]
pub struct ListBackupsResponse {
    pub backups: Vec<BackupInfoResponse>,
}

#[derive(Debug, Serialize)]
pub struct BackupInfoResponse {
    pub id: String,
    pub household_id: String,
    pub description: Option<String>,
    pub size_bytes: i64,
    pub created_at: i64,
}

#[derive(Debug, Serialize)]
pub struct BackupUsageResponse {
    pub used_bytes: i64,
    pub quota_bytes: i64,
    pub used_percent: f64,
}

// ========== Endpoints ==========

/// POST /api/v1/backup/upload — upload an encrypted backup (multipart/form-data)
///
/// Fields: `file` (required, raw encrypted bytes), `description` (optional text).
/// The household_id comes from the JWT claims, not the body.
pub async fn upload_backup(
    headers: HeaderMap,
    State(state): State<AppState>,
    mut multipart: Multipart,
) -> impl IntoResponse {
    let claims = match auth::extract_household_claims_from_header(
        &headers,
        &state.config.jwt_secret,
    ) {
        Ok(c) => c,
        Err(resp) => return resp.into_response(),
    };

    let household_id = claims.household_id.clone();
    let quota_bytes = state.config.backup_quota_bytes();

    // Pre-upload quota check
    let usage = match state.db.get_backup_usage(&household_id, quota_bytes).await {
        Ok(u) => u,
        Err(e) => {
            error!(
                "Failed to check backup quota for {}: {}",
                household_id, e
            );
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: "Failed to check storage quota".to_string(),
                    code: "QUOTA_CHECK_FAILED".to_string(),
                }),
            )
                .into_response();
        }
    };

    if usage.used_bytes >= usage.quota_bytes {
        return (
            StatusCode::PAYLOAD_TOO_LARGE,
            Json(ErrorResponse {
                error: "Backup quota exceeded".to_string(),
                code: "QUOTA_EXCEEDED".to_string(),
            }),
        )
            .into_response();
    }

    let backup_id = Uuid::new_v4().to_string();
    let dir = format!("{}/{}", state.config.backup_dir, household_id);
    if let Err(e) = tokio::fs::create_dir_all(&dir).await {
        error!("Failed to create backup directory {}: {}", dir, e);
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: "Failed to prepare storage".to_string(),
                code: "STORAGE_ERROR".to_string(),
            }),
        )
            .into_response();
    }

    let file_path = format!("{}/{}", dir, backup_id);
    let mut description: Option<String> = None;
    let mut file_saved = false;
    let mut file_size: i64 = 0;
    let max_size = state.config.max_upload_bytes() as i64;
    let now = chrono::Utc::now().timestamp();

    while let Ok(Some(field)) = multipart.next_field().await {
        let field_name = field.name().unwrap_or("").to_string();
        match field_name.as_str() {
            "file" => {
                let mut f = match tokio::fs::File::create(&file_path).await {
                    Ok(f) => f,
                    Err(e) => {
                        error!("Failed to create backup file {}: {}", file_path, e);
                        return (
                            StatusCode::INTERNAL_SERVER_ERROR,
                            Json(ErrorResponse {
                                error: "Failed to write file".to_string(),
                                code: "STORAGE_ERROR".to_string(),
                            }),
                        )
                            .into_response();
                    }
                };
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
                        )
                            .into_response();
                    }
                };
                file_size = bytes.len() as i64;
                if file_size > max_size {
                    let _ = tokio::fs::remove_file(&file_path).await;
                    return (
                        StatusCode::PAYLOAD_TOO_LARGE,
                        Json(ErrorResponse {
                            error: format!(
                                "File too large (max {}MB)",
                                state.config.max_upload_size_mb
                            ),
                            code: "FILE_TOO_LARGE".to_string(),
                        }),
                    )
                        .into_response();
                }
                if usage.used_bytes + file_size > usage.quota_bytes {
                    let _ = tokio::fs::remove_file(&file_path).await;
                    return (
                        StatusCode::PAYLOAD_TOO_LARGE,
                        Json(ErrorResponse {
                            error: "Upload would exceed backup quota".to_string(),
                            code: "QUOTA_EXCEEDED".to_string(),
                        }),
                    )
                        .into_response();
                }
                if let Err(e) = f.write_all(&bytes).await {
                    error!("Failed to write backup file: {}", e);
                    let _ = tokio::fs::remove_file(&file_path).await;
                    return (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        Json(ErrorResponse {
                            error: "Failed to write file".to_string(),
                            code: "STORAGE_ERROR".to_string(),
                        }),
                    )
                        .into_response();
                }
                file_saved = true;
            }
            "description" => {
                if let Ok(text) = field.text().await {
                    description = Some(text.chars().take(255).collect());
                }
            }
            _ => {}
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
        )
            .into_response();
    }

    if let Err(e) = state
        .db
        .store_backup_meta(&backup_id, &household_id, description.as_deref(), file_size)
        .await
    {
        error!("Failed to store backup metadata {}: {}", backup_id, e);
        let _ = tokio::fs::remove_file(&file_path).await;
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: "Failed to store file metadata".to_string(),
                code: "STORAGE_ERROR".to_string(),
            }),
        )
            .into_response();
    }

    if let Err(e) = state
        .db
        .update_backup_usage(&household_id, file_size)
        .await
    {
        error!(
            "Failed to update backup quota for {}: {}",
            household_id, e
        );
    }

    info!(
        "Backup uploaded: {} ({} bytes) for household {}",
        backup_id, file_size, household_id
    );
    (
        StatusCode::CREATED,
        Json(UploadBackupResponse {
            backup_id,
            created_at: now,
        }),
    )
        .into_response()
}

/// GET /api/v1/backup/list?household_id=xxx
pub async fn list_backups(
    headers: HeaderMap,
    State(state): State<AppState>,
    Query(params): Query<ListBackupsParams>,
) -> impl IntoResponse {
    let claims = match auth::extract_household_claims_from_header(
        &headers,
        &state.config.jwt_secret,
    ) {
        Ok(c) => c,
        Err(resp) => return resp.into_response(),
    };

    if params.household_id != claims.household_id {
        return (
            StatusCode::FORBIDDEN,
            Json(ErrorResponse {
                error: "Access denied".to_string(),
                code: "FORBIDDEN".to_string(),
            }),
        )
            .into_response();
    }

    match state.db.list_backups(&params.household_id).await {
        Ok(backups) => {
            debug!(
                "Listed {} backups for household {}",
                backups.len(),
                params.household_id
            );
            let response = ListBackupsResponse {
                backups: backups
                    .into_iter()
                    .map(|b| BackupInfoResponse {
                        id: b.id,
                        household_id: b.household_id,
                        description: b.description,
                        size_bytes: b.size_bytes,
                        created_at: b.created_at,
                    })
                    .collect(),
            };
            (StatusCode::OK, Json(response)).into_response()
        }
        Err(e) => {
            error!(
                "Failed to list backups for {}: {}",
                params.household_id, e
            );
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: "Internal server error".to_string(),
                    code: "BACKUP_LIST_FAILED".to_string(),
                }),
            )
                .into_response()
        }
    }
}

/// GET /api/v1/backup/:id — stream the encrypted backup file
pub async fn download_backup(
    headers: HeaderMap,
    State(state): State<AppState>,
    Path(backup_id): Path<String>,
) -> impl IntoResponse {
    let claims = match auth::extract_household_claims_from_header(
        &headers,
        &state.config.jwt_secret,
    ) {
        Ok(c) => c,
        Err(resp) => return resp.into_response(),
    };

    let meta = match state.db.get_backup_meta(&backup_id).await {
        Ok(Some(m)) => m,
        Ok(None) => {
            return (
                StatusCode::NOT_FOUND,
                Json(ErrorResponse {
                    error: "Backup not found".to_string(),
                    code: "BACKUP_NOT_FOUND".to_string(),
                }),
            )
                .into_response();
        }
        Err(e) => {
            error!("DB error fetching backup {}: {}", backup_id, e);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: "Internal server error".to_string(),
                    code: "BACKUP_GET_FAILED".to_string(),
                }),
            )
                .into_response();
        }
    };

    let (household_id, size_bytes) = meta;
    if household_id != claims.household_id {
        return (
            StatusCode::FORBIDDEN,
            Json(ErrorResponse {
                error: "Access denied".to_string(),
                code: "FORBIDDEN".to_string(),
            }),
        )
            .into_response();
    }

    let file_path = format!(
        "{}/{}/{}",
        state.config.backup_dir, household_id, backup_id
    );
    let file = match tokio::fs::File::open(&file_path).await {
        Ok(f) => f,
        Err(e) => {
            error!("Failed to open backup file {}: {}", file_path, e);
            return (
                StatusCode::NOT_FOUND,
                Json(ErrorResponse {
                    error: "Backup file not found on disk".to_string(),
                    code: "FILE_MISSING".to_string(),
                }),
            )
                .into_response();
        }
    };

    debug!("Streaming backup {} ({} bytes)", backup_id, size_bytes);
    let stream = ReaderStream::new(file);
    let body = Body::from_stream(stream);
    let mut resp_headers = HeaderMap::new();
    resp_headers.insert(
        header::CONTENT_TYPE,
        "application/octet-stream".parse().unwrap(),
    );
    resp_headers.insert(
        header::CONTENT_LENGTH,
        size_bytes.to_string().parse().unwrap(),
    );
    // Defense-in-depth stored-XSS guard (audit 2026-07-07).
    resp_headers.insert(header::CONTENT_DISPOSITION, "attachment".parse().unwrap());
    resp_headers.insert("x-content-type-options", "nosniff".parse().unwrap());
    (StatusCode::OK, resp_headers, body).into_response()
}

/// DELETE /api/v1/backup/:id
pub async fn delete_backup(
    headers: HeaderMap,
    State(state): State<AppState>,
    Path(backup_id): Path<String>,
) -> impl IntoResponse {
    let claims = match auth::extract_household_claims_from_header(
        &headers,
        &state.config.jwt_secret,
    ) {
        Ok(c) => c,
        Err(resp) => return resp.into_response(),
    };

    let meta = match state.db.get_backup_meta(&backup_id).await {
        Ok(Some(m)) => m,
        Ok(None) => {
            return (
                StatusCode::NOT_FOUND,
                Json(ErrorResponse {
                    error: "Backup not found".to_string(),
                    code: "BACKUP_NOT_FOUND".to_string(),
                }),
            )
                .into_response();
        }
        Err(e) => {
            error!("DB error fetching backup {}: {}", backup_id, e);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: "Internal server error".to_string(),
                    code: "BACKUP_DELETE_FAILED".to_string(),
                }),
            )
                .into_response();
        }
    };

    let (household_id, size_bytes) = meta;
    if household_id != claims.household_id {
        return (
            StatusCode::FORBIDDEN,
            Json(ErrorResponse {
                error: "Access denied".to_string(),
                code: "FORBIDDEN".to_string(),
            }),
        )
            .into_response();
    }

    match state.db.delete_backup(&backup_id).await {
        Ok(Some(_)) => {
            let file_path = format!(
                "{}/{}/{}",
                state.config.backup_dir, household_id, backup_id
            );
            if let Err(e) = tokio::fs::remove_file(&file_path).await {
                error!("Failed to delete backup file {}: {}", file_path, e);
            }
            if let Err(e) = state
                .db
                .update_backup_usage(&household_id, -size_bytes)
                .await
            {
                error!("Failed to update backup quota after delete: {}", e);
            }
            info!(
                "Deleted backup {} ({} bytes) from household {}",
                backup_id, size_bytes, household_id
            );
            StatusCode::OK.into_response()
        }
        Ok(None) => (
            StatusCode::NOT_FOUND,
            Json(ErrorResponse {
                error: "Backup not found".to_string(),
                code: "BACKUP_NOT_FOUND".to_string(),
            }),
        )
            .into_response(),
        Err(e) => {
            error!("Failed to delete backup {}: {}", backup_id, e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: "Internal server error".to_string(),
                    code: "BACKUP_DELETE_FAILED".to_string(),
                }),
            )
                .into_response()
        }
    }
}

/// GET /api/v1/backup/usage
pub async fn get_backup_usage(
    headers: HeaderMap,
    State(state): State<AppState>,
) -> impl IntoResponse {
    let claims = match auth::extract_household_claims_from_header(
        &headers,
        &state.config.jwt_secret,
    ) {
        Ok(c) => c,
        Err(resp) => return resp.into_response(),
    };

    let quota_bytes = state.config.backup_quota_bytes();
    match state
        .db
        .get_backup_usage(&claims.household_id, quota_bytes)
        .await
    {
        Ok(usage) => {
            let used_percent = if usage.quota_bytes > 0 {
                (usage.used_bytes as f64 / usage.quota_bytes as f64) * 100.0
            } else {
                0.0
            };
            (
                StatusCode::OK,
                Json(BackupUsageResponse {
                    used_bytes: usage.used_bytes,
                    quota_bytes: usage.quota_bytes,
                    used_percent,
                }),
            )
                .into_response()
        }
        Err(e) => {
            error!(
                "Failed to get backup usage for {}: {}",
                claims.household_id, e
            );
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: "Failed to get backup usage".to_string(),
                    code: "USAGE_CHECK_FAILED".to_string(),
                }),
            )
                .into_response()
        }
    }
}
