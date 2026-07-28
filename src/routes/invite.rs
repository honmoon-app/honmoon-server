use axum::{
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
    Json,
};
use serde::{Deserialize, Serialize};
use tracing::{debug, error};

use crate::auth;
use crate::AppState;

use super::auth::ErrorResponse;

/// Max validity a host may request: 7 days.
const MAX_TTL_SECONDS: i64 = 7 * 24 * 3600;

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PutInviteRequest {
    pub code: String,
    /// JSON `{nonce, ciphertext}` of the encrypted household snapshot.
    pub blob: String,
    pub ttl_seconds: i64,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PutInviteResponse {
    pub success: bool,
    pub expires_at: i64,
}

/// Store / replace a sealed invite. Household-JWT authenticated.
pub async fn put_invite(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<PutInviteRequest>,
) -> impl IntoResponse {
    let claims =
        match auth::extract_household_claims_from_header(&headers, &state.config.jwt_secret) {
            Ok(c) => c,
            Err(_) => {
                return (
                    StatusCode::UNAUTHORIZED,
                    Json(ErrorResponse {
                        error: "Authentication required".to_string(),
                        code: "UNAUTHORIZED".to_string(),
                    }),
                )
                    .into_response();
            }
        };

    let normalized = request.code.replace('-', "").to_uppercase();
    if !auth::validate_invite_code(&normalized) {
        return (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "Invalid invite code format".to_string(),
                code: "INVALID_REQUEST".to_string(),
            }),
        )
            .into_response();
    }
    if request.blob.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "Empty blob".to_string(),
                code: "INVALID_REQUEST".to_string(),
            }),
        )
            .into_response();
    }

    let ttl = request.ttl_seconds.clamp(60, MAX_TTL_SECONDS);
    let expires_at = chrono::Utc::now().timestamp() + ttl;

    match state
        .db
        .store_sealed_invite(&normalized, &request.blob, expires_at, &claims.household_id)
        .await
    {
        Ok(()) => {
            debug!(
                "Sealed invite stored for {} by household {}",
                normalized, claims.household_id
            );
            (
                StatusCode::OK,
                Json(PutInviteResponse {
                    success: true,
                    expires_at,
                }),
            )
                .into_response()
        }
        Err(e) => {
            error!("Failed to store sealed invite: {}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: "Failed to store invite".to_string(),
                    code: "INVITE_STORE_FAILED".to_string(),
                }),
            )
                .into_response()
        }
    }
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GetInviteResponse {
    /// JSON `{nonce, ciphertext}` of the encrypted household snapshot.
    pub blob: String,
}

/// Fetch a sealed invite blob. Unauthenticated — the `?s=` secret in
/// the link is the credential, and the relay cannot use it. Returns
/// 404 for unknown or expired codes.
pub async fn get_invite(
    State(state): State<AppState>,
    Path(code): Path<String>,
) -> impl IntoResponse {
    let normalized = code.replace('-', "").to_uppercase();
    if !auth::validate_invite_code(&normalized) {
        return (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "Invalid invite code format".to_string(),
                code: "INVALID_REQUEST".to_string(),
            }),
        )
            .into_response();
    }

    match state.db.get_sealed_invite(&normalized).await {
        Ok(Some(blob)) => {
            debug!("Sealed invite served for {}", normalized);
            (StatusCode::OK, Json(GetInviteResponse { blob })).into_response()
        }
        Ok(None) => (
            StatusCode::NOT_FOUND,
            Json(ErrorResponse {
                error: "Invite not found or expired".to_string(),
                code: "INVITE_NOT_FOUND".to_string(),
            }),
        )
            .into_response(),
        Err(e) => {
            error!("Failed to fetch sealed invite: {}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: "Failed to fetch invite".to_string(),
                    code: "INVITE_FETCH_FAILED".to_string(),
                }),
            )
                .into_response()
        }
    }
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DeleteInviteResponse {
    pub success: bool,
}

/// Revoke a sealed invite. Household-JWT authenticated — only a client
/// that can authenticate as the household may delete its invite.
/// Idempotent: deleting an unknown or already-expired code returns 200.
pub async fn delete_invite(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(code): Path<String>,
) -> impl IntoResponse {
    let claims =
        match auth::extract_household_claims_from_header(&headers, &state.config.jwt_secret) {
            Ok(c) => c,
            Err(_) => {
                return (
                    StatusCode::UNAUTHORIZED,
                    Json(ErrorResponse {
                        error: "Authentication required".to_string(),
                        code: "UNAUTHORIZED".to_string(),
                    }),
                )
                    .into_response();
            }
        };

    let normalized = code.replace('-', "").to_uppercase();
    if !auth::validate_invite_code(&normalized) {
        return (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "Invalid invite code format".to_string(),
                code: "INVALID_REQUEST".to_string(),
            }),
        )
            .into_response();
    }

    match state.db.delete_sealed_invite(&normalized, &claims.household_id).await {
        Ok(count) => {
            debug!(
                "Sealed invite {} revoked by household {} ({} row(s))",
                normalized, claims.household_id, count
            );
            (
                StatusCode::OK,
                Json(DeleteInviteResponse { success: true }),
            )
                .into_response()
        }
        Err(e) => {
            error!("Failed to delete sealed invite: {}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: "Failed to delete invite".to_string(),
                    code: "INVITE_DELETE_FAILED".to_string(),
                }),
            )
                .into_response()
        }
    }
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GetActiveInvitesResponse {
    pub invites: Vec<crate::db::invite::ActiveInvite>,
}

pub async fn get_active_invites(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let claims =
        match auth::extract_household_claims_from_header(&headers, &state.config.jwt_secret) {
            Ok(c) => c,
            Err(_) => {
                return (
                    StatusCode::UNAUTHORIZED,
                    Json(ErrorResponse {
                        error: "Authentication required".to_string(),
                        code: "UNAUTHORIZED".to_string(),
                    }),
                )
                    .into_response();
            }
        };

    match state.db.list_active_invites(&claims.household_id).await {
        Ok(invites) => (
            StatusCode::OK,
            Json(GetActiveInvitesResponse { invites }),
        )
            .into_response(),
        Err(e) => {
            error!("Failed to list active invites: {}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: "Failed to list invites".to_string(),
                    code: "INVITE_LIST_FAILED".to_string(),
                }),
            )
                .into_response()
        }
    }
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GetInviteStatsResponse {
    pub downloads: i64,
}

pub async fn get_invite_stats(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(code): Path<String>,
) -> impl IntoResponse {
    let claims =
        match auth::extract_household_claims_from_header(&headers, &state.config.jwt_secret) {
            Ok(c) => c,
            Err(_) => {
                return (
                    StatusCode::UNAUTHORIZED,
                    Json(ErrorResponse {
                        error: "Authentication required".to_string(),
                        code: "UNAUTHORIZED".to_string(),
                    }),
                )
                    .into_response();
            }
        };

    let normalized = code.replace('-', "").to_uppercase();
    if !auth::validate_invite_code(&normalized) {
        return (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "Invalid invite code format".to_string(),
                code: "INVALID_REQUEST".to_string(),
            }),
        )
            .into_response();
    }

    match state
        .db
        .get_invite_stats(&normalized, &claims.household_id)
        .await
    {
        Ok(Some(downloads)) => (
            StatusCode::OK,
            Json(GetInviteStatsResponse { downloads }),
        )
            .into_response(),
        Ok(None) => (
            StatusCode::NOT_FOUND,
            Json(ErrorResponse {
                error: "Invite not found or expired".to_string(),
                code: "INVITE_NOT_FOUND".to_string(),
            }),
        )
            .into_response(),
        Err(e) => {
            error!("Failed to fetch invite stats: {}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: "Failed to fetch invite stats".to_string(),
                    code: "INVITE_STATS_FAILED".to_string(),
                }),
            )
                .into_response()
        }
    }
}
