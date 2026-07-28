use axum::{extract::State, http::{HeaderMap, StatusCode}, response::IntoResponse, Json};
use serde::{Deserialize, Serialize};
use tracing::{debug, error};

use super::auth::ErrorResponse;
use crate::{auth, AppState};

#[derive(Debug, Deserialize)]
pub struct RegisterTokenRequest {
    pub token: String,
    pub user_id: String,
    pub device_id: String,
    /// "android", "ios", "web", "linux", "macos", "windows"
    pub platform: String,
    /// "fcm" (default), "unified_push", "web_push", or "relay"
    #[serde(default = "default_endpoint_type")]
    pub endpoint_type: String,
    /// GDPR consent string version the user accepted. Required when
    /// `endpoint_type == "fcm"` (Google as third-party processor); ignored
    /// for `unified_push` / `web_push` / `relay`. The client sends the
    /// canonical text version, e.g. `"v1"`. See
    /// `docs/spec/18-push-delivery.md` § GDPR consent tracking.
    #[serde(default)]
    pub consent_text_version: Option<String>,
}

fn default_endpoint_type() -> String {
    "fcm".to_string()
}

#[derive(Debug, Deserialize)]
pub struct UnregisterTokenRequest {
    pub token: String,
}

/// POST /api/v1/push/register -- register a push notification token or endpoint
pub async fn register_token(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<RegisterTokenRequest>,
) -> impl IntoResponse {
    if request.token.is_empty() || request.user_id.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "Token and user_id are required".to_string(),
                code: "INVALID_REQUEST".to_string(),
            }),
        )
            .into_response();
    }

    // Authenticate via JWT
    let claims = match auth::extract_household_claims_from_header(&headers, &state.config.jwt_secret) {
        Ok(c) => c,
        Err(resp) => return resp.into_response(),
    };

    // Verify user_id matches the authenticated member
    if request.user_id != claims.member_id {
        return (
            StatusCode::FORBIDDEN,
            Json(ErrorResponse {
                error: "user_id does not match authenticated user".to_string(),
                code: "FORBIDDEN".to_string(),
            }),
        )
            .into_response();
    }

    // Validate endpoint_type
    let endpoint_type = match request.endpoint_type.as_str() {
        "fcm" | "unified_push" | "web_push" | "relay" => &request.endpoint_type,
        _ => "fcm", // Default to FCM for backward compatibility
    };

    // SSRF guard at the trust boundary: a UnifiedPush token IS a URL the
    // server later POSTs to (push_dispatch::ntfy_post). Reject internal/
    // private/loopback endpoints at registration time (audit 2026-07-07).
    if endpoint_type == "unified_push"
        && !crate::unified_push::UnifiedPushSender::is_safe_url(&request.token)
    {
        return (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "endpoint URL is not allowed".to_string(),
                code: "INVALID_ENDPOINT".to_string(),
            }),
        )
            .into_response();
    }

    // FCM uses Google as a third-party processor — the client MUST have
    // recorded explicit consent before registering. The other endpoint
    // types deliver via Honmoon's own infrastructure and need no consent.
    if endpoint_type == "fcm" && request.consent_text_version.is_none() {
        return (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "consent_text_version is required for FCM endpoints".to_string(),
                code: "CONSENT_REQUIRED".to_string(),
            }),
        )
            .into_response();
    }

    let consent_version = request.consent_text_version.as_deref();

    match state.db.upsert_push_token(
        &request.token,
        &request.user_id,
        &request.device_id,
        &request.platform,
        endpoint_type,
        consent_version,
    ).await {
        Ok(()) => {
            debug!(
                "Registered push token for user {} on {} (type: {})",
                request.user_id, request.platform, endpoint_type
            );
            StatusCode::OK.into_response()
        }
        Err(e) => {
            error!("Failed to register push token: {}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: "Failed to register token".to_string(),
                    code: "REGISTRATION_FAILED".to_string(),
                }),
            )
                .into_response()
        }
    }
}

/// POST /api/v1/push/unregister -- remove a push notification token
pub async fn unregister_token(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<UnregisterTokenRequest>,
) -> impl IntoResponse {
    if request.token.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "Token is required".to_string(),
                code: "INVALID_REQUEST".to_string(),
            }),
        )
            .into_response();
    }

    // Authenticate via JWT and scope the delete to the caller's own member —
    // deleting by token value alone let any authenticated user unregister
    // someone else's token (audit #32).
    let claims = match auth::extract_household_claims_from_header(&headers, &state.config.jwt_secret) {
        Ok(c) => c,
        Err(resp) => return resp.into_response(),
    };

    match state.db.delete_push_token_for_user(&request.token, &claims.member_id).await {
        Ok(deleted) => {
            if deleted {
                debug!("Unregistered push token");
            }
            StatusCode::OK.into_response()
        }
        Err(e) => {
            error!("Failed to unregister push token: {}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: "Failed to unregister token".to_string(),
                    code: "UNREGISTRATION_FAILED".to_string(),
                }),
            )
                .into_response()
        }
    }
}

/// Response for the VAPID public key endpoint.
#[derive(Serialize)]
pub struct VapidKeyResponse {
    pub public_key: String,
}

/// GET /api/v1/push/vapid-key -- return the public VAPID key for Web Push
pub async fn get_vapid_key(
    State(state): State<AppState>,
) -> impl IntoResponse {
    match state.fcm.get_vapid_public_key() {
        Some(key) => (
            StatusCode::OK,
            Json(VapidKeyResponse {
                public_key: key.to_string(),
            }),
        )
            .into_response(),
        None => (
            StatusCode::NOT_FOUND,
            Json(ErrorResponse {
                error: "Web Push is not configured on this server".to_string(),
                code: "WEB_PUSH_NOT_CONFIGURED".to_string(),
            }),
        )
            .into_response(),
    }
}

#[derive(Serialize)]
pub struct PushHealthResponse {
    /// True when this relay can deliver UnifiedPush wake-ups (NTFY_URL set).
    /// Clients in `unified_push` mode use this to distinguish "my
    /// registration failed" from "this relay has no push configured" — the
    /// dashboard banner shows different wording in each case.
    pub unified_push_configured: bool,
    /// True when this relay can deliver FCM wake-ups (FCM v1 credentials
    /// configured server-side).
    pub fcm_configured: bool,
    /// True when this relay can deliver Web Push wake-ups (VAPID key
    /// configured).
    pub web_push_configured: bool,
}

/// GET /api/v1/push/health -- report which push backends this relay can
/// deliver to. No auth required: the client may call this before it has
/// a JWT (e.g. on first launch to decide which onboarding default to show).
pub async fn get_push_health(
    State(state): State<AppState>,
) -> impl IntoResponse {
    let response = PushHealthResponse {
        unified_push_configured: state.config.ntfy_url.is_some(),
        fcm_configured: state.fcm.is_fcm_available(),
        web_push_configured: state.fcm.is_web_push_available(),
    };
    (StatusCode::OK, Json(response)).into_response()
}
