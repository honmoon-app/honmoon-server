use axum::{
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
    Json,
};
use serde::{Deserialize, Serialize};
use tracing::{debug, error};

use crate::{auth, AppState};
use super::auth::ErrorResponse;

#[derive(Debug, Deserialize)]
pub struct FeedbackRequest {
    pub household_id: String,
    pub member_id: String,
    pub category: String,
    pub message: String,
    pub severity: Option<String>,
    pub title: Option<String>,
    pub steps_to_reproduce: Option<String>,
    pub expected_behavior: Option<String>,
    pub device_info: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct FeedbackResponse {
    pub feedback_id: String,
}

#[derive(Debug, Deserialize)]
pub struct ListFeedbackParams {
    pub status: Option<String>,
    pub category: Option<String>,
    pub include_archived: Option<bool>,
}

#[derive(Debug, Deserialize)]
pub struct UpdateFeedbackRequest {
    pub status: String,
    pub notes: Option<String>,
}

/// Verify the admin bearer token from Authorization header
fn verify_admin_token(
    headers: &HeaderMap,
    expected_token: &str,
) -> Result<(), (StatusCode, Json<ErrorResponse>)> {
    let auth_header = headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");

    let token = auth_header.strip_prefix("Bearer ").unwrap_or("");

    // Constant-time comparison to avoid a timing oracle on the admin token
    // (audit 2026-07-07). Mirrors the Stripe-signature path.
    use subtle::ConstantTimeEq;
    let matches: bool = token.as_bytes().ct_eq(expected_token.as_bytes()).into();
    if token.is_empty() || !matches {
        return Err((
            StatusCode::UNAUTHORIZED,
            Json(ErrorResponse {
                error: "Invalid or missing admin token".to_string(),
                code: "UNAUTHORIZED".to_string(),
            }),
        ));
    }

    Ok(())
}

/// Max length for the feedback message field
const MAX_MESSAGE_LEN: usize = 5000;
/// Max length for device_info field
const MAX_DEVICE_INFO_LEN: usize = 500;
/// Max length for other string fields
const MAX_FIELD_LEN: usize = 500;

pub async fn submit_feedback(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(mut request): Json<FeedbackRequest>,
) -> impl IntoResponse {
    // Require JWT auth to prevent spam from unauthenticated clients
    let claims = match auth::extract_household_claims_from_header(&headers, &state.config.jwt_secret) {
        Ok(c) => c,
        Err(err) => return err.into_response(),
    };

    // Use authenticated household_id and member_id, ignore client-supplied values
    request.household_id = claims.household_id;
    request.member_id = claims.member_id;

    if request.message.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "message is required".to_string(),
                code: "INVALID_REQUEST".to_string(),
            }),
        )
            .into_response();
    }

    // Enforce field length limits
    if request.message.len() > MAX_MESSAGE_LEN {
        return (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: format!("message must be at most {} characters", MAX_MESSAGE_LEN),
                code: "FIELD_TOO_LONG".to_string(),
            }),
        )
            .into_response();
    }
    if request.device_info.as_ref().is_some_and(|s| s.len() > MAX_DEVICE_INFO_LEN) {
        return (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: format!("device_info must be at most {} characters", MAX_DEVICE_INFO_LEN),
                code: "FIELD_TOO_LONG".to_string(),
            }),
        )
            .into_response();
    }

    // Truncate other string fields to MAX_FIELD_LEN
    request.household_id.truncate(MAX_FIELD_LEN);
    request.member_id.truncate(MAX_FIELD_LEN);
    request.category.truncate(MAX_FIELD_LEN);
    if let Some(ref mut s) = request.severity { s.truncate(MAX_FIELD_LEN); }
    if let Some(ref mut s) = request.title { s.truncate(MAX_FIELD_LEN); }
    if let Some(ref mut s) = request.steps_to_reproduce { s.truncate(MAX_MESSAGE_LEN); }
    if let Some(ref mut s) = request.expected_behavior { s.truncate(MAX_MESSAGE_LEN); }

    match state.db.store_feedback(
        &request.household_id,
        &request.member_id,
        &request.category,
        &request.message,
        request.severity.as_deref(),
        request.title.as_deref(),
        request.steps_to_reproduce.as_deref(),
        request.expected_behavior.as_deref(),
        request.device_info.as_deref(),
    ).await {
        Ok(feedback_id) => {
            debug!("Stored feedback {} from member {}", feedback_id, request.member_id);
            (
                StatusCode::CREATED,
                Json(FeedbackResponse { feedback_id }),
            )
                .into_response()
        }
        Err(e) => {
            error!("Failed to store feedback: {}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: "Internal server error".to_string(),
                    code: "STORAGE_FAILED".to_string(),
                }),
            )
                .into_response()
        }
    }
}

pub async fn list_feedback(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(params): Query<ListFeedbackParams>,
) -> impl IntoResponse {
    if let Err(err) = verify_admin_token(&headers, &state.config.feedback_admin_token) {
        return err.into_response();
    }

    match state.db.list_feedback(
        params.status.as_deref(),
        params.category.as_deref(),
        params.include_archived.unwrap_or(false),
    ).await {
        Ok(items) => (StatusCode::OK, Json(items)).into_response(),
        Err(e) => {
            error!("Failed to list feedback: {}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: "Internal server error".to_string(),
                    code: "LIST_FAILED".to_string(),
                }),
            )
                .into_response()
        }
    }
}

pub async fn update_feedback(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(request): Json<UpdateFeedbackRequest>,
) -> impl IntoResponse {
    if let Err(err) = verify_admin_token(&headers, &state.config.feedback_admin_token) {
        return err.into_response();
    }

    let valid_statuses = ["open", "in_progress", "resolved", "wont_fix", "archived"];
    if !valid_statuses.contains(&request.status.as_str()) {
        return (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: format!("Invalid status. Must be one of: {}", valid_statuses.join(", ")),
                code: "INVALID_STATUS".to_string(),
            }),
        )
            .into_response();
    }

    match state.db.update_feedback_status(&id, &request.status, request.notes.as_deref()).await {
        Ok(true) => {
            debug!("Updated feedback {} status to {}", id, request.status);
            (StatusCode::OK, Json(serde_json::json!({ "success": true }))).into_response()
        }
        Ok(false) => (
            StatusCode::NOT_FOUND,
            Json(ErrorResponse {
                error: "Feedback not found".to_string(),
                code: "NOT_FOUND".to_string(),
            }),
        )
            .into_response(),
        Err(e) => {
            error!("Failed to update feedback {}: {}", id, e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: "Internal server error".to_string(),
                    code: "UPDATE_FAILED".to_string(),
                }),
            )
                .into_response()
        }
    }
}
