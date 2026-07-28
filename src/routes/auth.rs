use axum::{extract::State, http::StatusCode, response::IntoResponse, Json};
use serde::{Deserialize, Serialize};

use crate::{auth, AppState};

#[derive(Debug, Deserialize)]
pub struct TokenRequest {
    pub household_id: String,
    pub invite_code: String,
    pub device_id: String,
    pub member_id: String,
}

#[derive(Debug, Serialize)]
pub struct TokenResponse {
    pub token: String,
    pub expires_at: i64,
}

#[derive(Debug, Serialize)]
pub struct ErrorResponse {
    pub error: String,
    pub code: String,
}

pub async fn get_token(
    State(state): State<AppState>,
    Json(request): Json<TokenRequest>,
) -> impl IntoResponse {
    // Validate invite code format
    if !auth::validate_invite_code(&request.invite_code) {
        return (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "Invalid invite code format".to_string(),
                code: "INVALID_INVITE_CODE".to_string(),
            }),
        )
            .into_response();
    }

    // Validate household_id and member_id are valid UUIDs (prevents abuse with arbitrary strings)
    if uuid::Uuid::parse_str(&request.household_id).is_err()
        || uuid::Uuid::parse_str(&request.member_id).is_err()
    {
        return (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "Invalid household_id or member_id format".to_string(),
                code: "INVALID_ID_FORMAT".to_string(),
            }),
        )
            .into_response();
    }

    // Bind or verify the invite_code → household_id mapping (TOFU).
    // The first token issued for a code locks it to a household; subsequent
    // requests with the same code must match. This prevents an attacker who
    // learns or guesses a valid invite code from minting a JWT for an
    // arbitrary household.
    match state
        .db
        .bind_or_check_invite(&request.invite_code, &request.household_id)
        .await
    {
        Ok(Ok(())) => {
            // Register the member now, at join time — not when they first open
            // a socket. store_pending_message snapshots recipients from
            // household_members; if the joiner isn't there yet, a message sent
            // while they're still connecting has no recipient and is dropped
            // (ack-and-drop), so they never receive it (audit #4). Best-effort.
            if let Err(e) = state
                .db
                .upsert_household_member(&request.household_id, &request.member_id)
                .await
            {
                tracing::warn!("Failed to register member at token issuance: {e}");
            }
        }
        Ok(Err(_existing)) => {
            return (
                StatusCode::FORBIDDEN,
                Json(ErrorResponse {
                    error: "Invite code does not match the requested household".to_string(),
                    code: "INVITE_HOUSEHOLD_MISMATCH".to_string(),
                }),
            )
                .into_response();
        }
        Err(e) => {
            tracing::error!("Failed to verify invite binding: {e}");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: "Internal server error".to_string(),
                    code: "INVITE_BINDING_FAILED".to_string(),
                }),
            )
                .into_response();
        }
    }

    // Create token
    match auth::create_token(
        &request.household_id,
        &request.device_id,
        &request.member_id,
        &state.config.jwt_secret,
        state.config.jwt_expiry_hours,
    ) {
        Ok(token_response) => (
            StatusCode::OK,
            Json(TokenResponse {
                token: token_response.token,
                expires_at: token_response.expires_at,
            }),
        )
            .into_response(),
        Err(_e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: "Internal server error".to_string(),
                code: "TOKEN_CREATION_FAILED".to_string(),
            }),
        )
            .into_response(),
    }
}

