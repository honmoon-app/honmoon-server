use axum::{
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
    Json,
};
use serde::Deserialize;
use serde_json::Value;
use tracing::warn;

use super::auth::ErrorResponse;
use crate::{auth, enable_banking, AppState};

/// Validate auth, EB config, and generate JWT in one step.
/// Returns (claims, app_id, pem_key, jwt) or an error response.
// The Err type is an axum Response by design (this helper feeds route
// handlers directly); boxing it just to satisfy the size lint adds noise.
#[allow(clippy::result_large_err)]
fn prepare_eb_context<'a>(
    headers: &HeaderMap,
    state: &'a AppState,
) -> Result<(auth::Claims, &'a str, &'a str, String), axum::response::Response> {
    let claims = auth::extract_household_claims_from_header(headers, &state.config.jwt_secret)
        .map_err(|resp| resp.into_response())?;

    let (app_id, pem_key) = match (&state.config.eb_app_id, &state.config.eb_pem_key) {
        (Some(a), Some(p)) => (a.as_str(), p.as_str()),
        _ => {
            return Err((
                StatusCode::SERVICE_UNAVAILABLE,
                Json(ErrorResponse {
                    error: "Bank sync is not configured on this server".to_string(),
                    code: "EB_NOT_CONFIGURED".to_string(),
                }),
            )
                .into_response());
        }
    };

    let jwt = enable_banking::generate_jwt(app_id, pem_key).map_err(|e| {
        warn!("EB JWT generation failed: {}", e);
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: "Internal authentication error".to_string(),
                code: "EB_JWT_ERROR".to_string(),
            }),
        )
            .into_response()
    })?;

    Ok((claims, app_id, pem_key, jwt))
}

/// Authorize a path-supplied EB id against the caller's household (audit #9).
///
/// `owner` is the household the id is bound to (`None` = never recorded).
/// Fail **open** on unbound — a pre-fix already-linked account the server
/// never saw must keep working — and reject only when the id is bound to a
/// DIFFERENT household. On a DB error we cannot verify ownership, so fail
/// **closed** (500) rather than open the deputy; it is transient so it locks
/// nobody out. Returns `Some(response)` to short-circuit, `None` to proceed.
fn authorize_binding(
    owner: Result<Option<String>, sqlx::Error>,
    household_id: &str,
) -> Option<axum::response::Response> {
    match owner {
        Ok(Some(bound)) if bound != household_id => Some(
            (
                StatusCode::FORBIDDEN,
                Json(ErrorResponse {
                    error: "This bank account belongs to another household".to_string(),
                    code: "EB_FORBIDDEN".to_string(),
                }),
            )
                .into_response(),
        ),
        Ok(_) => None,
        Err(e) => {
            warn!("EB binding lookup failed: {}", e);
            Some(
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(ErrorResponse {
                        error: "Could not verify account ownership".to_string(),
                        code: "EB_BINDING_ERROR".to_string(),
                    }),
                )
                    .into_response(),
            )
        }
    }
}

/// Map EB API errors to HTTP responses (forward status code).
fn eb_error_response(status: u16, body: String) -> impl IntoResponse {
    let code = StatusCode::from_u16(status).unwrap_or(StatusCode::BAD_GATEWAY);
    // Try to parse as JSON, otherwise wrap as string
    let json_body: Value = serde_json::from_str(&body).unwrap_or_else(|_| {
        serde_json::json!({ "error": body, "code": "EB_API_ERROR" })
    });
    (code, Json(json_body)).into_response()
}

// ── Query / Request types ────────────────────────────────────────────

#[derive(Deserialize)]
pub struct BanksQuery {
    pub country: Option<String>,
}

#[derive(Deserialize)]
pub struct StartAuthRequest {
    pub aspsp_name: String,
    pub aspsp_country: String,
    pub valid_for_days: Option<u32>,
}

#[derive(Deserialize)]
pub struct CreateSessionRequest {
    pub code: String,
}

#[derive(Deserialize)]
pub struct TransactionsQuery {
    pub date_from: Option<String>,
    pub date_to: Option<String>,
    pub continuation_key: Option<String>,
}

// ── Endpoints ────────────────────────────────────────────────────────

/// GET /api/v1/eb/banks?country=CZ — list available banks
pub async fn get_banks(
    headers: HeaderMap,
    State(state): State<AppState>,
    Query(query): Query<BanksQuery>,
) -> impl IntoResponse {
    let (_claims, _app_id, _pem_key, jwt) = match prepare_eb_context(&headers, &state) {
        Ok(ctx) => ctx,
        Err(resp) => return resp.into_response(),
    };

    let mut url = format!("{}/aspsps", enable_banking::EB_API_BASE);
    if let Some(country) = &query.country {
        url = format!("{}?country={}", url, country);
    }

    match enable_banking::get(&state.http_client, &url, &jwt).await {
        Ok(json) => (StatusCode::OK, Json(json)).into_response(),
        Err((status, body)) => eb_error_response(status, body).into_response(),
    }
}

/// POST /api/v1/eb/auth — start bank authorization
pub async fn start_auth(
    headers: HeaderMap,
    State(state): State<AppState>,
    Json(request): Json<StartAuthRequest>,
) -> impl IntoResponse {
    let (_claims, _app_id, _pem_key, jwt) = match prepare_eb_context(&headers, &state) {
        Ok(ctx) => ctx,
        Err(resp) => return resp.into_response(),
    };

    let valid_days = request.valid_for_days.unwrap_or(90);
    let valid_until = chrono::Utc::now() + chrono::Duration::days(valid_days as i64);

    let body = serde_json::json!({
        "access": {
            "valid_until": valid_until.to_rfc3339(),
            "balances": true,
            "transactions": true,
        },
        "aspsp": {
            "name": request.aspsp_name,
            "country": request.aspsp_country,
        },
        "redirect_url": enable_banking::redirect_url(),
        "psu_type": "personal",
    });

    let url = format!("{}/auth", enable_banking::EB_API_BASE);
    match enable_banking::post(&state.http_client, &url, &jwt, &body).await {
        Ok(json) => (StatusCode::OK, Json(json)).into_response(),
        Err((status, body)) => eb_error_response(status, body).into_response(),
    }
}

/// POST /api/v1/eb/sessions — exchange auth code for session
pub async fn create_session(
    headers: HeaderMap,
    State(state): State<AppState>,
    Json(request): Json<CreateSessionRequest>,
) -> impl IntoResponse {
    let (claims, _app_id, _pem_key, jwt) = match prepare_eb_context(&headers, &state) {
        Ok(ctx) => ctx,
        Err(resp) => return resp.into_response(),
    };

    let body = serde_json::json!({ "code": request.code });
    let url = format!("{}/sessions", enable_banking::EB_API_BASE);

    match enable_banking::post(&state.http_client, &url, &jwt, &body).await {
        Ok(json) => {
            // Bind the returned session + account uids to the caller's
            // household so later per-account/per-session calls can be
            // authorized (audit #9). The uids come from EB's response to the
            // caller's OWN consent, so a caller can only bind accounts they
            // actually authorized.
            if let Some(session_id) = json.get("session_id").and_then(|v| v.as_str()) {
                let uids: Vec<String> = json
                    .get("accounts")
                    .and_then(|v| v.as_array())
                    .map(|arr| {
                        arr.iter()
                            .filter_map(|a| a.get("uid").and_then(|v| v.as_str()))
                            .map(str::to_string)
                            .collect()
                    })
                    .unwrap_or_default();
                if let Err(e) = state
                    .db
                    .bind_eb_accounts(&claims.household_id, session_id, &uids)
                    .await
                {
                    // Fail-open: don't break a legitimate link on a DB hiccup;
                    // that one session simply stays unbound.
                    warn!("EB binding write failed: {}", e);
                }
            }
            (StatusCode::OK, Json(json)).into_response()
        }
        Err((status, body)) => eb_error_response(status, body).into_response(),
    }
}

/// GET /api/v1/eb/sessions/:id — check session status
pub async fn get_session(
    headers: HeaderMap,
    State(state): State<AppState>,
    Path(session_id): Path<String>,
) -> impl IntoResponse {
    let (claims, _app_id, _pem_key, jwt) = match prepare_eb_context(&headers, &state) {
        Ok(ctx) => ctx,
        Err(resp) => return resp.into_response(),
    };

    if let Some(resp) = authorize_binding(
        state.db.eb_household_for_session(&session_id).await,
        &claims.household_id,
    ) {
        return resp;
    }

    let url = format!("{}/sessions/{}", enable_banking::EB_API_BASE, session_id);
    match enable_banking::get(&state.http_client, &url, &jwt).await {
        Ok(json) => (StatusCode::OK, Json(json)).into_response(),
        Err((status, body)) => eb_error_response(status, body).into_response(),
    }
}

/// DELETE /api/v1/eb/sessions/:id — revoke session
pub async fn delete_session(
    headers: HeaderMap,
    State(state): State<AppState>,
    Path(session_id): Path<String>,
) -> impl IntoResponse {
    let (claims, _app_id, _pem_key, jwt) = match prepare_eb_context(&headers, &state) {
        Ok(ctx) => ctx,
        Err(resp) => return resp.into_response(),
    };

    if let Some(resp) = authorize_binding(
        state.db.eb_household_for_session(&session_id).await,
        &claims.household_id,
    ) {
        return resp;
    }

    let url = format!("{}/sessions/{}", enable_banking::EB_API_BASE, session_id);
    match enable_banking::delete(&state.http_client, &url, &jwt).await {
        Ok(()) => (StatusCode::OK, Json(serde_json::json!({"ok": true}))).into_response(),
        Err((status, body)) => eb_error_response(status, body).into_response(),
    }
}

/// GET /api/v1/eb/accounts/:uid/balances — get account balances
pub async fn get_balances(
    headers: HeaderMap,
    State(state): State<AppState>,
    Path(account_uid): Path<String>,
) -> impl IntoResponse {
    let (claims, _app_id, _pem_key, jwt) = match prepare_eb_context(&headers, &state) {
        Ok(ctx) => ctx,
        Err(resp) => return resp.into_response(),
    };

    if let Some(resp) = authorize_binding(
        state.db.eb_household_for_account(&account_uid).await,
        &claims.household_id,
    ) {
        return resp;
    }

    let url = format!("{}/accounts/{}/balances", enable_banking::EB_API_BASE, account_uid);
    match enable_banking::get(&state.http_client, &url, &jwt).await {
        Ok(json) => (StatusCode::OK, Json(json)).into_response(),
        Err((status, body)) => eb_error_response(status, body).into_response(),
    }
}

/// GET /api/v1/eb/accounts/:uid/transactions — get transactions
pub async fn get_transactions(
    headers: HeaderMap,
    State(state): State<AppState>,
    Path(account_uid): Path<String>,
    Query(query): Query<TransactionsQuery>,
) -> impl IntoResponse {
    let (claims, _app_id, _pem_key, jwt) = match prepare_eb_context(&headers, &state) {
        Ok(ctx) => ctx,
        Err(resp) => return resp.into_response(),
    };

    if let Some(resp) = authorize_binding(
        state.db.eb_household_for_account(&account_uid).await,
        &claims.household_id,
    ) {
        return resp;
    }

    let mut params = Vec::new();
    if let Some(date_from) = &query.date_from {
        params.push(format!("date_from={}", date_from));
    }
    if let Some(date_to) = &query.date_to {
        params.push(format!("date_to={}", date_to));
    }
    if let Some(continuation_key) = &query.continuation_key {
        params.push(format!("continuation_key={}", continuation_key));
    }

    let mut url = format!(
        "{}/accounts/{}/transactions",
        enable_banking::EB_API_BASE,
        account_uid
    );
    if !params.is_empty() {
        url = format!("{}?{}", url, params.join("&"));
    }

    match enable_banking::get(&state.http_client, &url, &jwt).await {
        Ok(json) => (StatusCode::OK, Json(json)).into_response(),
        Err((status, body)) => eb_error_response(status, body).into_response(),
    }
}
