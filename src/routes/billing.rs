use axum::{
    body::Bytes,
    extract::State,
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
    Json,
};
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use tracing::{error, info, warn};

use crate::{auth, routes::auth::ErrorResponse, AppState};

type HmacSha256 = Hmac<Sha256>;

/// Guard: returns 503 if billing is not licensed
fn require_license(state: &AppState) -> Option<axum::response::Response> {
    if !state.config.has_valid_license {
        Some(
            (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(ErrorResponse {
                    error: "Billing is not available on this server".to_string(),
                    code: "BILLING_NOT_LICENSED".to_string(),
                }),
            )
                .into_response(),
        )
    } else {
        None
    }
}

// ── Request / Response types ────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct StartTrialRequest {
    pub email: String,
}

#[derive(Debug, Serialize)]
pub struct CheckoutResponse {
    pub checkout_url: String,
}

#[derive(Debug, Serialize)]
pub struct PortalResponse {
    pub portal_url: String,
}

// ── Stripe JSON shapes (partial) ───────────────────────────────────────────

#[derive(Debug, Deserialize)]
struct StripeCheckoutSession {
    pub url: Option<String>,
}

#[derive(Debug, Deserialize)]
struct StripePortalSession {
    pub url: String,
}

#[derive(Debug, Deserialize)]
struct StripeEvent {
    #[serde(rename = "type")]
    pub event_type: String,
    pub data: StripeEventData,
}

#[derive(Debug, Deserialize)]
struct StripeEventData {
    pub object: serde_json::Value,
}

// ── 1. POST /api/v1/billing/start-trial ────────────────────────────────────

pub async fn start_trial(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<StartTrialRequest>,
) -> impl IntoResponse {
    if let Some(r) = require_license(&state) { return r; }

    let claims = match auth::extract_household_claims_from_header(&headers, &state.config.jwt_secret)
    {
        Ok(c) => c,
        Err(err) => return err.into_response(),
    };

    match state.db.start_trial(
        &claims.household_id,
        &claims.device_id,
        &request.email,
        state.config.trial_days,
    ).await {
        Ok(result) => (StatusCode::OK, Json(result)).into_response(),
        Err(e) => {
            error!("start_trial failed: {e}");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: "Failed to start trial".to_string(),
                    code: "TRIAL_START_FAILED".to_string(),
                }),
            )
                .into_response()
        }
    }
}

// ── 2. GET /api/v1/billing/status ──────────────────────────────────────────

pub async fn get_status(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> impl IntoResponse {
    if let Some(r) = require_license(&state) { return r; }

    let claims = match auth::extract_household_claims_from_header(&headers, &state.config.jwt_secret)
    {
        Ok(c) => c,
        Err(err) => return err.into_response(),
    };

    match state.db.get_subscription_status(&claims.household_id).await {
        Ok(info) => (StatusCode::OK, Json(info)).into_response(),
        Err(e) => {
            error!("get_subscription_status failed: {e}");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: "Failed to get subscription status".to_string(),
                    code: "STATUS_FETCH_FAILED".to_string(),
                }),
            )
                .into_response()
        }
    }
}

// ── 3. POST /api/v1/billing/checkout ───────────────────────────────────────

pub async fn create_checkout(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> impl IntoResponse {
    if let Some(r) = require_license(&state) { return r; }

    let claims = match auth::extract_household_claims_from_header(&headers, &state.config.jwt_secret)
    {
        Ok(c) => c,
        Err(err) => return err.into_response(),
    };

    let params = [
        ("mode", "subscription"),
        ("line_items[0][price]", &state.config.stripe_price_id),
        ("line_items[0][quantity]", "1"),
        ("metadata[household_id]", &claims.household_id),
        ("success_url", "honmoon://subscription/success"),
        ("cancel_url", "honmoon://subscription/cancel"),
    ];

    let res = state
        .http_client
        .post("https://api.stripe.com/v1/checkout/sessions")
        .bearer_auth(&state.config.stripe_secret_key)
        .form(&params)
        .send()
        .await;

    match res {
        Ok(response) => {
            if !response.status().is_success() {
                let status = response.status();
                let body = response.text().await.unwrap_or_default();
                error!("Stripe checkout API error {status}: {body}");
                return (
                    StatusCode::BAD_GATEWAY,
                    Json(ErrorResponse {
                        error: "Stripe API error".to_string(),
                        code: "STRIPE_ERROR".to_string(),
                    }),
                )
                    .into_response();
            }

            match response.json::<StripeCheckoutSession>().await {
                Ok(session) => {
                    if let Some(url) = session.url {
                        (StatusCode::OK, Json(CheckoutResponse { checkout_url: url }))
                            .into_response()
                    } else {
                        (
                            StatusCode::BAD_GATEWAY,
                            Json(ErrorResponse {
                                error: "No checkout URL in Stripe response".to_string(),
                                code: "STRIPE_NO_URL".to_string(),
                            }),
                        )
                            .into_response()
                    }
                }
                Err(e) => {
                    error!("Failed to parse Stripe checkout response: {e}");
                    (
                        StatusCode::BAD_GATEWAY,
                        Json(ErrorResponse {
                            error: "Failed to parse Stripe response".to_string(),
                            code: "STRIPE_PARSE_ERROR".to_string(),
                        }),
                    )
                        .into_response()
                }
            }
        }
        Err(e) => {
            error!("Stripe checkout request failed: {e}");
            (
                StatusCode::BAD_GATEWAY,
                Json(ErrorResponse {
                    error: "Failed to reach Stripe".to_string(),
                    code: "STRIPE_UNREACHABLE".to_string(),
                }),
            )
                .into_response()
        }
    }
}

// ── 4. POST /api/v1/billing/portal ─────────────────────────────────────────

pub async fn create_portal(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> impl IntoResponse {
    if let Some(r) = require_license(&state) { return r; }

    let claims = match auth::extract_household_claims_from_header(&headers, &state.config.jwt_secret)
    {
        Ok(c) => c,
        Err(err) => return err.into_response(),
    };

    let customer_id: String = match state.db.get_stripe_customer_id(&claims.household_id).await {
        Ok(Some(id)) => id,
        Ok(None) => {
            return (
                StatusCode::NOT_FOUND,
                Json(ErrorResponse {
                    error: "No Stripe customer found for this household".to_string(),
                    code: "NO_STRIPE_CUSTOMER".to_string(),
                }),
            )
                .into_response();
        }
        Err(e) => {
            error!("get_stripe_customer_id failed: {e}");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: "Database error".to_string(),
                    code: "DB_ERROR".to_string(),
                }),
            )
                .into_response();
        }
    };

    let params = [
        ("customer", customer_id.as_str()),
        ("return_url", "honmoon://subscription/manage"),
    ];

    let res = state
        .http_client
        .post("https://api.stripe.com/v1/billing_portal/sessions")
        .bearer_auth(&state.config.stripe_secret_key)
        .form(&params)
        .send()
        .await;

    match res {
        Ok(response) => {
            if !response.status().is_success() {
                let status = response.status();
                let body = response.text().await.unwrap_or_default();
                error!("Stripe portal API error {status}: {body}");
                return (
                    StatusCode::BAD_GATEWAY,
                    Json(ErrorResponse {
                        error: "Stripe API error".to_string(),
                        code: "STRIPE_ERROR".to_string(),
                    }),
                )
                    .into_response();
            }

            match response.json::<StripePortalSession>().await {
                Ok(session) => (
                    StatusCode::OK,
                    Json(PortalResponse {
                        portal_url: session.url,
                    }),
                )
                    .into_response(),
                Err(e) => {
                    error!("Failed to parse Stripe portal response: {e}");
                    (
                        StatusCode::BAD_GATEWAY,
                        Json(ErrorResponse {
                            error: "Failed to parse Stripe response".to_string(),
                            code: "STRIPE_PARSE_ERROR".to_string(),
                        }),
                    )
                        .into_response()
                }
            }
        }
        Err(e) => {
            error!("Stripe portal request failed: {e}");
            (
                StatusCode::BAD_GATEWAY,
                Json(ErrorResponse {
                    error: "Failed to reach Stripe".to_string(),
                    code: "STRIPE_UNREACHABLE".to_string(),
                }),
            )
                .into_response()
        }
    }
}

// ── 5. POST /api/v1/billing/webhook ────────────────────────────────────────

pub async fn stripe_webhook(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: Bytes,
) -> impl IntoResponse {
    if let Some(r) = require_license(&state) { return r; }

    // Refuse to verify against an empty secret: docker-compose passes
    // STRIPE_WEBHOOK_SECRET=${...:-} which is an empty (but set) string, so the
    // config panic is bypassed and verify_stripe_signature would HMAC with ""
    // — anyone could forge a valid signature (audit 2026-07-07).
    if state.config.stripe_webhook_secret.is_empty() {
        error!("Stripe webhook secret not configured — refusing webhook");
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    }

    let body_str = match std::str::from_utf8(&body) {
        Ok(s) => s,
        Err(_) => {
            warn!("Webhook body is not valid UTF-8");
            return StatusCode::BAD_REQUEST.into_response();
        }
    };

    // Verify Stripe signature
    let sig_header = headers
        .get("stripe-signature")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");

    if let Err(e) = verify_stripe_signature(sig_header, body_str, &state.config.stripe_webhook_secret)
    {
        warn!("Stripe webhook signature verification failed: {e}");
        return StatusCode::BAD_REQUEST.into_response();
    }

    // Parse the event
    let event: StripeEvent = match serde_json::from_str(body_str) {
        Ok(e) => e,
        Err(e) => {
            warn!("Failed to parse Stripe event JSON: {e}");
            return StatusCode::BAD_REQUEST.into_response();
        }
    };

    info!("Stripe webhook received: {}", event.event_type);

    let obj = &event.data.object;

    match event.event_type.as_str() {
        "checkout.session.completed" => {
            let customer = obj["customer"].as_str().unwrap_or_default();
            let subscription = obj["subscription"].as_str().unwrap_or_default();
            let household_id = obj["metadata"]["household_id"].as_str().unwrap_or_default();
            let email = obj["customer_details"]["email"].as_str().unwrap_or_default();

            if household_id.is_empty() {
                warn!("checkout.session.completed missing metadata.household_id");
                return StatusCode::OK.into_response();
            }

            if let Err(e) = state
                .db
                .set_subscription_from_stripe(household_id, customer, subscription, email, "active")
                .await
            {
                error!("set_subscription_from_stripe failed: {e}");
            }
        }

        "customer.subscription.updated" => {
            let customer = obj["customer"].as_str().unwrap_or_default();
            let status = obj["status"].as_str().unwrap_or_default();

            if customer.is_empty() {
                warn!("customer.subscription.updated missing customer");
                return StatusCode::OK.into_response();
            }

            if let Err(e) = state
                .db
                .update_subscription_status_by_customer(customer, status)
                .await
            {
                error!("update_subscription_status_by_customer failed: {e}");
            }
        }

        "customer.subscription.deleted" => {
            let customer = obj["customer"].as_str().unwrap_or_default();

            if customer.is_empty() {
                warn!("customer.subscription.deleted missing customer");
                return StatusCode::OK.into_response();
            }

            if let Err(e) = state
                .db
                .update_subscription_status_by_customer(customer, "canceled")
                .await
            {
                error!("update status to canceled failed: {e}");
            }

            if let Err(e) = state
                .db
                .set_grace_period_by_customer(customer, state.config.grace_days)
                .await
            {
                error!("set_grace_period_by_customer failed: {e}");
            }
        }

        "invoice.payment_failed" => {
            let customer = obj["customer"].as_str().unwrap_or_default();

            if customer.is_empty() {
                warn!("invoice.payment_failed missing customer");
                return StatusCode::OK.into_response();
            }

            if let Err(e) = state
                .db
                .update_subscription_status_by_customer(customer, "past_due")
                .await
            {
                error!("update status to past_due failed: {e}");
            }
        }

        other => {
            info!("Unhandled Stripe event type: {other}");
        }
    }

    // Stripe expects 200 OK always
    StatusCode::OK.into_response()
}

// ── Stripe signature verification ──────────────────────────────────────────

fn verify_stripe_signature(
    sig_header: &str,
    body: &str,
    webhook_secret: &str,
) -> Result<(), String> {
    let mut timestamp: Option<&str> = None;
    let mut signature: Option<&str> = None;

    for part in sig_header.split(',') {
        let part = part.trim();
        if let Some(t) = part.strip_prefix("t=") {
            timestamp = Some(t);
        } else if let Some(v) = part.strip_prefix("v1=") {
            signature = Some(v);
        }
    }

    let timestamp = timestamp.ok_or_else(|| "Missing timestamp in Stripe-Signature".to_string())?;
    let signature = signature.ok_or_else(|| "Missing v1 signature in Stripe-Signature".to_string())?;

    // Verify timestamp is within 5 minutes (300 seconds)
    let ts: i64 = timestamp
        .parse()
        .map_err(|_| "Invalid timestamp in Stripe-Signature".to_string())?;
    let now = chrono::Utc::now().timestamp();
    if (now - ts).abs() > 300 {
        return Err("Stripe webhook timestamp is too old or too far in the future".to_string());
    }

    // Compute expected signature
    let signed_payload = format!("{timestamp}.{body}");
    let mut mac = HmacSha256::new_from_slice(webhook_secret.as_bytes())
        .map_err(|e| format!("HMAC key error: {e}"))?;
    mac.update(signed_payload.as_bytes());
    let computed = hex::encode(mac.finalize().into_bytes());

    // Use constant-time comparison to prevent timing attacks
    use subtle::ConstantTimeEq;
    if computed.as_bytes().ct_eq(signature.as_bytes()).into() {
        Ok(())
    } else {
        Err("Signature mismatch".to_string())
    }
}
