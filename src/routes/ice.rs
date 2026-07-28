use axum::{extract::State, http::StatusCode, Json};
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha1::Sha1;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::AppState;

type HmacSha1 = Hmac<Sha1>;

/// ICE server configuration for WebRTC
#[derive(Debug, Serialize)]
pub struct IceServer {
    pub urls: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub credential: Option<String>,
}

/// Response containing ICE servers
#[derive(Debug, Serialize)]
pub struct IceServersResponse {
    pub ice_servers: Vec<IceServer>,
    pub ttl: u64,
}

/// Request for ICE servers (requires authenticated user)
#[derive(Debug, Deserialize)]
pub struct IceServersRequest {
    pub token: String,
}

/// Generate time-limited TURN credentials using HMAC-SHA1
/// This implements the TURN REST API credential format:
/// username = timestamp:user_id
/// credential = base64(hmac-sha1(secret, username))
fn generate_turn_credentials(secret: &str, user_id: &str, ttl_seconds: u64) -> Result<(String, String), StatusCode> {
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| {
            tracing::error!("System clock is before UNIX epoch");
            StatusCode::INTERNAL_SERVER_ERROR
        })?
        .as_secs()
        + ttl_seconds;

    let username = format!("{}:{}", timestamp, user_id);

    let mut mac =
        HmacSha1::new_from_slice(secret.as_bytes()).expect("HMAC can take key of any size");
    mac.update(username.as_bytes());
    let result = mac.finalize();
    let credential = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, result.into_bytes());

    Ok((username, credential))
}

/// Get ICE servers endpoint
/// Returns STUN and TURN server configurations with time-limited credentials
pub async fn get_ice_servers(
    State(state): State<AppState>,
    Json(request): Json<IceServersRequest>,
) -> Result<Json<IceServersResponse>, StatusCode> {
    // Validate the JWT token
    let claims = crate::auth::validate_token(&request.token, &state.config.jwt_secret)
        .map_err(|_| StatusCode::UNAUTHORIZED)?;

    // Gate TURN credentials on an active subscription — mirror the WebSocket
    // relay gate (skip when self-hosted). Without it a free JWT pulls unlimited
    // 1h TURN creds and coturn becomes an open relay (audit 2026-07-07 #11).
    // Fail open on a DB error, exactly as the WS handler does, so a transient
    // hiccup never blocks paying users.
    if !state.config.self_hosted {
        match state.db.get_subscription_status(&claims.household_id).await {
            Ok(info) => {
                if !crate::subscription::is_allowed(&info.status) {
                    return Err(StatusCode::FORBIDDEN);
                }
            }
            Err(e) => {
                tracing::error!("ICE: failed to check subscription status: {}", e);
            }
        }
    }

    let turn_server = &state.config.turn_server;
    let turn_secret = &state.config.turn_secret;

    // TTL for TURN credentials (1 hour)
    let ttl_seconds: u64 = 3600;

    // Generate time-limited credentials
    let (username, credential) = generate_turn_credentials(
        turn_secret,
        &claims.device_id,
        ttl_seconds,
    )?;

    let ice_servers = vec![
        // STUN server (no auth needed)
        IceServer {
            urls: vec![
                format!("stun:{}:3478", turn_server),
            ],
            username: None,
            credential: None,
        },
        // TURN server with credentials (UDP)
        IceServer {
            urls: vec![
                format!("turn:{}:3478?transport=udp", turn_server),
                format!("turn:{}:3478?transport=tcp", turn_server),
            ],
            username: Some(username.clone()),
            credential: Some(credential.clone()),
        },
        // TURNS server with TLS (more reliable through firewalls)
        IceServer {
            urls: vec![
                format!("turns:{}:5349?transport=tcp", turn_server),
            ],
            username: Some(username),
            credential: Some(credential),
        },
    ];

    Ok(Json(IceServersResponse {
        ice_servers,
        ttl: ttl_seconds,
    }))
}
