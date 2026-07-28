use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use tokio::sync::RwLock;
use tracing::{debug, error, info, warn};

use crate::db::Database;
use crate::unified_push::{UnifiedPushPayload, UnifiedPushSender};
use crate::web_push::WebPushSender;

/// Cached OAuth 2.0 access token for FCM v1 API.
struct CachedToken {
    access_token: String,
    /// Unix timestamp when this token expires (with 60s safety margin).
    expires_at: u64,
}

/// Service account credentials parsed from the JSON key file.
struct ServiceAccountCredentials {
    client_email: String,
    private_key: String,
    project_id: String,
}

/// Push notification sender supporting multiple backends.
///
/// Supports:
/// - FCM v1 HTTP API (OAuth 2.0 service account auth) for tokens with endpoint_type = "fcm"
/// - UnifiedPush for tokens with endpoint_type = "unified_push"
pub struct PushSender {
    credentials: Option<ServiceAccountCredentials>,
    token_cache: Arc<RwLock<Option<CachedToken>>>,
    unified_push: UnifiedPushSender,
    web_push: Option<WebPushSender>,
    client: reqwest::Client,
    db: Arc<Database>,
}

// Keep the old name as an alias for backward compatibility
pub type FcmSender = PushSender;

/// FCM v1 API request body.
#[derive(serde::Serialize)]
struct FcmV1Request {
    message: FcmV1Message,
}

#[derive(serde::Serialize)]
struct FcmV1Message {
    token: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    notification: Option<FcmV1Notification>,
    #[serde(skip_serializing_if = "Option::is_none")]
    data: Option<std::collections::HashMap<String, String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    android: Option<FcmV1Android>,
}

#[derive(serde::Serialize)]
struct FcmV1Notification {
    title: String,
    body: String,
}

#[derive(serde::Serialize)]
struct FcmV1Android {
    priority: String,
}

/// Google OAuth 2.0 token response.
#[derive(serde::Deserialize)]
struct GoogleTokenResponse {
    access_token: String,
    expires_in: u64,
}

impl PushSender {
    /// Create a new PushSender.
    ///
    /// Reads Firebase config from environment:
    /// - `FIREBASE_SERVICE_ACCOUNT_KEY`: path to the service account JSON key file
    /// - `FIREBASE_PROJECT_ID`: (optional) override project_id from the key file
    pub fn new(db: Arc<Database>) -> Self {
        let credentials = Self::load_credentials();

        if credentials.is_some() {
            info!("PushSender: FCM v1 API configured, FCM push enabled");
        } else {
            info!("PushSender: No Firebase service account configured, FCM push disabled");
        }
        info!("PushSender: UnifiedPush support enabled (no config needed)");

        let web_push = WebPushSender::from_env();
        if web_push.is_some() {
            info!("PushSender: Web Push (VAPID) configured and enabled");
        }

        let client = reqwest::Client::new();

        Self {
            credentials,
            token_cache: Arc::new(RwLock::new(None)),
            unified_push: UnifiedPushSender::with_client(client.clone()),
            web_push,
            client,
            db,
        }
    }

    /// Load service account credentials from the JSON key file.
    fn load_credentials() -> Option<ServiceAccountCredentials> {
        let key_path = std::env::var("FIREBASE_SERVICE_ACCOUNT_KEY").ok()?;

        let key_json = match std::fs::read_to_string(&key_path) {
            Ok(json) => json,
            Err(e) => {
                error!(
                    "PushSender: Failed to read service account key file {}: {}",
                    key_path, e
                );
                return None;
            }
        };

        let parsed: serde_json::Value = match serde_json::from_str(&key_json) {
            Ok(v) => v,
            Err(e) => {
                error!(
                    "PushSender: Failed to parse service account key JSON: {}",
                    e
                );
                return None;
            }
        };

        let client_email = parsed
            .get("client_email")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());
        let private_key = parsed
            .get("private_key")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());
        let project_id_from_file = parsed
            .get("project_id")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());

        // Allow env override for project_id
        let project_id = std::env::var("FIREBASE_PROJECT_ID")
            .ok()
            .or(project_id_from_file);

        match (client_email, private_key, project_id) {
            (Some(email), Some(key), Some(project)) => Some(ServiceAccountCredentials {
                client_email: email,
                private_key: key,
                project_id: project,
            }),
            _ => {
                error!(
                    "PushSender: Service account key file missing required fields \
                     (client_email, private_key, project_id)"
                );
                None
            }
        }
    }

    /// Whether FCM sending is available
    pub fn is_fcm_available(&self) -> bool {
        self.credentials.is_some()
    }

    /// Whether Web Push (VAPID) is available
    pub fn is_web_push_available(&self) -> bool {
        self.web_push.is_some()
    }

    /// Get the public VAPID key for Web Push clients, if configured.
    pub fn get_vapid_public_key(&self) -> Option<&str> {
        self.web_push.as_ref().map(|wp| wp.public_key())
    }

    /// Backward-compatible alias
    pub fn is_available(&self) -> bool {
        self.is_fcm_available()
    }

    /// Get a valid OAuth 2.0 access token, refreshing if expired or missing.
    async fn get_access_token(&self) -> Option<String> {
        let creds = self.credentials.as_ref()?;

        // Check cache first
        {
            let cache = self.token_cache.read().await;
            if let Some(cached) = cache.as_ref() {
                let now = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs();
                if now < cached.expires_at {
                    return Some(cached.access_token.clone());
                }
            }
        }

        // Token expired or missing -- create a new JWT and exchange it
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let jwt_claims = serde_json::json!({
            "iss": creds.client_email,
            "sub": creds.client_email,
            "aud": "https://oauth2.googleapis.com/token",
            "iat": now,
            "exp": now + 3600,
            "scope": "https://www.googleapis.com/auth/firebase.messaging"
        });

        let header = jsonwebtoken::Header::new(jsonwebtoken::Algorithm::RS256);
        let encoding_key =
            match jsonwebtoken::EncodingKey::from_rsa_pem(creds.private_key.as_bytes()) {
                Ok(k) => k,
                Err(e) => {
                    error!("PushSender: Failed to parse RSA private key: {}", e);
                    return None;
                }
            };

        let jwt = match jsonwebtoken::encode(&header, &jwt_claims, &encoding_key) {
            Ok(t) => t,
            Err(e) => {
                error!("PushSender: Failed to sign JWT: {}", e);
                return None;
            }
        };

        // Exchange JWT for access token
        let token_response = self
            .client
            .post("https://oauth2.googleapis.com/token")
            .form(&[
                ("grant_type", "urn:ietf:params:oauth:grant-type:jwt-bearer"),
                ("assertion", &jwt),
            ])
            .send()
            .await;

        match token_response {
            Ok(resp) => {
                if !resp.status().is_success() {
                    let status = resp.status();
                    let body = resp.text().await.unwrap_or_default();
                    error!(
                        "PushSender: OAuth token exchange failed ({}): {}",
                        status, body
                    );
                    return None;
                }

                match resp.json::<GoogleTokenResponse>().await {
                    Ok(token_resp) => {
                        let access_token = token_resp.access_token.clone();

                        // Cache with 60s safety margin
                        let expires_at = now + token_resp.expires_in.saturating_sub(60);
                        let mut cache = self.token_cache.write().await;
                        *cache = Some(CachedToken {
                            access_token: access_token.clone(),
                            expires_at,
                        });

                        debug!("PushSender: Obtained new FCM OAuth access token");
                        Some(access_token)
                    }
                    Err(e) => {
                        error!("PushSender: Failed to parse OAuth token response: {}", e);
                        None
                    }
                }
            }
            Err(e) => {
                error!("PushSender: OAuth token exchange HTTP error: {}", e);
                None
            }
        }
    }

    /// Send a push notification to all devices registered for a user.
    /// Routes to the correct backend (FCM or UnifiedPush) based on each
    /// token's endpoint_type.
    /// Send a single FCM v1 message to one token. Returns `true` on success.
    /// Shared by the legacy `send_to_user` fan-out and the `push_dispatch`
    /// per-token delivery path so there is one FCM implementation.
    pub async fn send_fcm_to_token(
        &self,
        token: &str,
        title: &str,
        body: &str,
        data: &serde_json::Value,
    ) -> bool {
        let creds = match &self.credentials {
            Some(c) => c,
            None => {
                debug!("PushSender: Skipping FCM (no credentials configured)");
                return false;
            }
        };
        let access_token = match self.get_access_token().await {
            Some(t) => t,
            None => {
                error!("PushSender: Cannot get FCM access token");
                return false;
            }
        };
        let data_map: Option<std::collections::HashMap<String, String>> =
            if let serde_json::Value::Object(map) = data {
                if map.is_empty() {
                    None
                } else {
                    Some(
                        map.iter()
                            .map(|(k, v)| {
                                let val = match v {
                                    serde_json::Value::String(s) => s.clone(),
                                    other => other.to_string(),
                                };
                                (k.clone(), val)
                            })
                            .collect(),
                    )
                }
            } else {
                None
            };
        let request = FcmV1Request {
            message: FcmV1Message {
                token: token.to_string(),
                notification: Some(FcmV1Notification {
                    title: title.to_string(),
                    body: body.to_string(),
                }),
                data: data_map,
                android: Some(FcmV1Android {
                    priority: "high".to_string(),
                }),
            },
        };
        let url = format!(
            "https://fcm.googleapis.com/v1/projects/{}/messages:send",
            creds.project_id
        );
        match self
            .client
            .post(&url)
            .header("Authorization", format!("Bearer {}", access_token))
            .json(&request)
            .send()
            .await
        {
            Ok(response) => {
                if response.status().is_success() {
                    return true;
                }
                let status = response.status();
                let body_text = response.text().await.unwrap_or_default();
                warn!("PushSender: FCM v1 returned {}: {}", status, body_text);
                // Invalid/expired token → remove it so we stop trying.
                if status.as_u16() == 404 || status.as_u16() == 410 {
                    let _ = self.db.delete_push_token(token).await;
                }
                // Auth expired → drop cached access token so the next send refreshes.
                if status.as_u16() == 401 {
                    let mut cache = self.token_cache.write().await;
                    *cache = None;
                }
                false
            }
            Err(e) => {
                error!("PushSender: HTTP error sending FCM v1: {}", e);
                false
            }
        }
    }

    pub async fn send_to_user(
        &self,
        user_id: &str,
        title: &str,
        body: &str,
        data: serde_json::Value,
    ) {
        let tokens = match self.db.get_push_tokens_for_user(user_id).await {
            Ok(t) => t,
            Err(e) => {
                error!(
                    "PushSender: Failed to get tokens for user {}: {}",
                    user_id, e
                );
                return;
            }
        };

        if tokens.is_empty() {
            debug!("PushSender: No push tokens for user {}", user_id);
            return;
        }

        for token_entry in &tokens {
            match token_entry.endpoint_type.as_str() {
                "unified_push" => {
                    // Extract entity info from data if available
                    let entity_type = data
                        .get("entity_type")
                        .and_then(|v| v.as_str())
                        .map(|s| s.to_string());
                    let entity_id = data
                        .get("entity_id")
                        .and_then(|v| v.as_str())
                        .map(|s| s.to_string());

                    let payload = UnifiedPushPayload {
                        title: title.to_string(),
                        message: body.to_string(),
                        entity_type,
                        entity_id,
                    };

                    let success = self.unified_push.send(&token_entry.token, &payload).await;

                    if success {
                        debug!(
                            "PushSender: Sent UnifiedPush to device {} for user {}",
                            token_entry.device_id, user_id
                        );
                    } else {
                        warn!(
                            "PushSender: UnifiedPush failed for device {} (user {})",
                            token_entry.device_id, user_id
                        );
                    }
                }
                "web_push" => {
                    let web_push = match &self.web_push {
                        Some(wp) => wp,
                        None => {
                            debug!(
                                "PushSender: Skipping web_push for device {} (VAPID not configured)",
                                token_entry.device_id
                            );
                            continue;
                        }
                    };

                    // Web push subscriptions store p256dh and auth in the token
                    // field as a JSON object: {"endpoint": "...", "p256dh": "...", "auth": "..."}
                    let sub: serde_json::Value = match serde_json::from_str(&token_entry.token) {
                        Ok(v) => v,
                        Err(e) => {
                            warn!(
                                "PushSender: Invalid web_push token JSON for device {}: {}",
                                token_entry.device_id, e
                            );
                            continue;
                        }
                    };

                    let endpoint = match sub.get("endpoint").and_then(|v| v.as_str()) {
                        Some(e) => e,
                        None => {
                            warn!(
                                "PushSender: web_push token missing 'endpoint' for device {}",
                                token_entry.device_id
                            );
                            continue;
                        }
                    };
                    let p256dh = match sub.get("p256dh").and_then(|v| v.as_str()) {
                        Some(k) => k,
                        None => {
                            warn!(
                                "PushSender: web_push token missing 'p256dh' for device {}",
                                token_entry.device_id
                            );
                            continue;
                        }
                    };
                    let auth = match sub.get("auth").and_then(|v| v.as_str()) {
                        Some(a) => a,
                        None => {
                            warn!(
                                "PushSender: web_push token missing 'auth' for device {}",
                                token_entry.device_id
                            );
                            continue;
                        }
                    };

                    // Build push payload (same JSON format as UnifiedPush)
                    let payload = serde_json::json!({
                        "title": title,
                        "message": body,
                        "entity_type": data.get("entity_type"),
                        "entity_id": data.get("entity_id"),
                    });
                    let payload_bytes = serde_json::to_vec(&payload).unwrap_or_default();

                    let success = web_push.send(endpoint, p256dh, auth, &payload_bytes).await;

                    if success {
                        debug!(
                            "PushSender: Sent web push to device {} for user {}",
                            token_entry.device_id, user_id
                        );
                    } else {
                        warn!(
                            "PushSender: Web push failed for device {} (user {})",
                            token_entry.device_id, user_id
                        );
                    }
                }
                _ => {
                    // FCM v1 (default — covers "fcm" and unrecognized types).
                    let _ = self
                        .send_fcm_to_token(&token_entry.token, title, body, &data)
                        .await;
                }
            }
        }
    }
}
