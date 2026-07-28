use std::net::IpAddr;
use tracing::{debug, error, warn};

/// Sends push notifications to UnifiedPush endpoints.
///
/// UnifiedPush endpoints are simply HTTP POST URLs provided by a distributor
/// app (ntfy, NextPush, UP-FCM, etc.) on the user's device. To send a push
/// notification, the server POSTs a JSON body to the endpoint URL.
///
/// This is much simpler than FCM -- no API keys, no SDKs, no Google dependency.
pub struct UnifiedPushSender {
    client: reqwest::Client,
}

/// The JSON payload sent to a UnifiedPush endpoint.
#[derive(serde::Serialize)]
pub struct UnifiedPushPayload {
    pub title: String,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub entity_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub entity_id: Option<String>,
}

impl UnifiedPushSender {
    /// Create a sender using a shared HTTP client.
    pub fn with_client(client: reqwest::Client) -> Self {
        Self { client }
    }

    /// Validate that a URL does not point to a private/internal network address (SSRF prevention).
    pub fn is_safe_url(endpoint_url: &str) -> bool {
        let parsed = match url::Url::parse(endpoint_url) {
            Ok(u) => u,
            Err(_) => return false,
        };

        // Only allow HTTPS (or HTTP for localhost in dev — but we block localhost anyway)
        match parsed.scheme() {
            "https" => {}
            "http" => {} // Some UP distributors use HTTP
            _ => return false,
        }

        let host = match parsed.host_str() {
            Some(h) => h,
            None => return false,
        };

        // Block localhost variants
        if host == "localhost" || host == "127.0.0.1" || host == "::1" || host == "[::1]" {
            return false;
        }

        // Block private/reserved IP ranges
        if let Ok(ip) = host.parse::<IpAddr>() {
            match ip {
                IpAddr::V4(v4) => {
                    if v4.is_private()
                        || v4.is_loopback()
                        || v4.is_link_local()
                        || v4.is_broadcast()
                        || v4.is_unspecified()
                        || v4.octets()[0] == 10
                        || (v4.octets()[0] == 172 && (16..=31).contains(&v4.octets()[1]))
                        || (v4.octets()[0] == 192 && v4.octets()[1] == 168)
                        || (v4.octets()[0] == 169 && v4.octets()[1] == 254)
                    {
                        return false;
                    }
                }
                IpAddr::V6(v6) => {
                    if v6.is_loopback() || v6.is_unspecified() {
                        return false;
                    }
                    // Block ULA (fc00::/7) and link-local (fe80::/10)
                    let first_byte = v6.octets()[0];
                    if (first_byte & 0xfe) == 0xfc || (first_byte == 0xfe && (v6.octets()[1] & 0xc0) == 0x80) {
                        return false;
                    }
                }
            }
        }

        true
    }

    /// Send a push notification to a UnifiedPush endpoint URL.
    ///
    /// The endpoint URL was previously registered by the client app via
    /// the /api/v1/push/register route with endpoint_type = "unified_push".
    ///
    /// Returns true if the push was delivered successfully, false otherwise.
    pub async fn send(
        &self,
        endpoint_url: &str,
        payload: &UnifiedPushPayload,
    ) -> bool {
        // SSRF prevention: reject requests to private/internal addresses
        if !Self::is_safe_url(endpoint_url) {
            warn!("UnifiedPush: Rejected unsafe endpoint URL: {}", endpoint_url);
            return false;
        }

        let body = match serde_json::to_vec(payload) {
            Ok(b) => b,
            Err(e) => {
                error!("UnifiedPush: Failed to serialize payload: {}", e);
                return false;
            }
        };

        match self
            .client
            .post(endpoint_url)
            .header("Content-Type", "application/json")
            .body(body)
            .send()
            .await
        {
            Ok(response) => {
                if response.status().is_success() {
                    debug!("UnifiedPush: Sent to {}", endpoint_url);
                    true
                } else {
                    let status = response.status();
                    let body_text = response.text().await.unwrap_or_default();
                    warn!(
                        "UnifiedPush: Endpoint returned {} for {}: {}",
                        status, endpoint_url, body_text
                    );
                    false
                }
            }
            Err(e) => {
                error!("UnifiedPush: HTTP error sending to {}: {}", endpoint_url, e);
                false
            }
        }
    }
}
