use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
use reqwest::Client;
use serde::Serialize;
use serde_json::Value;
use tracing::debug;

pub const EB_API_BASE: &str = "https://api.enablebanking.com";

/// Return the Enable Banking OAuth redirect URL.
/// Reads `EB_REDIRECT_URL` env var first, then falls back to `BASE_URL` + path,
/// then to the hardcoded default.
pub fn redirect_url() -> String {
    if let Ok(url) = std::env::var("EB_REDIRECT_URL") {
        return url;
    }
    if let Ok(base) = std::env::var("BASE_URL") {
        let base = base.trim_end_matches('/');
        return format!("{}/api/v1/oauth/eb-callback", base);
    }
    "https://sync.honmoon.app/api/v1/oauth/eb-callback".to_string()
}

#[derive(Debug, Serialize)]
struct EbClaims {
    iss: String,
    aud: String,
    iat: usize,
    exp: usize,
}

/// Generate a JWT Bearer token for Enable Banking API (RS256).
pub fn generate_jwt(app_id: &str, pem_key: &str) -> Result<String, String> {
    let now = chrono::Utc::now().timestamp() as usize;
    let claims = EbClaims {
        iss: "enablebanking.com".to_string(),
        aud: "api.enablebanking.com".to_string(),
        iat: now,
        exp: now + 3600,
    };

    let mut header = Header::new(Algorithm::RS256);
    header.kid = Some(app_id.to_string());

    let key = EncodingKey::from_rsa_pem(pem_key.as_bytes())
        .map_err(|e| format!("Invalid PEM key: {}", e))?;

    encode(&header, &claims, &key).map_err(|e| format!("JWT encode error: {}", e))
}

/// Send an authenticated request to Enable Banking API and handle the response.
/// Shared implementation for GET, POST, and DELETE.
async fn send_request(
    request: reqwest::RequestBuilder,
    method: &str,
    url: &str,
    jwt: &str,
) -> Result<reqwest::Response, (u16, String)> {
    debug!("EB {} {}", method, redact_eb_url(url));
    let response = request
        .header("Authorization", format!("Bearer {}", jwt))
        .send()
        .await
        .map_err(|e| (502u16, format!("Request failed: {}", e)))?;

    let status = response.status().as_u16();
    if status >= 400 {
        let body = response
            .text()
            .await
            .unwrap_or_default();
        return Err((status, body));
    }

    Ok(response)
}

/// Redact the bank-account identifier from an EB URL before logging: the
/// path segment right after `sessions` or `accounts` is a session_id /
/// account_uid and must never reach logs (audit 2026-07-07 #9). Only date
/// query params survive, which are not sensitive.
fn redact_eb_url(url: &str) -> String {
    let mut out: Vec<String> = Vec::new();
    let mut redact_next = false;
    for seg in url.split('/') {
        if redact_next && !seg.is_empty() {
            out.push("***".to_string());
            redact_next = false;
        } else {
            redact_next = seg == "sessions" || seg == "accounts";
            out.push(seg.to_string());
        }
    }
    out.join("/")
}

/// Parse a successful response body as JSON.
async fn parse_json_response(response: reqwest::Response) -> Result<Value, (u16, String)> {
    let body = response
        .text()
        .await
        .map_err(|e| (502u16, format!("Failed to read response: {}", e)))?;
    serde_json::from_str(&body).map_err(|e| (502u16, format!("Invalid JSON: {}", e)))
}

/// Make an authenticated GET request to Enable Banking API.
pub async fn get(client: &Client, url: &str, jwt: &str) -> Result<Value, (u16, String)> {
    let response = send_request(client.get(url), "GET", url, jwt).await?;
    parse_json_response(response).await
}

/// Make an authenticated POST request to Enable Banking API.
pub async fn post(
    client: &Client,
    url: &str,
    jwt: &str,
    body: &Value,
) -> Result<Value, (u16, String)> {
    let request = client
        .post(url)
        .header("Content-Type", "application/json")
        .json(body);
    let response = send_request(request, "POST", url, jwt).await?;
    parse_json_response(response).await
}

/// Make an authenticated DELETE request to Enable Banking API.
pub async fn delete(client: &Client, url: &str, jwt: &str) -> Result<(), (u16, String)> {
    send_request(client.delete(url), "DELETE", url, jwt).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::redact_eb_url;

    #[test]
    fn redacts_session_and_account_ids_but_keeps_dates() {
        let base = "https://api.enablebanking.com";
        assert_eq!(
            redact_eb_url(&format!("{base}/sessions/sess-abc-123")),
            format!("{base}/sessions/***")
        );
        assert_eq!(
            redact_eb_url(&format!("{base}/accounts/uid-9/balances")),
            format!("{base}/accounts/***/balances")
        );
        assert_eq!(
            redact_eb_url(&format!("{base}/accounts/uid-9/transactions?date_from=2026-01-01")),
            format!("{base}/accounts/***/transactions?date_from=2026-01-01")
        );
        // No id to redact — left unchanged.
        assert_eq!(redact_eb_url(&format!("{base}/sessions")), format!("{base}/sessions"));
        assert_eq!(
            redact_eb_url(&format!("{base}/aspsps?country=CZ")),
            format!("{base}/aspsps?country=CZ")
        );
    }
}
