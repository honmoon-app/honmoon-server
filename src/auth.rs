use chrono::{Duration, Utc};
use jsonwebtoken::{decode, encode, DecodingKey, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Claims {
    pub household_id: String,
    pub device_id: String,
    pub member_id: String,
    pub exp: usize,
    pub iat: usize,
}

#[derive(Debug, Serialize)]
pub struct TokenResponse {
    pub token: String,
    pub expires_at: i64,
}

pub fn create_token(
    household_id: &str,
    device_id: &str,
    member_id: &str,
    secret: &str,
    expiry_hours: u64,
) -> Result<TokenResponse, jsonwebtoken::errors::Error> {
    let now = Utc::now();
    let expires_at = now + Duration::hours(expiry_hours as i64);

    let claims = Claims {
        household_id: household_id.to_string(),
        device_id: device_id.to_string(),
        member_id: member_id.to_string(),
        exp: expires_at.timestamp() as usize,
        iat: now.timestamp() as usize,
    };

    let token = encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(secret.as_bytes()),
    )?;

    Ok(TokenResponse {
        token,
        expires_at: expires_at.timestamp(),
    })
}

pub fn validate_token(token: &str, secret: &str) -> Result<Claims, jsonwebtoken::errors::Error> {
    let token_data = decode::<Claims>(
        token,
        &DecodingKey::from_secret(secret.as_bytes()),
        &Validation::default(),
    )?;

    Ok(token_data.claims)
}

// Invite code: 6 chars from a 31-symbol alphabet (ambiguous glyphs
// 0/O/1/I/L excluded), one cosmetic dash — XXX-XXX. The dash and case
// are normalized away before matching.
static INVITE_CODE_RE: std::sync::LazyLock<regex::Regex> = std::sync::LazyLock::new(|| {
    regex::Regex::new(r"^[A-HJKMNP-Z2-9]{6}$").expect("valid regex")
});

/// Validate invite code format (XXX-XXX, dash optional, case-insensitive).
pub fn validate_invite_code(code: &str) -> bool {
    let normalized = code.replace('-', "").to_uppercase();
    INVITE_CODE_RE.is_match(&normalized)
}

/// Extract and validate household JWT from Authorization: Bearer header.
/// Reusable helper for any endpoint that requires household authentication.
pub fn extract_household_claims_from_header(
    headers: &axum::http::HeaderMap,
    jwt_secret: &str,
) -> Result<Claims, (axum::http::StatusCode, axum::Json<crate::routes::auth::ErrorResponse>)> {
    let auth_header = headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");

    let token = if let Some(stripped) = auth_header.strip_prefix("Bearer ") {
        stripped
    } else {
        return Err((
            axum::http::StatusCode::UNAUTHORIZED,
            axum::Json(crate::routes::auth::ErrorResponse {
                error: "Missing or invalid Authorization header".to_string(),
                code: "UNAUTHORIZED".to_string(),
            }),
        ));
    };

    validate_token(token, jwt_secret).map_err(|_| {
        (
            axum::http::StatusCode::UNAUTHORIZED,
            axum::Json(crate::routes::auth::ErrorResponse {
                error: "Invalid or expired token".to_string(),
                code: "INVALID_TOKEN".to_string(),
            }),
        )
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_and_validate_token() {
        let secret = "test-secret";
        let household_id = "test-household";
        let device_id = "test-device";
        let member_id = "test-member";

        let response = create_token(household_id, device_id, member_id, secret, 1).unwrap();
        let claims = validate_token(&response.token, secret).unwrap();

        assert_eq!(claims.household_id, household_id);
        assert_eq!(claims.device_id, device_id);
        assert_eq!(claims.member_id, member_id);
    }

    #[test]
    fn validate_invite_code_accepts_new_format() {
        assert!(validate_invite_code("7K2-MQP"));
        assert!(validate_invite_code("7K2MQP"));
        assert!(validate_invite_code("7k2-mqp"));
    }

    #[test]
    fn validate_invite_code_rejects_bad_input() {
        assert!(!validate_invite_code("HNMN-JEB6-3I4C")); // old format
        assert!(!validate_invite_code("7K2-MQ"));          // too short
        assert!(!validate_invite_code("7K2MQ0"));          // ambiguous 0
        assert!(!validate_invite_code("7K2MQI"));          // ambiguous I
        assert!(!validate_invite_code("7K2MQL"));          // ambiguous L
    }

}
