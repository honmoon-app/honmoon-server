use sqlx::Row;
use tracing::debug;

use super::{Database, PushToken};

impl Database {
    // ========== Push Token Operations ==========

    /// Register or update a push notification token.
    ///
    /// `consent_text_version` is set when the endpoint requires explicit
    /// GDPR consent (FCM-empty); UnifiedPush / Web Push / relay pass `None`.
    /// When non-`None`, `consent_recorded_at` is stamped to the current
    /// time so we can audit when the user accepted which consent string.
    pub async fn upsert_push_token(
        &self,
        token: &str,
        user_id: &str,
        device_id: &str,
        platform: &str,
        endpoint_type: &str,
        consent_text_version: Option<&str>,
    ) -> Result<(), sqlx::Error> {
        let now = chrono::Utc::now().timestamp();
        let consent_at = consent_text_version.map(|_| now);
        sqlx::query(
            "INSERT INTO push_tokens (
                token, user_id, device_id, platform, endpoint_type,
                created_at, updated_at,
                consent_recorded_at, consent_text_version,
                consecutive_failures
             )
             VALUES ($1, $2, $3, $4, $5, $6, $6, $7, $8, 0)
             ON CONFLICT(user_id, device_id) DO UPDATE SET
                token = $1,
                platform = $4,
                endpoint_type = $5,
                updated_at = $6,
                consent_recorded_at = COALESCE($7, push_tokens.consent_recorded_at),
                consent_text_version = COALESCE($8, push_tokens.consent_text_version),
                last_push_at = NULL,
                last_push_status = NULL,
                consecutive_failures = 0",
        )
        .bind(token)
        .bind(user_id)
        .bind(device_id)
        .bind(platform)
        .bind(endpoint_type)
        .bind(now)
        .bind(consent_at)
        .bind(consent_text_version)
        .execute(&self.pool)
        .await?;
        debug!(
            "Upserted push token for user {} device {} (type: {}, consent: {:?})",
            user_id, device_id, endpoint_type, consent_text_version
        );
        Ok(())
    }

    /// Record the result of a push delivery attempt — used by the client
    /// `pushHealthProvider` to show the failure banner after 3 consecutive
    /// failures or when the last successful push is too old.
    pub async fn record_push_attempt(
        &self,
        token: &str,
        status: &str,
        success: bool,
    ) -> Result<(), sqlx::Error> {
        let now = chrono::Utc::now().timestamp();
        if success {
            sqlx::query(
                "UPDATE push_tokens
                 SET last_push_at = $1,
                     last_push_status = $2,
                     consecutive_failures = 0
                 WHERE token = $3",
            )
            .bind(now)
            .bind(status)
            .bind(token)
            .execute(&self.pool)
            .await?;
        } else {
            sqlx::query(
                "UPDATE push_tokens
                 SET last_push_at = $1,
                     last_push_status = $2,
                     consecutive_failures = consecutive_failures + 1
                 WHERE token = $3",
            )
            .bind(now)
            .bind(status)
            .bind(token)
            .execute(&self.pool)
            .await?;
        }
        Ok(())
    }

    /// Remove a push notification token (server-side cleanup of a dead token).
    pub async fn delete_push_token(&self, token: &str) -> Result<bool, sqlx::Error> {
        let result = sqlx::query("DELETE FROM push_tokens WHERE token = $1")
            .bind(token)
            .execute(&self.pool)
            .await?;
        Ok(result.rows_affected() > 0)
    }

    /// Remove a push token only if it belongs to `user_id`. Scopes the
    /// unregister route to the authenticated member so one member can't
    /// delete another member's token (audit #32).
    pub async fn delete_push_token_for_user(
        &self,
        token: &str,
        user_id: &str,
    ) -> Result<bool, sqlx::Error> {
        let result = sqlx::query("DELETE FROM push_tokens WHERE token = $1 AND user_id = $2")
            .bind(token)
            .bind(user_id)
            .execute(&self.pool)
            .await?;
        Ok(result.rows_affected() > 0)
    }

    /// Get all push tokens for a user
    pub async fn get_push_tokens_for_user(&self, user_id: &str) -> Result<Vec<PushToken>, sqlx::Error> {
        let rows = sqlx::query(
            "SELECT token, user_id, device_id, platform, COALESCE(endpoint_type, 'fcm') as endpoint_type FROM push_tokens WHERE user_id = $1",
        )
        .bind(user_id)
        .fetch_all(&self.pool)
        .await?;

        Ok(rows
            .iter()
            .map(|row| PushToken {
                token: row.get("token"),
                user_id: row.get("user_id"),
                device_id: row.get("device_id"),
                platform: row.get("platform"),
                endpoint_type: row.get("endpoint_type"),
            })
            .collect())
    }
}
