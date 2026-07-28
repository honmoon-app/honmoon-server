use sqlx::PgPool;
use tracing::debug;

use super::Database;

/// Result of a subscribe attempt.
///
/// `token` is the one that belongs in the confirmation link. `already_active`
/// is true when the address was a confirmed subscriber before this call — the
/// caller must NOT mail those, otherwise anyone could use the public form to
/// send repeated mail to an address they do not own.
#[derive(Debug, Clone)]
pub struct SubscribeOutcome {
    pub token: String,
    pub already_active: bool,
}

impl Database {
    pub(super) async fn init_newsletter_tables(pool: &PgPool) -> Result<(), sqlx::Error> {
        // Double opt-in: a row appears the moment the form is submitted, but
        // it only counts as a subscriber once `confirmed_at` is set from the
        // link in the confirmation mail. `created_at` doubles as the consent
        // timestamp, `confirmed_at` as the proof of it.
        sqlx::query(
            "CREATE TABLE IF NOT EXISTS newsletter_subscribers (
                email TEXT PRIMARY KEY,
                lang TEXT NOT NULL DEFAULT 'en',
                token TEXT NOT NULL,
                source TEXT,
                created_at BIGINT NOT NULL,
                confirmed_at BIGINT,
                unsubscribed_at BIGINT
            )",
        )
        .execute(pool)
        .await?;

        sqlx::query(
            "CREATE UNIQUE INDEX IF NOT EXISTS idx_newsletter_token
             ON newsletter_subscribers(token)",
        )
        .execute(pool)
        .await?;

        Ok(())
    }

    /// Record a subscribe request. Idempotent by email.
    ///
    /// - pending row → keeps the existing token, so a confirmation mail that
    ///   is already sitting in the inbox keeps working
    /// - confirmed + active → left untouched, reported as `already_active`
    /// - previously unsubscribed → reset to pending with a fresh token, so
    ///   coming back always costs another confirmation click
    pub async fn subscribe_newsletter(
        &self,
        email: &str,
        lang: &str,
        source: &str,
    ) -> Result<SubscribeOutcome, sqlx::Error> {
        let email = email.trim().to_lowercase();
        let token = uuid::Uuid::new_v4().to_string();
        let now = chrono::Utc::now().timestamp();

        let (token, confirmed_at): (String, Option<i64>) = sqlx::query_as(
            "INSERT INTO newsletter_subscribers (email, lang, token, source, created_at)
             VALUES ($1, $2, $3, $4, $5)
             ON CONFLICT (email) DO UPDATE SET
                lang = EXCLUDED.lang,
                token = CASE
                    WHEN newsletter_subscribers.unsubscribed_at IS NOT NULL
                        THEN EXCLUDED.token
                    ELSE newsletter_subscribers.token
                END,
                confirmed_at = CASE
                    WHEN newsletter_subscribers.unsubscribed_at IS NOT NULL
                        THEN NULL
                    ELSE newsletter_subscribers.confirmed_at
                END,
                created_at = CASE
                    WHEN newsletter_subscribers.unsubscribed_at IS NOT NULL
                        THEN EXCLUDED.created_at
                    ELSE newsletter_subscribers.created_at
                END,
                unsubscribed_at = NULL
             RETURNING token, confirmed_at",
        )
        .bind(&email)
        .bind(lang)
        .bind(&token)
        .bind(source)
        .bind(now)
        .fetch_one(&self.pool)
        .await?;

        Ok(SubscribeOutcome {
            token,
            already_active: confirmed_at.is_some(),
        })
    }

    /// Mark a pending subscriber confirmed. Returns the language to render the
    /// landing page in, or `None` when the token is unknown.
    pub async fn confirm_newsletter(&self, token: &str) -> Result<Option<String>, sqlx::Error> {
        let now = chrono::Utc::now().timestamp();
        let row: Option<(String,)> = sqlx::query_as(
            "UPDATE newsletter_subscribers
             SET confirmed_at = COALESCE(confirmed_at, $2), unsubscribed_at = NULL
             WHERE token = $1
             RETURNING lang",
        )
        .bind(token)
        .bind(now)
        .fetch_optional(&self.pool)
        .await?;

        debug!("newsletter confirm: token matched = {}", row.is_some());
        Ok(row.map(|r| r.0))
    }

    /// Mark a subscriber unsubscribed. The row is kept (not deleted) so a
    /// later re-subscribe still has to pass double opt-in, and so we never
    /// silently re-add someone who opted out.
    pub async fn unsubscribe_newsletter(&self, token: &str) -> Result<Option<String>, sqlx::Error> {
        let now = chrono::Utc::now().timestamp();
        let row: Option<(String,)> = sqlx::query_as(
            "UPDATE newsletter_subscribers
             SET unsubscribed_at = COALESCE(unsubscribed_at, $2)
             WHERE token = $1
             RETURNING lang",
        )
        .bind(token)
        .bind(now)
        .fetch_optional(&self.pool)
        .await?;

        Ok(row.map(|r| r.0))
    }

    /// Confirmed, still-subscribed addresses — the actual send list.
    pub async fn newsletter_recipients(&self) -> Result<Vec<(String, String, String)>, sqlx::Error> {
        let rows: Vec<(String, String, String)> = sqlx::query_as(
            "SELECT email, lang, token FROM newsletter_subscribers
             WHERE confirmed_at IS NOT NULL AND unsubscribed_at IS NULL
             ORDER BY created_at ASC",
        )
        .fetch_all(&self.pool)
        .await?;
        Ok(rows)
    }
}
