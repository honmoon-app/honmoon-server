use super::Database;
use sqlx::Row;
use tracing::{debug, info};

impl Database {
    /// Upsert a sealed invite. Re-creating a link for the same code
    /// overwrites the previous blob and expiry.
    pub async fn store_sealed_invite(
        &self,
        code: &str,
        blob: &str,
        expires_at: i64,
        household_id: &str,
    ) -> Result<(), sqlx::Error> {
        let now = chrono::Utc::now().timestamp();
        // The DO UPDATE is scoped to the SAME household: a code collision
        // owned by a DIFFERENT household is a no-op, so an attacker cannot
        // PUT their own blob under a victim's code to hijack the invite
        // (audit 2026-07-07). `code` is a global PK, so without this guard a
        // colliding code would silently reassign household_id.
        sqlx::query(
            "INSERT INTO sealed_invites (code, blob, expires_at, created_at, household_id, downloads)
             VALUES ($1, $2, $3, $4, $5, 0)
             ON CONFLICT (code) DO UPDATE
               SET blob = EXCLUDED.blob,
                   expires_at = EXCLUDED.expires_at,
                   created_at = EXCLUDED.created_at,
                   downloads = 0
             WHERE sealed_invites.household_id = EXCLUDED.household_id",
        )
        .bind(code)
        .bind(blob)
        .bind(expires_at)
        .bind(now)
        .bind(household_id)
        .execute(&self.pool)
        .await?;
        debug!(
            "Stored sealed invite {} for household {} (expires {})",
            code, household_id, expires_at
        );
        Ok(())
    }

    /// Fetch a sealed invite blob. Returns `None` when the code is
    /// unknown or the entry has expired. Atomically increments the
    /// downloads counter on successful lookup.
    pub async fn get_sealed_invite(
        &self,
        code: &str,
    ) -> Result<Option<String>, sqlx::Error> {
        let now = chrono::Utc::now().timestamp();
        // Atomic: condition the increment on non-expiry in a single
        // statement so we never race a competing lookup or cleanup job.
        let row = sqlx::query(
            "UPDATE sealed_invites
                SET downloads = downloads + 1
              WHERE code = $1 AND expires_at > $2
              RETURNING blob",
        )
        .bind(code)
        .bind(now)
        .fetch_optional(&self.pool)
        .await?;
        Ok(row.map(|r| r.get("blob")))
    }

    /// Delete a sealed invite by code. Idempotent — deleting a code
    /// that does not exist is not an error. Used when a household
    /// revokes its invite (e.g. the owner deletes their account).
    pub async fn delete_sealed_invite(
        &self,
        code: &str,
        household_id: &str,
    ) -> Result<u64, sqlx::Error> {
        // Scoped to the caller's household: `code` is a global PK, so an
        // unscoped DELETE let any authenticated user revoke another
        // household's invite (audit 2026-07-07). Cross-household deletes now
        // match no row (idempotent no-op).
        let result = sqlx::query("DELETE FROM sealed_invites WHERE code = $1 AND household_id = $2")
            .bind(code)
            .bind(household_id)
            .execute(&self.pool)
            .await?;
        let count = result.rows_affected();
        debug!("Deleted sealed invite {} ({} row(s))", code, count);
        Ok(count)
    }

    /// Delete expired sealed invites. Called from the hourly cleanup job.
    pub async fn cleanup_expired_invites(&self) -> Result<usize, sqlx::Error> {
        let now = chrono::Utc::now().timestamp();
        let result = sqlx::query("DELETE FROM sealed_invites WHERE expires_at < $1")
            .bind(now)
            .execute(&self.pool)
            .await?;
        let count = result.rows_affected() as usize;
        if count > 0 {
            info!("Cleaned up {} expired sealed invites", count);
        }
        Ok(count)
    }
}

#[derive(Debug, Clone, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ActiveInvite {
    pub code: String,
    pub created_at: i64,
    pub expires_at: i64,
    pub ttl_seconds: i64,
    pub downloads: i64,
}

impl Database {
    pub async fn list_active_invites(
        &self,
        household_id: &str,
    ) -> Result<Vec<ActiveInvite>, sqlx::Error> {
        let now = chrono::Utc::now().timestamp();
        let rows = sqlx::query(
            "SELECT code, created_at, expires_at, downloads
               FROM sealed_invites
              WHERE household_id = $1 AND expires_at > $2
              ORDER BY created_at DESC",
        )
        .bind(household_id)
        .bind(now)
        .fetch_all(&self.pool)
        .await?;
        Ok(rows
            .into_iter()
            .map(|r| {
                let created_at: i64 = r.get("created_at");
                let expires_at: i64 = r.get("expires_at");
                ActiveInvite {
                    code: r.get("code"),
                    created_at,
                    expires_at,
                    ttl_seconds: expires_at - created_at,
                    downloads: r.get("downloads"),
                }
            })
            .collect())
    }

    pub async fn get_invite_stats(
        &self,
        code: &str,
        household_id: &str,
    ) -> Result<Option<i64>, sqlx::Error> {
        let now = chrono::Utc::now().timestamp();
        let row = sqlx::query(
            "SELECT downloads FROM sealed_invites
              WHERE code = $1 AND household_id = $2 AND expires_at > $3",
        )
        .bind(code)
        .bind(household_id)
        .bind(now)
        .fetch_optional(&self.pool)
        .await?;
        Ok(row.map(|r| r.get("downloads")))
    }
}
