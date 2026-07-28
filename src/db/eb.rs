use sqlx::PgPool;

use super::Database;

impl Database {
    /// Create the Enable Banking account-binding table (idempotent, run at
    /// boot). Maps an EB `account_uid` / `session_id` to the household that
    /// linked it, so the EB proxy can authorize a path-supplied id against the
    /// caller's household (audit 2026-07-07 #9 — confused deputy). One row per
    /// account uid; `session_id` is denormalized so session lookups need no
    /// second table.
    pub(super) async fn init_eb_tables(pool: &PgPool) -> Result<(), sqlx::Error> {
        sqlx::query(
            "CREATE TABLE IF NOT EXISTS eb_account_bindings (
                account_uid  TEXT PRIMARY KEY,
                session_id   TEXT NOT NULL,
                household_id TEXT NOT NULL,
                created_at   BIGINT NOT NULL
            )",
        )
        .execute(pool)
        .await?;

        sqlx::query(
            "CREATE INDEX IF NOT EXISTS idx_eb_bindings_session
                ON eb_account_bindings(session_id)",
        )
        .execute(pool)
        .await?;

        Ok(())
    }

    /// Bind every account uid from a freshly created EB session to the
    /// household that created it. Called only from `create_session`, whose
    /// uids come from EB's response to the caller's own OAuth consent — so a
    /// caller can only bind accounts they actually authorized. A legitimate
    /// re-link of the same account yields a fresh `session_id` for the same
    /// uid and updates the row in place (latest linker wins).
    pub async fn bind_eb_accounts(
        &self,
        household_id: &str,
        session_id: &str,
        account_uids: &[String],
    ) -> Result<(), sqlx::Error> {
        let now = chrono::Utc::now().timestamp();
        for uid in account_uids {
            sqlx::query(
                "INSERT INTO eb_account_bindings
                     (account_uid, session_id, household_id, created_at)
                 VALUES ($1, $2, $3, $4)
                 ON CONFLICT (account_uid) DO UPDATE
                   SET session_id = $2, household_id = $3, created_at = $4",
            )
            .bind(uid)
            .bind(session_id)
            .bind(household_id)
            .bind(now)
            .execute(&self.pool)
            .await?;
        }
        Ok(())
    }

    /// The household that owns an EB account uid, or `None` if unbound.
    pub async fn eb_household_for_account(
        &self,
        account_uid: &str,
    ) -> Result<Option<String>, sqlx::Error> {
        sqlx::query_scalar(
            "SELECT household_id FROM eb_account_bindings WHERE account_uid = $1",
        )
        .bind(account_uid)
        .fetch_optional(&self.pool)
        .await
    }

    /// The household that owns an EB session id, or `None` if unbound.
    pub async fn eb_household_for_session(
        &self,
        session_id: &str,
    ) -> Result<Option<String>, sqlx::Error> {
        sqlx::query_scalar(
            "SELECT household_id FROM eb_account_bindings WHERE session_id = $1 LIMIT 1",
        )
        .bind(session_id)
        .fetch_optional(&self.pool)
        .await
    }
}
