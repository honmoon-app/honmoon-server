use sqlx::Row;
use uuid::Uuid;

use super::{Database, FeedbackItem};

impl Database {
    /// Bind an invite code to a household, or verify an existing binding.
    ///
    /// First-writer-wins on BOTH sides (audit 2026-07-07 #2):
    /// - **household side:** a household's authoritative invite_code is the
    ///   earliest one ever bound to it. Once bound, only that exact code mints
    ///   a token for it. This closes the free-JWT hole: previously an attacker
    ///   who learned only a household_id (a UUID) could present any fresh,
    ///   never-seen code and the INSERT would happily bind it → valid JWT. A
    ///   household_id never reaches the server before the founder's own first
    ///   mint (the sealed-invite blob that could leak it needs a token to
    ///   create), so the founder is causally the first writer; an attacker
    ///   cannot present the real code they don't know.
    /// - **code side:** a code already bound to a *different* household still
    ///   can't be reused (unchanged).
    ///
    /// Returns Ok(()) when the (code, household) pair is authoritative,
    /// Err(existing) — ignored by the caller, mapped to 403 — otherwise.
    /// `ORDER BY created_at ASC` also heals a DB already polluted by the old
    /// hole: the founder's original code wins, rogue later rows are inert.
    ///
    /// Residual (needs per-member/device auth, audit #3/#27 — not this fix):
    /// a hostile-LAN attacker who sniffs household_id+code from mDNS before the
    /// founder's first mint could race a rogue bind and lock the founder out
    /// (DoS, no data access — the sniffer already holds join capability).
    pub async fn bind_or_check_invite(
        &self,
        invite_code: &str,
        household_id: &str,
    ) -> Result<Result<(), String>, sqlx::Error> {
        let mut tx = self.pool.begin().await?;

        // Household-side first-writer-wins.
        let bound_code: Option<String> = sqlx::query_scalar(
            "SELECT invite_code FROM household_invites
              WHERE household_id = $1
              ORDER BY created_at ASC
              LIMIT 1",
        )
        .bind(household_id)
        .fetch_optional(&mut *tx)
        .await?;

        if let Some(code) = bound_code {
            tx.commit().await?;
            return if code == invite_code {
                Ok(Ok(()))
            } else {
                Ok(Err(code))
            };
        }

        // No code bound to this household yet — the first-ever mint
        // (founder / solo). Bind it, keeping the code-side guard.
        let now = chrono::Utc::now().timestamp();
        let inserted: Option<String> = sqlx::query_scalar(
            "INSERT INTO household_invites (invite_code, household_id, created_at)
             VALUES ($1, $2, $3)
             ON CONFLICT (invite_code) DO NOTHING
             RETURNING household_id",
        )
        .bind(invite_code)
        .bind(household_id)
        .bind(now)
        .fetch_optional(&mut *tx)
        .await?;

        if inserted.is_some() {
            tx.commit().await?;
            return Ok(Ok(()));
        }

        // The code is already bound to some household — compare.
        let existing: String = sqlx::query_scalar(
            "SELECT household_id FROM household_invites WHERE invite_code = $1",
        )
        .bind(invite_code)
        .fetch_one(&mut *tx)
        .await?;
        tx.commit().await?;

        if existing == household_id {
            Ok(Ok(()))
        } else {
            Ok(Err(existing))
        }
    }

    /// Store a feedback or bug report
    // Args mirror the feedback table columns 1:1 — a params struct would
    // just be ceremony for a single call site.
    #[allow(clippy::too_many_arguments)]
    pub async fn store_feedback(
        &self,
        household_id: &str,
        member_id: &str,
        category: &str,
        message: &str,
        severity: Option<&str>,
        title: Option<&str>,
        steps_to_reproduce: Option<&str>,
        expected_behavior: Option<&str>,
        device_info: Option<&str>,
    ) -> Result<String, sqlx::Error> {
        let id = Uuid::new_v4().to_string();
        let now = chrono::Utc::now().timestamp();
        sqlx::query(
            "INSERT INTO feedback (id, household_id, member_id, category, message, severity, title, steps_to_reproduce, expected_behavior, device_info, created_at)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)",
        )
        .bind(&id)
        .bind(household_id)
        .bind(member_id)
        .bind(category)
        .bind(message)
        .bind(severity)
        .bind(title)
        .bind(steps_to_reproduce)
        .bind(expected_behavior)
        .bind(device_info)
        .bind(now)
        .execute(&self.pool)
        .await?;
        Ok(id)
    }

    /// List feedback with optional filters
    pub async fn list_feedback(
        &self,
        status_filter: Option<&str>,
        category_filter: Option<&str>,
        include_archived: bool,
    ) -> Result<Vec<FeedbackItem>, sqlx::Error> {
        let rows = sqlx::query(
            "SELECT id, household_id, member_id, category, message, severity, title,
                    steps_to_reproduce, expected_behavior, device_info, status, admin_notes, created_at
             FROM feedback
             WHERE ($1::TEXT IS NOT NULL AND status = $1)
                OR ($1::TEXT IS NULL AND ($2 OR status != 'archived'))
             AND ($3::TEXT IS NULL OR category = $3)
             ORDER BY created_at DESC",
        )
        .bind(status_filter)
        .bind(include_archived)
        .bind(category_filter)
        .fetch_all(&self.pool)
        .await?;

        let items = rows
            .iter()
            .map(|row| FeedbackItem {
                id: row.get("id"),
                household_id: row.get("household_id"),
                member_id: row.get("member_id"),
                category: row.get("category"),
                message: row.get("message"),
                severity: row.get("severity"),
                title: row.get("title"),
                steps_to_reproduce: row.get("steps_to_reproduce"),
                expected_behavior: row.get("expected_behavior"),
                device_info: row.get("device_info"),
                status: row.get("status"),
                admin_notes: row.get("admin_notes"),
                created_at: row.get("created_at"),
            })
            .collect();
        Ok(items)
    }

    /// Update feedback status and admin notes
    pub async fn update_feedback_status(
        &self,
        id: &str,
        status: &str,
        notes: Option<&str>,
    ) -> Result<bool, sqlx::Error> {
        let result = sqlx::query(
            "UPDATE feedback SET status = $1, admin_notes = $2 WHERE id = $3",
        )
        .bind(status)
        .bind(notes)
        .bind(id)
        .execute(&self.pool)
        .await?;
        Ok(result.rows_affected() > 0)
    }
}
