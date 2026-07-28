use sqlx::Row;
use tracing::{debug, info};

use super::{BackupInfo, BackupUsage, Database};

impl Database {
    // ========== Backup Database Operations ==========

    /// Insert backup metadata row (file already written to disk by caller).
    pub async fn store_backup_meta(
        &self,
        id: &str,
        household_id: &str,
        description: Option<&str>,
        size_bytes: i64,
    ) -> Result<(), sqlx::Error> {
        let now = chrono::Utc::now().timestamp();
        sqlx::query(
            "INSERT INTO backups (id, household_id, description, size_bytes, created_at)
             VALUES ($1, $2, $3, $4, $5)",
        )
        .bind(id)
        .bind(household_id)
        .bind(description)
        .bind(size_bytes)
        .bind(now)
        .execute(&self.pool)
        .await?;
        debug!(
            "Stored backup meta {} for household {} ({} bytes)",
            id, household_id, size_bytes
        );
        Ok(())
    }

    /// List backups for a household (most recent first).
    pub async fn list_backups(&self, household_id: &str) -> Result<Vec<BackupInfo>, sqlx::Error> {
        let rows = sqlx::query(
            "SELECT id, household_id, description, size_bytes, created_at
             FROM backups WHERE household_id = $1 ORDER BY created_at DESC",
        )
        .bind(household_id)
        .fetch_all(&self.pool)
        .await?;

        Ok(rows
            .iter()
            .map(|row| BackupInfo {
                id: row.get("id"),
                household_id: row.get("household_id"),
                description: row.get("description"),
                size_bytes: row.get("size_bytes"),
                created_at: row.get("created_at"),
            })
            .collect())
    }

    /// Get backup metadata (household_id + size_bytes) for a single backup.
    pub async fn get_backup_meta(
        &self,
        backup_id: &str,
    ) -> Result<Option<(String, i64)>, sqlx::Error> {
        let row = sqlx::query(
            "SELECT household_id, size_bytes FROM backups WHERE id = $1",
        )
        .bind(backup_id)
        .fetch_optional(&self.pool)
        .await?;
        Ok(row.map(|r| (r.get("household_id"), r.get("size_bytes"))))
    }

    /// Delete a backup row. Returns `(household_id, size_bytes)` for quota update
    /// and filesystem cleanup, or `None` if not found.
    pub async fn delete_backup(
        &self,
        id: &str,
    ) -> Result<Option<(String, i64)>, sqlx::Error> {
        let meta = self.get_backup_meta(id).await?;
        if meta.is_some() {
            sqlx::query("DELETE FROM backups WHERE id = $1")
                .bind(id)
                .execute(&self.pool)
                .await?;
        }
        Ok(meta)
    }

    // ========== Backup Quota Operations ==========

    /// Ensure a quota row exists and return current backup usage.
    pub async fn get_backup_usage(
        &self,
        household_id: &str,
        default_quota_bytes: i64,
    ) -> Result<BackupUsage, sqlx::Error> {
        // Ensure row exists (shared with media quotas)
        sqlx::query(
            "INSERT INTO household_quotas (household_id, used_bytes, quota_bytes)
             VALUES ($1, 0, 0)
             ON CONFLICT (household_id) DO NOTHING",
        )
        .bind(household_id)
        .execute(&self.pool)
        .await?;

        // Fill default backup_quota_bytes for households that have never had it set
        sqlx::query(
            "UPDATE household_quotas
             SET backup_quota_bytes = $1
             WHERE household_id = $2 AND backup_quota_bytes = 0",
        )
        .bind(default_quota_bytes)
        .bind(household_id)
        .execute(&self.pool)
        .await?;

        let row = sqlx::query(
            "SELECT backup_used_bytes, backup_quota_bytes
             FROM household_quotas WHERE household_id = $1",
        )
        .bind(household_id)
        .fetch_one(&self.pool)
        .await?;

        Ok(BackupUsage {
            used_bytes: row.get("backup_used_bytes"),
            quota_bytes: row.get("backup_quota_bytes"),
        })
    }

    /// Atomically adjust backup_used_bytes by delta (can be negative for deletes).
    pub async fn update_backup_usage(
        &self,
        household_id: &str,
        delta_bytes: i64,
    ) -> Result<(), sqlx::Error> {
        sqlx::query(
            "UPDATE household_quotas
             SET backup_used_bytes = GREATEST(0, backup_used_bytes + $1)
             WHERE household_id = $2",
        )
        .bind(delta_bytes)
        .bind(household_id)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// Delete backups older than `max_age_hours`. Returns list of
    /// `(backup_id, household_id, size_bytes)` for filesystem + quota cleanup.
    pub async fn cleanup_old_backups(
        &self,
        max_age_hours: i64,
    ) -> Result<Vec<(String, String, i64)>, sqlx::Error> {
        let cutoff = chrono::Utc::now().timestamp() - (max_age_hours * 3600);

        let rows = sqlx::query(
            "SELECT id, household_id, size_bytes FROM backups WHERE created_at < $1",
        )
        .bind(cutoff)
        .fetch_all(&self.pool)
        .await?;

        let expired: Vec<(String, String, i64)> = rows
            .iter()
            .map(|r| (r.get("id"), r.get("household_id"), r.get("size_bytes")))
            .collect();

        if !expired.is_empty() {
            sqlx::query("DELETE FROM backups WHERE created_at < $1")
                .bind(cutoff)
                .execute(&self.pool)
                .await?;

            // Update quotas per household
            let mut deltas: std::collections::HashMap<String, i64> =
                std::collections::HashMap::new();
            for (_, hid, size) in &expired {
                *deltas.entry(hid.clone()).or_insert(0) += size;
            }
            for (hid, total) in &deltas {
                sqlx::query(
                    "UPDATE household_quotas
                     SET backup_used_bytes = GREATEST(0, backup_used_bytes - $1)
                     WHERE household_id = $2",
                )
                .bind(total)
                .bind(hid)
                .execute(&self.pool)
                .await?;
            }

            info!(
                "Cleaned up {} expired backups (older than {} hours)",
                expired.len(),
                max_age_hours
            );
        }

        Ok(expired)
    }
}
