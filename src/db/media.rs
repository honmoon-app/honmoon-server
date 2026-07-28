use sqlx::Row;
use tracing::{info, debug};

use super::{Database, MediaFileInfo, StorageUsage};

impl Database {
    // ========== Media Database Operations ==========

    /// Insert a media file record
    pub async fn insert_media_file(
        &self,
        id: &str,
        household_id: &str,
        member_id: &str,
        original_name: Option<&str>,
        size_bytes: i64,
        checksum: Option<&str>,
    ) -> Result<(), sqlx::Error> {
        let now = chrono::Utc::now().timestamp();

        sqlx::query(
            "INSERT INTO media_files (id, household_id, member_id, original_name, size_bytes, checksum, created_at)
             VALUES ($1, $2, $3, $4, $5, $6, $7)",
        )
        .bind(id)
        .bind(household_id)
        .bind(member_id)
        .bind(original_name)
        .bind(size_bytes)
        .bind(checksum)
        .bind(now)
        .execute(&self.pool)
        .await?;

        debug!(
            "Stored media file {} for household {} ({} bytes)",
            id, household_id, size_bytes
        );
        Ok(())
    }

    /// Get media file metadata by ID
    pub async fn get_media_file(&self, id: &str) -> Result<Option<MediaFileInfo>, sqlx::Error> {
        let row = sqlx::query(
            "SELECT id, household_id, member_id, original_name, size_bytes, checksum, created_at
             FROM media_files WHERE id = $1",
        )
        .bind(id)
        .fetch_optional(&self.pool)
        .await?;

        Ok(row.map(|r| MediaFileInfo {
            id: r.get("id"),
            household_id: r.get("household_id"),
            member_id: r.get("member_id"),
            original_name: r.get("original_name"),
            size_bytes: r.get("size_bytes"),
            checksum: r.get("checksum"),
            created_at: r.get("created_at"),
        }))
    }

    /// Delete a media file record and return its info for filesystem cleanup
    pub async fn delete_media_file(&self, id: &str) -> Result<Option<MediaFileInfo>, sqlx::Error> {
        // Get info first
        let info = self.get_media_file(id).await?;

        if info.is_some() {
            sqlx::query("DELETE FROM media_files WHERE id = $1")
                .bind(id)
                .execute(&self.pool)
                .await?;
        }

        Ok(info)
    }

    /// Get storage usage for a household
    pub async fn get_household_usage(
        &self,
        household_id: &str,
        default_quota_bytes: i64,
    ) -> Result<StorageUsage, sqlx::Error> {
        // Ensure quota entry exists
        sqlx::query(
            "INSERT INTO household_quotas (household_id, used_bytes, quota_bytes)
             VALUES ($1, 0, $2)
             ON CONFLICT (household_id) DO NOTHING",
        )
        .bind(household_id)
        .bind(default_quota_bytes)
        .execute(&self.pool)
        .await?;

        let row = sqlx::query(
            "SELECT used_bytes, quota_bytes FROM household_quotas WHERE household_id = $1",
        )
        .bind(household_id)
        .fetch_one(&self.pool)
        .await?;

        Ok(StorageUsage {
            used_bytes: row.get("used_bytes"),
            quota_bytes: row.get("quota_bytes"),
        })
    }

    /// Update household storage usage by adding delta_bytes
    pub async fn update_household_usage(
        &self,
        household_id: &str,
        delta_bytes: i64,
    ) -> Result<(), sqlx::Error> {
        sqlx::query(
            "UPDATE household_quotas SET used_bytes = GREATEST(0, used_bytes + $1) WHERE household_id = $2",
        )
        .bind(delta_bytes)
        .bind(household_id)
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    /// Clean up old media files (older than specified hours).
    /// Returns list of (media_id, household_id, size_bytes) for filesystem cleanup.
    pub async fn cleanup_old_media(
        &self,
        max_age_hours: i64,
    ) -> Result<Vec<(String, String, i64)>, sqlx::Error> {
        let cutoff = chrono::Utc::now().timestamp() - (max_age_hours * 3600);

        // Get files to delete
        let rows = sqlx::query(
            "SELECT id, household_id, size_bytes FROM media_files WHERE created_at < $1",
        )
        .bind(cutoff)
        .fetch_all(&self.pool)
        .await?;

        let files: Vec<(String, String, i64)> = rows
            .iter()
            .map(|row| {
                (
                    row.get("id"),
                    row.get("household_id"),
                    row.get("size_bytes"),
                )
            })
            .collect();

        if !files.is_empty() {
            // Delete from DB
            sqlx::query("DELETE FROM media_files WHERE created_at < $1")
                .bind(cutoff)
                .execute(&self.pool)
                .await?;

            // Update quotas for each affected household
            let mut household_deltas: std::collections::HashMap<String, i64> =
                std::collections::HashMap::new();
            for (_, household_id, size_bytes) in &files {
                *household_deltas.entry(household_id.clone()).or_insert(0) += size_bytes;
            }

            for (household_id, total_bytes) in &household_deltas {
                sqlx::query(
                    "UPDATE household_quotas SET used_bytes = GREATEST(0, used_bytes - $1) WHERE household_id = $2",
                )
                .bind(total_bytes)
                .bind(household_id)
                .execute(&self.pool)
                .await?;
            }

            info!(
                "Cleaned up {} old media files (older than {} hours)",
                files.len(),
                max_age_hours
            );
        }

        Ok(files)
    }

}
