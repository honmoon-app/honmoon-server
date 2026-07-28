use sqlx::Row;
use tracing::{info, debug};
use uuid::Uuid;

use super::{Database, MessageDelivery, PendingMessage, SyncStatus};

impl Database {
    /// Register or update a household member
    pub async fn upsert_household_member(&self, household_id: &str, member_id: &str) -> Result<(), sqlx::Error> {
        let now = chrono::Utc::now().timestamp();
        sqlx::query(
            "INSERT INTO household_members (household_id, member_id, last_seen_at)
             VALUES ($1, $2, $3)
             ON CONFLICT(household_id, member_id) DO UPDATE SET last_seen_at = $3",
        )
        .bind(household_id)
        .bind(member_id)
        .bind(now)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// Get all members of a household
    pub async fn get_household_members(&self, household_id: &str) -> Result<Vec<String>, sqlx::Error> {
        let rows = sqlx::query(
            "SELECT member_id FROM household_members WHERE household_id = $1",
        )
        .bind(household_id)
        .fetch_all(&self.pool)
        .await?;

        Ok(rows.iter().map(|row| row.get("member_id")).collect())
    }

    /// Store a new pending message and create delivery entries for household members.
    /// Idempotent insert keyed on `(household_id, from_device_id,
    /// correlation_id)`. On duplicate, returns the existing row's `id`
    /// without inserting again or touching deliveries — letting the caller
    /// re-ack a retried client send without re-broadcasting.
    // Args mirror the pending-message table columns 1:1 — a params struct
    // would just be ceremony for a single call site.
    #[allow(clippy::too_many_arguments)]
    pub async fn store_pending_message(
        &self,
        household_id: &str,
        from_device_id: &str,
        from_member_id: &str,
        correlation_id: &str,
        payload: &str,
        entity_type: Option<&str>,
        change_type: Option<&str>,
        description: Option<&str>,
        recipients: Option<&[String]>,
    ) -> Result<(String, bool), sqlx::Error> {
        let message_id = Uuid::new_v4().to_string();
        let now = chrono::Utc::now().timestamp();

        // Resolve effective recipients up-front. If there's no one to deliver
        // to (solo household, or recipient filter excludes everyone in this
        // household), there's nothing to persist — ack and drop. Otherwise
        // we'd leave orphan rows in pending_messages with no deliveries,
        // and the sender's UI would show them as "waiting to send" forever.
        let other_members: Vec<String> = sqlx::query(
            "SELECT member_id FROM household_members WHERE household_id = $1 AND member_id != $2",
        )
        .bind(household_id)
        .bind(from_member_id)
        .fetch_all(&self.pool)
        .await?
        .iter()
        .map(|row| row.get("member_id"))
        .collect();

        let effective_recipients: Vec<&String> = match &recipients {
            Some(filter) => other_members
                .iter()
                .filter(|m| filter.iter().any(|r| &r == m))
                .collect(),
            None => other_members.iter().collect(),
        };

        if effective_recipients.is_empty() {
            debug!(
                "store_pending_message: no recipients for {} in household {}, skipping persist",
                correlation_id, household_id
            );
            return Ok((message_id, true));
        }

        // The pending-message row and its delivery rows must commit together —
        // a crash between them would orphan a message with no (or partial)
        // recipients, undrainable forever (audit #40). One transaction.
        let mut tx = self.pool.begin().await?;

        let inserted: Option<String> = sqlx::query_scalar(
            "INSERT INTO pending_messages (id, household_id, from_device_id, from_member_id, correlation_id, payload, created_at, entity_type, change_type, description)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
             ON CONFLICT (household_id, from_device_id, correlation_id) DO NOTHING
             RETURNING id",
        )
        .bind(&message_id)
        .bind(household_id)
        .bind(from_device_id)
        .bind(from_member_id)
        .bind(correlation_id)
        .bind(payload)
        .bind(now)
        .bind(entity_type)
        .bind(change_type)
        .bind(description)
        .fetch_optional(&mut *tx)
        .await?;

        if let Some(existing_id) = inserted {
            // Fresh insert path — continue below to populate deliveries
            debug_assert_eq!(existing_id, message_id);
        } else {
            // Duplicate retry — fetch existing id and short-circuit. No writes
            // to commit, so the transaction just rolls back on drop.
            let existing_id: String = sqlx::query_scalar(
                "SELECT id FROM pending_messages
                 WHERE household_id = $1 AND from_device_id = $2 AND correlation_id = $3",
            )
            .bind(household_id)
            .bind(from_device_id)
            .bind(correlation_id)
            .fetch_one(&mut *tx)
            .await?;
            debug!(
                "store_pending_message duplicate for correlation {} -> existing id {}",
                correlation_id, existing_id
            );
            return Ok((existing_id, false));
        }

        for member_id in &effective_recipients {
            sqlx::query(
                "INSERT INTO message_deliveries (message_id, member_id, delivered_at)
                 VALUES ($1, $2, NULL)",
            )
            .bind(&message_id)
            .bind(member_id)
            .execute(&mut *tx)
            .await?;
        }

        tx.commit().await?;
        debug!("Stored pending message {} for household {}", message_id, household_id);
        Ok((message_id, true))
    }

    /// Mark a message as delivered to a specific member
    pub async fn mark_delivered(&self, message_id: &str, member_id: &str) -> Result<bool, sqlx::Error> {
        let now = chrono::Utc::now().timestamp();
        let result = sqlx::query(
            "UPDATE message_deliveries SET delivered_at = $1
             WHERE message_id = $2 AND member_id = $3 AND delivered_at IS NULL",
        )
        .bind(now)
        .bind(message_id)
        .bind(member_id)
        .execute(&self.pool)
        .await?;

        if result.rows_affected() > 0 {
            debug!("Marked message {} as delivered to member {}", message_id, member_id);
            self.cleanup_fully_delivered_message(message_id).await?;
        }

        Ok(result.rows_affected() > 0)
    }

    /// Check if a message is fully delivered and clean it up
    async fn cleanup_fully_delivered_message(&self, message_id: &str) -> Result<(), sqlx::Error> {
        let row = sqlx::query(
            "SELECT COUNT(*) as cnt FROM message_deliveries
             WHERE message_id = $1 AND delivered_at IS NULL",
        )
        .bind(message_id)
        .fetch_one(&self.pool)
        .await?;
        let undelivered: i64 = row.get("cnt");

        if undelivered == 0 {
            sqlx::query("DELETE FROM message_deliveries WHERE message_id = $1")
                .bind(message_id)
                .execute(&self.pool)
                .await?;
            sqlx::query("DELETE FROM pending_messages WHERE id = $1")
                .bind(message_id)
                .execute(&self.pool)
                .await?;
            debug!("Cleaned up fully delivered message {}", message_id);
        }

        Ok(())
    }

    /// Get pending messages for a specific member
    pub async fn get_pending_messages_for_member(
        &self,
        household_id: &str,
        member_id: &str,
    ) -> Result<Vec<PendingMessage>, sqlx::Error> {
        let rows = sqlx::query(
            "SELECT pm.id, pm.household_id, pm.from_device_id, pm.from_member_id, pm.payload, pm.created_at, pm.entity_type, pm.change_type, pm.description
             FROM pending_messages pm
             INNER JOIN message_deliveries md ON pm.id = md.message_id
             WHERE pm.household_id = $1 AND md.member_id = $2 AND md.delivered_at IS NULL
             ORDER BY pm.created_at ASC",
        )
        .bind(household_id)
        .bind(member_id)
        .fetch_all(&self.pool)
        .await?;

        let messages: Vec<PendingMessage> = rows
            .iter()
            .map(|row| PendingMessage {
                id: row.get("id"),
                household_id: row.get("household_id"),
                from_device_id: row.get("from_device_id"),
                from_member_id: row.get("from_member_id"),
                payload: row.get("payload"),
                created_at: row.get("created_at"),
                entity_type: row.get("entity_type"),
                change_type: row.get("change_type"),
                description: row.get("description"),
            })
            .collect();

        debug!(
            "Found {} pending messages for member {} in household {}",
            messages.len(),
            member_id,
            household_id
        );
        Ok(messages)
    }

    /// Get pending messages created by a specific member (for sync status tracking)
    pub async fn get_pending_messages_from_member(
        &self,
        household_id: &str,
        member_id: &str,
    ) -> Result<Vec<(PendingMessage, Vec<MessageDelivery>)>, sqlx::Error> {
        let rows = sqlx::query(
            "SELECT pm.id, pm.household_id, pm.from_device_id, pm.from_member_id, pm.payload,
                    pm.created_at, pm.entity_type, pm.change_type, pm.description,
                    md.member_id as del_member_id, md.delivered_at
             FROM pending_messages pm
             LEFT JOIN message_deliveries md ON pm.id = md.message_id
             WHERE pm.household_id = $1 AND pm.from_member_id = $2
             ORDER BY pm.created_at DESC",
        )
        .bind(household_id)
        .bind(member_id)
        .fetch_all(&self.pool)
        .await?;

        let mut result: Vec<(PendingMessage, Vec<MessageDelivery>)> = Vec::new();
        let mut last_id: Option<String> = None;

        for row in &rows {
            let id: String = row.get("id");

            if last_id.as_ref() != Some(&id) {
                last_id = Some(id.clone());
                result.push((
                    PendingMessage {
                        id: id.clone(),
                        household_id: row.get("household_id"),
                        from_device_id: row.get("from_device_id"),
                        from_member_id: row.get("from_member_id"),
                        payload: row.get("payload"),
                        created_at: row.get("created_at"),
                        entity_type: row.get("entity_type"),
                        change_type: row.get("change_type"),
                        description: row.get("description"),
                    },
                    Vec::new(),
                ));
            }

            let del_member_id: Option<String> = row.get("del_member_id");
            if let Some(del_mid) = del_member_id {
                if let Some(last) = result.last_mut() {
                    last.1.push(MessageDelivery {
                        message_id: last.0.id.clone(),
                        member_id: del_mid,
                        delivered_at: row.get("delivered_at"),
                    });
                }
            }
        }

        Ok(result)
    }

    /// Clean up old messages (older than specified hours)
    pub async fn cleanup_old_messages(&self, max_age_hours: i64) -> Result<usize, sqlx::Error> {
        let cutoff = chrono::Utc::now().timestamp() - (max_age_hours * 3600);

        sqlx::query(
            "DELETE FROM message_deliveries WHERE message_id IN (
                SELECT id FROM pending_messages WHERE created_at < $1
            )",
        )
        .bind(cutoff)
        .execute(&self.pool)
        .await?;

        let result = sqlx::query("DELETE FROM pending_messages WHERE created_at < $1")
            .bind(cutoff)
            .execute(&self.pool)
            .await?;

        let deleted = result.rows_affected() as usize;
        if deleted > 0 {
            info!(
                "Cleaned up {} old messages (older than {} hours)",
                deleted, max_age_hours
            );
        }

        Ok(deleted)
    }

    /// Get delivery status summary for a member's pending messages
    pub async fn get_sync_status_for_member(
        &self,
        household_id: &str,
        member_id: &str,
    ) -> Result<SyncStatus, sqlx::Error> {
        let row = sqlx::query(
            "SELECT COUNT(*) as cnt FROM pending_messages
             WHERE household_id = $1 AND from_member_id = $2",
        )
        .bind(household_id)
        .bind(member_id)
        .fetch_one(&self.pool)
        .await?;
        let total_pending: i64 = row.get("cnt");

        let row = sqlx::query(
            "SELECT COUNT(*) as cnt FROM message_deliveries md
             INNER JOIN pending_messages pm ON md.message_id = pm.id
             WHERE pm.household_id = $1 AND pm.from_member_id = $2 AND md.delivered_at IS NULL",
        )
        .bind(household_id)
        .bind(member_id)
        .fetch_one(&self.pool)
        .await?;
        let total_undelivered: i64 = row.get("cnt");

        Ok(SyncStatus {
            pending_messages: total_pending as u32,
            pending_deliveries: total_undelivered as u32,
        })
    }
}
