use sqlx::PgPool;
use tracing::{info, debug};

mod feedback;
pub mod invite;
mod messages;
mod newsletter;
mod push;
mod backup;
mod media;
mod subscription;
mod eb;

const SECONDS_PER_DAY: i64 = 86_400;

/// Database wrapper for message persistence.
/// Uses a PostgreSQL connection pool via sqlx.
#[derive(Clone)]
pub struct Database {
    pool: PgPool,
}

/// A pending message waiting to be delivered to household members
#[derive(Debug, Clone)]
pub struct PendingMessage {
    pub id: String,
    pub household_id: String,
    pub from_device_id: String,
    pub from_member_id: String,
    pub payload: String,
    pub created_at: i64,
    pub entity_type: Option<String>,
    pub change_type: Option<String>,
    pub description: Option<String>,
}

/// Tracks which members have received a message
#[derive(Debug, Clone)]
pub struct MessageDelivery {
    pub message_id: String,
    pub member_id: String,
    pub delivered_at: Option<i64>,
}

/// A feedback or bug report entry
#[derive(Debug, Clone, serde::Serialize)]
pub struct FeedbackItem {
    pub id: String,
    pub household_id: String,
    pub member_id: String,
    pub category: String,
    pub message: String,
    pub severity: Option<String>,
    pub title: Option<String>,
    pub steps_to_reproduce: Option<String>,
    pub expected_behavior: Option<String>,
    pub device_info: Option<String>,
    pub status: String,
    pub admin_notes: Option<String>,
    pub created_at: i64,
}

/// A registered push notification token
#[derive(Debug, Clone, serde::Serialize)]
pub struct PushToken {
    pub token: String,
    pub user_id: String,
    pub device_id: String,
    pub platform: String,
    /// "fcm" for Firebase Cloud Messaging, "unified_push" for UnifiedPush endpoints
    pub endpoint_type: String,
}

/// Summary of sync status for a member
#[derive(Debug, Clone, serde::Serialize)]
pub struct SyncStatus {
    pub pending_messages: u32,
    pub pending_deliveries: u32,
}

/// Metadata about a stored backup (excludes the data blob)
#[derive(Debug, Clone)]
pub struct BackupInfo {
    pub id: String,
    pub household_id: String,
    pub description: Option<String>,
    pub size_bytes: i64,
    pub created_at: i64,
}

/// Backup storage usage for a household
#[derive(Debug, Clone, serde::Serialize)]
pub struct BackupUsage {
    pub used_bytes: i64,
    pub quota_bytes: i64,
}

/// Metadata about a stored media file
#[derive(Debug, Clone, serde::Serialize)]
pub struct MediaFileInfo {
    pub id: String,
    pub household_id: String,
    pub member_id: String,
    pub original_name: Option<String>,
    pub size_bytes: i64,
    pub checksum: Option<String>,
    pub created_at: i64,
}

/// Storage usage for a household
#[derive(Debug, Clone, serde::Serialize)]
pub struct StorageUsage {
    pub used_bytes: i64,
    pub quota_bytes: i64,
}

impl Database {
    /// Create a new database connection pool and initialize tables
    pub async fn new(database_url: &str) -> Result<Self, sqlx::Error> {
        let pool = PgPool::connect(database_url).await?;

        let db = Self { pool };

        db.init_tables().await?;
        info!("Database initialized (PostgreSQL)");

        Ok(db)
    }

    /// Initialize database tables
    async fn init_tables(&self) -> Result<(), sqlx::Error> {
        // Pending messages table. `correlation_id` is client-generated and
        // makes retried sends idempotent — see `store_pending_message`.
        sqlx::query(
            "CREATE TABLE IF NOT EXISTS pending_messages (
                id TEXT PRIMARY KEY,
                household_id TEXT NOT NULL,
                from_device_id TEXT NOT NULL,
                from_member_id TEXT NOT NULL,
                correlation_id TEXT NOT NULL,
                payload TEXT NOT NULL,
                created_at BIGINT NOT NULL,
                entity_type TEXT,
                change_type TEXT,
                description TEXT,
                UNIQUE (household_id, from_device_id, correlation_id)
            )",
        )
        .execute(&self.pool)
        .await?;

        // Message deliveries table
        sqlx::query(
            "CREATE TABLE IF NOT EXISTS message_deliveries (
                message_id TEXT NOT NULL,
                member_id TEXT NOT NULL,
                delivered_at BIGINT,
                PRIMARY KEY (message_id, member_id),
                FOREIGN KEY (message_id) REFERENCES pending_messages(id) ON DELETE CASCADE
            )",
        )
        .execute(&self.pool)
        .await?;

        // Household members table
        sqlx::query(
            "CREATE TABLE IF NOT EXISTS household_members (
                household_id TEXT NOT NULL,
                member_id TEXT NOT NULL,
                last_seen_at BIGINT,
                PRIMARY KEY (household_id, member_id)
            )",
        )
        .execute(&self.pool)
        .await?;

        // Indexes
        sqlx::query(
            "CREATE INDEX IF NOT EXISTS idx_pending_messages_household
             ON pending_messages(household_id)",
        )
        .execute(&self.pool)
        .await?;

        sqlx::query(
            "CREATE INDEX IF NOT EXISTS idx_message_deliveries_member
             ON message_deliveries(member_id)",
        )
        .execute(&self.pool)
        .await?;

        sqlx::query(
            "CREATE INDEX IF NOT EXISTS idx_household_members_household
             ON household_members(household_id)",
        )
        .execute(&self.pool)
        .await?;

        // Push notification tokens table
        sqlx::query(
            "CREATE TABLE IF NOT EXISTS push_tokens (
                token TEXT PRIMARY KEY,
                user_id TEXT NOT NULL,
                device_id TEXT NOT NULL,
                platform TEXT NOT NULL,
                endpoint_type TEXT NOT NULL DEFAULT 'fcm',
                created_at BIGINT NOT NULL,
                updated_at BIGINT NOT NULL
            )",
        )
        .execute(&self.pool)
        .await?;

        sqlx::query(
            "CREATE INDEX IF NOT EXISTS idx_push_tokens_user
             ON push_tokens(user_id)",
        )
        .execute(&self.pool)
        .await?;

        // M1 additions (spec/18-push-delivery v1.1): consent audit trail +
        // delivery status for the client banner trigger. ALTER ADD COLUMN IF
        // NOT EXISTS keeps existing deployments forward-compatible without a
        // separate migration.
        for stmt in [
            "ALTER TABLE push_tokens ADD COLUMN IF NOT EXISTS consent_recorded_at BIGINT",
            "ALTER TABLE push_tokens ADD COLUMN IF NOT EXISTS consent_text_version TEXT",
            "ALTER TABLE push_tokens ADD COLUMN IF NOT EXISTS last_push_at BIGINT",
            "ALTER TABLE push_tokens ADD COLUMN IF NOT EXISTS last_push_status TEXT",
            "ALTER TABLE push_tokens ADD COLUMN IF NOT EXISTS consecutive_failures INT NOT NULL DEFAULT 0",
        ] {
            sqlx::query(stmt).execute(&self.pool).await?;
        }

        // F-026 (round-08): re-registration produced a fresh endpoint URL
        // each time, and the upsert keyed on `token` only — so stale rows
        // piled up (5–6 per device observed). The push coalescer then POSTed
        // to one arbitrary row, almost never the live one. Collapse to the
        // newest row per (user_id, device_id), then enforce one endpoint per
        // device with a unique index the upsert can conflict-target.
        sqlx::query(
            "DELETE FROM push_tokens a
             USING push_tokens b
             WHERE a.user_id = b.user_id
               AND a.device_id = b.device_id
               AND (a.updated_at < b.updated_at
                    OR (a.updated_at = b.updated_at AND a.token < b.token))",
        )
        .execute(&self.pool)
        .await?;
        sqlx::query(
            "CREATE UNIQUE INDEX IF NOT EXISTS idx_push_tokens_user_device
             ON push_tokens(user_id, device_id)",
        )
        .execute(&self.pool)
        .await?;

        // Backups table — data stored as files on disk, not in Postgres
        sqlx::query(
            "CREATE TABLE IF NOT EXISTS backups (
                id TEXT PRIMARY KEY,
                household_id TEXT NOT NULL,
                description TEXT,
                size_bytes BIGINT NOT NULL,
                created_at BIGINT NOT NULL
            )",
        )
        .execute(&self.pool)
        .await?;

        // One-time dev cutover: wipe legacy base64 backup rows, but ONLY on the
        // boot where the old `data` column still exists. After the DROP below it
        // no-ops on every subsequent startup, so real file-backed backups
        // survive restarts. Destructive is fine pre-deploy (no testers yet).
        sqlx::query(
            "DELETE FROM backups WHERE EXISTS (
                SELECT 1 FROM information_schema.columns
                WHERE table_name = 'backups' AND column_name = 'data'
            )",
        )
        .execute(&self.pool)
        .await?;

        // Drop the legacy base64 data column if it still exists on a deployed DB
        sqlx::query("ALTER TABLE backups DROP COLUMN IF EXISTS data")
            .execute(&self.pool)
            .await?;

        sqlx::query(
            "CREATE INDEX IF NOT EXISTS idx_backups_household
             ON backups(household_id)",
        )
        .execute(&self.pool)
        .await?;

        // Feedback / bug reports table
        sqlx::query(
            "CREATE TABLE IF NOT EXISTS feedback (
                id TEXT PRIMARY KEY,
                household_id TEXT NOT NULL,
                member_id TEXT NOT NULL,
                category TEXT NOT NULL,
                message TEXT NOT NULL,
                severity TEXT,
                title TEXT,
                steps_to_reproduce TEXT,
                expected_behavior TEXT,
                device_info TEXT,
                status TEXT NOT NULL DEFAULT 'open',
                admin_notes TEXT,
                created_at BIGINT NOT NULL
            )",
        )
        .execute(&self.pool)
        .await?;

        sqlx::query(
            "CREATE INDEX IF NOT EXISTS idx_feedback_household
             ON feedback(household_id)",
        )
        .execute(&self.pool)
        .await?;

        // Subscription tables
        Self::init_subscription_tables(&self.pool).await?;

        // Enable Banking account-binding table (audit #9)
        Self::init_eb_tables(&self.pool).await?;

        // Newsletter subscribers (landing page signup)
        Self::init_newsletter_tables(&self.pool).await?;

        // Media files table
        sqlx::query(
            "CREATE TABLE IF NOT EXISTS media_files (
                id TEXT PRIMARY KEY,
                household_id TEXT NOT NULL,
                member_id TEXT NOT NULL,
                original_name TEXT,
                size_bytes BIGINT NOT NULL,
                checksum TEXT,
                created_at BIGINT NOT NULL
            )",
        )
        .execute(&self.pool)
        .await?;

        sqlx::query(
            "CREATE INDEX IF NOT EXISTS idx_media_files_household
             ON media_files(household_id)",
        )
        .execute(&self.pool)
        .await?;

        // Household storage quotas
        sqlx::query(
            "CREATE TABLE IF NOT EXISTS household_quotas (
                household_id TEXT PRIMARY KEY,
                used_bytes BIGINT NOT NULL DEFAULT 0,
                quota_bytes BIGINT NOT NULL
            )",
        )
        .execute(&self.pool)
        .await?;

        // Add backup quota columns (idempotent — safe on already-deployed DBs)
        for stmt in [
            "ALTER TABLE household_quotas ADD COLUMN IF NOT EXISTS \
             backup_used_bytes BIGINT NOT NULL DEFAULT 0",
            "ALTER TABLE household_quotas ADD COLUMN IF NOT EXISTS \
             backup_quota_bytes BIGINT NOT NULL DEFAULT 0",
        ] {
            sqlx::query(stmt).execute(&self.pool).await?;
        }

        // Invite-code → household binding (TOFU). The first JWT issued for an
        // invite code locks it to a household_id; subsequent token requests
        // with that code must match the bound household_id. This blocks a
        // cross-household impersonation: an attacker cannot mint a JWT for
        // household B using a code that legitimately belongs to household A.
        sqlx::query(
            "CREATE TABLE IF NOT EXISTS household_invites (
                invite_code TEXT PRIMARY KEY,
                household_id TEXT NOT NULL,
                created_at BIGINT NOT NULL
            )",
        )
        .execute(&self.pool)
        .await?;

        sqlx::query(
            "CREATE TABLE IF NOT EXISTS sealed_invites (
                code TEXT PRIMARY KEY,
                blob TEXT NOT NULL,
                expires_at BIGINT NOT NULL,
                created_at BIGINT NOT NULL,
                household_id TEXT NOT NULL DEFAULT '',
                downloads BIGINT NOT NULL DEFAULT 0
            )",
        )
        .execute(&self.pool)
        .await?;
        // Idempotent: add the new columns on already-deployed databases where
        // the original CREATE TABLE ran without them. PostgreSQL 9.6+ supports
        // ADD COLUMN IF NOT EXISTS.
        sqlx::query(
            "ALTER TABLE sealed_invites
               ADD COLUMN IF NOT EXISTS household_id TEXT NOT NULL DEFAULT ''",
        )
        .execute(&self.pool)
        .await?;
        sqlx::query(
            "ALTER TABLE sealed_invites
               ADD COLUMN IF NOT EXISTS downloads BIGINT NOT NULL DEFAULT 0",
        )
        .execute(&self.pool)
        .await?;

        // Global traffic totals. One row per day, deliberately no
        // household_id — see src/traffic.rs for why. Read it by hand; it does
        // not need an endpoint.
        sqlx::query(
            "CREATE TABLE IF NOT EXISTS traffic_daily (
                day DATE PRIMARY KEY,
                bytes_in BIGINT NOT NULL DEFAULT 0,
                bytes_out BIGINT NOT NULL DEFAULT 0,
                active_households BIGINT NOT NULL DEFAULT 0
            )",
        )
        .execute(&self.pool)
        .await?;

        debug!("Database tables initialized");
        Ok(())
    }

    /// Add a flush of traffic counters to today's row. Bytes accumulate;
    /// `active_households` is a running total for the day, so it overwrites.
    pub async fn record_traffic(
        &self,
        day: &str,
        bytes_in: i64,
        bytes_out: i64,
        active_households: i64,
    ) -> Result<(), sqlx::Error> {
        sqlx::query(
            "INSERT INTO traffic_daily (day, bytes_in, bytes_out, active_households)
             VALUES ($1::date, $2, $3, $4)
             ON CONFLICT (day) DO UPDATE SET
                 bytes_in = traffic_daily.bytes_in + EXCLUDED.bytes_in,
                 bytes_out = traffic_daily.bytes_out + EXCLUDED.bytes_out,
                 active_households = EXCLUDED.active_households",
        )
        .bind(day)
        .bind(bytes_in)
        .bind(bytes_out)
        .bind(active_households)
        .execute(&self.pool)
        .await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    // Tests require a running PostgreSQL instance.
    // Set TEST_DATABASE_URL environment variable to run these tests.
    // Example: TEST_DATABASE_URL=postgres://user:pass@localhost/honmoon_test

    use super::*;

    async fn test_db() -> Database {
        let url = std::env::var("TEST_DATABASE_URL")
            .unwrap_or_else(|_| "postgres://honmoon:honmoon@localhost/honmoon_test".to_string());
        let db = Database::new(&url).await.expect("Failed to connect to test database");

        // Clean all tables for test isolation
        sqlx::query("DELETE FROM message_deliveries").execute(&db.pool).await.unwrap();
        sqlx::query("DELETE FROM pending_messages").execute(&db.pool).await.unwrap();
        sqlx::query("DELETE FROM household_members").execute(&db.pool).await.unwrap();
        sqlx::query("DELETE FROM push_tokens").execute(&db.pool).await.unwrap();
        sqlx::query("DELETE FROM backups").execute(&db.pool).await.unwrap();
        sqlx::query("DELETE FROM feedback").execute(&db.pool).await.unwrap();
        sqlx::query("DELETE FROM trial_usage").execute(&db.pool).await.unwrap();
        sqlx::query("DELETE FROM subscriptions").execute(&db.pool).await.unwrap();
        sqlx::query("DELETE FROM media_files").execute(&db.pool).await.unwrap();
        sqlx::query("DELETE FROM household_quotas").execute(&db.pool).await.unwrap();
        sqlx::query("DELETE FROM household_invites").execute(&db.pool).await.unwrap();
        sqlx::query("DELETE FROM eb_account_bindings").execute(&db.pool).await.unwrap();

        db
    }

    // Audit 2026-07-07 #2: the invite-mint gate must be first-writer-wins on
    // BOTH the code and the household, so knowing only a household_id can no
    // longer mint a JWT for it.
    #[tokio::test]
    #[ignore] // Requires a running PostgreSQL instance
    async fn test_invite_mint_first_writer_wins() {
        let db = test_db().await;
        let h = "hh-founder";
        let c = "ABC123";
        let x = "XYZ789";
        let h2 = "hh-other";

        // 1. Founder's first-ever mint binds the code.
        assert_eq!(db.bind_or_check_invite(c, h).await.unwrap(), Ok(()));
        // 2. Reconnect with the same code still passes.
        assert_eq!(db.bind_or_check_invite(c, h).await.unwrap(), Ok(()));
        // 3. THE EXPLOIT: knowing only the household_id, a fresh code is rejected.
        assert_eq!(
            db.bind_or_check_invite(x, h).await.unwrap(),
            Err(c.to_string())
        );
        // 4. A code already bound to a different household can't be reused.
        assert_eq!(
            db.bind_or_check_invite(c, h2).await.unwrap(),
            Err(h.to_string())
        );
        // 5. Heal: a rogue, later-bound code for h is inert — the founder's
        //    original (earliest) code still wins.
        let later = chrono::Utc::now().timestamp() + 1000;
        sqlx::query(
            "INSERT INTO household_invites (invite_code, household_id, created_at)
             VALUES ($1, $2, $3)",
        )
        .bind(x)
        .bind(h)
        .bind(later)
        .execute(&db.pool)
        .await
        .unwrap();
        assert_eq!(db.bind_or_check_invite(c, h).await.unwrap(), Ok(()));
        assert_eq!(
            db.bind_or_check_invite(x, h).await.unwrap(),
            Err(c.to_string())
        );
    }

    // Audit 2026-07-07 #9: EB account/session ownership binding. The handler
    // fails open on unbound (pre-fix links) and 403s only when the id is bound
    // to a DIFFERENT household — that decision is exercised via these lookups.
    #[tokio::test]
    #[ignore] // Requires a running PostgreSQL instance
    async fn test_eb_binding_ownership() {
        let db = test_db().await;
        let ha = "hh-a";
        let hb = "hh-b";
        let sess = "sess-1";
        let uid = "acct-uid-1";

        // Unbound → None → handler proceeds (fail-open on pre-fix links).
        assert_eq!(db.eb_household_for_account(uid).await.unwrap(), None);

        // create_session binds the account + session to household A.
        db.bind_eb_accounts(ha, sess, &[uid.to_string()])
            .await
            .unwrap();
        assert_eq!(
            db.eb_household_for_account(uid).await.unwrap(),
            Some(ha.to_string())
        );
        assert_eq!(
            db.eb_household_for_session(sess).await.unwrap(),
            Some(ha.to_string())
        );

        // THE EXPLOIT: household B looks up A's uid → owner is A ≠ B → 403.
        let owner = db.eb_household_for_account(uid).await.unwrap();
        assert_ne!(owner.as_deref(), Some(hb));
        assert_eq!(owner, Some(ha.to_string()));

        // Legit re-link by A with a new session updates the row in place.
        db.bind_eb_accounts(ha, "sess-2", &[uid.to_string()])
            .await
            .unwrap();
        assert_eq!(
            db.eb_household_for_session("sess-2").await.unwrap(),
            Some(ha.to_string())
        );
        assert_eq!(
            db.eb_household_for_account(uid).await.unwrap(),
            Some(ha.to_string())
        );
    }

    #[tokio::test]
    #[ignore] // Requires a running PostgreSQL instance
    async fn test_message_persistence_flow() {
        let db = test_db().await;

        let household_id = "test-household";
        let member1 = "member-1";
        let member2 = "member-2";
        let member3 = "member-3";
        let device1 = "device-1";

        // Register household members
        db.upsert_household_member(household_id, member1).await.unwrap();
        db.upsert_household_member(household_id, member2).await.unwrap();
        db.upsert_household_member(household_id, member3).await.unwrap();

        // Store a message from member1
        let (msg_id, _fresh) = db.store_pending_message(
            household_id,
            device1,
            member1,
            "corr-1",
            "test-payload",
            Some("task"),
            Some("create"),
            Some("Created a new task"),
            None,
        ).await.unwrap();

        // Check pending messages for member2
        let pending = db.get_pending_messages_for_member(household_id, member2).await.unwrap();
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].id, msg_id);

        // Check pending messages for member3
        let pending = db.get_pending_messages_for_member(household_id, member3).await.unwrap();
        assert_eq!(pending.len(), 1);

        // Member1 (sender) should have no pending messages
        let pending = db.get_pending_messages_for_member(household_id, member1).await.unwrap();
        assert_eq!(pending.len(), 0);

        // Mark as delivered to member2
        db.mark_delivered(&msg_id, member2).await.unwrap();

        // Message should still exist (member3 hasn't received it)
        let pending = db.get_pending_messages_for_member(household_id, member2).await.unwrap();
        assert_eq!(pending.len(), 0);
        let pending = db.get_pending_messages_for_member(household_id, member3).await.unwrap();
        assert_eq!(pending.len(), 1);

        // Mark as delivered to member3
        db.mark_delivered(&msg_id, member3).await.unwrap();

        // Message should be cleaned up
        let pending = db.get_pending_messages_for_member(household_id, member3).await.unwrap();
        assert_eq!(pending.len(), 0);
    }

    #[tokio::test]
    #[ignore] // Requires a running PostgreSQL instance
    async fn test_sync_status() {
        let db = test_db().await;

        let household_id = "test-household";
        let member1 = "member-1";
        let member2 = "member-2";
        let device1 = "device-1";

        // Register members
        db.upsert_household_member(household_id, member1).await.unwrap();
        db.upsert_household_member(household_id, member2).await.unwrap();

        // Store messages from member1
        db.store_pending_message(household_id, device1, member1, "corr-a", "test1", None, None, None, None).await.unwrap();
        db.store_pending_message(household_id, device1, member1, "corr-b", "test2", None, None, None, None).await.unwrap();

        // Check sync status for member1
        let status = db.get_sync_status_for_member(household_id, member1).await.unwrap();
        assert_eq!(status.pending_messages, 2);
        assert_eq!(status.pending_deliveries, 2);
    }
}
