use sqlx::PgPool;
use sqlx::Row;
use tracing::{info, debug};

use crate::subscription::{SubscriptionInfo, SubscriptionStatus, TrialResult};

use super::{Database, SECONDS_PER_DAY};

impl Database {
    // ========== Subscription Database Operations ==========

    /// Initialize subscription-related tables
    pub(super) async fn init_subscription_tables(pool: &PgPool) -> Result<(), sqlx::Error> {
        sqlx::query(
            "CREATE TABLE IF NOT EXISTS subscriptions (
                household_id TEXT PRIMARY KEY,
                stripe_customer_id TEXT,
                stripe_subscription_id TEXT,
                email TEXT,
                status TEXT NOT NULL DEFAULT 'trialing',
                trial_start BIGINT,
                trial_end BIGINT,
                grace_end BIGINT,
                created_at BIGINT NOT NULL,
                updated_at BIGINT NOT NULL
            )",
        )
        .execute(pool)
        .await?;

        sqlx::query(
            "CREATE TABLE IF NOT EXISTS trial_usage (
                id BIGSERIAL PRIMARY KEY,
                device_id TEXT NOT NULL,
                email TEXT,
                household_id TEXT NOT NULL,
                used_at BIGINT NOT NULL
            )",
        )
        .execute(pool)
        .await?;

        // Use CREATE UNIQUE INDEX IF NOT EXISTS for idempotency
        sqlx::query(
            "CREATE UNIQUE INDEX IF NOT EXISTS idx_trial_device ON trial_usage(device_id)",
        )
        .execute(pool)
        .await?;

        sqlx::query("CREATE INDEX IF NOT EXISTS idx_trial_email ON trial_usage(email)")
            .execute(pool)
            .await?;

        sqlx::query(
            "CREATE INDEX IF NOT EXISTS idx_subscriptions_email ON subscriptions(email)",
        )
        .execute(pool)
        .await?;

        Ok(())
    }

    /// Get the subscription status for a household
    pub async fn get_subscription_status(
        &self,
        household_id: &str,
    ) -> Result<SubscriptionInfo, sqlx::Error> {
        let row = sqlx::query(
            "SELECT status, trial_end, grace_end FROM subscriptions WHERE household_id = $1",
        )
        .bind(household_id)
        .fetch_optional(&self.pool)
        .await?;

        let row = match row {
            Some(r) => r,
            None => {
                return Ok(SubscriptionInfo {
                    status: SubscriptionStatus::None,
                    trial_days_remaining: None,
                    grace_days_remaining: None,
                });
            }
        };

        let status_str: String = row.get("status");
        let trial_end: Option<i64> = row.get("trial_end");
        let grace_end: Option<i64> = row.get("grace_end");
        let now = chrono::Utc::now().timestamp();

        let info = match status_str.as_str() {
            "trialing" => {
                if let Some(end) = trial_end {
                    if end > now {
                        let days_remaining = (end - now) / SECONDS_PER_DAY;
                        SubscriptionInfo {
                            status: SubscriptionStatus::Trialing,
                            trial_days_remaining: Some(days_remaining),
                            grace_days_remaining: None,
                        }
                    } else {
                        SubscriptionInfo {
                            status: SubscriptionStatus::Expired,
                            trial_days_remaining: Some(0),
                            grace_days_remaining: None,
                        }
                    }
                } else {
                    SubscriptionInfo {
                        status: SubscriptionStatus::Expired,
                        trial_days_remaining: None,
                        grace_days_remaining: None,
                    }
                }
            }
            "active" => SubscriptionInfo {
                status: SubscriptionStatus::Active,
                trial_days_remaining: None,
                grace_days_remaining: None,
            },
            "past_due" => SubscriptionInfo {
                status: SubscriptionStatus::PastDue,
                trial_days_remaining: None,
                grace_days_remaining: None,
            },
            "canceled" => {
                if let Some(end) = grace_end {
                    if end > now {
                        let days_remaining = (end - now) / SECONDS_PER_DAY;
                        SubscriptionInfo {
                            status: SubscriptionStatus::GracePeriod,
                            trial_days_remaining: None,
                            grace_days_remaining: Some(days_remaining),
                        }
                    } else {
                        SubscriptionInfo {
                            status: SubscriptionStatus::Expired,
                            trial_days_remaining: None,
                            grace_days_remaining: Some(0),
                        }
                    }
                } else {
                    SubscriptionInfo {
                        status: SubscriptionStatus::Expired,
                        trial_days_remaining: None,
                        grace_days_remaining: None,
                    }
                }
            }
            _ => SubscriptionInfo {
                status: SubscriptionStatus::Expired,
                trial_days_remaining: None,
                grace_days_remaining: None,
            },
        };

        Ok(info)
    }

    /// Start a trial for a household, checking device and email uniqueness
    pub async fn start_trial(
        &self,
        household_id: &str,
        device_id: &str,
        email: &str,
        trial_days: i64,
    ) -> Result<TrialResult, sqlx::Error> {
        let now = chrono::Utc::now().timestamp();

        // Check if household already has an active subscription
        let existing = sqlx::query(
            "SELECT status FROM subscriptions WHERE household_id = $1",
        )
        .bind(household_id)
        .fetch_optional(&self.pool)
        .await?;

        if let Some(row) = existing {
            let status: String = row.get("status");
            if status == "active" || status == "trialing" {
                return Ok(TrialResult::AlreadyActive);
            }
        }

        // Check if device already used a trial
        let row = sqlx::query("SELECT COUNT(*) as cnt FROM trial_usage WHERE device_id = $1")
            .bind(device_id)
            .fetch_one(&self.pool)
            .await?;
        let device_used: i64 = row.get("cnt");

        if device_used > 0 {
            return Ok(TrialResult::AlreadyUsedByDevice);
        }

        // Check if email already used a trial
        let row = sqlx::query("SELECT COUNT(*) as cnt FROM trial_usage WHERE email = $1")
            .bind(email)
            .fetch_one(&self.pool)
            .await?;
        let email_used: i64 = row.get("cnt");

        if email_used > 0 {
            return Ok(TrialResult::AlreadyUsedByEmail);
        }

        // Record trial usage
        let trial_end = now + (trial_days * SECONDS_PER_DAY);

        sqlx::query(
            "INSERT INTO trial_usage (device_id, email, household_id, used_at)
             VALUES ($1, $2, $3, $4)",
        )
        .bind(device_id)
        .bind(email)
        .bind(household_id)
        .bind(now)
        .execute(&self.pool)
        .await?;

        // Create or update subscription
        sqlx::query(
            "INSERT INTO subscriptions (household_id, email, status, trial_start, trial_end, created_at, updated_at)
             VALUES ($1, $2, 'trialing', $3, $4, $3, $3)
             ON CONFLICT(household_id) DO UPDATE SET
                email = $2, status = 'trialing', trial_start = $3, trial_end = $4, updated_at = $3",
        )
        .bind(household_id)
        .bind(email)
        .bind(now)
        .bind(trial_end)
        .execute(&self.pool)
        .await?;

        info!(
            "Started trial for household {} (device: {}, email: {})",
            household_id, device_id, email
        );
        Ok(TrialResult::Started { trial_end })
    }

    /// Upsert a subscription from Stripe webhook data
    pub async fn set_subscription_from_stripe(
        &self,
        household_id: &str,
        stripe_customer_id: &str,
        stripe_subscription_id: &str,
        email: &str,
        status: &str,
    ) -> Result<(), sqlx::Error> {
        let now = chrono::Utc::now().timestamp();

        sqlx::query(
            "INSERT INTO subscriptions (household_id, stripe_customer_id, stripe_subscription_id, email, status, created_at, updated_at)
             VALUES ($1, $2, $3, $4, $5, $6, $6)
             ON CONFLICT(household_id) DO UPDATE SET
                stripe_customer_id = $2, stripe_subscription_id = $3, email = $4, status = $5, updated_at = $6",
        )
        .bind(household_id)
        .bind(stripe_customer_id)
        .bind(stripe_subscription_id)
        .bind(email)
        .bind(status)
        .bind(now)
        .execute(&self.pool)
        .await?;

        info!(
            "Set Stripe subscription for household {} (customer: {}, status: {})",
            household_id, stripe_customer_id, status
        );
        Ok(())
    }

    /// Set a grace period for a canceled subscription
    pub async fn set_grace_period(
        &self,
        household_id: &str,
        grace_days: i64,
    ) -> Result<(), sqlx::Error> {
        let now = chrono::Utc::now().timestamp();
        let grace_end = now + (grace_days * SECONDS_PER_DAY);

        sqlx::query(
            "UPDATE subscriptions SET grace_end = $1, updated_at = $2 WHERE household_id = $3",
        )
        .bind(grace_end)
        .bind(now)
        .bind(household_id)
        .execute(&self.pool)
        .await?;

        debug!(
            "Set grace period for household {} ({} days, ends at {})",
            household_id, grace_days, grace_end
        );
        Ok(())
    }

    /// Get the number of members in a household
    pub async fn get_member_count(&self, household_id: &str) -> Result<i64, sqlx::Error> {
        let row = sqlx::query(
            "SELECT COUNT(*) as cnt FROM household_members WHERE household_id = $1",
        )
        .bind(household_id)
        .fetch_one(&self.pool)
        .await?;

        Ok(row.get("cnt"))
    }

    /// Get the Stripe customer ID for a household
    pub async fn get_stripe_customer_id(
        &self,
        household_id: &str,
    ) -> Result<Option<String>, sqlx::Error> {
        let row = sqlx::query(
            "SELECT stripe_customer_id FROM subscriptions WHERE household_id = $1",
        )
        .bind(household_id)
        .fetch_optional(&self.pool)
        .await?;

        // stripe_customer_id is itself nullable
        Ok(row.and_then(|r| r.get("stripe_customer_id")))
    }

    /// Update subscription status by Stripe customer ID
    pub async fn update_subscription_status_by_customer(
        &self,
        stripe_customer_id: &str,
        status: &str,
    ) -> Result<(), sqlx::Error> {
        let now = chrono::Utc::now().timestamp();

        sqlx::query(
            "UPDATE subscriptions SET status = $1, updated_at = $2 WHERE stripe_customer_id = $3",
        )
        .bind(status)
        .bind(now)
        .bind(stripe_customer_id)
        .execute(&self.pool)
        .await?;

        debug!(
            "Updated subscription status by customer {} to {}",
            stripe_customer_id, status
        );
        Ok(())
    }

    /// Set grace period by Stripe customer ID
    pub async fn set_grace_period_by_customer(
        &self,
        stripe_customer_id: &str,
        grace_days: i64,
    ) -> Result<(), sqlx::Error> {
        let now = chrono::Utc::now().timestamp();
        let grace_end = now + (grace_days * SECONDS_PER_DAY);

        sqlx::query(
            "UPDATE subscriptions SET grace_end = $1, updated_at = $2 WHERE stripe_customer_id = $3",
        )
        .bind(grace_end)
        .bind(now)
        .bind(stripe_customer_id)
        .execute(&self.pool)
        .await?;

        debug!(
            "Set grace period by customer {} ({} days)",
            stripe_customer_id, grace_days
        );
        Ok(())
    }
}
