use std::env;

use tracing::{info, warn};

use crate::license;
use crate::secrets;

#[derive(Clone)]
pub struct Config {
    pub bind_addr: String,
    pub jwt_secret: String,
    pub jwt_expiry_hours: u64,
    pub turn_secret: String,
    pub turn_server: String,
    pub feedback_admin_token: String,
    pub is_development: bool,
    // Media settings
    pub media_dir: String,
    pub media_quota_mb: u64,
    pub media_retention_days: u64,
    /// Retention for user-uploaded backups, in days. Backups are a recovery
    /// safety net, so this is intentionally decoupled from `media_retention_days`
    /// (media is transient, backups are not). `0` disables backup expiry entirely.
    pub backup_retention_days: u64,
    pub backup_dir: String,
    pub backup_quota_mb: u64,
    pub max_upload_size_mb: u64,
    // Enable Banking (optional — endpoints return 503 if not configured)
    pub eb_app_id: Option<String>,
    pub eb_pem_key: Option<String>,
    // Stripe billing
    pub stripe_secret_key: String,
    pub stripe_webhook_secret: String,
    pub stripe_price_id: String,
    // Subscription settings
    pub trial_days: i64,
    pub grace_days: i64,
    pub max_household_members: i64,
    pub self_hosted: bool,
    pub has_valid_license: bool,
    /// UnifiedPush relay base URL (e.g. `http://ntfy:80`). `None` means push
    /// fan-out via UnifiedPush is disabled on this server — self-hosters who
    /// don't run ntfy alongside the relay will see this. The push delivery
    /// hook short-circuits when `None`.
    pub ntfy_url: Option<String>,
}

impl Config {
    pub fn from_env() -> Self {
        // Only an explicit truthy value enables dev mode. `is_ok()` treated
        // HONMOON_DEV=0 / =false as dev-enabled, silently swapping in insecure
        // default secrets + permissive CORS (audit 2026-07-07).
        let is_development = matches!(env::var("HONMOON_DEV").as_deref(), Ok("1") | Ok("true"));

        // Check server license
        let has_valid_license = if is_development {
            true // Dev mode allows billing without license
        } else {
            env::var("SERVER_LICENSE")
                .ok()
                .map(|l| license::verify_license(&l))
                .unwrap_or(false)
        };

        let explicitly_self_hosted = env::var("SELF_HOSTED").is_ok();
        let self_hosted = if explicitly_self_hosted {
            true
        } else if !has_valid_license {
            warn!("No valid SERVER_LICENSE — forcing self-hosted mode (billing disabled)");
            true
        } else {
            false
        };

        // Self-hosters get their secrets generated on first boot instead of
        // being sent to `openssl rand` — or, worse, to HONMOON_DEV=1 and its
        // publicly known signing key. Runs before any secret is read.
        if self_hosted && !is_development {
            secrets::bootstrap(&secrets::default_path());
        }

        let jwt_secret = env::var("JWT_SECRET").unwrap_or_else(|_| {
            if is_development {
                warn!("JWT_SECRET not set — using insecure dev default");
                "development-secret-change-in-production".to_string()
            } else {
                panic!("JWT_SECRET environment variable is required in production. Set HONMOON_DEV=1 for development mode.");
            }
        });

        let turn_secret = env::var("TURN_SECRET").unwrap_or_else(|_| {
            if is_development {
                warn!("TURN_SECRET not set — using insecure dev default");
                "development-turn-secret".to_string()
            } else {
                panic!("TURN_SECRET environment variable is required in production. Set HONMOON_DEV=1 for development mode.");
            }
        });

        let feedback_admin_token = env::var("FEEDBACK_ADMIN_TOKEN").unwrap_or_else(|_| {
            if is_development {
                warn!("FEEDBACK_ADMIN_TOKEN not set — using insecure dev default");
                "dev-feedback-token".to_string()
            } else {
                panic!("FEEDBACK_ADMIN_TOKEN environment variable is required in production. Set HONMOON_DEV=1 for development mode.");
            }
        });

        Self {
            bind_addr: env::var("BIND_ADDR").unwrap_or_else(|_| "0.0.0.0:8080".to_string()),
            jwt_secret,
            jwt_expiry_hours: env::var("JWT_EXPIRY_HOURS")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(24),
            turn_secret,
            turn_server: env::var("TURN_SERVER")
                .unwrap_or_else(|_| "localhost".to_string()),
            feedback_admin_token,
            is_development,
            media_dir: env::var("MEDIA_DIR")
                .unwrap_or_else(|_| "/app/data/media".to_string()),
            media_quota_mb: env::var("MEDIA_QUOTA_MB")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(500),
            media_retention_days: env::var("MEDIA_RETENTION_DAYS")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(30),
            backup_retention_days: env::var("BACKUP_RETENTION_DAYS")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(365),
            backup_dir: env::var("BACKUP_DIR")
                .unwrap_or_else(|_| "/app/data/backups".to_string()),
            backup_quota_mb: env::var("BACKUP_QUOTA_MB")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(1024),
            max_upload_size_mb: env::var("MAX_UPLOAD_SIZE_MB")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(50),
            has_valid_license,
            self_hosted,
            stripe_secret_key: env::var("STRIPE_SECRET_KEY").unwrap_or_else(|_| {
                if is_development {
                    warn!("STRIPE_SECRET_KEY not set — billing endpoints will fail");
                    String::new()
                } else {
                    warn!("STRIPE_SECRET_KEY not set — billing endpoints will fail");
                    String::new()
                }
            }),
            stripe_webhook_secret: env::var("STRIPE_WEBHOOK_SECRET").unwrap_or_else(|_| {
                if is_development {
                    warn!("STRIPE_WEBHOOK_SECRET not set");
                    "whsec_dev_secret".to_string()
                } else if self_hosted {
                    // Self-hosted mode has billing disabled, so demanding a
                    // Stripe webhook secret only meant the server refused to
                    // boot for everyone who followed the self-host guide.
                    String::new()
                } else {
                    panic!("STRIPE_WEBHOOK_SECRET environment variable is required in production. Set HONMOON_DEV=1 for development mode.");
                }
            }),
            stripe_price_id: env::var("STRIPE_PRICE_ID").unwrap_or_else(|_| {
                warn!("STRIPE_PRICE_ID not set — checkout will fail");
                String::new()
            }),
            trial_days: env::var("TRIAL_DAYS")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(14),
            grace_days: env::var("GRACE_DAYS")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(3),
            max_household_members: env::var("MAX_HOUSEHOLD_MEMBERS")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(8),
            ntfy_url: env::var("NTFY_URL").ok().and_then(|v| {
                let trimmed = v.trim();
                if trimmed.is_empty() || trimmed.eq_ignore_ascii_case("disabled") {
                    None
                } else {
                    Some(trimmed.to_string())
                }
            }),
            eb_app_id: env::var("EB_APP_ID").ok(),
            eb_pem_key: env::var("EB_PEM_KEY")
                .ok()
                .or_else(|| {
                    env::var("EB_PEM_KEY_FILE").ok().and_then(|path| {
                        match std::fs::read_to_string(&path) {
                            Ok(key) => {
                                info!("Loaded Enable Banking PEM key from {}", path);
                                Some(key)
                            }
                            Err(e) => {
                                warn!("Failed to read EB_PEM_KEY_FILE {}: {}", path, e);
                                None
                            }
                        }
                    })
                }),
        }
    }

    /// Media quota in bytes
    pub fn media_quota_bytes(&self) -> i64 {
        (self.media_quota_mb as i64) * 1024 * 1024
    }

    /// Backup quota in bytes
    pub fn backup_quota_bytes(&self) -> i64 {
        (self.backup_quota_mb as i64) * 1024 * 1024
    }

    /// Max upload size in bytes
    pub fn max_upload_bytes(&self) -> usize {
        (self.max_upload_size_mb as usize) * 1024 * 1024
    }

    /// Media retention in hours
    pub fn media_retention_hours(&self) -> i64 {
        (self.media_retention_days as i64) * 24
    }

    /// Backup retention in hours, or `None` when expiry is disabled
    /// (`BACKUP_RETENTION_DAYS=0`).
    pub fn backup_retention_hours(&self) -> Option<i64> {
        if self.backup_retention_days == 0 {
            None
        } else {
            Some((self.backup_retention_days as i64) * 24)
        }
    }
}
