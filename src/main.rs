use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use axum::{
    extract::DefaultBodyLimit,
    routing::get,
    Router,
};
use tokio::sync::{broadcast, RwLock};
use tower_governor::{governor::GovernorConfigBuilder, GovernorLayer};
use tower_governor::key_extractor::SmartIpKeyExtractor;
use tower_http::cors::CorsLayer;
use tower_http::trace::TraceLayer;
use tracing::{error, info};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

mod auth;
mod config;
mod db;
mod enable_banking;
mod license;
mod mailer;
mod push;
mod push_dispatch;
mod routes;
mod secrets;
mod subscription;
mod traffic;
mod unified_push;
mod web_push;
mod websocket;

use config::Config;
use db::Database;
use push::FcmSender;
use push_dispatch::PushCoalescer;
use traffic::TrafficCounter;

/// Per-household broadcast channel for sync messages
type HouseholdChannels = Arc<RwLock<HashMap<String, broadcast::Sender<(String, String)>>>>;

/// Connected devices per household: household_id -> (device_id -> member_id)
// device_id -> (member_id, conn_id). conn_id tags each socket so a slow
// disconnect can't evict a faster reconnect's live slot (audit #10).
type ConnectedDevices = Arc<RwLock<HashMap<String, HashMap<String, (String, String)>>>>;

#[derive(Clone)]
pub struct AppState {
    pub config: Config,
    pub channels: HouseholdChannels,
    pub connected: ConnectedDevices,
    pub db: Arc<Database>,
    pub fcm: Arc<FcmSender>,
    pub http_client: reqwest::Client,
    /// Outgoing mail. Disabled (sends become log lines) when SMTP_HOST is
    /// unset, so a server without a mail relay still boots and serves.
    pub mailer: Arc<mailer::Mailer>,
    /// In-memory per-device coalescer for push fan-out. Lives for the
    /// process lifetime so rapid-fire chats from the same conversation
    /// don't spam recipients' tray notifications.
    /// See `docs/spec/18-push-delivery.md` § Delivery hook.
    pub push_coalescer: PushCoalescer,
    /// Global byte counters, flushed to `traffic_daily` hourly. Feeds the
    /// v2 tunnel decision — see src/traffic.rs.
    pub traffic: Arc<TrafficCounter>,
}

#[tokio::main]
async fn main() {
    // Initialize tracing
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "honmoon_server=debug,tower_http=debug".into()),
        )
        .with(tracing_subscriber::fmt::layer())
        .init();

    // Load config
    dotenvy::dotenv().ok();
    let config = Config::from_env();

    info!("Starting Honmoon Sync Server on {}", config.bind_addr);

    // Initialize database
    let database_url = std::env::var("DATABASE_URL").unwrap_or_else(|_| {
        // Build from individual components, URL-encoding the password
        let user = std::env::var("POSTGRES_USER").unwrap_or_else(|_| "honmoon".to_string());
        let pass = std::env::var("POSTGRES_PASSWORD").unwrap_or_else(|_| "honmoon".to_string());
        let host = std::env::var("POSTGRES_HOST").unwrap_or_else(|_| "localhost".to_string());
        let port = std::env::var("POSTGRES_PORT").unwrap_or_else(|_| "5432".to_string());
        let db = std::env::var("POSTGRES_DB").unwrap_or_else(|_| "honmoon".to_string());
        let encoded_pass = urlencoding::encode(&pass);
        format!("postgres://{}:{}@{}:{}/{}", user, encoded_pass, host, port, db)
    });
    let db = Arc::new(Database::new(&database_url).await.expect("Failed to initialize database"));

    let fcm = Arc::new(FcmSender::new(db.clone()));

    let state = AppState {
        config: config.clone(),
        channels: Arc::new(RwLock::new(HashMap::new())),
        connected: Arc::new(RwLock::new(HashMap::new())),
        db: db.clone(),
        fcm,
        mailer: Arc::new(mailer::Mailer::from_env()),
        http_client: reqwest::Client::new(),
        push_coalescer: PushCoalescer::default(),
        traffic: Arc::new(TrafficCounter::default()),
    };

    // Spawn task to cleanup old pending messages (older than 7 days)
    let cleanup_db = db.clone();
    let cleanup_traffic = state.traffic.clone();
    let media_dir = config.media_dir.clone();
    let backup_dir_clone = config.backup_dir.clone();
    let media_retention_hours = config.media_retention_hours();
    let backup_retention_hours = config.backup_retention_hours();
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(tokio::time::Duration::from_secs(3600)).await; // Every hour
            // ponytail: 30-day retention (was 7). Fully-delivered messages are
            // already pruned eagerly on the final ack, so this purge only ever
            // hits UNDELIVERED ones — deleting them loses data for a member
            // who's merely offline, not gone (audit #6). 30d covers realistic
            // offline; the proper fix for >30d is a needs-full-resync flag set
            // on prune so the member recovers on return.
            if let Err(e) = cleanup_db.cleanup_old_messages(720).await { // 30 days
                error!("Failed to cleanup old messages: {}", e);
            }
            // Cleanup old media files
            match cleanup_db.cleanup_old_media(media_retention_hours).await {
                Ok(files) => {
                    for (media_id, household_id, _) in &files {
                        let path = format!("{}/{}/{}", media_dir, household_id, media_id);
                        if let Err(e) = tokio::fs::remove_file(&path).await {
                            error!("Failed to delete expired media file {}: {}", path, e);
                        }
                    }
                }
                Err(e) => error!("Failed to cleanup old media: {}", e),
            }
            // Cleanup old backups. Backups are a recovery safety net, so they
            // have their own (much longer) retention, and expiry can be disabled
            // entirely with BACKUP_RETENTION_DAYS=0.
            if let Some(backup_hours) = backup_retention_hours {
                match cleanup_db.cleanup_old_backups(backup_hours).await {
                    Ok(expired) => {
                        for (backup_id, household_id, _) in &expired {
                            let path = format!(
                                "{}/{}/{}",
                                backup_dir_clone, household_id, backup_id
                            );
                            if let Err(e) = tokio::fs::remove_file(&path).await {
                                error!(
                                    "Failed to delete expired backup file {}: {}",
                                    path, e
                                );
                            }
                        }
                    }
                    Err(e) => error!("Failed to cleanup old backups: {}", e),
                }
            }
            if let Err(e) = cleanup_db.cleanup_expired_invites().await {
                error!("Failed to cleanup expired sealed invites: {}", e);
            }

            // Traffic flush rides along on this loop rather than getting a
            // timer of its own. The counters are in memory, so a crash loses
            // up to an hour of them — fine for a monthly average, and the
            // alternative is a database write per relayed message.
            let today = chrono::Utc::now().format("%Y-%m-%d").to_string();
            let (bytes_in, bytes_out, households) = cleanup_traffic.take(&today);
            if bytes_in > 0 || bytes_out > 0 {
                if let Err(e) = cleanup_db
                    .record_traffic(&today, bytes_in, bytes_out, households)
                    .await
                {
                    error!("Failed to record traffic totals: {}", e);
                }
            }
        }
    });

    // CORS: very_permissive in dev (convenience), permissive in production
    let cors_layer = if config.is_development {
        CorsLayer::very_permissive()
    } else {
        CorsLayer::permissive()
    };

    // Media upload body limit
    let media_upload_limit = config.max_upload_bytes();

    // ── Rate limiting configs (per IP via X-Forwarded-For) ──────────
    // Tier 1: Auth endpoints — strict (5 req/min = 1 req per 12s, burst 5)
    let auth_governor = Arc::new(
        GovernorConfigBuilder::default()
            .key_extractor(SmartIpKeyExtractor)
            .per_second(12)
            .burst_size(5)
            .finish()
            .unwrap(),
    );

    // Tier 2: General API — moderate (60 req/min = 1 req/s, burst 60)
    let api_governor = Arc::new(
        GovernorConfigBuilder::default()
            .key_extractor(SmartIpKeyExtractor)
            .per_second(1)
            .burst_size(60)
            .finish()
            .unwrap(),
    );

    // Tier 3: WebSocket connections — tight (3 conn/min = 1 per 20s, burst 3)
    let ws_governor = Arc::new(
        GovernorConfigBuilder::default()
            .key_extractor(SmartIpKeyExtractor)
            .per_second(20)
            .burst_size(3)
            .finish()
            .unwrap(),
    );

    // Tier 4: Unauthenticated sealed-invite fetch — very strict.
    // GET /api/v1/invite/:code is public and serves encrypted sealed-invite
    // blobs keyed by 6-char invite code. Tight per-IP rate limiting makes
    // online brute-force enumeration impractical despite short TTL.
    // 1 req every 5s, burst 3 → ~720 attempts/hour per IP at peak.
    let lookup_governor = Arc::new(
        GovernorConfigBuilder::default()
            .key_extractor(SmartIpKeyExtractor)
            .per_second(5)
            .burst_size(3)
            .finish()
            .unwrap(),
    );

    // Tier 5: Newsletter signup — a public write endpoint, so keep it slow.
    // 1 req every 30s, burst 3 per IP: plenty for a human filling in a form,
    // useless for stuffing the table with throwaway addresses.
    let newsletter_governor = Arc::new(
        GovernorConfigBuilder::default()
            .key_extractor(SmartIpKeyExtractor)
            .per_second(30)
            .burst_size(3)
            .finish()
            .unwrap(),
    );

    // Spawn background task to periodically clean up rate limiter storage
    let auth_limiter = auth_governor.limiter().clone();
    let api_limiter = api_governor.limiter().clone();
    let ws_limiter = ws_governor.limiter().clone();
    let lookup_limiter = lookup_governor.limiter().clone();
    let newsletter_limiter = newsletter_governor.limiter().clone();
    tokio::spawn(async move {
        let interval = Duration::from_secs(60);
        loop {
            tokio::time::sleep(interval).await;
            auth_limiter.retain_recent();
            api_limiter.retain_recent();
            ws_limiter.retain_recent();
            lookup_limiter.retain_recent();
            newsletter_limiter.retain_recent();
        }
    });

    // ── Health route (no rate limit) ────────────────────────────────
    let health_routes = Router::new()
        .route("/health", get(routes::health::health_check));

    // ── Auth routes (Tier 1: strict rate limit) ─────────────────────
    let auth_routes = Router::new()
        .route("/api/v1/auth/token", axum::routing::post(routes::auth::get_token))
        .layer(GovernorLayer {
            config: auth_governor,
        });

    // ── WebSocket routes (Tier 3: connection rate limit) ────────────
    let ws_routes = Router::new()
        .route("/ws", get(websocket::handler::websocket_handler))
        .layer(GovernorLayer {
            config: ws_governor,
        });

    // ── General API routes (Tier 2: moderate rate limit) ────────────
    let api_routes = Router::new()
        .route("/api/v1/ice-servers", axum::routing::post(routes::ice::get_ice_servers))
        .route("/api/v1/push/register", axum::routing::post(routes::push::register_token))
        .route("/api/v1/push/unregister", axum::routing::post(routes::push::unregister_token))
        .route("/api/v1/push/vapid-key", get(routes::push::get_vapid_key))
        .route("/api/v1/push/health", get(routes::push::get_push_health))
        // Enable Banking OAuth callback (redirects to honmoon:// deep link)
        .route("/api/v1/oauth/eb-callback", get(routes::oauth::eb_callback))
        // Enable Banking proxy endpoints (JWT auth required)
        .route("/api/v1/eb/banks", get(routes::enable_banking::get_banks))
        .route("/api/v1/eb/auth", axum::routing::post(routes::enable_banking::start_auth))
        .route("/api/v1/eb/sessions", axum::routing::post(routes::enable_banking::create_session))
        .route("/api/v1/eb/sessions/:id", get(routes::enable_banking::get_session)
            .delete(routes::enable_banking::delete_session))
        .route("/api/v1/eb/accounts/:uid/balances", get(routes::enable_banking::get_balances))
        .route("/api/v1/eb/accounts/:uid/transactions", get(routes::enable_banking::get_transactions))
        // Feedback endpoints
        .route("/api/v1/feedback/submit", axum::routing::post(routes::feedback::submit_feedback))
        .route("/api/v1/feedback/list", get(routes::feedback::list_feedback))
        .route("/api/v1/feedback/update/:id", axum::routing::post(routes::feedback::update_feedback))
        // Backup endpoints (JWT auth required)
        .route("/api/v1/backup/upload", axum::routing::post(routes::backup::upload_backup)
            .layer(DefaultBodyLimit::max(50 * 1024 * 1024))) // 50MB for backups
        .route("/api/v1/backup/list", get(routes::backup::list_backups))
        .route("/api/v1/backup/usage", get(routes::backup::get_backup_usage))
        .route("/api/v1/backup/:id", get(routes::backup::download_backup).delete(routes::backup::delete_backup))
        // Media endpoints (JWT auth required, streaming)
        .route("/api/v1/media/upload", axum::routing::post(routes::media::upload_media)
            .layer(DefaultBodyLimit::max(media_upload_limit)))
        .route("/api/v1/media/usage", get(routes::media::get_usage))
        .route("/api/v1/media/:id", get(routes::media::download_media).delete(routes::media::delete_media))
        // Billing endpoints
        .route("/api/v1/billing/start-trial", axum::routing::post(routes::billing::start_trial))
        .route("/api/v1/billing/status", get(routes::billing::get_status))
        .route("/api/v1/billing/checkout", axum::routing::post(routes::billing::create_checkout))
        .route("/api/v1/billing/portal", axum::routing::post(routes::billing::create_portal))
        .route("/api/v1/billing/webhook", axum::routing::post(routes::billing::stripe_webhook))
        .route("/api/v1/invite", axum::routing::put(routes::invite::put_invite))
        .route(
            "/api/v1/invite/active",
            axum::routing::get(routes::invite::get_active_invites),
        )
        .route(
            "/api/v1/invite/:code/stats",
            axum::routing::get(routes::invite::get_invite_stats),
        )
        .route(
            "/api/v1/invite/:code",
            axum::routing::delete(routes::invite::delete_invite),
        )
        .layer(GovernorLayer {
            config: api_governor,
        });

    // ── Lookup route (Tier 4: anti-brute-force rate limit) ──────────
    // /api/v1/invite/:code is unauthenticated and reveals the sealed
    // invite payload for a valid code, so it sits behind the tightest
    // tier so that online code guessing is uneconomical within the TTL.
    let lookup_routes = Router::new()
        .route("/api/v1/invite/:code", get(routes::invite::get_invite))
        .layer(GovernorLayer {
            config: lookup_governor,
        });

    // ── Newsletter (Tier 5) ─────────────────────────────────────────
    // Public: the landing page posts here directly. Confirm/unsubscribe are
    // plain GET links opened from a mail client, so they answer with HTML
    // rather than JSON.
    let newsletter_routes = Router::new()
        .route(
            "/api/v1/newsletter/subscribe",
            axum::routing::post(routes::newsletter::subscribe),
        )
        .route(
            "/api/v1/newsletter/confirm",
            get(routes::newsletter::confirm),
        )
        .route(
            "/api/v1/newsletter/unsubscribe",
            get(routes::newsletter::unsubscribe),
        )
        .layer(GovernorLayer {
            config: newsletter_governor,
        });

    // ── Merge all route groups ──────────────────────────────────────
    let app = Router::new()
        .merge(health_routes)
        .merge(auth_routes)
        .merge(ws_routes)
        .merge(lookup_routes)
        .merge(newsletter_routes)
        .merge(api_routes)
        .with_state(state)
        .layer(DefaultBodyLimit::max(1024 * 1024)) // 1MB default for all other endpoints
        .layer(TraceLayer::new_for_http())
        .layer(cors_layer);

    let addr: SocketAddr = config.bind_addr.parse().expect("Invalid bind address");
    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();

    info!("Server listening on {}", addr);

    axum::serve(listener, app.into_make_service_with_connect_info::<SocketAddr>()).await.unwrap();
}
