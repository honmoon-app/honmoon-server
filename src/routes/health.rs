use axum::response::IntoResponse;
use serde::Serialize;

#[derive(Serialize)]
struct HealthResponse {
    status: &'static str,
    version: &'static str,
    /// Commit + timestamp stamped in by `make deploy-build`, or "unknown" for
    /// a local/unstamped build. `version` alone is useless — Cargo.toml has
    /// read 0.1.0 since the file was created, so there was no way to tell
    /// which commit a VPS was actually running.
    build: String,
}

pub async fn health_check() -> impl IntoResponse {
    axum::Json(HealthResponse {
        status: "ok",
        version: env!("CARGO_PKG_VERSION"),
        build: std::env::var("HONMOON_BUILD").unwrap_or_else(|_| "unknown".to_string()),
    })
}
