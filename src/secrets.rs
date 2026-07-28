//! Zero-config secret bootstrap for self-hosted servers.
//!
//! A self-hoster runs `docker compose up -d` and nothing else. Secrets that
//! are missing on first boot get generated and appended to a file on the data
//! volume (chmod 600), so they survive restarts and `docker compose down`.
//!
//! Anything already present in the environment always wins — someone who
//! wants to manage secrets themselves just sets them and this never fires.
//! The dev defaults (`development-secret-change-in-production`) are never
//! reachable from self-hosted mode, which is the whole point: once the server
//! source is public, a well-known signing key is a forged token away from
//! every server that took the path of least resistance.

use std::fs::OpenOptions;
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;

use tracing::{info, warn};
use uuid::Uuid;

/// Secrets the server will generate for itself. Everything else stays opt-in:
/// a missing Stripe key means "no billing", not "no boot".
const GENERATED: [&str; 3] = ["JWT_SECRET", "TURN_SECRET", "FEEDBACK_ADMIN_TOKEN"];

pub fn default_path() -> String {
    std::env::var("SECRETS_FILE").unwrap_or_else(|_| "/app/data/secrets.env".to_string())
}

/// Load stored secrets, generate whatever is still missing, persist it.
pub fn bootstrap(path: &str) {
    // dotenvy never overrides a variable that is already set, so an explicit
    // env var beats the stored value without any extra logic here.
    if Path::new(path).exists() {
        match dotenvy::from_path(path) {
            Ok(()) => info!("Loaded self-hosted secrets from {}", path),
            Err(e) => warn!("Could not read {}: {} — regenerating", path, e),
        }
    }

    let missing: Vec<&str> = GENERATED
        .iter()
        .copied()
        .filter(|key| std::env::var(key).map_or(true, |v| v.trim().is_empty()))
        .collect();
    if missing.is_empty() {
        return;
    }

    let generated: Vec<(&str, String)> = missing
        .into_iter()
        .map(|key| {
            let value = random_secret();
            std::env::set_var(key, &value);
            (key, value)
        })
        .collect();

    if let Some(parent) = Path::new(path).parent() {
        let _ = std::fs::create_dir_all(parent);
    }

    let stored = OpenOptions::new()
        .create(true)
        .append(true)
        .mode(0o600)
        .open(path)
        .and_then(|mut file| {
            for (key, value) in &generated {
                writeln!(file, "{}={}", key, value)?;
            }
            Ok(())
        });

    let names: Vec<&str> = generated.iter().map(|(key, _)| *key).collect();
    match stored {
        Ok(()) => info!("Generated {} and saved them to {}", names.join(", "), path),
        // Not fatal, but loud: without a writable volume these rotate on every
        // restart, which logs every device out and looks like a sync bug.
        Err(e) => warn!(
            "Generated {} but could NOT write {}: {}. They will change on \
             every restart and all devices will have to log in again — mount \
             a writable volume at the parent directory.",
            names.join(", "),
            path,
            e
        ),
    }
}

/// 244 bits of CSPRNG output as hex.
// ponytail: uuid v4 is already a dependency and is getrandom-backed, so no
// `rand` dep just to fill 32 bytes.
fn random_secret() -> String {
    format!("{}{}", Uuid::new_v4().simple(), Uuid::new_v4().simple())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The file is the only thing standing between a restart and every device
    /// being logged out, so: generate once, reuse forever, never override an
    /// explicitly set value.
    #[test]
    fn generates_once_and_respects_the_environment() {
        let dir = std::env::temp_dir().join(format!("honmoon-secrets-{}", Uuid::new_v4()));
        let path = dir.join("secrets.env");
        let path = path.to_str().unwrap();

        for key in GENERATED {
            std::env::remove_var(key);
        }
        std::env::set_var("TURN_SECRET", "set-by-hand");

        bootstrap(path);
        let first = std::env::var("JWT_SECRET").unwrap();
        assert_eq!(first.len(), 64, "expected 32 bytes of hex");
        assert_eq!(std::env::var("TURN_SECRET").unwrap(), "set-by-hand");

        // Second boot: env cleared, file present — the same secret comes back.
        for key in GENERATED {
            std::env::remove_var(key);
        }
        bootstrap(path);
        assert_eq!(std::env::var("JWT_SECRET").unwrap(), first);
        assert!(
            std::env::var("TURN_SECRET").unwrap() != "set-by-hand",
            "a hand-set value must not be persisted to the file"
        );

        std::fs::remove_dir_all(dir).ok();
    }
}
