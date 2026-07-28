//! Push fan-out hook fired after a sync message lands in the relay's
//! pending queue. Implements the spec/18 v1.1 event whitelist and the
//! per-device coalescing window so rapid-fire chat messages don't spam
//! recipients' tray notifications.
//!
//! See `docs/spec/18-push-delivery.md` § Delivery hook.

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use reqwest::Client;
use tracing::{debug, error, warn};

use crate::db::Database;
use crate::push::FcmSender;

/// Coalesce window per device — see spec § Delivery hook. 5 s for normal
/// pushes; reaction-to-mine uses 10 s but reactions aren't routed yet in
/// M2 (we currently fire only for `entity_type == "message"`).
const COALESCE_WINDOW: Duration = Duration::from_secs(5);

/// HTTP timeout for the upstream UnifiedPush POST. The destination is
/// usually ntfy on the same VPS, so 5 s is generous.
const NTFY_TIMEOUT: Duration = Duration::from_secs(5);

/// In-memory record of "device X was just pushed to at time T". On a
/// repeat dispatch within [`COALESCE_WINDOW`] we skip the fan-out for
/// that device. Lives in `AppState` so all WebSocket handlers share it.
#[derive(Clone, Default)]
pub struct PushCoalescer {
    inner: Arc<Mutex<HashMap<String, Instant>>>,
}

impl PushCoalescer {
    /// Returns `true` when push for `device_id` should fire now, `false`
    /// when we're still inside the coalesce window from the previous
    /// fan-out. Side-effect: updates the device's last-pushed timestamp
    /// when allowed.
    pub fn allow(&self, device_id: &str) -> bool {
        let mut map = self.inner.lock().expect("coalescer mutex poisoned");
        let now = Instant::now();
        if let Some(prev) = map.get(device_id) {
            if now.duration_since(*prev) < COALESCE_WINDOW {
                return false;
            }
        }
        map.insert(device_id.to_string(), now);
        // Opportunistic cleanup of long-stale entries — the map would
        // otherwise grow unbounded for devices that disconnect forever.
        // Cheap because we only touch the entries we just inserted past.
        if map.len() > 1024 {
            map.retain(|_, last| now.duration_since(*last) < COALESCE_WINDOW * 8);
        }
        true
    }
}

/// Whitelist of (entity_type, change_type) pairs that trigger push.
///
/// Spec § Push event whitelist. M2 only knows about chat messages. Edits
/// also pass this gate because the relay's encrypted payload is opaque
/// to us — the client's `_showChatNotificationIfEnabled` discriminates
/// new vs edit via `isNewMessage` so an edit just wakes the device with
/// no visible tray notification, which is acceptable.
///
/// Call offers (`entity_type="call"`, `change_type="offer"`) also trigger
/// a wake-up so the callee can open the socket and pull the pending offer.
/// Other call signals (answer/ice/hangup/decline/busy) travel over the
/// already-open live socket once the app is awake — no push needed for them.
pub fn should_trigger_push(
    entity_type: Option<&str>,
    change_type: Option<&str>,
) -> bool {
    matches!(
        (entity_type, change_type),
        (Some("message"), Some("update"))
            | (Some("message"), Some("create"))
            | (Some("call"), Some("offer"))
    )
}

/// Returns `true` when the coalescer should be BYPASSED (i.e. push must
/// always fire, never be rate-limited). Call offers need immediate delivery
/// regardless of recent chat activity on the same device.
pub fn should_bypass_coalescer(entity_type: Option<&str>) -> bool {
    matches!(entity_type, Some("call"))
}

/// Generic wake-up text for an FCM notification. The relay never sees the
/// (E2E-encrypted) content, so this is a placeholder; the app shows the real
/// message once it wakes and syncs.
fn fcm_wake_text(entity_type: Option<&str>) -> (&'static str, &'static str) {
    match entity_type {
        Some("call") => ("Příchozí hovor", "Klepnutím otevřete Honmoon"),
        _ => ("Nová zpráva", "Máte novou zprávu v Honmoonu"),
    }
}

/// Fan out a push wake-up to all eligible recipients of a household
/// message. Best-effort: errors from individual tokens are recorded
/// but never propagated.
///
/// `recipients == None` fans out to every household member except the
/// sender. `recipients == Some(list)` honors the explicit list (the
/// sender is filtered out either way).
///
/// `entity_type` is forwarded from the Sync message so the coalescer can
/// be bypassed for time-critical entities (call offers).
#[allow(clippy::too_many_arguments)]
pub async fn dispatch_push(
    db: &Arc<Database>,
    http: &Client,
    fcm: &Arc<FcmSender>,
    ntfy_configured: bool,
    coalescer: &PushCoalescer,
    household_id: &str,
    sender_member_id: &str,
    recipients: Option<&[String]>,
    entity_type: Option<&str>,
) {
    let member_ids: Vec<String> = match recipients {
        Some(list) => list
            .iter()
            .filter(|m| m.as_str() != sender_member_id)
            .cloned()
            .collect(),
        None => match db.get_household_members(household_id).await {
            Ok(all) => all
                .into_iter()
                .filter(|m| m != sender_member_id)
                .collect(),
            Err(e) => {
                error!(
                    "dispatch_push: load members for household {}: {}",
                    household_id, e
                );
                return;
            }
        },
    };

    if member_ids.is_empty() {
        return;
    }

    debug!(
        "dispatch_push: household={} sender={} recipients={}",
        household_id,
        sender_member_id,
        member_ids.len()
    );

    for member_id in member_ids {
        let tokens = match db.get_push_tokens_for_user(&member_id).await {
            Ok(t) => t,
            Err(e) => {
                warn!("dispatch_push: tokens for {}: {}", member_id, e);
                continue;
            }
        };

        for token in tokens {
            // Call offers bypass the coalescer — they must always fire so
            // the callee isn't silently dropped during the coalesce window.
            let bypass = should_bypass_coalescer(entity_type);
            if !bypass && !coalescer.allow(&token.device_id) {
                debug!(
                    "dispatch_push: coalesced device {} (within {}s window)",
                    token.device_id,
                    COALESCE_WINDOW.as_secs()
                );
                continue;
            }

            match token.endpoint_type.as_str() {
                "unified_push" => {
                    if !ntfy_configured {
                        // Self-hosters without ntfy: declared at relay
                        // startup. Record the skip so the client banner
                        // can surface a *server-has-no-push* message.
                        let _ = db
                            .record_push_attempt(
                                &token.token,
                                "ntfy_disabled",
                                false,
                            )
                            .await;
                        continue;
                    }
                    let result = ntfy_post(http, &token.token).await;
                    record_attempt(db, &token.token, result).await;
                }
                "fcm" => {
                    // FCM v1 wake. The relay can't read the (E2E-encrypted)
                    // content, so title/body are a generic placeholder; the
                    // tapped app opens and pulls the real message.
                    // TODO: data-only + client bg-handler for localized,
                    // content-rich notifications (background-sync-gap work).
                    let (title, body) = fcm_wake_text(entity_type);
                    let ok = fcm
                        .send_fcm_to_token(
                            &token.token,
                            title,
                            body,
                            &serde_json::json!({
                                "entity_type": entity_type,
                                "route": "chat",
                            }),
                        )
                        .await;
                    record_attempt(
                        db,
                        &token.token,
                        if ok {
                            Ok(())
                        } else {
                            Err("fcm send failed".to_string())
                        },
                    )
                    .await;
                }
                other => {
                    debug!(
                        "dispatch_push: ignoring endpoint_type={} for device {}",
                        other, token.device_id
                    );
                }
            }
        }
    }
}

/// POST an empty UnifiedPush wake-up to the endpoint URL the client
/// registered. The body is intentionally empty — the wake-up carries no
/// content; the client opens the relay WebSocket on wake and pulls the
/// pending message through the existing encrypted channel.
async fn ntfy_post(http: &Client, endpoint: &str) -> Result<(), String> {
    // SSRF guard: `endpoint` is the raw client-registered UnifiedPush URL.
    // Never POST to loopback/private/link-local hosts (cloud metadata,
    // internal services). This is the LIVE push path — the guarded
    // UnifiedPushSender::send() is unused legacy (audit 2026-07-07).
    if !crate::unified_push::UnifiedPushSender::is_safe_url(endpoint) {
        return Err("unsafe endpoint url".to_string());
    }
    let response = http
        .post(endpoint)
        .header("Content-Type", "application/octet-stream")
        .body("{}")
        .timeout(NTFY_TIMEOUT)
        .send()
        .await
        .map_err(|e| format!("send: {}", e))?;

    let status = response.status();
    if !status.is_success() {
        return Err(format!("http {}", status.as_u16()));
    }
    Ok(())
}

async fn record_attempt(
    db: &Arc<Database>,
    token: &str,
    result: Result<(), String>,
) {
    let (status, success) = match result {
        Ok(()) => ("ok".to_string(), true),
        Err(e) => (format!("err: {}", e), false),
    };
    if let Err(e) = db.record_push_attempt(token, &status, success).await {
        warn!("record_push_attempt failed for token (truncated): {}", e);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn whitelist_message_update_creates_trigger() {
        assert!(should_trigger_push(Some("message"), Some("update")));
        assert!(should_trigger_push(Some("message"), Some("create")));
    }

    #[test]
    fn whitelist_other_entities_silent() {
        assert!(!should_trigger_push(Some("task"), Some("update")));
        assert!(!should_trigger_push(Some("calendar_event"), Some("update")));
        assert!(!should_trigger_push(Some("shopping_item"), Some("create")));
        assert!(!should_trigger_push(Some("message"), Some("delete")));
        assert!(!should_trigger_push(None, None));
    }

    #[test]
    fn coalescer_blocks_repeat_within_window() {
        let c = PushCoalescer::default();
        assert!(c.allow("d1"), "first call must allow");
        assert!(!c.allow("d1"), "second call inside window must block");
        assert!(c.allow("d2"), "different device unaffected");
    }

    #[test]
    fn call_offer_triggers_wake() {
        assert!(should_trigger_push(Some("call"), Some("offer")));
    }

    #[test]
    fn other_call_signals_do_not_wake() {
        assert!(!should_trigger_push(Some("call"), Some("answer")));
        assert!(!should_trigger_push(Some("call"), Some("ice")));
        assert!(!should_trigger_push(Some("call"), Some("hangup")));
        assert!(!should_trigger_push(Some("call"), Some("decline")));
        assert!(!should_trigger_push(Some("call"), Some("busy")));
    }

    #[test]
    fn call_bypasses_coalescer_non_call_does_not() {
        assert!(should_bypass_coalescer(Some("call")), "call must bypass");
        assert!(!should_bypass_coalescer(Some("message")), "message must not bypass");
        assert!(!should_bypass_coalescer(Some("task")), "task must not bypass");
        assert!(!should_bypass_coalescer(None), "None must not bypass");
    }
}
