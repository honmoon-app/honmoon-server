use axum::{
    extract::ws::{Message, WebSocket, WebSocketUpgrade},
    extract::{Query, State},
    response::IntoResponse,
};
use futures_util::{SinkExt, StreamExt};
use tokio::sync::broadcast;
use tracing::{debug, error, info, warn};

use crate::auth::{self, Claims};
use crate::push_dispatch;
use crate::subscription;
use crate::websocket::message::{
    ClientMessage, PendingSyncMessage, QueuedMessage, ServerMessage,
};
use crate::AppState;

#[derive(serde::Deserialize)]
pub struct WsQuery {
    token: String,
}

pub async fn websocket_handler(
    ws: WebSocketUpgrade,
    Query(query): Query<WsQuery>,
    State(state): State<AppState>,
) -> impl IntoResponse {
    // Validate JWT token
    match auth::validate_token(&query.token, &state.config.jwt_secret) {
        Ok(claims) => {
            info!(
                "WebSocket connection from device {} (household: {})",
                claims.device_id, claims.household_id
            );

            // Check subscription status (skip if self-hosted)
            if !state.config.self_hosted {
                match state.db.get_subscription_status(&claims.household_id).await {
                    Ok(info) => {
                        if !subscription::is_allowed(&info.status) {
                            warn!(
                                "WebSocket rejected for household {} — subscription status: {:?}",
                                claims.household_id, info.status
                            );
                            return ws.on_upgrade(|mut socket| async move {
                                let error = ServerMessage::Error {
                                    code: "SUBSCRIPTION_REQUIRED".to_string(),
                                    message: "Active subscription required for sync".to_string(),
                                };
                                if let Ok(json) = serde_json::to_string(&error) {
                                    let _ = socket.send(Message::Text(json)).await;
                                }
                                let _ = socket.close().await;
                            });
                        }
                    }
                    Err(e) => {
                        error!("Failed to check subscription status: {}", e);
                        // Allow connection on DB error to avoid blocking users
                    }
                }

                // Check member limit
                match state.db.get_member_count(&claims.household_id).await {
                    Ok(count) if count > state.config.max_household_members => {
                        warn!(
                            "WebSocket rejected for household {} — member limit exceeded ({}/{})",
                            claims.household_id, count, state.config.max_household_members
                        );
                        return ws.on_upgrade(|mut socket| async move {
                            let error = ServerMessage::Error {
                                code: "MEMBER_LIMIT_EXCEEDED".to_string(),
                                message: "Household has reached the maximum number of members".to_string(),
                            };
                            if let Ok(json) = serde_json::to_string(&error) {
                                let _ = socket.send(Message::Text(json)).await;
                            }
                            let _ = socket.close().await;
                        });
                    }
                    Err(e) => {
                        error!("Failed to check member count: {}", e);
                    }
                    _ => {}
                }
            }

            ws.max_message_size(2 * 1024 * 1024) // 2MB max WebSocket message
                .on_upgrade(move |socket| handle_socket(socket, claims, state))
        }
        Err(e) => {
            warn!("Invalid token: {}", e);
            ws.on_upgrade(|mut socket| async move {
                let error = ServerMessage::Error {
                    code: "AUTH_FAILED".to_string(),
                    message: "Invalid or expired token".to_string(),
                };
                if let Ok(json) = serde_json::to_string(&error) {
                    let _ = socket.send(Message::Text(json)).await;
                }
                let _ = socket.close().await;
            })
        }
    }
}

async fn handle_socket(socket: WebSocket, claims: Claims, state: AppState) {
    let (mut sender, mut receiver) = socket.split();

    let household_id = claims.household_id.clone();
    let device_id = claims.device_id.clone();
    let member_id = claims.member_id.clone();
    // Tags this specific socket. On disconnect we only evict the connected
    // slot if it still holds OUR conn_id — a fast reconnect may have already
    // replaced it, and removing that live slot (and its broadcast channel)
    // stranded the reconnected device (audit #10).
    let conn_id = uuid::Uuid::new_v4().to_string();

    // Register this member in the database
    if let Err(e) = state.db.upsert_household_member(&household_id, &member_id).await {
        error!("Failed to register household member: {}", e);
    }

    // Get or create broadcast channel for this household
    let mut rx = {
        let mut channels = state.channels.write().await;
        let tx = channels
            .entry(household_id.clone())
            .or_insert_with(|| broadcast::channel(500).0);
        tx.subscribe()
    };

    // Register device as connected
    {
        let mut connected = state.connected.write().await;
        let household_devices = connected.entry(household_id.clone()).or_default();
        household_devices.insert(device_id.clone(), (member_id.clone(), conn_id.clone()));

        // Broadcast presence to other devices
        if let Some(tx) = state.channels.read().await.get(&household_id) {
            let presence = ServerMessage::Presence {
                device_id: device_id.clone(),
                member_id: member_id.clone(),
                online: true,
            };
            if let Ok(json) = serde_json::to_string(&presence) {
                let _ = tx.send((device_id.clone(), json));
            }
        }
    }

    info!(
        "Device {} connected to household {}",
        device_id, household_id
    );

    // Deliver any queued messages for this member
    match state.db.get_pending_messages_for_member(&household_id, &member_id).await {
        Ok(pending_messages) if !pending_messages.is_empty() => {
            debug!("Delivering {} queued messages to member {}", pending_messages.len(), member_id);
            let queued: Vec<QueuedMessage> = pending_messages
                .iter()
                .map(|pm| QueuedMessage {
                    id: pm.id.clone(),
                    from: pm.from_device_id.clone(),
                    payload: pm.payload.clone(),
                    timestamp: pm.created_at,
                    // Preserve routing hints so a redelivered call frame reaches
                    // the call layer, not the CRDT decrypt path (audit #11).
                    entity_type: pm.entity_type.clone(),
                    change_type: pm.change_type.clone(),
                })
                .collect();

            let queued_msg = ServerMessage::Queued { messages: queued };
            match serde_json::to_string(&queued_msg) {
                Ok(json) => {
                    if let Err(e) = sender.send(Message::Text(json)).await {
                        error!("Failed to send queued messages: {}", e);
                    }
                }
                Err(e) => error!("Failed to serialize queued messages: {} -- skipping", e),
            }
        }
        Ok(_) => debug!("No queued messages for member {}", member_id),
        Err(e) => error!("Failed to get pending messages: {}", e),
    }

    // Clone for the receive task
    let device_id_recv = device_id.clone();
    let household_id_recv = household_id.clone();
    let member_id_recv = member_id.clone();
    let state_recv = state.clone();

    // Task to receive messages from client and broadcast to household.
    //
    // Each await on the next frame is bounded by IDLE_TIMEOUT. Clients are
    // expected to send a Ping every 30s; 90s without any frame means the
    // connection is stale and we drop it so its slot in the per-household
    // broadcast channel (cap 500) does not get held forever.
    let recv_task = tokio::spawn(async move {
        const IDLE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(90);
        loop {
            let next = match tokio::time::timeout(IDLE_TIMEOUT, receiver.next()).await {
                Ok(next) => next,
                Err(_) => {
                    info!(
                        "WebSocket idle timeout for device {} — closing stale connection",
                        device_id_recv
                    );
                    break;
                }
            };
            let Some(result) = next else { break };
            match result {
                Ok(Message::Text(text)) => {
                    // Global volume only — never per household. See src/traffic.rs.
                    state_recv.traffic.record_in(text.len());
                    state_recv.traffic.record_active(
                        &chrono::Utc::now().format("%Y-%m-%d").to_string(),
                        &household_id_recv,
                    );
                    match serde_json::from_str::<ClientMessage>(&text) {
                        Ok(ClientMessage::Sync { payload, correlation_id, entity_type, change_type, description, recipients }) => {
                            // Store the message in the database for persistence.
                            // Returns (message_id, freshly_inserted) — duplicates from
                            // sender-side retry are idempotent and skip broadcast.
                            let store_result = state_recv.db.store_pending_message(
                                &household_id_recv,
                                &device_id_recv,
                                &member_id_recv,
                                &correlation_id,
                                &payload,
                                entity_type.as_deref(),
                                change_type.as_deref(),
                                description.as_deref(),
                                recipients.as_deref(),
                            ).await;

                            let (message_id, fresh) = match store_result {
                                Ok(pair) => pair,
                                Err(e) => {
                                    error!("Failed to store pending message: {}", e);
                                    // Skip ack — sender will retry on timeout
                                    continue;
                                }
                            };

                            // Ack the sender so it can clear its pending-retry buffer
                            // for this correlation_id. We do this for both fresh and
                            // duplicate inserts.
                            if let Some(tx) =
                                state_recv.channels.read().await.get(&household_id_recv)
                            {
                                let ack = ServerMessage::SyncReceived {
                                    correlation_id: correlation_id.clone(),
                                    message_id: message_id.clone(),
                                };
                                if let Ok(json) = serde_json::to_string(&ack) {
                                    let _ = tx.send((
                                        format!("__self__{}", device_id_recv),
                                        json,
                                    ));
                                }
                            }

                            // Skip broadcasting on duplicate — recipients already got it
                            // on the original send (or will via their queued/pending path).
                            if !fresh {
                                continue;
                            }

                            // Push fan-out (spec/18 § Delivery hook). Fires
                            // only for the entity/change combos on the
                            // whitelist; coalesced per-device. Spawned so
                            // the WebSocket recv loop isn't blocked on
                            // outbound HTTP — push is strictly best-effort.
                            if push_dispatch::should_trigger_push(
                                entity_type.as_deref(),
                                change_type.as_deref(),
                            ) {
                                let push_state = state_recv.clone();
                                let push_household = household_id_recv.clone();
                                let push_sender = member_id_recv.clone();
                                let push_recipients = recipients.clone();
                                let push_entity_type = entity_type.clone();
                                tokio::spawn(async move {
                                    let ntfy_configured =
                                        push_state.config.ntfy_url.is_some();
                                    push_dispatch::dispatch_push(
                                        &push_state.db,
                                        &push_state.http_client,
                                        &push_state.fcm,
                                        ntfy_configured,
                                        &push_state.push_coalescer,
                                        &push_household,
                                        &push_sender,
                                        push_recipients.as_deref(),
                                        push_entity_type.as_deref(),
                                    )
                                    .await;
                                });
                            }

                            // Broadcast to devices in the sender's household
                            if let Some(tx) =
                                state_recv.channels.read().await.get(&household_id_recv)
                            {
                                let msg = ServerMessage::Sync {
                                    from: device_id_recv.clone(),
                                    payload: payload.clone(),
                                    message_id: message_id.clone(),
                                    recipients: recipients.clone(),
                                    entity_type: entity_type.clone(),
                                    change_type: change_type.clone(),
                                };
                                let Ok(json) = serde_json::to_string(&msg) else {
                                    error!("Failed to serialize sync message -- skipping");
                                    continue;
                                };
                                let _ = tx.send((device_id_recv.clone(), json));
                            }
                        }
                        Ok(ClientMessage::Presence { online }) => {
                            if let Some(tx) =
                                state_recv.channels.read().await.get(&household_id_recv)
                            {
                                let msg = ServerMessage::Presence {
                                    device_id: device_id_recv.clone(),
                                    member_id: member_id_recv.clone(),
                                    online,
                                };
                                let Ok(json) = serde_json::to_string(&msg) else {
                                    error!("Failed to serialize presence message -- skipping");
                                    continue;
                                };
                                let _ = tx.send((device_id_recv.clone(), json));
                            }
                        }
                        Ok(ClientMessage::Ping) => {
                            // Pong is handled in send task
                        }
                        Ok(ClientMessage::Ack { message_id }) => {
                            // Mark message as delivered to this member
                            debug!("Received ack for message {} from member {}", message_id, member_id_recv);
                            if let Err(e) = state_recv.db.mark_delivered(&message_id, &member_id_recv).await {
                                error!("Failed to mark message as delivered: {}", e);
                            }

                            // Notify the sender about the delivery (find sender from connected devices)
                            // The sender will receive a DeliveryStatus message
                            if let Some(tx) =
                                state_recv.channels.read().await.get(&household_id_recv)
                            {
                                let delivery_status = ServerMessage::DeliveryStatus {
                                    message_id,
                                    member_id: member_id_recv.clone(),
                                    delivered: true,
                                };
                                let Ok(json) = serde_json::to_string(&delivery_status) else {
                                    error!("Failed to serialize delivery status -- skipping");
                                    continue;
                                };
                                let _ = tx.send((device_id_recv.clone(), json));
                            }
                        }
                        Ok(ClientMessage::SyncStatusRequest) => {
                            // Get pending messages from this member
                            match state_recv.db.get_pending_messages_from_member(&household_id_recv, &member_id_recv).await {
                                Ok(pending) => {
                                    let pending_messages: Vec<PendingSyncMessage> = pending
                                        .into_iter()
                                        .map(|(msg, deliveries): (crate::db::PendingMessage, Vec<crate::db::MessageDelivery>)| {
                                            let pending_members: Vec<String> = deliveries
                                                .iter()
                                                .filter(|d| d.delivered_at.is_none())
                                                .map(|d| d.member_id.clone())
                                                .collect();
                                            let delivered_members: Vec<String> = deliveries
                                                .iter()
                                                .filter(|d| d.delivered_at.is_some())
                                                .map(|d| d.member_id.clone())
                                                .collect();
                                            PendingSyncMessage {
                                                id: msg.id,
                                                payload: msg.payload,
                                                created_at: msg.created_at,
                                                pending_members,
                                                delivered_members,
                                                entity_type: msg.entity_type,
                                                change_type: msg.change_type,
                                                description: msg.description,
                                            }
                                        })
                                        .collect();

                                    // Send directly to this socket (not broadcast)
                                    // This will be sent via the broadcast channel but filtered
                                    if let Some(tx) =
                                        state_recv.channels.read().await.get(&household_id_recv)
                                    {
                                        let status_msg = ServerMessage::SyncStatus { pending_messages };
                                        // Use a special "self" marker to send back to sender
                                        let Ok(json) = serde_json::to_string(&status_msg) else {
                                            error!("Failed to serialize sync status -- skipping");
                                            continue;
                                        };
                                        let _ = tx.send((
                                            format!("__self__{}", device_id_recv),
                                            json,
                                        ));
                                    }
                                }
                                Err(e) => {
                                    error!("Failed to get sync status: {}", e);
                                }
                            }
                        }
                        Err(e) => {
                            warn!("Failed to parse message: {}", e);
                        }
                    }
                }
                Ok(Message::Close(_)) => {
                    info!("Device {} disconnected", device_id_recv);
                    break;
                }
                Err(e) => {
                    error!("WebSocket error: {}", e);
                    break;
                }
                _ => {}
            }
        }
    });

    // Task to send broadcast messages to client
    let device_id_send = device_id.clone();
    let member_id_send = member_id.clone();
    let state_send = state.clone();
    let send_task = tokio::spawn(async move {
        loop {
            let (from_device, msg) = match rx.recv().await {
                Ok(v) => v,
                // Slow receiver fell behind the 500-cap channel. Skip the gap
                // and keep the socket alive instead of dropping it — a drop
                // here triggers a reconnect storm exactly at peak load (audit
                // #20). Missed broadcasts recover via pending-message
                // redelivery + full resync.
                Err(broadcast::error::RecvError::Lagged(n)) => {
                    warn!("send task lagged {} messages for device {}", n, device_id_send);
                    continue;
                }
                Err(broadcast::error::RecvError::Closed) => break,
            };
            // Handle special self-message for sync status
            if from_device == format!("__self__{}", device_id_send) {
                state_send.traffic.record_out(msg.len());
                if sender.send(Message::Text(msg)).await.is_err() {
                    break;
                }
                continue;
            }

            // Don't send messages back to the sender
            if from_device != device_id_send {
                // For sync messages, apply the recipient filter. Do NOT mark
                // delivered here: delivery is confirmed solely by the client's
                // Ack, which it now sends only AFTER durably applying the
                // payload (at-least-once delivery, audit #1). Marking delivered
                // on socket-write deleted the pending row before the client
                // merged it, so a crash/kill/decrypt-failure permanently lost
                // the change with no way to redeliver.
                if let Ok(ServerMessage::Sync { ref recipients, .. }) =
                    serde_json::from_str::<ServerMessage>(&msg)
                {
                    // If recipients are specified, only deliver to those members
                    if let Some(ref filter) = recipients {
                        if !filter.iter().any(|r| r == &member_id_send) {
                            // This member is not in the recipient list, skip
                            continue;
                        }
                    }

                    state_send.traffic.record_out(msg.len());
                    if sender.send(Message::Text(msg.clone())).await.is_err() {
                        break;
                    }
                    continue;
                }

                state_send.traffic.record_out(msg.len());
                if sender.send(Message::Text(msg)).await.is_err() {
                    break;
                }
            }
        }
    });

    // Wait for either task to complete
    tokio::select! {
        _ = recv_task => {},
        _ = send_task => {},
    }

    // Cleanup on disconnect
    {
        let mut connected = state.connected.write().await;
        let household_empty = match connected.get_mut(&household_id) {
            Some(devices) => {
                // Compare-and-remove: only drop the slot if it's still ours. A
                // faster reconnect may have replaced it with a live conn_id —
                // evicting that (and tearing down the channel below) would
                // strand the reconnected device (audit #10).
                if devices.get(&device_id).map(|(_, c)| c.as_str()) == Some(conn_id.as_str()) {
                    devices.remove(&device_id);
                }
                devices.is_empty()
            }
            None => false,
        };

        // Broadcast offline presence before any channel teardown below.
        if let Some(tx) = state.channels.read().await.get(&household_id) {
            let presence = ServerMessage::Presence {
                device_id: device_id.clone(),
                member_id,
                online: false,
            };
            if let Ok(json) = serde_json::to_string(&presence) {
                let _ = tx.send((device_id.clone(), json));
            }
        }

        // Last device gone: prune the empty `connected` entry and the
        // household's broadcast channel. Without this both maps grow
        // unboundedly — one leaked entry per household ever seen.
        // A reconnecting device re-creates the channel via or_insert_with.
        if household_empty {
            connected.remove(&household_id);
            state.channels.write().await.remove(&household_id);
        }
    }

    info!("Device {} disconnected from household {}", device_id, household_id);
}
