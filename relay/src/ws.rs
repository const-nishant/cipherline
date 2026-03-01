//! WebSocket connection handler for the relay.
//!
//! Each connected client goes through:
//! 1. Challenge → Authenticate handshake
//! 2. Message handling loop (send/receive envelopes, ACKs, pre-key ops)
//!
//! The handler is spawned per-connection by axum.

use std::sync::Arc;
use std::time::Duration;

use axum::extract::ws::{Message, WebSocket};
use futures::stream::SplitSink;
use futures::{SinkExt, StreamExt};
use tokio::sync::Mutex;
use tokio::time::{interval, timeout};
use tracing::{debug, info, warn};

use cipherline_common::identity::verify_signed_device_list;
use cipherline_common::protocol::{
    deserialize_client_msg, serialize_server_msg, AuthChallenge, ClientMessage, ServerErrorCode,
    ServerMessage,
};
use cipherline_common::types::{DeviceId, UserId};

use crate::auth::AuthenticatedPeer;
use crate::queue::MessageQueue;
use crate::state::RelayState;

/// Handle a single WebSocket connection.
pub async fn handle_connection(ws: WebSocket, state: Arc<RelayState>) {
    let (sender, mut receiver) = ws.split();
    let sender = Arc::new(Mutex::new(sender));

    // --- Phase 1: Authentication ---
    let peer = match authenticate(&sender, &mut receiver, &state).await {
        Ok(peer) => peer,
        Err(e) => {
            warn!("auth failed: {e}");
            return;
        }
    };

    info!(
        "device {:?} authenticated for user {:?}",
        peer.device_id, peer.user_id
    );

    // Register this connection as online.
    state.register_online(peer.user_id, peer.device_id, sender.clone());

    // Deliver any queued messages.
    deliver_queued(&sender, &peer.user_id, &peer.device_id, &state.queue).await;

    // --- Phase 2: Message loop ---
    let ping_interval = Duration::from_secs(state.config.ping_interval_secs);
    let idle_timeout = Duration::from_secs(state.config.idle_timeout_secs);
    let mut ping_timer = interval(ping_interval);

    loop {
        tokio::select! {
            // Incoming message from client.
            msg = timeout(idle_timeout, receiver.next()) => {
                match msg {
                    Ok(Some(Ok(Message::Binary(data)))) => {
                        handle_client_message(&data, &peer, &sender, &state).await;
                    }
                    Ok(Some(Ok(Message::Ping(payload)))) => {
                        let _ = sender.lock().await.send(Message::Pong(payload)).await;
                    }
                    Ok(Some(Ok(Message::Pong(_)))) => {
                        // Expected response to our ping.
                    }
                    Ok(Some(Ok(Message::Close(_)))) | Ok(None) => {
                        debug!("client disconnected gracefully");
                        break;
                    }
                    Ok(Some(Ok(Message::Text(_)))) => {
                        // We only use binary messages.
                        let _ = send_error(&sender, ServerErrorCode::InvalidMessage, "text messages not supported").await;
                    }
                    Ok(Some(Err(e))) => {
                        warn!("ws receive error: {e}");
                        break;
                    }
                    Err(_) => {
                        // Idle timeout.
                        info!("idle timeout for device {:?}", peer.device_id);
                        break;
                    }
                }
            }

            // Periodic ping.
            _ = ping_timer.tick() => {
                if sender.lock().await.send(Message::Ping(vec![].into())).await.is_err() {
                    break;
                }
            }
        }
    }

    // Cleanup: unregister from online set.
    state.unregister_online(&peer.user_id, &peer.device_id);
    info!("connection closed for device {:?}", peer.device_id);
}

/// Perform the challenge-response authentication handshake.
async fn authenticate(
    sender: &Arc<Mutex<SplitSink<WebSocket, Message>>>,
    receiver: &mut futures::stream::SplitStream<WebSocket>,
    state: &Arc<RelayState>,
) -> Result<AuthenticatedPeer, String> {
    // Generate and send challenge.
    let pending = state.auth.lock().await.generate_challenge();
    let challenge_msg = ServerMessage::Challenge(AuthChallenge {
        challenge: pending.challenge.to_vec(),
    });

    send_server_msg(sender, &challenge_msg)
        .await
        .map_err(|e| format!("failed to send challenge: {e}"))?;

    // Wait for auth response (with timeout).
    let auth_timeout = Duration::from_secs(state.config.auth_timestamp_tolerance_secs);
    let response = timeout(auth_timeout, receiver.next())
        .await
        .map_err(|_| "auth timeout".to_string())?
        .ok_or_else(|| "connection closed during auth".to_string())?
        .map_err(|e| format!("ws error during auth: {e}"))?;

    let data = match response {
        Message::Binary(data) => data,
        _ => return Err("expected binary auth response".to_string()),
    };

    let client_msg =
        deserialize_client_msg(&data).map_err(|e| format!("invalid auth message: {e}"))?;

    match client_msg {
        ClientMessage::Authenticate(auth_resp) => {
            let peer = state
                .auth
                .lock()
                .await
                .verify_response(
                    &pending.challenge,
                    pending.created_at,
                    auth_resp.user_id,
                    auth_resp.device_id,
                    &auth_resp.device_public_key,
                    &auth_resp.signature,
                    auth_resp.timestamp.0,
                )
                .map_err(|e| format!("auth verification failed: {e}"))?;

            // Send auth success.
            send_server_msg(sender, &ServerMessage::AuthSuccess)
                .await
                .map_err(|e| format!("failed to send auth success: {e}"))?;

            Ok(peer)
        }
        _ => Err("expected Authenticate message".to_string()),
    }
}

/// Handle a deserialized client message.
async fn handle_client_message(
    data: &[u8],
    peer: &AuthenticatedPeer,
    sender: &Arc<Mutex<SplitSink<WebSocket, Message>>>,
    state: &Arc<RelayState>,
) {
    let msg = match deserialize_client_msg(data) {
        Ok(m) => m,
        Err(e) => {
            warn!("invalid client message: {e}");
            let _ = send_error(sender, ServerErrorCode::InvalidMessage, &e.to_string()).await;
            return;
        }
    };

    match msg {
        ClientMessage::SendEnvelope(envelope) => {
            handle_send_envelope(envelope, peer, sender, state).await;
        }
        ClientMessage::SendInitialMessage(init_msg) => {
            handle_send_initial_message(init_msg, peer, sender, state).await;
        }
        ClientMessage::Ack(ack) => {
            handle_ack(ack, peer, state).await;
        }
        ClientMessage::FetchPreKeys { user_id, device_id } => {
            handle_fetch_prekeys(user_id, device_id, sender, state).await;
        }
        ClientMessage::UploadPreKeys(bundle) => {
            handle_upload_prekeys(bundle, peer, sender, state).await;
        }
        ClientMessage::RegisterDevice(reg) => {
            handle_register_device(reg, peer, sender, state).await;
        }
        ClientMessage::RevokeDevice(rev) => {
            handle_revoke_device(rev, peer, sender, state).await;
        }
        ClientMessage::FetchDeviceList { user_id } => {
            handle_fetch_device_list(user_id, sender, state).await;
        }
        ClientMessage::Authenticate(_) => {
            // Already authenticated.
            let _ = send_error(
                sender,
                ServerErrorCode::InvalidMessage,
                "already authenticated",
            )
            .await;
        }
    }
}

/// Handle `SendEnvelope`: validate, enqueue, deliver if online, ACK sender.
async fn handle_send_envelope(
    envelope: cipherline_common::protocol::Envelope,
    peer: &AuthenticatedPeer,
    sender: &Arc<Mutex<SplitSink<WebSocket, Message>>>,
    state: &Arc<RelayState>,
) {
    // Validate envelope.
    if let Err(e) = envelope.validate() {
        let _ = send_error(sender, ServerErrorCode::MessageTooLarge, &e.to_string()).await;
        return;
    }

    // Verify sender matches authenticated peer.
    if envelope.sender_id != peer.user_id || envelope.sender_device_id != peer.device_id {
        let _ = send_error(sender, ServerErrorCode::InvalidMessage, "sender mismatch").await;
        return;
    }

    let message_id = envelope.message_id;
    let recipient_id = envelope.recipient_id;
    let recipient_device_id = envelope.recipient_device_id;

    // Enqueue for the recipient device.
    if let Err(e) = state
        .queue
        .enqueue(recipient_id, recipient_device_id, envelope.clone())
    {
        let _ = send_error(sender, ServerErrorCode::InvalidMessage, &e.to_string()).await;
        return;
    }

    // Try to deliver immediately if recipient is online.
    if let Some(recipient_sender) = state.get_online_sender(&recipient_id, &recipient_device_id) {
        let deliver_msg = ServerMessage::Deliver(envelope);
        if send_server_msg(&recipient_sender, &deliver_msg)
            .await
            .is_ok()
        {
            // Remove from queue since delivered directly.
            state
                .queue
                .remove_by_id(&recipient_id, &recipient_device_id, &message_id);
        }
    }

    // ACK the sender.
    let _ = send_server_msg(sender, &ServerMessage::Ack(message_id)).await;
}

/// Handle `SendInitialMessage`: similar to SendEnvelope but with X3DH header.
async fn handle_send_initial_message(
    init_msg: cipherline_common::protocol::InitialMessage,
    peer: &AuthenticatedPeer,
    sender: &Arc<Mutex<SplitSink<WebSocket, Message>>>,
    state: &Arc<RelayState>,
) {
    if let Err(e) = init_msg.envelope.validate() {
        let _ = send_error(sender, ServerErrorCode::MessageTooLarge, &e.to_string()).await;
        return;
    }

    if init_msg.envelope.sender_id != peer.user_id
        || init_msg.envelope.sender_device_id != peer.device_id
    {
        let _ = send_error(sender, ServerErrorCode::InvalidMessage, "sender mismatch").await;
        return;
    }

    let message_id = init_msg.envelope.message_id;
    let recipient_id = init_msg.envelope.recipient_id;
    let recipient_device_id = init_msg.envelope.recipient_device_id;

    // Consume the one-time pre-key used by the initiator.
    if let Some(opk_id) = init_msg.x3dh_header.one_time_pre_key_id {
        state.consume_opk(&recipient_id, &recipient_device_id, opk_id);
    }

    // Enqueue the envelope portion.
    if let Err(e) =
        state
            .queue
            .enqueue(recipient_id, recipient_device_id, init_msg.envelope.clone())
    {
        let _ = send_error(sender, ServerErrorCode::InvalidMessage, &e.to_string()).await;
        return;
    }

    // Try direct delivery.
    if let Some(recipient_sender) = state.get_online_sender(&recipient_id, &recipient_device_id) {
        let deliver_msg = ServerMessage::DeliverInitialMessage(init_msg);
        if send_server_msg(&recipient_sender, &deliver_msg)
            .await
            .is_ok()
        {
            state
                .queue
                .remove_by_id(&recipient_id, &recipient_device_id, &message_id);
        }
    }

    let _ = send_server_msg(sender, &ServerMessage::Ack(message_id)).await;
}

/// Handle `Ack`: remove delivered message from queue.
async fn handle_ack(
    ack: cipherline_common::protocol::AckMessage,
    peer: &AuthenticatedPeer,
    state: &Arc<RelayState>,
) {
    state
        .queue
        .remove_by_id(&peer.user_id, &peer.device_id, &ack.message_id);
    debug!("ACK received for message {:?}", ack.message_id);
}

/// Handle `FetchPreKeys`: return stored pre-key bundle.
async fn handle_fetch_prekeys(
    user_id: UserId,
    device_id: Option<DeviceId>,
    sender: &Arc<Mutex<SplitSink<WebSocket, Message>>>,
    state: &Arc<RelayState>,
) {
    // If device_id is specified, fetch for that device. Otherwise, pick any device.
    if let Some(did) = device_id {
        match state.get_prekey_bundle(&user_id, &did) {
            Some(bundle) => {
                let _ = send_server_msg(sender, &ServerMessage::PreKeys(bundle)).await;
            }
            None => {
                let _ = send_error(
                    sender,
                    ServerErrorCode::DeviceNotFound,
                    "no pre-key bundle found",
                )
                .await;
            }
        }
    } else {
        // Fetch for any registered device of this user.
        match state.get_any_prekey_bundle(&user_id) {
            Some(bundle) => {
                let _ = send_server_msg(sender, &ServerMessage::PreKeys(bundle)).await;
            }
            None => {
                let _ = send_error(
                    sender,
                    ServerErrorCode::UserNotFound,
                    "no pre-key bundles found for user",
                )
                .await;
            }
        }
    }
}

/// Handle `UploadPreKeys`: store/replace pre-key bundle.
async fn handle_upload_prekeys(
    bundle: cipherline_common::identity::PreKeyBundle,
    peer: &AuthenticatedPeer,
    sender: &Arc<Mutex<SplitSink<WebSocket, Message>>>,
    state: &Arc<RelayState>,
) {
    // Verify the bundle belongs to the authenticated peer.
    if bundle.device_id != peer.device_id {
        let _ = send_error(
            sender,
            ServerErrorCode::InvalidMessage,
            "pre-key bundle device mismatch",
        )
        .await;
        return;
    }

    let remaining = bundle.one_time_pre_keys.len() as u32;
    state.store_prekey_bundle(peer.user_id, peer.device_id, bundle);

    let _ = send_server_msg(sender, &ServerMessage::PreKeyCount { remaining }).await;
}

/// Handle `RegisterDevice`: register a new device for the user.
async fn handle_register_device(
    reg: cipherline_common::protocol::DeviceRegistration,
    peer: &AuthenticatedPeer,
    sender: &Arc<Mutex<SplitSink<WebSocket, Message>>>,
    state: &Arc<RelayState>,
) {
    // Verify the certificate's user_id matches the authenticated peer.
    if reg.certificate.user_id != peer.user_id {
        let _ = send_error(
            sender,
            ServerErrorCode::InvalidMessage,
            "device registration user mismatch",
        )
        .await;
        return;
    }

    // Verify the device certificate's root signature using the peer's verifying key.
    if let Err(e) = reg.certificate.verify(&peer.verifying_key) {
        warn!("device certificate verification failed: {e}");
        let _ = send_error(
            sender,
            ServerErrorCode::InvalidMessage,
            "device certificate signature verification failed",
        )
        .await;
        return;
    }

    // Check device limit.
    let current_count = state.device_count(&peer.user_id);
    if current_count >= cipherline_common::types::MAX_DEVICES_PER_USER {
        let _ = send_error(
            sender,
            ServerErrorCode::DeviceLimitExceeded,
            "maximum devices reached",
        )
        .await;
        return;
    }

    // Verify the signed device list.
    if let Err(e) = verify_signed_device_list(&reg.device_list, &peer.verifying_key) {
        warn!("device list signature verification failed: {e}");
        let _ = send_error(
            sender,
            ServerErrorCode::InvalidMessage,
            "device list signature verification failed",
        )
        .await;
        return;
    }

    state.register_device(reg.certificate.user_id, reg.certificate.device_id);
    state.store_device_list(reg.certificate.user_id, reg.device_list);
    let _ = send_server_msg(sender, &ServerMessage::AuthSuccess).await;

    debug!(
        "registered device {:?} for user {:?}",
        reg.certificate.device_id, reg.certificate.user_id
    );
}

/// Handle `RevokeDevice`: mark a device as revoked.
async fn handle_revoke_device(
    rev: cipherline_common::protocol::DeviceRevocation,
    peer: &AuthenticatedPeer,
    sender: &Arc<Mutex<SplitSink<WebSocket, Message>>>,
    state: &Arc<RelayState>,
) {
    if rev.user_id != peer.user_id {
        let _ = send_error(
            sender,
            ServerErrorCode::InvalidMessage,
            "revocation user mismatch",
        )
        .await;
        return;
    }

    // Verify the revocation signature.
    {
        use ed25519_dalek::Verifier;
        let mut payload = Vec::new();
        payload.extend_from_slice(&rev.version.to_le_bytes());
        payload.extend_from_slice(&rev.user_id.0);
        payload.extend_from_slice(&rev.revoked_device_id.0);
        payload.extend_from_slice(&rev.timestamp.0.to_le_bytes());

        let sig = match ed25519_dalek::Signature::from_slice(&rev.signature) {
            Ok(s) => s,
            Err(_) => {
                let _ = send_error(
                    sender,
                    ServerErrorCode::InvalidMessage,
                    "invalid revocation signature bytes",
                )
                .await;
                return;
            }
        };

        if peer.verifying_key.verify(&payload, &sig).is_err() {
            warn!("revocation signature verification failed");
            let _ = send_error(
                sender,
                ServerErrorCode::InvalidMessage,
                "revocation signature verification failed",
            )
            .await;
            return;
        }
    }

    state.revoke_device(&rev.user_id, &rev.revoked_device_id);

    // Notify the revoked device if online.
    if let Some(revoked_sender) = state.get_online_sender(&rev.user_id, &rev.revoked_device_id) {
        let _ = send_server_msg(&revoked_sender, &ServerMessage::DeviceRevoked(rev)).await;
    }

    let _ = send_server_msg(sender, &ServerMessage::AuthSuccess).await;
}

/// Handle `FetchDeviceList`: return the signed device list.
async fn handle_fetch_device_list(
    user_id: UserId,
    sender: &Arc<Mutex<SplitSink<WebSocket, Message>>>,
    state: &Arc<RelayState>,
) {
    match state.get_device_list(&user_id) {
        Some(list) => {
            let _ = send_server_msg(sender, &ServerMessage::DeviceList(list)).await;
        }
        None => {
            let _ = send_error(
                sender,
                ServerErrorCode::UserNotFound,
                "no device list found",
            )
            .await;
        }
    }
}

/// Deliver all queued messages for a device.
async fn deliver_queued(
    sender: &Arc<Mutex<SplitSink<WebSocket, Message>>>,
    user_id: &UserId,
    device_id: &DeviceId,
    queue: &MessageQueue,
) {
    let messages = queue.drain(user_id, device_id);
    if messages.is_empty() {
        return;
    }

    info!(
        "delivering {} queued messages to {:?}",
        messages.len(),
        device_id
    );
    for envelope in messages {
        if send_server_msg(sender, &ServerMessage::Deliver(envelope))
            .await
            .is_err()
        {
            warn!("failed to deliver queued message");
            break;
        }
    }
}

/// Send a ServerMessage as binary WebSocket frame.
async fn send_server_msg(
    sender: &Arc<Mutex<SplitSink<WebSocket, Message>>>,
    msg: &ServerMessage,
) -> Result<(), String> {
    let data = serialize_server_msg(msg).map_err(|e| e.to_string())?;
    sender
        .lock()
        .await
        .send(Message::Binary(data.into()))
        .await
        .map_err(|e| e.to_string())
}

/// Send an error message to the client.
async fn send_error(
    sender: &Arc<Mutex<SplitSink<WebSocket, Message>>>,
    code: ServerErrorCode,
    message: &str,
) -> Result<(), String> {
    send_server_msg(
        sender,
        &ServerMessage::Error {
            code,
            message: message.to_string(),
        },
    )
    .await
}
