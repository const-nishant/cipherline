//! Application state managed by Tauri.
//!
//! `AppState` ties together the encrypted store, WebSocket client, and
//! identity cache. A background task listens for incoming `ServerMessage`s,
//! decrypts envelopes, stores plaintext, and emits Tauri events.

use std::path::PathBuf;
use std::sync::Arc;
use tauri::Emitter;
use tokio::sync::Mutex;
use tracing::{debug, error, info, warn};

use ed25519_dalek::{Signature as Ed25519Signature, SigningKey, VerifyingKey};
use x25519_dalek::StaticSecret as X25519StaticSecret;
use zeroize::Zeroize;

use cipherline_common::crypto;
use cipherline_common::identity::{
    build_pre_key_bundle, generate_one_time_pre_keys, generate_signed_pre_key,
    verify_signed_device_list,
};
use cipherline_common::protocol::{ClientMessage, Envelope, InitialMessage, ServerMessage};
use cipherline_common::ratchet::{x3dh_initiate, x3dh_respond, RatchetState};
use cipherline_common::types::{DeviceId, Timestamp, UserId};

use crate::store::{Store, StoredContact, StoredMessage};
use crate::ws_client::{AuthCredentials, ConnectionStatus, WsClient, WsClientConfig};

// ---------------------------------------------------------------------------
// AppState
// ---------------------------------------------------------------------------

/// Central application state, shared across Tauri commands.
pub struct AppState {
    /// Encrypted local database.
    pub store: Arc<Mutex<Store>>,
    /// WebSocket client (None until identity is created and connected).
    pub ws_client: Arc<Mutex<Option<WsClient>>>,
    /// Cached user identity.
    pub user_id: Arc<Mutex<Option<UserId>>>,
    pub device_id: Arc<Mutex<Option<DeviceId>>>,
    /// Path to the database file.
    pub db_path: PathBuf,
    /// Relay URL.
    pub relay_url: String,
}

impl AppState {
    /// Create a new AppState, opening the encrypted store.
    pub fn new(db_path: PathBuf, relay_url: String) -> Result<Self, crate::store::StoreError> {
        let store = Store::open(&db_path)?;

        // Try to load cached identity.
        let (user_id, device_id) = if let Some(identity) = store.load_identity()? {
            (Some(identity.user_id), Some(identity.device_id))
        } else {
            (None, None)
        };

        Ok(Self {
            store: Arc::new(Mutex::new(store)),
            ws_client: Arc::new(Mutex::new(None)),
            user_id: Arc::new(Mutex::new(user_id)),
            device_id: Arc::new(Mutex::new(device_id)),
            db_path,
            relay_url,
        })
    }

    /// Check if an identity has been created.
    pub async fn has_identity(&self) -> bool {
        self.user_id.lock().await.is_some()
    }

    /// Get the current connection status.
    pub async fn connection_status(&self) -> ConnectionStatus {
        let ws = self.ws_client.lock().await;
        match ws.as_ref() {
            Some(client) => client.connection_status().await,
            None => ConnectionStatus::Disconnected,
        }
    }

    /// Connect to the relay server using stored credentials.
    ///
    /// Requires identity to be created first. Starts the background
    /// message listener.
    pub async fn connect_to_relay(
        &self,
        app_handle: tauri::AppHandle,
    ) -> Result<(), crate::ws_client::WsClientError> {
        let store = self.store.lock().await;
        let identity = store
            .load_identity()
            .map_err(|e| crate::ws_client::WsClientError::Connection(e.to_string()))?
            .ok_or_else(|| {
                crate::ws_client::WsClientError::Connection("no identity created".into())
            })?;
        drop(store);

        let device_signing_key: [u8; 32] = identity
            .signing_key
            .as_slice()
            .try_into()
            .map_err(|_| crate::ws_client::WsClientError::Connection("bad key".into()))?;

        let device_public_key = {
            let sk = ed25519_dalek::SigningKey::from_bytes(&device_signing_key);
            sk.verifying_key().to_bytes()
        };

        let credentials = AuthCredentials {
            user_id: identity.user_id,
            device_id: identity.device_id,
            device_public_key,
            signing_key_bytes: identity.signing_key.clone(),
        };

        let config = WsClientConfig {
            relay_url: self.relay_url.clone(),
            ..Default::default()
        };

        let client = WsClient::start(config, credentials);

        // Spawn a task to watch the connection status and emit events.
        let status_handle = client.status.clone();
        let status_app = app_handle.clone();
        tokio::spawn(async move {
            let mut last = String::new();
            loop {
                let current = format!("{:?}", *status_handle.lock().await);
                if current != last {
                    let _ = status_app.emit("connection-status", &current);
                    last = current;
                }
                tokio::time::sleep(std::time::Duration::from_millis(500)).await;
            }
        });

        // Start the background message listener.
        let inbound_rx = client.inbound_rx.clone();
        let store_ref = self.store.clone();
        let ws_ref = self.ws_client.clone();
        let user_id = identity.user_id;
        let device_id = identity.device_id;

        tokio::spawn(async move {
            message_listener(
                inbound_rx, store_ref, ws_ref, user_id, device_id, app_handle,
            )
            .await;
        });

        *self.ws_client.lock().await = Some(client);
        info!("Relay connection initiated");

        // Auto-upload pre-keys to relay after connection is established.
        let store_for_prekeys = self.store.clone();
        let ws_for_prekeys = self.ws_client.clone();
        tokio::spawn(async move {
            // Wait for connection to be authenticated.
            for _ in 0..60 {
                tokio::time::sleep(std::time::Duration::from_millis(500)).await;
                let ws = ws_for_prekeys.lock().await;
                if let Some(client) = ws.as_ref() {
                    let status = client.connection_status().await;
                    if matches!(status, ConnectionStatus::Connected) {
                        drop(ws);
                        // Upload pre-keys.
                        if let Err(e) =
                            auto_upload_prekeys(store_for_prekeys.clone(), ws_for_prekeys.clone())
                                .await
                        {
                            error!("Failed to auto-upload pre-keys: {e}");
                        }
                        return;
                    }
                }
            }
            warn!("Timed out waiting for connection to upload pre-keys");
        });

        Ok(())
    }

    /// Send a ClientMessage through the WebSocket.
    pub async fn send_message(
        &self,
        msg: ClientMessage,
    ) -> Result<(), crate::ws_client::WsClientError> {
        let ws = self.ws_client.lock().await;
        match ws.as_ref() {
            Some(client) => client.send(msg).await,
            None => Err(crate::ws_client::WsClientError::NotConnected),
        }
    }

    /// Disconnect from the relay.
    pub async fn disconnect(&self) {
        let mut ws = self.ws_client.lock().await;
        if let Some(client) = ws.take() {
            client.shutdown();
            info!("Disconnected from relay");
        }
    }
}

// ---------------------------------------------------------------------------
// Background message listener
// ---------------------------------------------------------------------------

/// Auto-upload pre-keys to the relay after authentication.
async fn auto_upload_prekeys(
    store: Arc<Mutex<Store>>,
    ws_client: Arc<Mutex<Option<WsClient>>>,
) -> Result<(), String> {
    let store_guard = store.lock().await;
    let identity = store_guard
        .load_identity()
        .map_err(|e| e.to_string())?
        .ok_or_else(|| "no identity".to_string())?;

    let existing_count = store_guard.prekey_count().map_err(|e| e.to_string())?;
    if existing_count == 0 {
        info!("No pre-keys to upload (they may have already been uploaded)");
        // Generate a fresh batch.
    }

    // Generate a new batch of OTPs.
    let next_id = store_guard.next_prekey_id().map_err(|e| e.to_string())?;
    let (otpks, otpk_privates) = generate_one_time_pre_keys(next_id, 100);
    for opk in &otpk_privates {
        store_guard
            .save_prekey(opk.id, &opk.secret.to_bytes())
            .map_err(|e| e.to_string())?;
    }

    // Reconstruct device identity.
    let device_sk_bytes: [u8; 32] = identity
        .signing_key
        .as_slice()
        .try_into()
        .map_err(|_| "invalid signing key".to_string())?;
    let xk_bytes: [u8; 32] = identity
        .exchange_secret
        .as_slice()
        .try_into()
        .map_err(|_| "invalid exchange key".to_string())?;

    let device = reconstruct_device_identity(identity.device_id, &device_sk_bytes, &xk_bytes);

    // Generate signed pre-key.
    let spk_id = store_guard
        .next_signed_prekey_id()
        .map_err(|e| e.to_string())?;
    let (spk_public, spk_sig, spk_private) = generate_signed_pre_key(&device, spk_id);
    store_guard
        .save_signed_prekey(spk_id, &spk_private.secret.to_bytes())
        .map_err(|e| e.to_string())?;

    // Root exchange public key.
    let root_xk_bytes: [u8; 32] = identity
        .root_exchange_secret
        .as_slice()
        .try_into()
        .map_err(|_| "invalid root exchange key".to_string())?;
    let root_xs = X25519StaticSecret::from(root_xk_bytes);
    let root_xp = x25519_dalek::PublicKey::from(&root_xs);

    let bundle = build_pre_key_bundle(
        &device,
        identity.user_id,
        *root_xp.as_bytes(),
        spk_id,
        spk_public,
        spk_sig,
        otpks,
    );
    drop(store_guard);

    // Send to relay.
    let ws = ws_client.lock().await;
    if let Some(client) = ws.as_ref() {
        client
            .send(ClientMessage::UploadPreKeys(bundle))
            .await
            .map_err(|e| e.to_string())?;
        info!("Auto-uploaded {} pre-keys to relay", otpk_privates.len());
    } else {
        return Err("WebSocket not connected".into());
    }

    Ok(())
}

/// Reconstruct a DeviceIdentity from stored key bytes.
fn reconstruct_device_identity(
    device_id: DeviceId,
    signing_key_bytes: &[u8; 32],
    exchange_secret_bytes: &[u8; 32],
) -> cipherline_common::identity::DeviceIdentity {
    let signing_key = SigningKey::from_bytes(signing_key_bytes);
    let exchange_secret = X25519StaticSecret::from(*exchange_secret_bytes);
    cipherline_common::identity::DeviceIdentity {
        device_id,
        signing_key,
        exchange_secret,
    }
}

/// Listens for inbound `ServerMessage`s from the relay:
/// - `Deliver(envelope)` → load DR session → decrypt → store → emit event
/// - `DeliverInitialMessage` → x3dh_respond → init DR → decrypt → store → emit
/// - `PreKeys(bundle)` → x3dh_initiate → init DR sender → save session → emit
/// - `PreKeyCount` → replenish pre-keys if low
/// - Other messages → log and ignore
async fn message_listener(
    inbound_rx: Arc<Mutex<crate::ws_client::InboundReceiver>>,
    store: Arc<Mutex<Store>>,
    ws_client: Arc<Mutex<Option<WsClient>>>,
    _our_user_id: UserId,
    _our_device_id: DeviceId,
    app_handle: tauri::AppHandle,
) {
    let mut rx = inbound_rx.lock().await;

    while let Some(server_msg) = rx.recv().await {
        match server_msg {
            // ----- Existing session: decrypt with Double Ratchet -----
            ServerMessage::Deliver(envelope) => {
                debug!("Received envelope from {:?}", envelope.sender_id);

                // --- Signature verification ---
                let store_guard = store.lock().await;
                let contact_opt = store_guard.get_contact(&envelope.sender_id).ok().flatten();
                let session_data = store_guard
                    .load_session(&envelope.sender_id, &envelope.sender_device_id)
                    .ok()
                    .flatten();
                drop(store_guard);

                // Verify envelope signature if we have the sender's signing key.
                if let Some(ref contact) = contact_opt {
                    if contact.signing_key != [0u8; 32] {
                        match VerifyingKey::from_bytes(&contact.signing_key) {
                            Ok(vk) => {
                                let signable =
                                    Envelope::signable_data(&envelope.header, &envelope.ciphertext);
                                if let Ok(sig) = Ed25519Signature::from_slice(&envelope.signature) {
                                    if let Err(e) = crypto::verify(&signable, &sig, &vk) {
                                        error!(
                                            "Envelope signature verification FAILED for {:?}: {e}",
                                            envelope.sender_id
                                        );
                                        continue; // Drop the message.
                                    }
                                    debug!(
                                        "Envelope signature verified for {:?}",
                                        envelope.sender_id
                                    );
                                } else {
                                    error!(
                                        "Invalid signature bytes from {:?}, dropping",
                                        envelope.sender_id
                                    );
                                    continue;
                                }
                            }
                            Err(e) => {
                                warn!(
                                    "Could not build verifying key for {:?}: {e}",
                                    envelope.sender_id
                                );
                            }
                        }
                    } else {
                        warn!(
                            "Contact {:?} has no signing key — rejecting message (require verified contact)",
                            envelope.sender_id
                        );
                        continue;
                    }
                } else {
                    warn!(
                        "No contact for {:?} — rejecting unsigned message",
                        envelope.sender_id
                    );
                    continue;
                }

                if let Some(mut session_bytes) = session_data {
                    match rmp_serde::from_slice::<RatchetState>(&session_bytes) {
                        Ok(mut ratchet) => {
                            // Zeroize the serialized ratchet state to avoid residual secrets.
                            session_bytes.zeroize();
                            match ratchet.ratchet_decrypt(&envelope.header, &envelope.ciphertext) {
                                Ok(plaintext) => {
                                    let content = String::from_utf8_lossy(&plaintext).to_string();

                                    let msg = StoredMessage {
                                        id: envelope.message_id.to_string(),
                                        conversation_id: envelope.sender_id.to_string(),
                                        sender_id: envelope.sender_id.0.to_vec(),
                                        sender_device_id: envelope.sender_device_id.0.to_vec(),
                                        timestamp: envelope.timestamp.0,
                                        content: content.clone(),
                                        is_outgoing: false,
                                        read: false,
                                    };

                                    let store_guard = store.lock().await;
                                    if let Ok(ratchet_bytes) = rmp_serde::to_vec(&ratchet) {
                                        let _ = store_guard.save_session(
                                            &envelope.sender_id,
                                            &envelope.sender_device_id,
                                            &ratchet_bytes,
                                        );
                                    }
                                    let _ = store_guard.save_message(&msg);
                                    drop(store_guard);

                                    let _ = app_handle.emit("new-message", &msg);
                                    info!("Decrypted message from {:?}", envelope.sender_id);
                                }
                                Err(e) => {
                                    error!(
                                        "Failed to decrypt message from {:?}: {e}",
                                        envelope.sender_id
                                    );
                                }
                            }
                        }
                        Err(e) => {
                            error!("Failed to deserialize ratchet state: {e}");
                        }
                    }
                } else {
                    warn!(
                        "No session found for sender {:?}/{:?}",
                        envelope.sender_id, envelope.sender_device_id
                    );
                }
            }

            // ----- Initial message: X3DH respond + DR init + decrypt -----
            ServerMessage::DeliverInitialMessage(initial_msg) => {
                info!(
                    "Received initial message from {:?}",
                    initial_msg.envelope.sender_id
                );

                let sender_id = initial_msg.envelope.sender_id;
                let sender_device_id = initial_msg.envelope.sender_device_id;

                // --- Signature verification using the sender's signing key ---
                let sig_ok = match VerifyingKey::from_bytes(&initial_msg.sender_signing_key) {
                    Ok(vk) => {
                        let signable = Envelope::signable_data(
                            &initial_msg.envelope.header,
                            &initial_msg.envelope.ciphertext,
                        );
                        match Ed25519Signature::from_slice(&initial_msg.envelope.signature) {
                            Ok(sig) => {
                                if let Err(e) = crypto::verify(&signable, &sig, &vk) {
                                    error!(
                                        "Initial message signature verification FAILED for {:?}: {e}",
                                        sender_id
                                    );
                                    false
                                } else {
                                    debug!(
                                        "Initial message signature verified for {:?}",
                                        sender_id
                                    );
                                    true
                                }
                            }
                            Err(_) => {
                                error!(
                                    "Invalid signature bytes in initial message from {:?}",
                                    sender_id
                                );
                                false
                            }
                        }
                    }
                    Err(e) => {
                        warn!(
                            "Invalid sender_signing_key in initial message from {:?}: {e}",
                            sender_id
                        );
                        false
                    }
                };

                if !sig_ok {
                    error!(
                        "Dropping initial message from {:?} — signature invalid",
                        sender_id
                    );
                    continue;
                }

                let result = handle_initial_message(&store, &initial_msg).await;
                match result {
                    Ok((plaintext, ratchet)) => {
                        let content = String::from_utf8_lossy(&plaintext).to_string();

                        let msg = StoredMessage {
                            id: initial_msg.envelope.message_id.to_string(),
                            conversation_id: sender_id.to_string(),
                            sender_id: sender_id.0.to_vec(),
                            sender_device_id: sender_device_id.0.to_vec(),
                            timestamp: initial_msg.envelope.timestamp.0,
                            content: content.clone(),
                            is_outgoing: false,
                            read: false,
                        };

                        let store_guard = store.lock().await;

                        // Save the DR session.
                        if let Ok(ratchet_bytes) = rmp_serde::to_vec(&ratchet) {
                            let _ = store_guard.save_session(
                                &sender_id,
                                &sender_device_id,
                                &ratchet_bytes,
                            );
                        }

                        // Save the message.
                        let _ = store_guard.save_message(&msg);

                        // Auto-create contact if not already known.
                        if store_guard.get_contact(&sender_id).ok().flatten().is_none() {
                            let contact = StoredContact {
                                user_id: sender_id,
                                display_name: sender_id.to_string(),
                                signing_key: initial_msg.sender_signing_key,
                                exchange_key: initial_msg.x3dh_header.identity_key,
                                added_at: Timestamp::now().0,
                            };
                            let _ = store_guard.save_contact(&contact);
                            info!("Auto-created contact for {:?}", sender_id);
                        }

                        drop(store_guard);

                        let _ = app_handle.emit("new-message", &msg);
                        info!(
                            "Processed initial message from {:?}: \"{}\"",
                            sender_id, content
                        );
                    }
                    Err(e) => {
                        error!(
                            "Failed to process initial message from {:?}: {e}",
                            sender_id
                        );
                    }
                }
            }

            // ----- Pre-key bundle response: X3DH initiate + DR init -----
            ServerMessage::PreKeys(bundle) => {
                info!(
                    "Received pre-key bundle for {:?}/{:?}",
                    bundle.user_id, bundle.device_id
                );

                let result = handle_prekey_bundle(&store, &bundle).await;
                match result {
                    Ok(()) => {
                        info!(
                            "Session established with {:?}/{:?}",
                            bundle.user_id, bundle.device_id
                        );
                        // Notify UI that session is ready.
                        let _ = app_handle.emit(
                            "session-established",
                            &serde_json::json!({
                                "user_id": bundle.user_id.to_string(),
                                "device_id": bundle.device_id.to_string(),
                            }),
                        );
                    }
                    Err(e) => {
                        error!("Failed to establish session with {:?}: {e}", bundle.user_id);
                    }
                }
            }

            ServerMessage::PreKeyCount { remaining } => {
                debug!("Pre-key count on relay: {remaining}");
                if remaining < 10 {
                    warn!("Pre-key count low ({remaining}), auto-replenishing");
                    let _ = app_handle.emit("prekey-low", remaining);

                    // Auto-replenish pre-keys in background.
                    let store_clone = store.clone();
                    let ws_clone = ws_client.clone();
                    tokio::spawn(async move {
                        if let Err(e) = auto_upload_prekeys(store_clone, ws_clone).await {
                            error!("Failed to auto-replenish pre-keys: {e}");
                        } else {
                            info!("Auto-replenished pre-keys on relay");
                        }
                    });
                }
            }

            ServerMessage::Ack(message_id) => {
                debug!("Relay ACK for message {message_id}");
            }

            ServerMessage::DeviceRevoked(revocation) => {
                warn!("Device revoked: {:?}", revocation.revoked_device_id);

                // If this is one of our own devices, mark it inactive locally.
                let store_guard = store.lock().await;
                let _ = store_guard.revoke_device(&revocation.revoked_device_id);
                drop(store_guard);

                let _ =
                    app_handle.emit("device-revoked", &revocation.revoked_device_id.to_string());
            }

            // ----- Device list response: store contact devices -----
            ServerMessage::DeviceList(device_list) => {
                info!(
                    "Received device list for {:?} ({} devices)",
                    device_list.user_id,
                    device_list.devices.len()
                );

                // Verify the device list signature using the contact's signing key.
                let store_guard = store.lock().await;
                let contact_opt = store_guard.get_contact(&device_list.user_id).ok().flatten();

                if let Some(contact) = contact_opt {
                    if contact.signing_key != [0u8; 32] {
                        match VerifyingKey::from_bytes(&contact.signing_key) {
                            Ok(vk) => {
                                if let Err(e) = verify_signed_device_list(&device_list, &vk) {
                                    error!(
                                        "Device list signature verification FAILED for {:?}: {e}",
                                        device_list.user_id
                                    );
                                    drop(store_guard);
                                    continue;
                                }
                                debug!(
                                    "Device list signature verified for {:?}",
                                    device_list.user_id
                                );
                            }
                            Err(e) => {
                                warn!(
                                    "Could not build verifying key for device list from {:?}: {e}",
                                    device_list.user_id
                                );
                            }
                        }
                    }
                }

                // Update stored contact devices.
                let device_entries: Vec<_> = device_list
                    .devices
                    .iter()
                    .map(|d| (d.device_id, d.signing_key, d.exchange_key, d.active))
                    .collect();
                let _ = store_guard.replace_contact_devices(&device_list.user_id, &device_entries);

                // Delete sessions for devices that are no longer active.
                for d in &device_list.devices {
                    if !d.active {
                        let _ = store_guard.delete_session(&device_list.user_id, &d.device_id);
                    }
                }

                drop(store_guard);

                let _ = app_handle.emit(
                    "device-list-updated",
                    &serde_json::json!({
                        "user_id": device_list.user_id.to_string(),
                        "device_count": device_list.devices.len(),
                    }),
                );
            }

            ServerMessage::Error { code, message } => {
                error!("Server error: {code:?} — {message}");
            }

            other => {
                debug!("Unhandled server message: {other:?}");
            }
        }
    }

    info!("Message listener ended");
}

// ---------------------------------------------------------------------------
// X3DH handlers
// ---------------------------------------------------------------------------

/// Handle an incoming initial message (we are the responder / Bob).
///
/// 1. Load our identity (X25519 root exchange secret).
/// 2. Load the signed pre-key secret referenced by the header.
/// 3. Load (and consume) the one-time pre-key if referenced.
/// 4. Compute X3DH shared secret via `x3dh_respond`.
/// 5. Init DR as receiver, decrypt the first message.
async fn handle_initial_message(
    store: &Arc<Mutex<Store>>,
    initial_msg: &InitialMessage,
) -> Result<(Vec<u8>, RatchetState), String> {
    let store_guard = store.lock().await;

    let identity = store_guard
        .load_identity()
        .map_err(|e| e.to_string())?
        .ok_or_else(|| "no identity".to_string())?;

    // Our root X25519 exchange secret.
    let root_xk_bytes: [u8; 32] = identity
        .root_exchange_secret
        .as_slice()
        .try_into()
        .map_err(|_| "invalid root exchange key")?;
    let our_identity_exchange = X25519StaticSecret::from(root_xk_bytes);

    // Load the signed pre-key secret.
    // The header doesn't carry the SPK ID directly, so we try recent SPK IDs.
    // After rotation, we keep old SPKs for a grace period.
    let max_spk_id = store_guard
        .next_signed_prekey_id()
        .map_err(|e| e.to_string())?;

    let mut spk_secret_opt: Option<X25519StaticSecret> = None;
    // Try from the latest SPK down to 0.
    for id in (0..max_spk_id).rev() {
        if let Some(spk_bytes) = store_guard
            .load_signed_prekey(id)
            .map_err(|e| e.to_string())?
        {
            let arr: [u8; 32] = spk_bytes
                .as_slice()
                .try_into()
                .map_err(|_| "invalid SPK secret")?;
            spk_secret_opt = Some(X25519StaticSecret::from(arr));
            break;
        }
    }
    let our_spk_secret = spk_secret_opt.ok_or_else(|| "no signed pre-key found".to_string())?;

    // Load and consume the one-time pre-key, if referenced by the header.
    let our_opk_secret = if let Some(opk_id) = initial_msg.x3dh_header.one_time_pre_key_id {
        let opk_bytes = store_guard
            .consume_prekey(opk_id)
            .map_err(|e| e.to_string())?
            .ok_or_else(|| format!("one-time pre-key {opk_id} not found or already consumed"))?;
        let opk_arr: [u8; 32] = opk_bytes
            .as_slice()
            .try_into()
            .map_err(|_| "invalid OPK secret")?;
        Some(X25519StaticSecret::from(opk_arr))
    } else {
        None
    };

    drop(store_guard);

    // Compute X3DH shared secret.
    let shared_secret = x3dh_respond(
        &our_identity_exchange,
        &our_spk_secret,
        our_opk_secret.as_ref(),
        &initial_msg.x3dh_header,
    )
    .map_err(|e| format!("x3dh_respond failed: {e}"))?;

    // Initialize Double Ratchet as receiver.
    // Bob uses his SPK as the initial ratchet keypair.
    let mut ratchet = RatchetState::init_receiver(shared_secret, our_spk_secret);

    // Decrypt the first message.
    let plaintext = ratchet
        .ratchet_decrypt(
            &initial_msg.envelope.header,
            &initial_msg.envelope.ciphertext,
        )
        .map_err(|e| format!("failed to decrypt initial message: {e}"))?;

    Ok((plaintext, ratchet))
}

/// Handle a received pre-key bundle (we are the initiator / Alice).
///
/// 1. Load our identity (X25519 root exchange secret + public).
/// 2. Perform X3DH initiation against the bundle.
/// 3. Init DR as sender.
/// 4. Save the session (no message is sent yet — `send_message` will use it).
async fn handle_prekey_bundle(
    store: &Arc<Mutex<Store>>,
    bundle: &cipherline_common::identity::PreKeyBundle,
) -> Result<(), String> {
    let store_guard = store.lock().await;

    let identity = store_guard
        .load_identity()
        .map_err(|e| e.to_string())?
        .ok_or_else(|| "no identity".to_string())?;

    // Our root X25519 exchange secret and public key.
    let root_xk_bytes: [u8; 32] = identity
        .root_exchange_secret
        .as_slice()
        .try_into()
        .map_err(|_| "invalid root exchange key")?;
    let our_identity_exchange = X25519StaticSecret::from(root_xk_bytes);
    let our_identity_public = *x25519_dalek::PublicKey::from(&our_identity_exchange).as_bytes();

    // Verify the signed pre-key signature before trusting the bundle.
    let spk_vk = VerifyingKey::from_bytes(&bundle.identity_signing_key)
        .map_err(|_| "invalid identity signing key in bundle".to_string())?;
    let spk_sig_bytes: [u8; 64] = bundle
        .signed_pre_key_signature
        .as_slice()
        .try_into()
        .map_err(|_| "invalid SPK signature length".to_string())?;
    let spk_sig = Ed25519Signature::from_bytes(&spk_sig_bytes);
    crypto::verify(&bundle.signed_pre_key, &spk_sig, &spk_vk)
        .map_err(|_| "SPK signature verification failed — possible MITM".to_string())?;

    // Perform X3DH initiation.
    let x3dh_result = x3dh_initiate(&our_identity_exchange, &our_identity_public, bundle)
        .map_err(|e| format!("x3dh_initiate failed: {e}"))?;

    // Initialize Double Ratchet as sender.
    // Alice uses Bob's signed pre-key as the initial their_ratchet_public.
    let ratchet = RatchetState::init_sender(x3dh_result.shared_secret, bundle.signed_pre_key)
        .map_err(|e| format!("DR init_sender failed: {e}"))?;

    // Save the session. Use the bundle's device_id as contact device id.
    let ratchet_bytes = rmp_serde::to_vec(&ratchet).map_err(|e| e.to_string())?;
    store_guard
        .save_session(&bundle.user_id, &bundle.device_id, &ratchet_bytes)
        .map_err(|e| e.to_string())?;

    // Also persist the X3DH header so send_message can build an InitialMessage
    // for the first message to this contact.
    // We store it as a special "pending_x3dh_header" in the session metadata.
    // For simplicity, we'll save it as a separate key in the prekey table with a known ID.
    let header_bytes = rmp_serde::to_vec(&x3dh_result.header).map_err(|e| e.to_string())?;
    // Use a magic ID based on the contact's user_id hash to store the pending header.
    let header_key = format!("x3dh_header_{}", bundle.user_id);
    store_guard
        .set_metadata(&header_key, &header_bytes)
        .map_err(|e| e.to_string())?;

    // Update the contact's signing_key and exchange_key if we have a stored contact.
    if let Ok(Some(mut contact)) = store_guard.get_contact(&bundle.user_id) {
        contact.signing_key = bundle.identity_signing_key;
        contact.exchange_key = bundle.identity_exchange_key;
        let _ = store_guard.save_contact(&contact);
    }

    drop(store_guard);

    info!(
        "X3DH session established with {:?}/{:?}",
        bundle.user_id, bundle.device_id
    );

    Ok(())
}
