//! Tauri IPC command handlers.
//!
//! All functions here are registered via `tauri::generate_handler![]` and
//! callable from the React frontend via `@tauri-apps/api invoke()`.

use ed25519_dalek::SigningKey;
use serde::Serialize;
use tauri::State;
use tracing::{info, warn};
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret as X25519StaticSecret};

use cipherline_common::crypto;
use cipherline_common::identity::{
    build_pre_key_bundle, build_signed_device_list, generate_one_time_pre_keys,
    generate_signed_pre_key, DeviceIdentity, DeviceListEntry, RootIdentity,
};
use cipherline_common::protocol::{ClientMessage, DeviceRevocation, Envelope, InitialMessage};
use cipherline_common::ratchet::RatchetState;
use cipherline_common::types::{DeviceId, MessageId, Timestamp, UserId, PROTOCOL_VERSION};

use crate::state::AppState;
use crate::store::{StoredContact, StoredDevice, StoredIdentity, StoredMessage};

// ---------------------------------------------------------------------------
// Response types (returned to the frontend as JSON)
// ---------------------------------------------------------------------------

#[derive(Serialize, Debug)]
pub struct IdentityInfo {
    pub user_id: String,
    pub device_id: String,
    pub signing_key: String,
    pub exchange_key: String,
    pub created_at: u64,
    pub has_identity: bool,
}

#[derive(Serialize, Debug)]
pub struct ContactInfo {
    pub user_id: String,
    pub display_name: String,
    pub added_at: u64,
}

#[derive(Serialize, Debug)]
pub struct MessageInfo {
    pub id: String,
    pub conversation_id: String,
    pub content: String,
    pub timestamp: u64,
    pub is_outgoing: bool,
    pub read: bool,
}

#[derive(Serialize, Debug)]
pub struct DeviceInfo {
    pub device_id: String,
    pub is_current: bool,
    pub active: bool,
    pub created_at: u64,
}

#[derive(Serialize, Debug)]
pub struct StatusInfo {
    pub connection: String,
    pub has_identity: bool,
    pub prekey_count: u32,
    pub relay_url: String,
}

// ---------------------------------------------------------------------------
// Error type for commands
// ---------------------------------------------------------------------------

#[derive(Debug, thiserror::Error)]
pub enum CommandError {
    #[error("{0}")]
    Store(#[from] crate::store::StoreError),

    #[error("{0}")]
    Protocol(String),

    #[error("{0}")]
    Crypto(String),

    #[error("{0}")]
    WebSocket(#[from] crate::ws_client::WsClientError),

    #[error("{0}")]
    Other(String),
}

// Tauri commands must return a serializable error type.
impl Serialize for CommandError {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&self.to_string())
    }
}

impl From<cipherline_common::types::CipherlineError> for CommandError {
    fn from(e: cipherline_common::types::CipherlineError) -> Self {
        CommandError::Protocol(e.to_string())
    }
}

// ---------------------------------------------------------------------------
// Commands
// ---------------------------------------------------------------------------

/// Generate a new root identity + first device. Stores keys in DB, uploads
/// pre-keys to the relay.
#[tauri::command]
pub async fn create_identity(state: State<'_, AppState>) -> Result<IdentityInfo, CommandError> {
    // Check if identity already exists.
    if state.has_identity().await {
        // Return existing identity.
        return get_identity(state).await;
    }

    info!("Creating new identity");

    // Generate root identity.
    let root = RootIdentity::generate();
    let user_id = root.user_id();
    let root_public = root.to_public();

    // Generate first device.
    let (device, certificate) = DeviceIdentity::generate(&root);
    let device_id = device.device_id;

    // Generate signed pre-key.
    let spk_id = 0u32;
    let (_spk_public, _spk_sig, spk_private) = generate_signed_pre_key(&device, spk_id);

    // Generate one-time pre-keys (batch of 100).
    let (_otpks, otpk_privates) = generate_one_time_pre_keys(0, 100);

    // Serialize the certificate for storage.
    let cert_bytes =
        rmp_serde::to_vec(&certificate).map_err(|e| CommandError::Other(e.to_string()))?;

    // Store identity in DB.
    let stored_identity = StoredIdentity {
        user_id,
        device_id,
        signing_key: device.signing_key.to_bytes().to_vec(),
        exchange_secret: device.exchange_secret.to_bytes().to_vec(),
        root_signing_key: root.signing_key.to_bytes().to_vec(),
        root_exchange_secret: root.exchange_secret.to_bytes().to_vec(),
        certificate: cert_bytes,
        created_at: Timestamp::now().0,
    };

    let store = state.store.lock().await;

    store.save_identity(&stored_identity)?;

    // Store device record.
    store.save_device(&StoredDevice {
        device_id,
        signing_key: device.verifying_key().to_bytes(),
        exchange_key: *device.exchange_public_key().as_bytes(),
        is_current: true,
        active: true,
        created_at: stored_identity.created_at,
    })?;

    // Store pre-key secrets.
    store.save_signed_prekey(spk_id, &spk_private.secret.to_bytes())?;
    for opk in &otpk_privates {
        store.save_prekey(opk.id, &opk.secret.to_bytes())?;
    }

    drop(store);

    // Update cached identity.
    *state.user_id.lock().await = Some(user_id);
    *state.device_id.lock().await = Some(device_id);

    info!("Identity created: {:?}", user_id);

    Ok(IdentityInfo {
        user_id: user_id.to_string(),
        device_id: device_id.to_string(),
        signing_key: base64::Engine::encode(
            &base64::engine::general_purpose::STANDARD,
            root_public.signing_key,
        ),
        exchange_key: base64::Engine::encode(
            &base64::engine::general_purpose::STANDARD,
            root_public.exchange_key,
        ),
        created_at: stored_identity.created_at,
        has_identity: true,
    })
}

/// Return the current identity info (or a "no identity" response).
#[tauri::command]
pub async fn get_identity(state: State<'_, AppState>) -> Result<IdentityInfo, CommandError> {
    let store = state.store.lock().await;
    match store.load_identity()? {
        Some(identity) => {
            // Derive public keys from stored private keys.
            let sk_bytes: [u8; 32] = identity
                .root_signing_key
                .as_slice()
                .try_into()
                .map_err(|_| CommandError::Crypto("invalid key".into()))?;
            let root_sk = SigningKey::from_bytes(&sk_bytes);
            let root_vk = root_sk.verifying_key();

            let xk_bytes: [u8; 32] = identity
                .root_exchange_secret
                .as_slice()
                .try_into()
                .map_err(|_| CommandError::Crypto("invalid key".into()))?;
            let root_xs = X25519StaticSecret::from(xk_bytes);
            let root_xp = X25519PublicKey::from(&root_xs);

            Ok(IdentityInfo {
                user_id: identity.user_id.to_string(),
                device_id: identity.device_id.to_string(),
                signing_key: base64::Engine::encode(
                    &base64::engine::general_purpose::STANDARD,
                    root_vk.to_bytes(),
                ),
                exchange_key: base64::Engine::encode(
                    &base64::engine::general_purpose::STANDARD,
                    root_xp.to_bytes(),
                ),
                created_at: identity.created_at,
                has_identity: true,
            })
        }
        None => Ok(IdentityInfo {
            user_id: String::new(),
            device_id: String::new(),
            signing_key: String::new(),
            exchange_key: String::new(),
            created_at: 0,
            has_identity: false,
        }),
    }
}

/// Connect to the relay server.
#[tauri::command]
pub async fn connect_relay(
    state: State<'_, AppState>,
    app_handle: tauri::AppHandle,
) -> Result<(), CommandError> {
    state.connect_to_relay(app_handle).await?;
    Ok(())
}

/// Get connection status.
#[tauri::command]
pub async fn get_status(state: State<'_, AppState>) -> Result<StatusInfo, CommandError> {
    let conn_status = state.connection_status().await;
    let has_identity = state.has_identity().await;
    let store = state.store.lock().await;
    let prekey_count = store.prekey_count()?;

    Ok(StatusInfo {
        connection: format!("{:?}", conn_status),
        has_identity,
        prekey_count,
        relay_url: state.relay_url.clone(),
    })
}

/// Add a contact. In a full implementation this would fetch pre-keys
/// from the relay and initiate an X3DH session.
#[tauri::command]
pub async fn add_contact(
    state: State<'_, AppState>,
    user_id_hex: String,
    display_name: String,
) -> Result<ContactInfo, CommandError> {
    // Parse hex user_id.
    let uid_bytes = hex_decode(&user_id_hex)
        .map_err(|e| CommandError::Other(format!("invalid user_id hex: {e}")))?;
    if uid_bytes.len() != 32 {
        return Err(CommandError::Other("user_id must be 32 bytes".into()));
    }
    let mut uid = [0u8; 32];
    uid.copy_from_slice(&uid_bytes);
    let user_id = UserId(uid);

    let now = Timestamp::now().0;

    let contact = StoredContact {
        user_id,
        display_name: display_name.clone(),
        // These will be populated when we fetch pre-keys and establish a session.
        signing_key: [0u8; 32],
        exchange_key: [0u8; 32],
        added_at: now,
    };

    let store = state.store.lock().await;
    store.save_contact(&contact)?;
    drop(store);

    info!("Contact added: {display_name} ({:?})", user_id);

    // Automatically fetch pre-keys to establish a session.
    if let Err(e) = state
        .send_message(ClientMessage::FetchPreKeys {
            user_id,
            device_id: None,
        })
        .await
    {
        warn!("Failed to fetch pre-keys for new contact: {e}");
        // Non-fatal: session will be established when pre-keys are fetched later.
    } else {
        info!("Requested pre-keys for new contact {:?}", user_id);
    }

    Ok(ContactInfo {
        user_id: user_id_hex,
        display_name,
        added_at: now,
    })
}

/// List all contacts.
#[tauri::command]
pub async fn get_contacts(state: State<'_, AppState>) -> Result<Vec<ContactInfo>, CommandError> {
    let store = state.store.lock().await;
    let contacts = store.list_contacts()?;

    Ok(contacts
        .into_iter()
        .map(|c| ContactInfo {
            user_id: c.user_id.to_string(),
            display_name: c.display_name,
            added_at: c.added_at,
        })
        .collect())
}

/// Send an encrypted message to a contact.
///
/// Loads DR sessions for all known devices, encrypts via ratchet per-device,
/// signs each envelope, and sends through the relay WebSocket (fan-out).
#[tauri::command]
pub async fn send_message(
    state: State<'_, AppState>,
    contact_id: String,
    text: String,
) -> Result<MessageInfo, CommandError> {
    // Parse contact user_id.
    let uid_bytes = hex_decode(&contact_id)
        .map_err(|e| CommandError::Other(format!("invalid contact_id hex: {e}")))?;
    if uid_bytes.len() != 32 {
        return Err(CommandError::Other("contact_id must be 32 bytes".into()));
    }
    let mut uid = [0u8; 32];
    uid.copy_from_slice(&uid_bytes);
    let contact_user_id = UserId(uid);

    // Load our identity.
    let store = state.store.lock().await;
    let identity = store
        .load_identity()?
        .ok_or_else(|| CommandError::Other("no identity".into()))?;

    let _contact = store
        .get_contact(&contact_user_id)?
        .ok_or_else(|| CommandError::Other("contact not found".into()))?;

    // Find ALL sessions with this contact (multi-device fan-out).
    let all_sessions = store.find_all_sessions(&contact_user_id)?;

    if all_sessions.is_empty() {
        return Err(CommandError::Other(
            "no session with contact — add contact and wait for session to be established".into(),
        ));
    }

    // Check if we have a pending X3DH header (first message scenario).
    // Pending headers are keyed per-contact (the first session established).
    let header_key = format!("x3dh_header_{}", contact_user_id);
    let pending_x3dh_header_bytes = store.get_metadata(&header_key)?;
    drop(store);

    // Prepare signing key.
    let device_sk_bytes: [u8; 32] = identity
        .signing_key
        .as_slice()
        .try_into()
        .map_err(|_| CommandError::Crypto("invalid key".into()))?;
    let device_sk = SigningKey::from_bytes(&device_sk_bytes);

    // We use a single message_id and timestamp for all copies (same logical message).
    let message_id = MessageId::generate();
    let timestamp = Timestamp::now();

    // Encrypt and send to each device session.
    let mut sent_count = 0u32;
    for (contact_device_id, session_bytes) in &all_sessions {
        let mut ratchet: RatchetState = match rmp_serde::from_slice(session_bytes) {
            Ok(r) => r,
            Err(e) => {
                warn!(
                    "Failed to deserialize ratchet for device {:?}: {e}",
                    contact_device_id
                );
                continue;
            }
        };

        let (header, ciphertext) = match ratchet.ratchet_encrypt(text.as_bytes()) {
            Ok(pair) => pair,
            Err(e) => {
                warn!("Failed to encrypt for device {:?}: {e}", contact_device_id);
                continue;
            }
        };

        // Sign the per-device envelope.
        let signable = Envelope::signable_data(&header, &ciphertext);
        let signature = crypto::sign(&signable, &device_sk);

        let envelope = Envelope {
            version: PROTOCOL_VERSION,
            sender_id: identity.user_id,
            sender_device_id: identity.device_id,
            recipient_id: contact_user_id,
            recipient_device_id: *contact_device_id,
            message_id,
            timestamp,
            header,
            ciphertext,
            signature: signature.to_bytes().to_vec(),
        };

        // First message to this device gets the X3DH header (InitialMessage).
        // For fan-out, only the device that triggered X3DH gets the initial msg.
        let is_initial = pending_x3dh_header_bytes.is_some() && sent_count == 0;
        if is_initial {
            if let Some(ref x3dh_bytes) = pending_x3dh_header_bytes {
                match rmp_serde::from_slice::<cipherline_common::ratchet::X3DHHeader>(x3dh_bytes) {
                    Ok(x3dh_header) => {
                        let initial = InitialMessage {
                            version: PROTOCOL_VERSION,
                            x3dh_header,
                            sender_signing_key: device_sk.verifying_key().to_bytes(),
                            envelope,
                        };
                        if let Err(e) = state
                            .send_message(ClientMessage::SendInitialMessage(initial))
                            .await
                        {
                            warn!(
                                "Failed to send initial message to {:?}: {e}",
                                contact_device_id
                            );
                            continue;
                        }
                    }
                    Err(e) => {
                        warn!("Failed to deserialize X3DH header: {e}");
                        // Fall through to regular send.
                        if let Err(e) = state
                            .send_message(ClientMessage::SendEnvelope(envelope))
                            .await
                        {
                            warn!("Failed to send envelope to {:?}: {e}", contact_device_id);
                            continue;
                        }
                    }
                }
            }
        } else {
            // Regular message with existing session.
            if let Err(e) = state
                .send_message(ClientMessage::SendEnvelope(envelope))
                .await
            {
                warn!("Failed to send envelope to {:?}: {e}", contact_device_id);
                continue;
            }
        }

        // Save updated ratchet state for this device.
        let store = state.store.lock().await;
        if let Ok(ratchet_bytes) = rmp_serde::to_vec(&ratchet) {
            let _ = store.save_session(&contact_user_id, contact_device_id, &ratchet_bytes);
        }
        drop(store);

        sent_count += 1;
    }

    if sent_count == 0 {
        return Err(CommandError::Other("failed to send to any device".into()));
    }

    // Remove pending X3DH header after first message sent.
    if pending_x3dh_header_bytes.is_some() {
        let store = state.store.lock().await;
        let _ = store.delete_metadata(&header_key);
        drop(store);
    }

    info!(
        "Sent message to {:?} ({} device(s))",
        contact_user_id, sent_count
    );

    // Save sent message locally (once — same logical message).
    let store = state.store.lock().await;
    let msg = StoredMessage {
        id: message_id.to_string(),
        conversation_id: contact_id.clone(),
        sender_id: identity.user_id.0.to_vec(),
        sender_device_id: identity.device_id.0.to_vec(),
        timestamp: timestamp.0,
        content: text.clone(),
        is_outgoing: true,
        read: true,
    };
    store.save_message(&msg)?;

    Ok(MessageInfo {
        id: message_id.to_string(),
        conversation_id: contact_id,
        content: text,
        timestamp: timestamp.0,
        is_outgoing: true,
        read: true,
    })
}

/// Get messages for a conversation.
#[tauri::command]
pub async fn get_messages(
    state: State<'_, AppState>,
    conversation_id: String,
    limit: Option<u32>,
    offset: Option<u32>,
) -> Result<Vec<MessageInfo>, CommandError> {
    let store = state.store.lock().await;
    let messages =
        store.get_messages(&conversation_id, limit.unwrap_or(100), offset.unwrap_or(0))?;

    Ok(messages
        .into_iter()
        .map(|m| MessageInfo {
            id: m.id,
            conversation_id: m.conversation_id,
            content: m.content,
            timestamp: m.timestamp,
            is_outgoing: m.is_outgoing,
            read: m.read,
        })
        .collect())
}

/// Mark a conversation as read.
#[tauri::command]
pub async fn mark_read(
    state: State<'_, AppState>,
    conversation_id: String,
) -> Result<(), CommandError> {
    let store = state.store.lock().await;
    store.mark_conversation_read(&conversation_id)?;
    Ok(())
}

/// List all our linked devices.
#[tauri::command]
pub async fn list_devices(state: State<'_, AppState>) -> Result<Vec<DeviceInfo>, CommandError> {
    let store = state.store.lock().await;
    let devices = store.list_devices()?;

    Ok(devices
        .into_iter()
        .map(|d| DeviceInfo {
            device_id: d.device_id.to_string(),
            is_current: d.is_current,
            active: d.active,
            created_at: d.created_at,
        })
        .collect())
}

/// Revoke a device and propagate to the relay.
#[tauri::command]
pub async fn revoke_device(
    state: State<'_, AppState>,
    device_id_hex: String,
) -> Result<(), CommandError> {
    let did_bytes = hex_decode(&device_id_hex)
        .map_err(|e| CommandError::Other(format!("invalid device_id hex: {e}")))?;
    if did_bytes.len() != 16 {
        return Err(CommandError::Other("device_id must be 16 bytes".into()));
    }
    let mut did = [0u8; 16];
    did.copy_from_slice(&did_bytes);
    let device_id = DeviceId(did);

    let store = state.store.lock().await;
    let identity = store
        .load_identity()?
        .ok_or_else(|| CommandError::Other("no identity".into()))?;

    // Mark locally revoked.
    store.revoke_device(&device_id)?;

    // Build revocation message signed by root identity.
    let root_sk_bytes: [u8; 32] = identity
        .root_signing_key
        .as_slice()
        .try_into()
        .map_err(|_| CommandError::Crypto("invalid root key".into()))?;
    let root_sk = SigningKey::from_bytes(&root_sk_bytes);

    let timestamp = Timestamp::now();
    // Build signable payload: version || user_id || revoked_device_id || timestamp
    let mut rev_payload = Vec::new();
    rev_payload.push(PROTOCOL_VERSION);
    rev_payload.extend_from_slice(&identity.user_id.0);
    rev_payload.extend_from_slice(&device_id.0);
    rev_payload.extend_from_slice(&timestamp.0.to_le_bytes());
    let rev_signature = crypto::sign(&rev_payload, &root_sk);

    let revocation = DeviceRevocation {
        version: PROTOCOL_VERSION,
        user_id: identity.user_id,
        revoked_device_id: device_id,
        timestamp,
        signature: rev_signature.to_bytes().to_vec(),
    };

    // Build updated signed device list.
    let devices = store.list_devices()?;
    let entries: Vec<DeviceListEntry> = devices
        .iter()
        .map(|d| DeviceListEntry {
            device_id: d.device_id,
            signing_key: d.signing_key,
            exchange_key: d.exchange_key,
            active: d.active,
        })
        .collect();
    drop(store);

    let _device_list = build_signed_device_list(&root_sk, identity.user_id, entries);

    // Send revocation to relay.
    if let Err(e) = state
        .send_message(ClientMessage::RevokeDevice(revocation))
        .await
    {
        warn!("Failed to send device revocation to relay: {e}");
        // Non-fatal: local revocation already applied.
    }

    info!("Device revoked: {:?}", device_id);
    Ok(())
}

/// Upload pre-keys to the relay.
#[tauri::command]
pub async fn upload_prekeys(state: State<'_, AppState>) -> Result<u32, CommandError> {
    let store = state.store.lock().await;
    let identity = store
        .load_identity()?
        .ok_or_else(|| CommandError::Other("no identity".into()))?;

    // Generate new batch of OTPs.
    let next_id = store.next_prekey_id()?;
    let (otpks, otpk_privates) = generate_one_time_pre_keys(next_id, 100);

    // Store private keys.
    for opk in &otpk_privates {
        store.save_prekey(opk.id, &opk.secret.to_bytes())?;
    }

    // Reconstruct device identity to build bundle.
    let device_sk_bytes: [u8; 32] = identity
        .signing_key
        .as_slice()
        .try_into()
        .map_err(|_| CommandError::Crypto("invalid key".into()))?;
    let _device_sk = SigningKey::from_bytes(&device_sk_bytes);

    let xk_bytes: [u8; 32] = identity
        .exchange_secret
        .as_slice()
        .try_into()
        .map_err(|_| CommandError::Crypto("invalid key".into()))?;
    let _device_xs = X25519StaticSecret::from(xk_bytes);

    // Load or generate signed pre-key.
    let spk_id = store.next_signed_prekey_id()?;
    let device_identity =
        reconstruct_device_identity(identity.device_id, &device_sk_bytes, &xk_bytes);
    let (spk_public, spk_sig, spk_private) = generate_signed_pre_key(&device_identity, spk_id);
    store.save_signed_prekey(spk_id, &spk_private.secret.to_bytes())?;

    // Root exchange public key.
    let root_xk_bytes: [u8; 32] = identity
        .root_exchange_secret
        .as_slice()
        .try_into()
        .map_err(|_| CommandError::Crypto("invalid key".into()))?;
    let root_xs = X25519StaticSecret::from(root_xk_bytes);
    let root_xp = X25519PublicKey::from(&root_xs);

    let bundle = build_pre_key_bundle(
        &device_identity,
        identity.user_id,
        *root_xp.as_bytes(),
        spk_id,
        spk_public,
        spk_sig,
        otpks,
    );

    drop(store);

    // Send to relay.
    state
        .send_message(ClientMessage::UploadPreKeys(bundle))
        .await?;

    let count = otpk_privates.len() as u32;
    info!("Uploaded {count} pre-keys");
    Ok(count)
}

/// Get unread message counts per conversation.
#[tauri::command]
pub async fn unread_counts(state: State<'_, AppState>) -> Result<Vec<(String, u32)>, CommandError> {
    let store = state.store.lock().await;
    Ok(store.unread_counts()?)
}

/// Initiate a session with a contact by fetching their pre-keys.
#[tauri::command]
pub async fn fetch_prekeys(
    state: State<'_, AppState>,
    user_id_hex: String,
) -> Result<(), CommandError> {
    let uid_bytes = hex_decode(&user_id_hex)
        .map_err(|e| CommandError::Other(format!("invalid user_id hex: {e}")))?;
    if uid_bytes.len() != 32 {
        return Err(CommandError::Other("user_id must be 32 bytes".into()));
    }
    let mut uid = [0u8; 32];
    uid.copy_from_slice(&uid_bytes);
    let user_id = UserId(uid);

    // Request pre-keys from relay (any device).
    state
        .send_message(ClientMessage::FetchPreKeys {
            user_id,
            device_id: None,
        })
        .await?;

    // The response will come as ServerMessage::PreKeys via the message listener.
    // Session establishment will be handled when the response arrives.
    info!("Requested pre-keys for {:?}", user_id);
    Ok(())
}

/// Disconnect from relay.
#[tauri::command]
pub async fn disconnect(state: State<'_, AppState>) -> Result<(), CommandError> {
    state.disconnect().await;
    Ok(())
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Decode a hex string to bytes.
fn hex_decode(hex: &str) -> Result<Vec<u8>, String> {
    if hex.len() % 2 != 0 {
        return Err("odd length".into());
    }
    (0..hex.len())
        .step_by(2)
        .map(|i| {
            u8::from_str_radix(&hex[i..i + 2], 16).map_err(|e| format!("invalid hex at {i}: {e}"))
        })
        .collect()
}

/// Reconstruct a DeviceIdentity from stored key bytes.
/// Note: This is a minimal reconstruction — we can't recreate the full
/// DeviceIdentity struct because DeviceIdentity::generate() is the canonical
/// constructor. Instead we build just enough for pre-key generation.
fn reconstruct_device_identity(
    device_id: DeviceId,
    signing_key_bytes: &[u8; 32],
    exchange_secret_bytes: &[u8; 32],
) -> DeviceIdentity {
    let signing_key = SigningKey::from_bytes(signing_key_bytes);
    let exchange_secret = X25519StaticSecret::from(*exchange_secret_bytes);
    DeviceIdentity {
        device_id,
        signing_key,
        exchange_secret,
    }
}
