//! Core domain types for CipherLine.
//!
//! All types include a `version` field for forward-compatible serialization.
//! All types derive `Serialize` and `Deserialize` for MessagePack wire format.

use serde::{Deserialize, Serialize};
use std::fmt;
use uuid::Uuid;
use zeroize::Zeroize;

/// Protocol version. Increment on breaking wire format changes.
pub const PROTOCOL_VERSION: u8 = 1;

/// Maximum number of skipped message keys per chain step in Double Ratchet.
pub const MAX_SKIP: u32 = 500;

/// Global maximum of stored skipped message keys across all chains.
pub const MAX_TOTAL_SKIPPED_KEYS: usize = 5000;

/// Maximum number of archived session states.
pub const MAX_ARCHIVED_SESSIONS: usize = 40;

/// Maximum number of devices per user identity.
pub const MAX_DEVICES_PER_USER: usize = 6;

/// Default message TTL in seconds (7 days).
pub const DEFAULT_MESSAGE_TTL_SECS: u64 = 604_800;

/// Maximum envelope size in bytes (64 KB).
pub const MAX_ENVELOPE_SIZE: usize = 65_536;

// ---------------------------------------------------------------------------
// UserId
// ---------------------------------------------------------------------------

/// A user identity derived from the BLAKE2b-256 hash of the root Ed25519 public key.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct UserId(pub [u8; 32]);

impl UserId {
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Returns the first 8 hex characters for safe logging (no full ID in logs).
    pub fn short_hex(&self) -> String {
        hex_prefix(&self.0, 4)
    }
}

impl fmt::Debug for UserId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "UserId({}…)", self.short_hex())
    }
}

impl fmt::Display for UserId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", hex_encode(&self.0))
    }
}

// ---------------------------------------------------------------------------
// DeviceId
// ---------------------------------------------------------------------------

/// A device identity — 16 random bytes generated on device creation.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct DeviceId(pub [u8; 16]);

impl DeviceId {
    pub fn generate() -> Self {
        let mut bytes = [0u8; 16];
        getrandom(&mut bytes);
        Self(bytes)
    }

    pub fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }

    pub fn short_hex(&self) -> String {
        hex_prefix(&self.0, 4)
    }
}

impl fmt::Debug for DeviceId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "DeviceId({}…)", self.short_hex())
    }
}

impl fmt::Display for DeviceId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", hex_encode(&self.0))
    }
}

// ---------------------------------------------------------------------------
// MessageId
// ---------------------------------------------------------------------------

/// Unique identifier for a message, wrapping a UUID v4.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct MessageId(pub Uuid);

impl MessageId {
    pub fn generate() -> Self {
        Self(Uuid::new_v4())
    }
}

impl fmt::Debug for MessageId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "MessageId({})", self.0)
    }
}

impl fmt::Display for MessageId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

// ---------------------------------------------------------------------------
// Timestamp
// ---------------------------------------------------------------------------

/// Unix timestamp in milliseconds.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, Debug)]
pub struct Timestamp(pub u64);

impl Timestamp {
    /// Current time as milliseconds since Unix epoch.
    pub fn now() -> Self {
        let ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("system clock before epoch")
            .as_millis() as u64;
        Self(ms)
    }

    /// Returns the number of seconds since this timestamp.
    pub fn elapsed_secs(&self) -> u64 {
        let now = Self::now().0;
        now.saturating_sub(self.0) / 1000
    }
}

// ---------------------------------------------------------------------------
// PublicKeyBundle
// ---------------------------------------------------------------------------

/// Serializable bundle of a device's public keys for sharing with contacts.
#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct PublicKeyBundle {
    pub version: u8,
    pub user_id: UserId,
    pub device_id: DeviceId,
    /// Ed25519 verifying (public) key bytes.
    pub signing_key: [u8; 32],
    /// X25519 public key bytes.
    pub exchange_key: [u8; 32],
}

// ---------------------------------------------------------------------------
// MessageHeader (Double Ratchet)
// ---------------------------------------------------------------------------

/// Header sent with each Double Ratchet message.
/// Contains the sender's current ratchet public key and chain counters.
#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct MessageHeader {
    pub version: u8,
    /// Sender's current DH ratchet public key (X25519, 32 bytes).
    pub ratchet_key: [u8; 32],
    /// Number of messages in the previous sending chain.
    pub previous_chain_length: u32,
    /// Message number in the current sending chain.
    pub message_number: u32,
}

// ---------------------------------------------------------------------------
// CiphertextPayload
// ---------------------------------------------------------------------------

/// Encrypted payload with nonce (for non-DR uses like local storage).
/// For DR messages, the nonce is fixed `[0u8; 12]` and not included here.
#[derive(Clone, Serialize, Deserialize, Debug, Zeroize)]
pub struct CiphertextPayload {
    pub ciphertext: Vec<u8>,
    pub nonce: [u8; 12],
}

// ---------------------------------------------------------------------------
// Error types
// ---------------------------------------------------------------------------

/// Top-level error type for all CipherLine operations.
#[derive(Debug, thiserror::Error)]
pub enum CipherlineError {
    #[error("encryption failed: {0}")]
    Encryption(String),

    #[error("decryption failed: {0}")]
    Decryption(String),

    #[error("signature verification failed")]
    SignatureVerification,

    #[error("invalid key material: {0}")]
    InvalidKey(String),

    #[error("ratchet error: {0}")]
    Ratchet(String),

    #[error("protocol error: {0}")]
    Protocol(String),

    #[error("serialization error: {0}")]
    Serialization(String),

    #[error("pre-key error: {0}")]
    PreKey(String),

    #[error("device limit exceeded (max {MAX_DEVICES_PER_USER})")]
    DeviceLimitExceeded,

    #[error("message too large (max {MAX_ENVELOPE_SIZE} bytes)")]
    MessageTooLarge,

    #[error("message expired")]
    MessageExpired,

    #[error("rate limited")]
    RateLimited,

    #[error("authentication failed: {0}")]
    AuthFailed(String),

    #[error("unknown protocol version: {0}")]
    UnknownVersion(u8),
}

impl From<rmp_serde::encode::Error> for CipherlineError {
    fn from(e: rmp_serde::encode::Error) -> Self {
        CipherlineError::Serialization(e.to_string())
    }
}

impl From<rmp_serde::decode::Error> for CipherlineError {
    fn from(e: rmp_serde::decode::Error) -> Self {
        CipherlineError::Serialization(e.to_string())
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn getrandom(buf: &mut [u8]) {
    use rand::RngCore;
    rand::rngs::OsRng.fill_bytes(buf);
}

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn hex_prefix(bytes: &[u8], n: usize) -> String {
    bytes.iter().take(n).map(|b| format!("{b:02x}")).collect()
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_device_id_generate_unique() {
        let a = DeviceId::generate();
        let b = DeviceId::generate();
        assert_ne!(a, b);
    }

    #[test]
    fn test_message_id_generate_unique() {
        let a = MessageId::generate();
        let b = MessageId::generate();
        assert_ne!(a, b);
    }

    #[test]
    fn test_timestamp_now() {
        let ts = Timestamp::now();
        assert!(ts.0 > 0);
    }

    #[test]
    fn test_user_id_short_hex() {
        let uid = UserId([0xab; 32]);
        assert_eq!(uid.short_hex(), "abababab");
    }

    #[test]
    fn test_user_id_serde_roundtrip() {
        let uid = UserId([42u8; 32]);
        let encoded = rmp_serde::to_vec(&uid).unwrap();
        let decoded: UserId = rmp_serde::from_slice(&encoded).unwrap();
        assert_eq!(uid, decoded);
    }

    #[test]
    fn test_message_header_serde_roundtrip() {
        let hdr = MessageHeader {
            version: PROTOCOL_VERSION,
            ratchet_key: [1u8; 32],
            previous_chain_length: 5,
            message_number: 10,
        };
        let encoded = rmp_serde::to_vec(&hdr).unwrap();
        let decoded: MessageHeader = rmp_serde::from_slice(&encoded).unwrap();
        assert_eq!(decoded.version, PROTOCOL_VERSION);
        assert_eq!(decoded.ratchet_key, [1u8; 32]);
        assert_eq!(decoded.previous_chain_length, 5);
        assert_eq!(decoded.message_number, 10);
    }
}
