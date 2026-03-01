//! Wire protocol types for CipherLine client ↔ relay communication.
//!
//! All types are serialized via MessagePack (`rmp-serde`).
//! Every type includes a `version` field for forward compatibility.
//!
//! # Message flow
//!
//! ```text
//! Client → Relay: ClientMessage (SendEnvelope, Ack, FetchPreKeys, UploadPreKeys, RegisterDevice, Authenticate)
//! Relay → Client: ServerMessage (Deliver, PreKeys, Ack, Error, Challenge, DeviceListResponse)
//! ```

use serde::{Deserialize, Serialize};

use crate::identity::{DeviceCertificate, PreKeyBundle, SignedDeviceList};
use crate::ratchet::X3DHHeader;
use crate::types::{
    CipherlineError, DeviceId, MessageHeader, MessageId, Timestamp, UserId, PROTOCOL_VERSION,
};

// ---------------------------------------------------------------------------
// Envelope — the encrypted message on the wire
// ---------------------------------------------------------------------------

/// An encrypted message envelope sent between clients via the relay.
///
/// The relay stores and forwards these opaquely. It can read the routing
/// fields (sender/recipient IDs) but not the plaintext.
#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct Envelope {
    pub version: u8,
    pub sender_id: UserId,
    pub sender_device_id: DeviceId,
    pub recipient_id: UserId,
    pub recipient_device_id: DeviceId,
    pub message_id: MessageId,
    pub timestamp: Timestamp,
    /// Double Ratchet header (ratchet key + counters).
    pub header: MessageHeader,
    /// ChaCha20-Poly1305 ciphertext.
    pub ciphertext: Vec<u8>,
    /// Ed25519 signature over `header_bytes || ciphertext`.
    pub signature: Vec<u8>,
}

impl Envelope {
    /// Build the data that is signed: serialized header || ciphertext.
    pub fn signable_data(header: &MessageHeader, ciphertext: &[u8]) -> Vec<u8> {
        // Serialization of a well-formed MessageHeader should never fail; if it
        // does we panic early to avoid signing/verifying an empty payload.
        let header_bytes =
            rmp_serde::to_vec(header).expect("MessageHeader serialization must not fail");
        let mut data = Vec::with_capacity(header_bytes.len() + ciphertext.len());
        data.extend_from_slice(&header_bytes);
        data.extend_from_slice(ciphertext);
        data
    }

    /// Validate basic envelope constraints (size, version).
    pub fn validate(&self) -> Result<(), CipherlineError> {
        if self.version != PROTOCOL_VERSION {
            return Err(CipherlineError::UnknownVersion(self.version));
        }
        let total_size = self.ciphertext.len() + self.signature.len();
        if total_size > crate::types::MAX_ENVELOPE_SIZE {
            return Err(CipherlineError::MessageTooLarge);
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Initial message (X3DH + first DR message)
// ---------------------------------------------------------------------------

/// The first message sent to a new contact, containing the X3DH header
/// alongside the first Double Ratchet encrypted message.
#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct InitialMessage {
    pub version: u8,
    pub x3dh_header: X3DHHeader,
    /// Sender's Ed25519 verifying key (32 bytes) so the recipient can verify
    /// the envelope signature and store it for future messages.
    pub sender_signing_key: [u8; 32],
    pub envelope: Envelope,
}

// ---------------------------------------------------------------------------
// ACK
// ---------------------------------------------------------------------------

/// Acknowledgment sent by a recipient device after successful decryption.
#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct AckMessage {
    pub message_id: MessageId,
    pub device_id: DeviceId,
}

// ---------------------------------------------------------------------------
// Authentication
// ---------------------------------------------------------------------------

/// Server-generated challenge for device authentication.
#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct AuthChallenge {
    /// 32-byte random nonce.
    pub challenge: Vec<u8>,
}

/// Client response to an auth challenge.
#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct AuthResponse {
    pub user_id: UserId,
    pub device_id: DeviceId,
    /// Device's Ed25519 public key.
    pub device_public_key: [u8; 32],
    /// Ed25519 signature over (challenge || timestamp).
    pub signature: Vec<u8>,
    /// Timestamp of the response (must be within 60s of server time).
    pub timestamp: Timestamp,
}

// ---------------------------------------------------------------------------
// Device registration
// ---------------------------------------------------------------------------

/// Request to register a new device on the relay.
#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct DeviceRegistration {
    pub certificate: DeviceCertificate,
    /// Updated signed device list from the root identity.
    pub device_list: SignedDeviceList,
}

/// Request to revoke a device.
#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct DeviceRevocation {
    pub version: u8,
    pub user_id: UserId,
    pub revoked_device_id: DeviceId,
    pub timestamp: Timestamp,
    /// Root Ed25519 signature over (version || user_id || revoked_device_id || timestamp).
    pub signature: Vec<u8>,
}

// ---------------------------------------------------------------------------
// ClientMessage — all messages from client to relay
// ---------------------------------------------------------------------------

/// All possible messages sent from a client to the relay server.
#[derive(Clone, Serialize, Deserialize, Debug)]
pub enum ClientMessage {
    /// Authenticate this WebSocket connection.
    Authenticate(AuthResponse),
    /// Send an encrypted envelope to a recipient.
    SendEnvelope(Envelope),
    /// Send an initial message (X3DH + first DR message) to a new contact.
    SendInitialMessage(InitialMessage),
    /// Acknowledge receipt of a message.
    Ack(AckMessage),
    /// Fetch pre-key bundle for a user's device.
    FetchPreKeys {
        user_id: UserId,
        device_id: Option<DeviceId>,
    },
    /// Upload/replace pre-key bundle for our device.
    UploadPreKeys(PreKeyBundle),
    /// Register a new device.
    RegisterDevice(DeviceRegistration),
    /// Revoke a device.
    RevokeDevice(DeviceRevocation),
    /// Fetch device list for a user.
    FetchDeviceList { user_id: UserId },
}

// ---------------------------------------------------------------------------
// ServerMessage — all messages from relay to client
// ---------------------------------------------------------------------------

/// Error codes sent by the relay.
#[derive(Clone, Serialize, Deserialize, Debug)]
pub enum ServerErrorCode {
    AuthFailed,
    RateLimited,
    MessageTooLarge,
    DeviceLimitExceeded,
    InvalidMessage,
    DeviceNotFound,
    UserNotFound,
    PreKeysExhausted,
    InternalError,
}

/// All possible messages sent from the relay server to a client.
#[derive(Clone, Serialize, Deserialize, Debug)]
pub enum ServerMessage {
    /// Authentication challenge (sent on connect).
    Challenge(AuthChallenge),
    /// Authentication succeeded.
    AuthSuccess,
    /// Deliver an encrypted envelope.
    Deliver(Envelope),
    /// Deliver an initial message (X3DH + first DR).
    DeliverInitialMessage(InitialMessage),
    /// Pre-key bundle response.
    PreKeys(PreKeyBundle),
    /// Device list response.
    DeviceList(SignedDeviceList),
    /// Acknowledgment that the relay received and queued a message.
    Ack(MessageId),
    /// Pre-key count report (how many OPKs remain for our device).
    PreKeyCount { remaining: u32 },
    /// Error.
    Error {
        code: ServerErrorCode,
        message: String,
    },
    /// Device revocation notification.
    DeviceRevoked(DeviceRevocation),
}

// ---------------------------------------------------------------------------
// Serialization helpers
// ---------------------------------------------------------------------------

/// Serialize a ClientMessage to MessagePack bytes.
pub fn serialize_client_msg(msg: &ClientMessage) -> Result<Vec<u8>, CipherlineError> {
    rmp_serde::to_vec(msg).map_err(|e| CipherlineError::Serialization(e.to_string()))
}

/// Deserialize a ClientMessage from MessagePack bytes.
pub fn deserialize_client_msg(data: &[u8]) -> Result<ClientMessage, CipherlineError> {
    rmp_serde::from_slice(data).map_err(|e| CipherlineError::Serialization(e.to_string()))
}

/// Serialize a ServerMessage to MessagePack bytes.
pub fn serialize_server_msg(msg: &ServerMessage) -> Result<Vec<u8>, CipherlineError> {
    rmp_serde::to_vec(msg).map_err(|e| CipherlineError::Serialization(e.to_string()))
}

/// Deserialize a ServerMessage from MessagePack bytes.
pub fn deserialize_server_msg(data: &[u8]) -> Result<ServerMessage, CipherlineError> {
    rmp_serde::from_slice(data).map_err(|e| CipherlineError::Serialization(e.to_string()))
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_envelope_signable_data_deterministic() {
        let header = MessageHeader {
            version: PROTOCOL_VERSION,
            ratchet_key: [0xAA; 32],
            previous_chain_length: 0,
            message_number: 42,
        };
        let ciphertext = vec![1, 2, 3, 4, 5];

        let data1 = Envelope::signable_data(&header, &ciphertext);
        let data2 = Envelope::signable_data(&header, &ciphertext);
        assert_eq!(data1, data2);
    }

    #[test]
    fn test_envelope_validate_valid() {
        let envelope = Envelope {
            version: PROTOCOL_VERSION,
            sender_id: UserId([1u8; 32]),
            sender_device_id: DeviceId([2u8; 16]),
            recipient_id: UserId([3u8; 32]),
            recipient_device_id: DeviceId([4u8; 16]),
            message_id: MessageId::generate(),
            timestamp: Timestamp::now(),
            header: MessageHeader {
                version: PROTOCOL_VERSION,
                ratchet_key: [5u8; 32],
                previous_chain_length: 0,
                message_number: 0,
            },
            ciphertext: vec![0u8; 100],
            signature: vec![0u8; 64],
        };
        assert!(envelope.validate().is_ok());
    }

    #[test]
    fn test_envelope_validate_wrong_version() {
        let envelope = Envelope {
            version: 255,
            sender_id: UserId([1u8; 32]),
            sender_device_id: DeviceId([2u8; 16]),
            recipient_id: UserId([3u8; 32]),
            recipient_device_id: DeviceId([4u8; 16]),
            message_id: MessageId::generate(),
            timestamp: Timestamp::now(),
            header: MessageHeader {
                version: PROTOCOL_VERSION,
                ratchet_key: [5u8; 32],
                previous_chain_length: 0,
                message_number: 0,
            },
            ciphertext: vec![0u8; 100],
            signature: vec![0u8; 64],
        };
        assert!(envelope.validate().is_err());
    }

    #[test]
    fn test_client_message_serde_roundtrip() {
        let msg = ClientMessage::Ack(AckMessage {
            message_id: MessageId::generate(),
            device_id: DeviceId::generate(),
        });

        let bytes = serialize_client_msg(&msg).unwrap();
        let decoded = deserialize_client_msg(&bytes).unwrap();

        match decoded {
            ClientMessage::Ack(ack) => {
                // Decoded successfully.
                assert_ne!(ack.device_id, DeviceId([0u8; 16]));
            }
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn test_server_message_serde_roundtrip() {
        let msg = ServerMessage::Error {
            code: ServerErrorCode::RateLimited,
            message: "too many requests".into(),
        };

        let bytes = serialize_server_msg(&msg).unwrap();
        let decoded = deserialize_server_msg(&bytes).unwrap();

        match decoded {
            ServerMessage::Error { code, message } => {
                assert!(matches!(code, ServerErrorCode::RateLimited));
                assert_eq!(message, "too many requests");
            }
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn test_auth_challenge_serde() {
        let challenge = AuthChallenge {
            challenge: vec![0xAB; 32],
        };
        let bytes = rmp_serde::to_vec(&challenge).unwrap();
        let decoded: AuthChallenge = rmp_serde::from_slice(&bytes).unwrap();
        assert_eq!(decoded.challenge, challenge.challenge);
    }
}
