//! # CipherLine Common
//!
//! Shared cryptography, protocol definitions, and types for the CipherLine
//! secure messaging system. This crate is used by both the client and relay server.
//!
//! ## Modules
//!
//! - `crypto` — Low-level cryptographic primitives (encrypt, decrypt, sign, verify, KDF)
//! - `types` — Core domain types (UserId, DeviceId, MessageId, etc.)
//! - `identity` — Root identity and device key management
//! - `ratchet` — X3DH key agreement and Double Ratchet session management
//! - `protocol` — Wire protocol message types (Envelope, ClientMessage, ServerMessage)

pub mod crypto;
pub mod identity;
pub mod protocol;
pub mod ratchet;
pub mod types;
