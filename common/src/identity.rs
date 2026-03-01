//! Identity management for CipherLine.
//!
//! # Identity model
//!
//! - **Root Identity**: Long-term Ed25519 + X25519 keypairs. Represents the user.
//!   Generated on first install. Never transmitted. The `UserId` is derived from
//!   the root Ed25519 public key (BLAKE2b-256 hash).
//!
//! - **Device Identity**: Per-device Ed25519 + X25519 keypairs, signed by the root
//!   identity. Can be revoked independently. Max 6 devices per user.
//!
//! - **Pre-Key Bundle**: Uploaded to the relay so contacts can initiate sessions
//!   via X3DH without both parties being online simultaneously.
//!
//! # Security invariants
//!
//! - Private keys derive `Zeroize` and are zeroed on drop.
//! - Separate Ed25519 (signing) and X25519 (key exchange) keypairs — no conversion.
//! - SPK signature verified by initiator before X3DH.

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret as X25519StaticSecret};

use crate::crypto;
use crate::types::{CipherlineError, DeviceId, UserId, PROTOCOL_VERSION};

// ---------------------------------------------------------------------------
// RootIdentity
// ---------------------------------------------------------------------------

/// The user's root identity. Generated once on first install.
///
/// Contains long-term Ed25519 (signing) and X25519 (key exchange) keypairs.
/// The `UserId` is the BLAKE2b-256 hash of the Ed25519 public key.
pub struct RootIdentity {
    /// Ed25519 signing key (private).
    pub signing_key: SigningKey,

    /// X25519 static secret (private).
    pub exchange_secret: X25519StaticSecret,
}

/// Public portion of a root identity, safe to share.
#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct RootIdentityPublic {
    pub version: u8,
    pub user_id: UserId,
    pub signing_key: [u8; 32],
    pub exchange_key: [u8; 32],
}

impl RootIdentity {
    /// Generate a new root identity from the OS CSPRNG.
    pub fn generate() -> Self {
        let signing_key = SigningKey::generate(&mut OsRng);
        let exchange_secret = X25519StaticSecret::random_from_rng(OsRng);
        Self {
            signing_key,
            exchange_secret,
        }
    }

    /// Derive the UserId from the Ed25519 public key.
    pub fn user_id(&self) -> UserId {
        UserId(crypto::blake2b_hash(self.verifying_key().as_bytes()))
    }

    /// Get the Ed25519 verifying (public) key.
    pub fn verifying_key(&self) -> VerifyingKey {
        self.signing_key.verifying_key()
    }

    /// Get the X25519 public key.
    pub fn exchange_public_key(&self) -> X25519PublicKey {
        X25519PublicKey::from(&self.exchange_secret)
    }

    /// Export the public portion for sharing.
    pub fn to_public(&self) -> RootIdentityPublic {
        RootIdentityPublic {
            version: PROTOCOL_VERSION,
            user_id: self.user_id(),
            signing_key: self.verifying_key().to_bytes(),
            exchange_key: self.exchange_public_key().to_bytes(),
        }
    }

    /// Sign arbitrary data with the root Ed25519 key.
    pub fn sign(&self, data: &[u8]) -> Signature {
        self.signing_key.sign(data)
    }
}

// ---------------------------------------------------------------------------
// DeviceIdentity
// ---------------------------------------------------------------------------

/// A per-device identity, signed by the root identity.
pub struct DeviceIdentity {
    pub device_id: DeviceId,
    pub signing_key: SigningKey,
    pub exchange_secret: X25519StaticSecret,
}

/// Certificate proving a device belongs to a root identity.
/// Created by the root identity signing the device's public keys.
#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct DeviceCertificate {
    pub version: u8,
    pub user_id: UserId,
    pub device_id: DeviceId,
    /// Device's Ed25519 public key.
    pub device_signing_key: [u8; 32],
    /// Device's X25519 public key.
    pub device_exchange_key: [u8; 32],
    /// Root identity's Ed25519 signature over the above fields.
    pub root_signature: Vec<u8>,
    /// Timestamp of certificate creation (ms since epoch).
    pub created_at: u64,
}

impl DeviceIdentity {
    /// Generate a new device identity and sign it with the root identity.
    pub fn generate(root: &RootIdentity) -> (Self, DeviceCertificate) {
        let device_id = DeviceId::generate();
        let signing_key = SigningKey::generate(&mut OsRng);
        let exchange_secret = X25519StaticSecret::random_from_rng(OsRng);
        let exchange_public = X25519PublicKey::from(&exchange_secret);

        let device = Self {
            device_id,
            signing_key,
            exchange_secret,
        };

        let cert = device.create_certificate(root, exchange_public);

        (device, cert)
    }

    fn create_certificate(
        &self,
        root: &RootIdentity,
        exchange_public: X25519PublicKey,
    ) -> DeviceCertificate {
        let user_id = root.user_id();
        let created_at = crate::types::Timestamp::now().0;
        let device_signing_key = self.signing_key.verifying_key().to_bytes();
        let device_exchange_key = *exchange_public.as_bytes();

        // The signed payload is: version || user_id || device_id || signing_key || exchange_key || created_at
        let payload = build_cert_payload(
            PROTOCOL_VERSION,
            &user_id,
            &self.device_id,
            &device_signing_key,
            &device_exchange_key,
            created_at,
        );

        let signature = root.sign(&payload);

        DeviceCertificate {
            version: PROTOCOL_VERSION,
            user_id,
            device_id: self.device_id,
            device_signing_key,
            device_exchange_key,
            root_signature: signature.to_bytes().to_vec(),
            created_at,
        }
    }

    /// Get the Ed25519 verifying (public) key.
    pub fn verifying_key(&self) -> VerifyingKey {
        self.signing_key.verifying_key()
    }

    /// Get the X25519 public key.
    pub fn exchange_public_key(&self) -> X25519PublicKey {
        X25519PublicKey::from(&self.exchange_secret)
    }

    /// Sign arbitrary data with the device Ed25519 key.
    pub fn sign(&self, data: &[u8]) -> Signature {
        self.signing_key.sign(data)
    }
}

impl DeviceCertificate {
    /// Verify that this certificate was signed by the claimed root identity.
    pub fn verify(&self, root_verifying_key: &VerifyingKey) -> Result<(), CipherlineError> {
        let payload = build_cert_payload(
            self.version,
            &self.user_id,
            &self.device_id,
            &self.device_signing_key,
            &self.device_exchange_key,
            self.created_at,
        );

        let sig_bytes: [u8; 64] = self
            .root_signature
            .as_slice()
            .try_into()
            .map_err(|_| CipherlineError::SignatureVerification)?;
        let signature = Signature::from_bytes(&sig_bytes);

        crypto::verify(&payload, &signature, root_verifying_key)
    }
}

// ---------------------------------------------------------------------------
// PreKeyBundle
// ---------------------------------------------------------------------------

/// Pre-key bundle uploaded to the relay for X3DH session initiation.
#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct PreKeyBundle {
    pub version: u8,
    pub user_id: UserId,
    pub device_id: DeviceId,

    /// Identity signing key (Ed25519 verifying key, 32 bytes).
    /// Used to verify the signed pre-key signature.
    pub identity_signing_key: [u8; 32],

    /// Identity exchange key (X25519 public, 32 bytes).
    /// Used in X3DH DH operations.
    pub identity_exchange_key: [u8; 32],

    /// Signed pre-key (X25519 public, 32 bytes).
    pub signed_pre_key: [u8; 32],
    /// Ed25519 signature of the signed pre-key by the device's signing key.
    pub signed_pre_key_signature: Vec<u8>,
    /// Unique ID of this signed pre-key (for rotation tracking).
    pub signed_pre_key_id: u32,

    /// One-time pre-keys (X25519 public, 32 bytes each).
    /// Consumed on use — each should be served at most once.
    pub one_time_pre_keys: Vec<OneTimePreKey>,
}

/// A single one-time pre-key with its ID.
#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct OneTimePreKey {
    pub id: u32,
    pub key: [u8; 32],
}

/// A stored one-time pre-key with its private key (client-side only, never sent).
pub struct OneTimePreKeyPrivate {
    pub id: u32,
    pub secret: X25519StaticSecret,
}

/// A stored signed pre-key with its private key (client-side only, never sent).
pub struct SignedPreKeyPrivate {
    pub id: u32,
    pub secret: X25519StaticSecret,
}

/// Generate a batch of one-time pre-keys.
///
/// Returns (public keys for upload, private keys for local storage).
pub fn generate_one_time_pre_keys(
    start_id: u32,
    count: u32,
) -> (Vec<OneTimePreKey>, Vec<OneTimePreKeyPrivate>) {
    let mut public_keys = Vec::with_capacity(count as usize);
    let mut private_keys = Vec::with_capacity(count as usize);

    for i in 0..count {
        let id = start_id + i;
        let secret = X25519StaticSecret::random_from_rng(OsRng);
        let public = X25519PublicKey::from(&secret);

        public_keys.push(OneTimePreKey {
            id,
            key: *public.as_bytes(),
        });
        private_keys.push(OneTimePreKeyPrivate { id, secret });
    }

    (public_keys, private_keys)
}

/// Generate a signed pre-key.
///
/// Returns (public key bytes, signature, private key for storage).
pub fn generate_signed_pre_key(
    device: &DeviceIdentity,
    id: u32,
) -> ([u8; 32], Vec<u8>, SignedPreKeyPrivate) {
    let secret = X25519StaticSecret::random_from_rng(OsRng);
    let public = X25519PublicKey::from(&secret);
    let public_bytes = *public.as_bytes();

    // Sign the public key with the device's Ed25519 signing key.
    let signature = device.sign(&public_bytes);

    let private = SignedPreKeyPrivate { id, secret };

    (public_bytes, signature.to_bytes().to_vec(), private)
}

/// Build a complete PreKeyBundle for upload.
pub fn build_pre_key_bundle(
    device: &DeviceIdentity,
    user_id: UserId,
    root_exchange_public: [u8; 32],
    signed_pre_key_id: u32,
    signed_pre_key: [u8; 32],
    signed_pre_key_signature: Vec<u8>,
    one_time_pre_keys: Vec<OneTimePreKey>,
) -> PreKeyBundle {
    PreKeyBundle {
        version: PROTOCOL_VERSION,
        user_id,
        device_id: device.device_id,
        identity_signing_key: device.verifying_key().to_bytes(),
        identity_exchange_key: root_exchange_public,
        signed_pre_key,
        signed_pre_key_signature,
        signed_pre_key_id,
        one_time_pre_keys,
    }
}

// ---------------------------------------------------------------------------
// DeviceList (signed by root identity)
// ---------------------------------------------------------------------------

/// A signed list of all devices belonging to a user.
/// Prevents the relay from injecting phantom devices.
#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct SignedDeviceList {
    pub version: u8,
    pub user_id: UserId,
    pub devices: Vec<DeviceListEntry>,
    /// Timestamp of this device list version.
    pub timestamp: u64,
    /// Root Ed25519 signature over the serialized list.
    pub signature: Vec<u8>,
}

#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct DeviceListEntry {
    pub device_id: DeviceId,
    pub signing_key: [u8; 32],
    pub exchange_key: [u8; 32],
    pub active: bool,
}

/// Build a signed device list for anti-phantom-device protection.
///
/// The list is signed by the root Ed25519 signing key, so only the user
/// who owns the root identity can modify the device list. Peers and the
/// relay can verify authenticity but cannot forge entries.
pub fn build_signed_device_list(
    root_signing_key: &SigningKey,
    user_id: UserId,
    devices: Vec<DeviceListEntry>,
) -> SignedDeviceList {
    let timestamp = crate::types::Timestamp::now().0;
    let payload = build_device_list_payload(PROTOCOL_VERSION, &user_id, &devices, timestamp);
    let signature = crypto::sign(&payload, root_signing_key);

    SignedDeviceList {
        version: PROTOCOL_VERSION,
        user_id,
        devices,
        timestamp,
        signature: signature.to_bytes().to_vec(),
    }
}

/// Verify that a signed device list was signed by the expected root identity.
pub fn verify_signed_device_list(
    list: &SignedDeviceList,
    root_verifying_key: &VerifyingKey,
) -> Result<(), CipherlineError> {
    let payload =
        build_device_list_payload(list.version, &list.user_id, &list.devices, list.timestamp);

    let sig_bytes: [u8; 64] = list
        .signature
        .as_slice()
        .try_into()
        .map_err(|_| CipherlineError::SignatureVerification)?;
    let signature = Signature::from_bytes(&sig_bytes);

    crypto::verify(&payload, &signature, root_verifying_key)
}

/// Build the signable payload for a device list.
fn build_device_list_payload(
    version: u8,
    user_id: &UserId,
    devices: &[DeviceListEntry],
    timestamp: u64,
) -> Vec<u8> {
    let mut payload = Vec::new();
    payload.push(version);
    payload.extend_from_slice(&user_id.0);
    payload.extend_from_slice(&timestamp.to_le_bytes());
    for d in devices {
        payload.extend_from_slice(&d.device_id.0);
        payload.extend_from_slice(&d.signing_key);
        payload.extend_from_slice(&d.exchange_key);
        payload.push(d.active as u8);
    }
    payload
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn build_cert_payload(
    version: u8,
    user_id: &UserId,
    device_id: &DeviceId,
    signing_key: &[u8; 32],
    exchange_key: &[u8; 32],
    created_at: u64,
) -> Vec<u8> {
    let mut payload = Vec::with_capacity(1 + 32 + 16 + 32 + 32 + 8);
    payload.push(version);
    payload.extend_from_slice(&user_id.0);
    payload.extend_from_slice(&device_id.0);
    payload.extend_from_slice(signing_key);
    payload.extend_from_slice(exchange_key);
    payload.extend_from_slice(&created_at.to_le_bytes());
    payload
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_root_identity_generate() {
        let root = RootIdentity::generate();
        let uid = root.user_id();
        // UserId is a BLAKE2b hash — should be 32 bytes and non-zero.
        assert_ne!(uid.0, [0u8; 32]);
    }

    #[test]
    fn test_root_identity_unique() {
        let r1 = RootIdentity::generate();
        let r2 = RootIdentity::generate();
        assert_ne!(r1.user_id(), r2.user_id());
    }

    #[test]
    fn test_root_identity_sign_verify() {
        let root = RootIdentity::generate();
        let msg = b"identity test";
        let sig = root.sign(msg);
        assert!(crypto::verify(msg, &sig, &root.verifying_key()).is_ok());
    }

    #[test]
    fn test_root_to_public() {
        let root = RootIdentity::generate();
        let public = root.to_public();
        assert_eq!(public.version, PROTOCOL_VERSION);
        assert_eq!(public.user_id, root.user_id());
        assert_eq!(public.signing_key, root.verifying_key().to_bytes());
        assert_eq!(public.exchange_key, *root.exchange_public_key().as_bytes());
    }

    #[test]
    fn test_device_identity_generate() {
        let root = RootIdentity::generate();
        let (device, cert) = DeviceIdentity::generate(&root);
        assert_eq!(cert.user_id, root.user_id());
        assert_eq!(cert.device_id, device.device_id);
    }

    #[test]
    fn test_device_certificate_verify() {
        let root = RootIdentity::generate();
        let (_device, cert) = DeviceIdentity::generate(&root);
        assert!(cert.verify(&root.verifying_key()).is_ok());
    }

    #[test]
    fn test_device_certificate_verify_wrong_root() {
        let root1 = RootIdentity::generate();
        let root2 = RootIdentity::generate();
        let (_device, cert) = DeviceIdentity::generate(&root1);
        assert!(cert.verify(&root2.verifying_key()).is_err());
    }

    #[test]
    fn test_generate_one_time_pre_keys() {
        let (pub_keys, priv_keys) = generate_one_time_pre_keys(0, 100);
        assert_eq!(pub_keys.len(), 100);
        assert_eq!(priv_keys.len(), 100);

        // IDs should be sequential.
        for (i, pk) in pub_keys.iter().enumerate() {
            assert_eq!(pk.id, i as u32);
        }

        // Keys should all be different.
        let unique: std::collections::HashSet<[u8; 32]> = pub_keys.iter().map(|k| k.key).collect();
        assert_eq!(unique.len(), 100);
    }

    #[test]
    fn test_generate_signed_pre_key() {
        let root = RootIdentity::generate();
        let (device, _cert) = DeviceIdentity::generate(&root);
        let (spk_public, spk_sig, _spk_private) = generate_signed_pre_key(&device, 1);

        // Verify the SPK signature with the device's verifying key.
        let sig_bytes: [u8; 64] = spk_sig.as_slice().try_into().unwrap();
        let signature = Signature::from_bytes(&sig_bytes);
        assert!(crypto::verify(&spk_public, &signature, &device.verifying_key()).is_ok());
    }

    #[test]
    fn test_build_pre_key_bundle() {
        let root = RootIdentity::generate();
        let (device, _cert) = DeviceIdentity::generate(&root);
        let (spk_pub, spk_sig, _spk_priv) = generate_signed_pre_key(&device, 1);
        let (otpks, _otpk_privs) = generate_one_time_pre_keys(0, 50);

        let bundle = build_pre_key_bundle(
            &device,
            root.user_id(),
            *root.exchange_public_key().as_bytes(),
            1,
            spk_pub,
            spk_sig,
            otpks,
        );

        assert_eq!(bundle.version, PROTOCOL_VERSION);
        assert_eq!(bundle.user_id, root.user_id());
        assert_eq!(bundle.one_time_pre_keys.len(), 50);
    }

    #[test]
    fn test_pre_key_bundle_serde_roundtrip() {
        let root = RootIdentity::generate();
        let (device, _cert) = DeviceIdentity::generate(&root);
        let (spk_pub, spk_sig, _spk_priv) = generate_signed_pre_key(&device, 1);
        let (otpks, _) = generate_one_time_pre_keys(0, 10);

        let bundle = build_pre_key_bundle(
            &device,
            root.user_id(),
            *root.exchange_public_key().as_bytes(),
            1,
            spk_pub,
            spk_sig,
            otpks,
        );

        let encoded = rmp_serde::to_vec(&bundle).unwrap();
        let decoded: PreKeyBundle = rmp_serde::from_slice(&encoded).unwrap();

        assert_eq!(decoded.version, bundle.version);
        assert_eq!(decoded.user_id, bundle.user_id);
        assert_eq!(decoded.signed_pre_key, bundle.signed_pre_key);
        assert_eq!(decoded.one_time_pre_keys.len(), 10);
    }
}
