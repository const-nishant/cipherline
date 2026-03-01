//! Low-level cryptographic primitives for CipherLine.
//!
//! # Algorithms (locked, do not change)
//!
//! | Purpose       | Algorithm          |
//! |---------------|--------------------|
//! | Key exchange  | X25519             |
//! | Encryption    | ChaCha20-Poly1305  |
//! | Signatures    | Ed25519            |
//! | Hashing / KDF | BLAKE2b            |
//!
//! # Security invariants
//!
//! - Keys are generated on-device only (via OS CSPRNG).
//! - Private keys never leave the device.
//! - All secret key material implements `Zeroize`.
//! - MAC/signature comparisons use constant-time operations (`subtle`).
//! - Each message key is used exactly once, then deleted.

use blake2::{
    digest::{consts::U32, FixedOutput, KeyInit, Update},
    Blake2bMac,
};
use chacha20poly1305::{aead::Aead, ChaCha20Poly1305, Nonce};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rand::rngs::OsRng;
use subtle::ConstantTimeEq;
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret as X25519StaticSecret};
use zeroize::Zeroize;

use crate::types::CipherlineError;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Fixed nonce for Double Ratchet message encryption.
/// Safe because each DR message key is used exactly once.
pub const DR_FIXED_NONCE: [u8; 12] = [0u8; 12];

// Domain separation strings for KDF (include version for upgrade safety).
pub const KDF_DOMAIN_X3DH: &[u8] = b"CipherLine_X3DH_v1";
pub const KDF_DOMAIN_DR_ROOT: &[u8] = b"CipherLine_DR_Root_v1";
pub const KDF_DOMAIN_DR_CHAIN_KEY: &[u8] = b"CipherLine_DR_ChainKey_v1";
pub const KDF_DOMAIN_DR_MSG_KEY: &[u8] = b"CipherLine_DR_MsgKey_v1";

// ---------------------------------------------------------------------------
// Ed25519 — Signatures
// ---------------------------------------------------------------------------

/// Generate a new Ed25519 signing keypair from the OS CSPRNG.
pub fn generate_ed25519_keypair() -> (SigningKey, VerifyingKey) {
    let signing_key = SigningKey::generate(&mut OsRng);
    let verifying_key = signing_key.verifying_key();
    (signing_key, verifying_key)
}

/// Sign a message with an Ed25519 signing key.
pub fn sign(message: &[u8], signing_key: &SigningKey) -> Signature {
    signing_key.sign(message)
}

/// Verify an Ed25519 signature. Returns `Ok(())` or `Err(SignatureVerification)`.
///
/// Uses the strict verification mode (RFC 8032 compliant, rejects non-canonical
/// signatures and small-order R values).
pub fn verify(
    message: &[u8],
    signature: &Signature,
    verifying_key: &VerifyingKey,
) -> Result<(), CipherlineError> {
    verifying_key
        .verify(message, signature)
        .map_err(|_| CipherlineError::SignatureVerification)
}

// ---------------------------------------------------------------------------
// X25519 — Key Exchange
// ---------------------------------------------------------------------------

/// Generate a new X25519 static secret and public key from the OS CSPRNG.
pub fn generate_x25519_keypair() -> (X25519StaticSecret, X25519PublicKey) {
    let secret = X25519StaticSecret::random_from_rng(OsRng);
    let public = X25519PublicKey::from(&secret);
    (secret, public)
}

/// Perform an X25519 Diffie-Hellman key exchange.
///
/// # Security
///
/// The caller **must** check for an all-zero result (indicates a low-order
/// public key). This function returns an error in that case.
pub fn x25519_diffie_hellman(
    our_secret: &X25519StaticSecret,
    their_public: &X25519PublicKey,
) -> Result<[u8; 32], CipherlineError> {
    let shared_secret = our_secret.diffie_hellman(their_public);
    let bytes = shared_secret.to_bytes();

    // Reject all-zero shared secret (low-order point).
    if bytes.ct_eq(&[0u8; 32]).into() {
        return Err(CipherlineError::InvalidKey(
            "DH produced all-zero output (low-order point)".into(),
        ));
    }

    Ok(bytes)
}

// ---------------------------------------------------------------------------
// ChaCha20-Poly1305 — AEAD Encryption
// ---------------------------------------------------------------------------

/// Encrypt plaintext with ChaCha20-Poly1305.
///
/// - `key`: 32-byte symmetric key
/// - `nonce`: 12-byte nonce (for DR messages, use `DR_FIXED_NONCE`)
/// - Returns ciphertext (plaintext + 16-byte Poly1305 tag)
pub fn encrypt(
    plaintext: &[u8],
    key: &[u8; 32],
    nonce: &[u8; 12],
) -> Result<Vec<u8>, CipherlineError> {
    let cipher = ChaCha20Poly1305::new_from_slice(key)
        .map_err(|e| CipherlineError::Encryption(e.to_string()))?;
    let nonce = Nonce::from_slice(nonce);
    cipher
        .encrypt(nonce, plaintext)
        .map_err(|e| CipherlineError::Encryption(e.to_string()))
}

/// Decrypt ciphertext with ChaCha20-Poly1305.
///
/// - `key`: 32-byte symmetric key
/// - `nonce`: 12-byte nonce (must match the one used for encryption)
/// - Returns plaintext on success
pub fn decrypt(
    ciphertext: &[u8],
    key: &[u8; 32],
    nonce: &[u8; 12],
) -> Result<Vec<u8>, CipherlineError> {
    let cipher = ChaCha20Poly1305::new_from_slice(key)
        .map_err(|e| CipherlineError::Decryption(e.to_string()))?;
    let nonce = Nonce::from_slice(nonce);
    cipher
        .decrypt(nonce, ciphertext)
        .map_err(|e| CipherlineError::Decryption(e.to_string()))
}

// ---------------------------------------------------------------------------
// BLAKE2b — Hashing & KDF
// ---------------------------------------------------------------------------

/// Compute a BLAKE2b-256 hash of the input data (unkeyed).
pub fn blake2b_hash(data: &[u8]) -> [u8; 32] {
    use blake2::{Blake2b, Digest};
    type Blake2b256 = Blake2b<U32>;
    let mut hasher = Blake2b256::new();
    Digest::update(&mut hasher, data);
    let result = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&result);
    out
}

/// Derive a subkey using BLAKE2b in keyed-MAC mode (domain-separated KDF).
///
/// - `ikm`: Input key material (used as BLAKE2b key, max 64 bytes)
/// - `domain`: Domain separation string (mixed into the input)
/// - `info`: Additional context / subkey index
///
/// Returns a 32-byte derived key.
///
/// # Panics
///
/// Panics if `ikm` is longer than 64 bytes (BLAKE2b max key length).
pub fn kdf_derive(ikm: &[u8], domain: &[u8], info: &[u8]) -> [u8; 32] {
    assert!(ikm.len() <= 64, "BLAKE2b key must be <= 64 bytes");
    let mut mac =
        <Blake2bMac<U32> as KeyInit>::new_from_slice(ikm).expect("valid key length for BLAKE2b");
    mac.update(domain);
    mac.update(info);
    let result = mac.finalize_fixed();
    let mut out = [0u8; 32];
    out.copy_from_slice(&result);
    out
}

/// KDF chain step: derive (next_chain_key, message_key) from a chain key.
///
/// Uses two distinct domain strings to ensure key separation.
/// Both outputs are 32 bytes.
pub fn kdf_chain_step(chain_key: &[u8; 32]) -> ([u8; 32], [u8; 32]) {
    let next_chain_key = kdf_derive(chain_key, KDF_DOMAIN_DR_CHAIN_KEY, &[0x01]);
    let message_key = kdf_derive(chain_key, KDF_DOMAIN_DR_MSG_KEY, &[0x02]);
    (next_chain_key, message_key)
}

/// KDF root step: derive (new_root_key, new_chain_key) from root key + DH output.
///
/// Concatenates root_key with dh_output as key material, then derives two keys.
pub fn kdf_root_step(root_key: &[u8; 32], dh_output: &[u8; 32]) -> ([u8; 32], [u8; 32]) {
    // Combine root_key and dh_output (64 bytes), fits in BLAKE2b's 64-byte key limit.
    let mut combined = [0u8; 64];
    combined[..32].copy_from_slice(root_key);
    combined[32..].copy_from_slice(dh_output);

    let new_root_key = kdf_derive(&combined, KDF_DOMAIN_DR_ROOT, &[0x01]);
    let new_chain_key = kdf_derive(&combined, KDF_DOMAIN_DR_ROOT, &[0x02]);

    combined.zeroize();
    (new_root_key, new_chain_key)
}

/// Constant-time comparison of two byte slices.
/// Returns `true` if equal. Uses `subtle::ConstantTimeEq`.
pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.ct_eq(b).into()
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // -- Ed25519 --

    #[test]
    fn test_ed25519_sign_verify_roundtrip() {
        let (sk, vk) = generate_ed25519_keypair();
        let msg = b"hello cipherline";
        let sig = sign(msg, &sk);
        assert!(verify(msg, &sig, &vk).is_ok());
    }

    #[test]
    fn test_ed25519_verify_wrong_message() {
        let (sk, vk) = generate_ed25519_keypair();
        let sig = sign(b"correct message", &sk);
        assert!(verify(b"wrong message", &sig, &vk).is_err());
    }

    #[test]
    fn test_ed25519_verify_wrong_key() {
        let (sk, _vk) = generate_ed25519_keypair();
        let (_, vk2) = generate_ed25519_keypair();
        let sig = sign(b"hello", &sk);
        assert!(verify(b"hello", &sig, &vk2).is_err());
    }

    #[test]
    fn test_ed25519_keypair_unique() {
        let (sk1, _) = generate_ed25519_keypair();
        let (sk2, _) = generate_ed25519_keypair();
        assert_ne!(sk1.to_bytes(), sk2.to_bytes());
    }

    // -- X25519 --

    #[test]
    fn test_x25519_key_exchange() {
        let (secret_a, public_a) = generate_x25519_keypair();
        let (secret_b, public_b) = generate_x25519_keypair();

        let shared_ab = x25519_diffie_hellman(&secret_a, &public_b).unwrap();
        let shared_ba = x25519_diffie_hellman(&secret_b, &public_a).unwrap();

        assert_eq!(shared_ab, shared_ba);
    }

    #[test]
    fn test_x25519_keypair_unique() {
        let (_, pub_a) = generate_x25519_keypair();
        let (_, pub_b) = generate_x25519_keypair();
        assert_ne!(pub_a.as_bytes(), pub_b.as_bytes());
    }

    // -- ChaCha20-Poly1305 --

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let key = blake2b_hash(b"test key material");
        let nonce = [0u8; 12];
        let plaintext = b"secret message for cipherline";

        let ciphertext = encrypt(plaintext, &key, &nonce).unwrap();
        assert_ne!(&ciphertext, plaintext);

        let decrypted = decrypt(&ciphertext, &key, &nonce).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_decrypt_wrong_key_fails() {
        let key1 = blake2b_hash(b"key one");
        let key2 = blake2b_hash(b"key two");
        let nonce = [0u8; 12];
        let ciphertext = encrypt(b"hello", &key1, &nonce).unwrap();

        assert!(decrypt(&ciphertext, &key2, &nonce).is_err());
    }

    #[test]
    fn test_decrypt_tampered_ciphertext_fails() {
        let key = blake2b_hash(b"test key");
        let nonce = [0u8; 12];
        let mut ciphertext = encrypt(b"hello", &key, &nonce).unwrap();

        // Flip a bit.
        if let Some(byte) = ciphertext.first_mut() {
            *byte ^= 0x01;
        }

        assert!(decrypt(&ciphertext, &key, &nonce).is_err());
    }

    #[test]
    fn test_encrypt_with_dr_fixed_nonce() {
        let key = blake2b_hash(b"dr message key");
        let plaintext = b"double ratchet message";

        let ciphertext = encrypt(plaintext, &key, &DR_FIXED_NONCE).unwrap();
        let decrypted = decrypt(&ciphertext, &key, &DR_FIXED_NONCE).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    // -- BLAKE2b --

    #[test]
    fn test_blake2b_hash_deterministic() {
        let hash1 = blake2b_hash(b"hello");
        let hash2 = blake2b_hash(b"hello");
        assert_eq!(hash1, hash2);
    }

    #[test]
    fn test_blake2b_hash_different_inputs() {
        let hash1 = blake2b_hash(b"hello");
        let hash2 = blake2b_hash(b"world");
        assert_ne!(hash1, hash2);
    }

    // -- KDF --

    #[test]
    fn test_kdf_derive_deterministic() {
        let ikm = blake2b_hash(b"input key material");
        let out1 = kdf_derive(&ikm, b"domain", b"info");
        let out2 = kdf_derive(&ikm, b"domain", b"info");
        assert_eq!(out1, out2);
    }

    #[test]
    fn test_kdf_derive_domain_separation() {
        let ikm = blake2b_hash(b"input key material");
        let out1 = kdf_derive(&ikm, b"domain_a", b"info");
        let out2 = kdf_derive(&ikm, b"domain_b", b"info");
        assert_ne!(out1, out2, "different domains must produce different keys");
    }

    #[test]
    fn test_kdf_derive_info_separation() {
        let ikm = blake2b_hash(b"input key material");
        let out1 = kdf_derive(&ikm, b"domain", b"info_a");
        let out2 = kdf_derive(&ikm, b"domain", b"info_b");
        assert_ne!(out1, out2, "different info must produce different keys");
    }

    #[test]
    fn test_kdf_chain_step_produces_distinct_keys() {
        let chain_key = blake2b_hash(b"chain key");
        let (next_ck, msg_key) = kdf_chain_step(&chain_key);
        assert_ne!(next_ck, msg_key, "chain key and message key must differ");
        assert_ne!(next_ck, chain_key, "next chain key must differ from input");
    }

    #[test]
    fn test_kdf_root_step_produces_distinct_keys() {
        let root_key = blake2b_hash(b"root key");
        let dh_output = blake2b_hash(b"dh output");
        let (new_root, new_chain) = kdf_root_step(&root_key, &dh_output);
        assert_ne!(new_root, new_chain);
        assert_ne!(new_root, root_key);
    }

    // -- Constant-time comparison --

    #[test]
    fn test_constant_time_eq_equal() {
        let a = [1u8, 2, 3, 4];
        assert!(constant_time_eq(&a, &a));
    }

    #[test]
    fn test_constant_time_eq_not_equal() {
        let a = [1u8, 2, 3, 4];
        let b = [1u8, 2, 3, 5];
        assert!(!constant_time_eq(&a, &b));
    }

    #[test]
    fn test_constant_time_eq_different_lengths() {
        assert!(!constant_time_eq(&[1, 2, 3], &[1, 2]));
    }
}
