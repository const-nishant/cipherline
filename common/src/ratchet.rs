//! X3DH Key Agreement and Double Ratchet session management.
//!
//! # Design
//!
//! This module implements the Signal Double Ratchet algorithm as specified in
//! "The Double Ratchet Algorithm" (Perrin & Marlinspike, 2016, revision 1),
//! adapted to use CipherLine's primitive choices:
//!
//! - X25519 for DH ratchet
//! - ChaCha20-Poly1305 for message encryption (fixed nonce, single-use keys)
//! - BLAKE2b for KDF chains (domain-separated)
//!
//! # Security invariants
//!
//! - Each message key is used exactly once, then zeroized.
//! - MAC comparisons use constant-time operations.
//! - Skipped message keys are bounded (`MAX_SKIP` per step, `MAX_TOTAL_SKIPPED_KEYS` global).
//! - State is serializable for atomic persistence to SQLCipher.
//! - All errors are returned as `Result` — no panics on bad input.

use std::collections::HashMap;

use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret as X25519StaticSecret};
use zeroize::Zeroize;

use crate::crypto::{
    self, kdf_chain_step, kdf_root_step, x25519_diffie_hellman, DR_FIXED_NONCE, KDF_DOMAIN_X3DH,
};
use crate::types::{
    CipherlineError, MessageHeader, MAX_SKIP, MAX_TOTAL_SKIPPED_KEYS, PROTOCOL_VERSION,
};

// ---------------------------------------------------------------------------
// X3DH — Extended Triple Diffie-Hellman Key Agreement
// ---------------------------------------------------------------------------

/// Output of X3DH from the initiator's perspective.
pub struct X3DHInitResult {
    /// Shared secret used to seed the Double Ratchet root key.
    pub shared_secret: [u8; 32],
    /// Header sent to responder so they can compute the same shared secret.
    pub header: X3DHHeader,
}

/// Header sent by the X3DH initiator to the responder.
#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct X3DHHeader {
    pub version: u8,
    /// Initiator's X25519 identity public key (exchange key).
    pub identity_key: [u8; 32],
    /// Initiator's ephemeral X25519 public key (generated for this exchange).
    pub ephemeral_key: [u8; 32],
    /// ID of the one-time pre-key used (if any).
    pub one_time_pre_key_id: Option<u32>,
}

/// Perform X3DH as the **initiator** (Alice).
///
/// # Arguments
///
/// - `our_identity_signing`: Our root Ed25519 signing key (for identity binding)
/// - `our_identity_exchange`: Our root X25519 secret
/// - `their_bundle`: The responder's pre-key bundle fetched from the relay
///
/// # Security
///
/// The caller **must** verify `their_bundle.signed_pre_key_signature` before calling.
pub fn x3dh_initiate(
    our_identity_exchange: &X25519StaticSecret,
    our_identity_public: &[u8; 32],
    their_bundle: &crate::identity::PreKeyBundle,
) -> Result<X3DHInitResult, CipherlineError> {
    // Generate ephemeral X25519 keypair for this exchange.
    let ephemeral_secret = X25519StaticSecret::random_from_rng(OsRng);
    let ephemeral_public = X25519PublicKey::from(&ephemeral_secret);

    let their_identity = X25519PublicKey::from(their_bundle.identity_exchange_key);
    let their_spk = X25519PublicKey::from(their_bundle.signed_pre_key);

    // DH1 = X25519(IK_A, SPK_B)
    let dh1 = x25519_diffie_hellman(our_identity_exchange, &their_spk)?;

    // DH2 = X25519(EK_A, IK_B) — note: identity_key in bundle is Ed25519,
    // but we use the exchange_key for DH. The bundle should carry the X25519 identity key.
    // For correct X3DH, the identity key used here must be an X25519 key.
    // In our model, we maintain separate Ed25519 and X25519 keys.
    // The `identity_key` field in PreKeyBundle is the Ed25519 key for signature verification.
    // We need the responder's X25519 identity key for DH2.
    // This is handled by using the device_exchange_key from their DeviceCertificate.
    // For now, we use `their_identity` as the X25519 exchange key from the bundle.
    let dh2 = x25519_diffie_hellman(&ephemeral_secret, &their_identity)?;

    // DH3 = X25519(EK_A, SPK_B)
    let dh3 = x25519_diffie_hellman(&ephemeral_secret, &their_spk)?;

    // DH4 = X25519(EK_A, OPK_B) — optional, only if OPK is available.
    let (dh4, opk_id) = if let Some(opk) = their_bundle.one_time_pre_keys.first() {
        let their_opk = X25519PublicKey::from(opk.key);
        let dh = x25519_diffie_hellman(&ephemeral_secret, &their_opk)?;
        (Some(dh), Some(opk.id))
    } else {
        (None, None)
    };

    // Combine DH outputs: SK = KDF(DH1 || DH2 || DH3 [|| DH4])
    let shared_secret = combine_x3dh_secrets(&dh1, &dh2, &dh3, dh4.as_ref())?;

    let header = X3DHHeader {
        version: PROTOCOL_VERSION,
        identity_key: *our_identity_public,
        ephemeral_key: *ephemeral_public.as_bytes(),
        one_time_pre_key_id: opk_id,
    };

    Ok(X3DHInitResult {
        shared_secret,
        header,
    })
}

/// Perform X3DH as the **responder** (Bob).
///
/// # Arguments
///
/// - `our_identity_exchange`: Our root X25519 secret
/// - `our_spk_secret`: The signed pre-key secret referenced by the initiator
/// - `our_opk_secret`: The one-time pre-key secret (if referenced)
/// - `their_header`: The X3DH header from the initiator
pub fn x3dh_respond(
    our_identity_exchange: &X25519StaticSecret,
    our_spk_secret: &X25519StaticSecret,
    our_opk_secret: Option<&X25519StaticSecret>,
    their_header: &X3DHHeader,
) -> Result<[u8; 32], CipherlineError> {
    let their_identity = X25519PublicKey::from(their_header.identity_key);
    let their_ephemeral = X25519PublicKey::from(their_header.ephemeral_key);

    // DH1 = X25519(SPK_B, IK_A) — mirror of initiator's DH1
    let dh1 = x25519_diffie_hellman(our_spk_secret, &their_identity)?;

    // DH2 = X25519(IK_B, EK_A)
    let dh2 = x25519_diffie_hellman(our_identity_exchange, &their_ephemeral)?;

    // DH3 = X25519(SPK_B, EK_A)
    let dh3 = x25519_diffie_hellman(our_spk_secret, &their_ephemeral)?;

    // DH4 = X25519(OPK_B, EK_A) — only if OPK was used
    let dh4 = if let Some(opk) = our_opk_secret {
        Some(x25519_diffie_hellman(opk, &their_ephemeral)?)
    } else {
        None
    };

    combine_x3dh_secrets(&dh1, &dh2, &dh3, dh4.as_ref())
}

/// Combine X3DH DH outputs into a single shared secret via BLAKE2b KDF.
fn combine_x3dh_secrets(
    dh1: &[u8; 32],
    dh2: &[u8; 32],
    dh3: &[u8; 32],
    dh4: Option<&[u8; 32]>,
) -> Result<[u8; 32], CipherlineError> {
    let mut combined = Vec::with_capacity(32 * 4);
    combined.extend_from_slice(dh1);
    combined.extend_from_slice(dh2);
    combined.extend_from_slice(dh3);
    if let Some(dh4) = dh4 {
        combined.extend_from_slice(dh4);
    }

    // Use BLAKE2b unkeyed hash with domain separation.
    // We hash domain || combined. The result is 32 bytes.
    let mut input = Vec::with_capacity(KDF_DOMAIN_X3DH.len() + combined.len());
    input.extend_from_slice(KDF_DOMAIN_X3DH);
    input.extend_from_slice(&combined);

    let result = crypto::blake2b_hash(&input);

    // Zeroize intermediates.
    combined.zeroize();
    input.zeroize();

    Ok(result)
}

// ---------------------------------------------------------------------------
// Double Ratchet
// ---------------------------------------------------------------------------

/// Key for indexing skipped message keys: (ratchet public key bytes, message number).
#[derive(Clone, PartialEq, Eq, Hash, Serialize, Deserialize, Debug)]
struct SkippedKeyIndex {
    ratchet_key: [u8; 32],
    message_number: u32,
}

/// The Double Ratchet session state.
///
/// Serializable for persistence to SQLCipher. All key material is zeroized on drop.
#[derive(Serialize, Deserialize)]
pub struct RatchetState {
    // -- Root chain --
    root_key: [u8; 32],

    // -- Sending chain --
    sending_chain_key: Option<[u8; 32]>,
    sending_chain_n: u32,

    // -- Receiving chain --
    receiving_chain_key: Option<[u8; 32]>,
    receiving_chain_n: u32,

    // -- DH ratchet --
    /// Our current ratchet X25519 secret key (serialized as 32 bytes).
    our_ratchet_secret: [u8; 32],
    /// Our current ratchet X25519 public key.
    our_ratchet_public: [u8; 32],
    /// Their current ratchet X25519 public key.
    their_ratchet_public: Option<[u8; 32]>,

    // -- Counters --
    /// Number of messages in the previous sending chain (for header).
    previous_sending_chain_n: u32,

    // -- Skipped message keys --
    skipped_keys: HashMap<SkippedKeyIndex, [u8; 32]>,
}

/// Drop implementation to zeroize all key material.
impl Drop for RatchetState {
    fn drop(&mut self) {
        self.root_key.zeroize();
        if let Some(ref mut k) = self.sending_chain_key {
            k.zeroize();
        }
        if let Some(ref mut k) = self.receiving_chain_key {
            k.zeroize();
        }
        self.our_ratchet_secret.zeroize();
        for (_, v) in self.skipped_keys.iter_mut() {
            v.zeroize();
        }
    }
}

impl RatchetState {
    /// Initialize as the **sender** (Alice, the X3DH initiator).
    ///
    /// Alice performs the first DH ratchet step using Bob's signed pre-key
    /// as the initial ratchet public key.
    pub fn init_sender(
        shared_secret: [u8; 32],
        their_ratchet_public: [u8; 32],
    ) -> Result<Self, CipherlineError> {
        // Generate our initial ratchet keypair.
        let our_secret = X25519StaticSecret::random_from_rng(OsRng);
        let our_public = X25519PublicKey::from(&our_secret);

        // Perform initial DH ratchet step.
        let their_pub = X25519PublicKey::from(their_ratchet_public);
        let dh_output = x25519_diffie_hellman(&our_secret, &their_pub)?;
        let (root_key, sending_chain_key) = kdf_root_step(&shared_secret, &dh_output);

        Ok(Self {
            root_key,
            sending_chain_key: Some(sending_chain_key),
            sending_chain_n: 0,
            receiving_chain_key: None,
            receiving_chain_n: 0,
            our_ratchet_secret: our_secret.to_bytes(),
            our_ratchet_public: *our_public.as_bytes(),
            their_ratchet_public: Some(their_ratchet_public),
            previous_sending_chain_n: 0,
            skipped_keys: HashMap::new(),
        })
    }

    /// Initialize as the **receiver** (Bob, the X3DH responder).
    ///
    /// Bob uses his signed pre-key as the initial ratchet keypair and waits
    /// for Alice's first message to trigger the DH ratchet.
    pub fn init_receiver(shared_secret: [u8; 32], our_ratchet_secret: X25519StaticSecret) -> Self {
        let our_public = X25519PublicKey::from(&our_ratchet_secret);

        Self {
            root_key: shared_secret,
            sending_chain_key: None,
            sending_chain_n: 0,
            receiving_chain_key: None,
            receiving_chain_n: 0,
            our_ratchet_secret: our_ratchet_secret.to_bytes(),
            our_ratchet_public: *our_public.as_bytes(),
            their_ratchet_public: None,
            previous_sending_chain_n: 0,
            skipped_keys: HashMap::new(),
        }
    }

    /// Encrypt a plaintext message using the Double Ratchet.
    ///
    /// Returns the message header and ciphertext. The sending chain
    /// is advanced by one step. The message key is zeroized after use.
    pub fn ratchet_encrypt(
        &mut self,
        plaintext: &[u8],
    ) -> Result<(MessageHeader, Vec<u8>), CipherlineError> {
        let chain_key = self
            .sending_chain_key
            .as_ref()
            .ok_or_else(|| CipherlineError::Ratchet("no sending chain key".into()))?;

        // Derive message key and advance chain.
        let (next_chain_key, mut message_key) = kdf_chain_step(chain_key);

        // Build header.
        let header = MessageHeader {
            version: PROTOCOL_VERSION,
            ratchet_key: self.our_ratchet_public,
            previous_chain_length: self.previous_sending_chain_n,
            message_number: self.sending_chain_n,
        };

        // Encrypt with the message key (fixed nonce, single-use key).
        let ciphertext = crypto::encrypt(plaintext, &message_key, &DR_FIXED_NONCE)?;

        // Update state.
        self.sending_chain_key = Some(next_chain_key);
        self.sending_chain_n += 1;

        // Zeroize the message key — it must never be used again.
        message_key.zeroize();

        Ok((header, ciphertext))
    }

    /// Decrypt a received ciphertext using the Double Ratchet.
    ///
    /// Handles:
    /// - Normal receiving chain advancement
    /// - DH ratchet step when a new ratchet public key is received
    /// - Out-of-order messages via skipped key lookup
    ///
    /// Message keys are zeroized after use.
    pub fn ratchet_decrypt(
        &mut self,
        header: &MessageHeader,
        ciphertext: &[u8],
    ) -> Result<Vec<u8>, CipherlineError> {
        // Reject unknown versions.
        if header.version != PROTOCOL_VERSION {
            return Err(CipherlineError::UnknownVersion(header.version));
        }

        // 1. Try skipped message keys first.
        let skip_idx = SkippedKeyIndex {
            ratchet_key: header.ratchet_key,
            message_number: header.message_number,
        };
        if let Some(mut mk) = self.skipped_keys.remove(&skip_idx) {
            let result = crypto::decrypt(ciphertext, &mk, &DR_FIXED_NONCE);
            mk.zeroize();
            return result;
        }

        // 2. Check if we need a DH ratchet step (new ratchet key from sender).
        let need_dh_ratchet = match self.their_ratchet_public {
            Some(ref their_key) => !crypto::constant_time_eq(&header.ratchet_key, their_key),
            None => true, // First message in this session (receiver side).
        };

        if need_dh_ratchet {
            // Skip any remaining messages on the current receiving chain.
            self.skip_message_keys(header.previous_chain_length)?;

            // Perform DH ratchet step.
            self.dh_ratchet_step(&header.ratchet_key)?;
        }

        // 3. Skip messages on the receiving chain up to the message number.
        self.skip_message_keys(header.message_number)?;

        // 4. Derive message key and decrypt.
        let chain_key = self
            .receiving_chain_key
            .as_ref()
            .ok_or_else(|| CipherlineError::Ratchet("no receiving chain key".into()))?;

        let (next_chain_key, mut message_key) = kdf_chain_step(chain_key);
        let result = crypto::decrypt(ciphertext, &message_key, &DR_FIXED_NONCE);

        // Zeroize message key immediately.
        message_key.zeroize();

        // Only advance chain state on successful decryption to avoid state
        // desynchronization from forged or corrupted ciphertexts.
        if result.is_ok() {
            self.receiving_chain_key = Some(next_chain_key);
            self.receiving_chain_n += 1;
        }

        result
    }

    /// Perform a DH ratchet step with a new ratchet public key from the peer.
    fn dh_ratchet_step(&mut self, their_new_ratchet_key: &[u8; 32]) -> Result<(), CipherlineError> {
        self.previous_sending_chain_n = self.sending_chain_n;
        self.sending_chain_n = 0;
        self.receiving_chain_n = 0;

        self.their_ratchet_public = Some(*their_new_ratchet_key);

        // Derive new receiving chain.
        let their_pub = X25519PublicKey::from(*their_new_ratchet_key);
        let our_secret = X25519StaticSecret::from(self.our_ratchet_secret);
        let dh_output = x25519_diffie_hellman(&our_secret, &their_pub)?;
        let (new_root, receiving_chain_key) = kdf_root_step(&self.root_key, &dh_output);
        self.root_key = new_root;
        self.receiving_chain_key = Some(receiving_chain_key);

        // Generate new ratchet keypair and derive new sending chain.
        let new_secret = X25519StaticSecret::random_from_rng(OsRng);
        let new_public = X25519PublicKey::from(&new_secret);

        let dh_output2 = x25519_diffie_hellman(&new_secret, &their_pub)?;
        let (new_root2, sending_chain_key) = kdf_root_step(&self.root_key, &dh_output2);

        // Zeroize old secret before replacing.
        self.our_ratchet_secret.zeroize();

        self.root_key = new_root2;
        self.sending_chain_key = Some(sending_chain_key);
        self.our_ratchet_secret = new_secret.to_bytes();
        self.our_ratchet_public = *new_public.as_bytes();

        Ok(())
    }

    /// Skip message keys on the current receiving chain, storing them for
    /// future out-of-order delivery.
    fn skip_message_keys(&mut self, until: u32) -> Result<(), CipherlineError> {
        let receiving_chain_key = match self.receiving_chain_key {
            Some(ref k) => k,
            None => return Ok(()), // No receiving chain yet — nothing to skip.
        };

        if self.receiving_chain_n >= until {
            return Ok(());
        }

        let to_skip = until - self.receiving_chain_n;

        // Enforce per-step limit.
        if to_skip > MAX_SKIP {
            return Err(CipherlineError::Ratchet(format!(
                "message too far in the future: skipping {to_skip} keys exceeds MAX_SKIP ({MAX_SKIP})"
            )));
        }

        // Enforce global limit.
        if self.skipped_keys.len() + to_skip as usize > MAX_TOTAL_SKIPPED_KEYS {
            return Err(CipherlineError::Ratchet(format!(
                "global skipped key limit reached ({MAX_TOTAL_SKIPPED_KEYS})"
            )));
        }

        let mut chain_key = *receiving_chain_key;
        let ratchet_key = self.their_ratchet_public.unwrap_or([0u8; 32]);

        for n in self.receiving_chain_n..until {
            let (next_ck, mk) = kdf_chain_step(&chain_key);
            let idx = SkippedKeyIndex {
                ratchet_key,
                message_number: n,
            };
            self.skipped_keys.insert(idx, mk);
            chain_key = next_ck;
        }

        self.receiving_chain_key = Some(chain_key);
        self.receiving_chain_n = until;

        Ok(())
    }

    /// Number of stored skipped message keys (for monitoring).
    pub fn skipped_key_count(&self) -> usize {
        self.skipped_keys.len()
    }

    /// Our current ratchet public key (for inclusion in message headers).
    pub fn our_ratchet_public_key(&self) -> [u8; 32] {
        self.our_ratchet_public
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::{
        generate_one_time_pre_keys, generate_signed_pre_key, DeviceIdentity, RootIdentity,
    };

    /// Helper: set up two users with identities and a PreKeyBundle for Bob.
    fn setup_users() -> (
        RootIdentity,
        DeviceIdentity,
        RootIdentity,
        DeviceIdentity,
        crate::identity::PreKeyBundle,
        crate::identity::SignedPreKeyPrivate,
        Vec<crate::identity::OneTimePreKeyPrivate>,
    ) {
        let alice_root = RootIdentity::generate();
        let (alice_device, _) = DeviceIdentity::generate(&alice_root);

        let bob_root = RootIdentity::generate();
        let (bob_device, _) = DeviceIdentity::generate(&bob_root);

        let (spk_pub, spk_sig, spk_priv) = generate_signed_pre_key(&bob_device, 1);
        let (otpks, otpk_privs) = generate_one_time_pre_keys(0, 10);

        let bundle = crate::identity::build_pre_key_bundle(
            &bob_device,
            bob_root.user_id(),
            *bob_root.exchange_public_key().as_bytes(),
            1,
            spk_pub,
            spk_sig,
            otpks,
        );

        (
            alice_root,
            alice_device,
            bob_root,
            bob_device,
            bundle,
            spk_priv,
            otpk_privs,
        )
    }

    /// Helper: perform X3DH and init ratchet sessions for Alice (sender) and Bob (receiver).
    fn establish_session() -> (RatchetState, RatchetState) {
        let (alice_root, _alice_device, _bob_root, _bob_device, bundle, spk_priv, otpk_privs) =
            setup_users();

        // Alice initiates X3DH.
        let alice_x3dh = x3dh_initiate(
            &alice_root.exchange_secret,
            alice_root.exchange_public_key().as_bytes(),
            &bundle,
        )
        .unwrap();

        // Bob responds to X3DH.
        let opk_secret = if alice_x3dh.header.one_time_pre_key_id.is_some() {
            Some(&otpk_privs[0].secret)
        } else {
            None
        };

        let bob_shared_secret = x3dh_respond(
            &_bob_root.exchange_secret,
            &spk_priv.secret,
            opk_secret,
            &alice_x3dh.header,
        )
        .unwrap();

        // Verify both sides derived the same shared secret.
        assert_eq!(alice_x3dh.shared_secret, bob_shared_secret);

        // Initialize ratchet states.
        let alice_state =
            RatchetState::init_sender(alice_x3dh.shared_secret, bundle.signed_pre_key).unwrap();

        let bob_state = RatchetState::init_receiver(bob_shared_secret, spk_priv.secret);

        (alice_state, bob_state)
    }

    #[test]
    fn test_x3dh_shared_secret_agreement() {
        let (alice_root, _, _bob_root, _, bundle, spk_priv, otpk_privs) = setup_users();

        let result = x3dh_initiate(
            &alice_root.exchange_secret,
            alice_root.exchange_public_key().as_bytes(),
            &bundle,
        )
        .unwrap();

        let opk = if result.header.one_time_pre_key_id.is_some() {
            Some(&otpk_privs[0].secret)
        } else {
            None
        };

        let bob_ss = x3dh_respond(
            &_bob_root.exchange_secret,
            &spk_priv.secret,
            opk,
            &result.header,
        )
        .unwrap();

        assert_eq!(result.shared_secret, bob_ss);
    }

    #[test]
    fn test_x3dh_without_opk() {
        let (alice_root, _, bob_root, bob_device, _, _spk_priv, _) = setup_users();

        // Build bundle with NO one-time pre-keys.
        let (spk_pub, spk_sig, spk_priv2) = generate_signed_pre_key(&bob_device, 2);
        let bundle_no_opk = crate::identity::build_pre_key_bundle(
            &bob_device,
            bob_root.user_id(),
            *bob_root.exchange_public_key().as_bytes(),
            2,
            spk_pub,
            spk_sig,
            vec![], // No OPKs
        );

        let result = x3dh_initiate(
            &alice_root.exchange_secret,
            alice_root.exchange_public_key().as_bytes(),
            &bundle_no_opk,
        )
        .unwrap();

        assert!(result.header.one_time_pre_key_id.is_none());

        let bob_ss = x3dh_respond(
            &bob_root.exchange_secret,
            &spk_priv2.secret,
            None,
            &result.header,
        )
        .unwrap();

        assert_eq!(result.shared_secret, bob_ss);
    }

    #[test]
    fn test_ratchet_single_message() {
        let (mut alice, mut bob) = establish_session();

        let plaintext = b"hello bob!";
        let (header, ciphertext) = alice.ratchet_encrypt(plaintext).unwrap();
        let decrypted = bob.ratchet_decrypt(&header, &ciphertext).unwrap();

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_ratchet_multiple_messages_one_direction() {
        let (mut alice, mut bob) = establish_session();

        for i in 0..20 {
            let msg = format!("message {i}");
            let (hdr, ct) = alice.ratchet_encrypt(msg.as_bytes()).unwrap();
            let pt = bob.ratchet_decrypt(&hdr, &ct).unwrap();
            assert_eq!(pt, msg.as_bytes());
        }
    }

    #[test]
    fn test_ratchet_bidirectional() {
        let (mut alice, mut bob) = establish_session();

        // Alice → Bob
        let (h1, c1) = alice.ratchet_encrypt(b"hello bob").unwrap();
        let p1 = bob.ratchet_decrypt(&h1, &c1).unwrap();
        assert_eq!(p1, b"hello bob");

        // Bob → Alice (triggers DH ratchet at Bob, then Alice on receipt)
        let (h2, c2) = bob.ratchet_encrypt(b"hello alice").unwrap();
        let p2 = alice.ratchet_decrypt(&h2, &c2).unwrap();
        assert_eq!(p2, b"hello alice");

        // Alice → Bob again.
        let (h3, c3) = alice.ratchet_encrypt(b"how are you?").unwrap();
        let p3 = bob.ratchet_decrypt(&h3, &c3).unwrap();
        assert_eq!(p3, b"how are you?");

        // Bob → Alice again.
        let (h4, c4) = bob.ratchet_encrypt(b"i'm fine!").unwrap();
        let p4 = alice.ratchet_decrypt(&h4, &c4).unwrap();
        assert_eq!(p4, b"i'm fine!");
    }

    #[test]
    fn test_ratchet_interleaved_100_messages() {
        let (mut alice, mut bob) = establish_session();

        for i in 0u32..100 {
            if i % 2 == 0 {
                let msg = format!("alice says {i}");
                let (h, c) = alice.ratchet_encrypt(msg.as_bytes()).unwrap();
                let p = bob.ratchet_decrypt(&h, &c).unwrap();
                assert_eq!(p, msg.as_bytes(), "failed at message {i}");
            } else {
                let msg = format!("bob says {i}");
                let (h, c) = bob.ratchet_encrypt(msg.as_bytes()).unwrap();
                let p = alice.ratchet_decrypt(&h, &c).unwrap();
                assert_eq!(p, msg.as_bytes(), "failed at message {i}");
            }
        }
    }

    #[test]
    fn test_ratchet_out_of_order() {
        let (mut alice, mut bob) = establish_session();

        // Alice sends 5 messages.
        let mut messages = Vec::new();
        for i in 0..5 {
            let msg = format!("msg {i}");
            let (h, c) = alice.ratchet_encrypt(msg.as_bytes()).unwrap();
            messages.push((h, c, msg));
        }

        // Bob receives them out of order: 4, 2, 0, 1, 3.
        let order = [4, 2, 0, 1, 3];
        for &idx in &order {
            let (ref h, ref c, ref expected) = messages[idx];
            let p = bob.ratchet_decrypt(h, c).unwrap();
            assert_eq!(p, expected.as_bytes(), "failed on idx {idx}");
        }
    }

    #[test]
    fn test_ratchet_max_skip_exceeded() {
        let (mut alice, mut bob) = establish_session();

        // Send one message to establish the chain.
        let (h, c) = alice.ratchet_encrypt(b"first").unwrap();
        bob.ratchet_decrypt(&h, &c).unwrap();

        // Forge a header with a very high message number.
        let (h_far, c_far) = alice.ratchet_encrypt(b"far future").unwrap();
        let mut forged_header = h_far;
        forged_header.message_number = MAX_SKIP + 100;

        let result = bob.ratchet_decrypt(&forged_header, &c_far);
        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(err_msg.contains("MAX_SKIP"), "unexpected error: {err_msg}");
    }

    #[test]
    fn test_ratchet_wrong_key_decrypt_fails() {
        let (mut alice, _bob) = establish_session();
        let (_alice2, mut bob2) = establish_session();

        let (h, c) = alice.ratchet_encrypt(b"for bob 1").unwrap();

        // Try decrypting with a different session's Bob.
        let result = bob2.ratchet_decrypt(&h, &c);
        assert!(result.is_err());
    }

    #[test]
    fn test_ratchet_state_serde_roundtrip() {
        let (alice, _bob) = establish_session();

        // Serialize to MessagePack.
        let encoded = rmp_serde::to_vec(&alice).unwrap();
        let decoded: RatchetState = rmp_serde::from_slice(&encoded).unwrap();

        assert_eq!(decoded.our_ratchet_public, alice.our_ratchet_public);
        assert_eq!(decoded.sending_chain_n, alice.sending_chain_n);
    }

    #[test]
    fn test_ratchet_state_persistence_across_messages() {
        let (mut alice, mut bob) = establish_session();

        // Send a message.
        let (h1, c1) = alice.ratchet_encrypt(b"before save").unwrap();
        bob.ratchet_decrypt(&h1, &c1).unwrap();

        // Serialize both states (simulating persistence).
        let alice_saved = rmp_serde::to_vec(&alice).unwrap();
        let bob_saved = rmp_serde::to_vec(&bob).unwrap();

        // Restore from saved state.
        let mut alice_restored: RatchetState = rmp_serde::from_slice(&alice_saved).unwrap();
        let mut bob_restored: RatchetState = rmp_serde::from_slice(&bob_saved).unwrap();

        // Continue conversation.
        let (h2, c2) = alice_restored.ratchet_encrypt(b"after restore").unwrap();
        let p2 = bob_restored.ratchet_decrypt(&h2, &c2).unwrap();
        assert_eq!(p2, b"after restore");
    }

    #[test]
    fn test_duplicate_message_fails() {
        let (mut alice, mut bob) = establish_session();

        let (h, c) = alice.ratchet_encrypt(b"once only").unwrap();

        // First decrypt succeeds.
        let p = bob.ratchet_decrypt(&h, &c).unwrap();
        assert_eq!(p, b"once only");

        // Second decrypt with same header should fail (key consumed).
        let result = bob.ratchet_decrypt(&h, &c);
        assert!(result.is_err());
    }
}
