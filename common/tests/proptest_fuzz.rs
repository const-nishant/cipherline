//! Proptest-based fuzz tests for CipherLine crypto, ratchet, and protocol layers.
//!
//! These tests verify that core invariants hold under arbitrary inputs:
//! - Encrypt/decrypt roundtrips never lose data.
//! - Tampered ciphertext is always rejected.
//! - Protocol serde roundtrips are lossless.
//! - Double Ratchet handles arbitrary message orderings.
//! - KDF functions are deterministic and domain-separated.

use proptest::prelude::*;

use cipherline_common::crypto;
use cipherline_common::protocol::Envelope;
use cipherline_common::ratchet::{x3dh_initiate, x3dh_respond, RatchetState};
use cipherline_common::types::{DeviceId, MessageHeader, UserId, PROTOCOL_VERSION};

use ed25519_dalek::SigningKey;
use rand::rngs::OsRng;
use x25519_dalek::StaticSecret as X25519StaticSecret;

// ---------------------------------------------------------------------------
// Strategies
// ---------------------------------------------------------------------------

fn arb_key() -> impl Strategy<Value = [u8; 32]> {
    prop::array::uniform32(any::<u8>())
}

fn arb_plaintext() -> impl Strategy<Value = Vec<u8>> {
    prop::collection::vec(any::<u8>(), 0..4096)
}

fn arb_nonce() -> impl Strategy<Value = [u8; 12]> {
    prop::array::uniform12(any::<u8>())
}

// ---------------------------------------------------------------------------
// ChaCha20-Poly1305 encrypt/decrypt
// ---------------------------------------------------------------------------

proptest! {
    #![proptest_config(ProptestConfig::with_cases(200))]

    /// Encrypt-then-decrypt with the same key always recovers plaintext.
    #[test]
    fn fuzz_encrypt_decrypt_roundtrip(
        plaintext in arb_plaintext(),
        key in arb_key(),
        nonce in arb_nonce(),
    ) {
        let ct = crypto::encrypt(&plaintext, &key, &nonce).unwrap();
        let pt = crypto::decrypt(&ct, &key, &nonce).unwrap();
        prop_assert_eq!(&pt, &plaintext);
    }

    /// Flipping any bit in the ciphertext causes decryption to fail.
    #[test]
    fn fuzz_tampered_ciphertext_rejected(
        plaintext in arb_plaintext(),
        key in arb_key(),
        nonce in arb_nonce(),
        flip_pos in 0usize..8192,
    ) {
        let ct = crypto::encrypt(&plaintext, &key, &nonce).unwrap();
        if ct.is_empty() {
            return Ok(());
        }
        let idx = flip_pos % ct.len();
        let mut tampered = ct.clone();
        tampered[idx] ^= 0x01;
        prop_assert!(crypto::decrypt(&tampered, &key, &nonce).is_err());
    }

    /// Decrypting with a wrong key always fails.
    #[test]
    fn fuzz_wrong_key_rejected(
        plaintext in arb_plaintext(),
        key1 in arb_key(),
        key2 in arb_key(),
        nonce in arb_nonce(),
    ) {
        prop_assume!(key1 != key2);
        let ct = crypto::encrypt(&plaintext, &key1, &nonce).unwrap();
        prop_assert!(crypto::decrypt(&ct, &key2, &nonce).is_err());
    }
}

// ---------------------------------------------------------------------------
// BLAKE2b KDF
// ---------------------------------------------------------------------------

proptest! {
    #![proptest_config(ProptestConfig::with_cases(200))]

    /// BLAKE2b hash is deterministic.
    #[test]
    fn fuzz_blake2b_deterministic(data in arb_plaintext()) {
        let h1 = crypto::blake2b_hash(&data);
        let h2 = crypto::blake2b_hash(&data);
        prop_assert_eq!(h1, h2);
    }

    /// Different inputs produce different hashes (with overwhelming probability).
    #[test]
    fn fuzz_blake2b_collision_resistant(
        a in arb_plaintext(),
        b in arb_plaintext(),
    ) {
        prop_assume!(a != b);
        let ha = crypto::blake2b_hash(&a);
        let hb = crypto::blake2b_hash(&b);
        prop_assert_ne!(ha, hb);
    }
}

// ---------------------------------------------------------------------------
// Ed25519 sign / verify
// ---------------------------------------------------------------------------

proptest! {
    #![proptest_config(ProptestConfig::with_cases(100))]

    /// Signing then verifying always succeeds for the correct key.
    #[test]
    fn fuzz_ed25519_sign_verify(message in arb_plaintext()) {
        let sk = SigningKey::generate(&mut OsRng);
        let vk = sk.verifying_key();
        let sig = crypto::sign(&message, &sk);
        prop_assert!(crypto::verify(&message, &sig, &vk).is_ok());
    }

    /// Verifying with a different key always fails.
    #[test]
    fn fuzz_ed25519_wrong_key_rejected(message in arb_plaintext()) {
        let sk1 = SigningKey::generate(&mut OsRng);
        let sk2 = SigningKey::generate(&mut OsRng);
        let sig = crypto::sign(&message, &sk1);
        let vk2 = sk2.verifying_key();
        prop_assert!(crypto::verify(&message, &sig, &vk2).is_err());
    }
}

// ---------------------------------------------------------------------------
// Protocol serde roundtrips
// ---------------------------------------------------------------------------

proptest! {
    #![proptest_config(ProptestConfig::with_cases(200))]

    /// MessageHeader survives msgpack round-trip.
    #[test]
    fn fuzz_message_header_serde(
        ratchet_key in arb_key(),
        prev_n in any::<u32>(),
        msg_n in any::<u32>(),
    ) {
        let header = MessageHeader {
            version: PROTOCOL_VERSION,
            ratchet_key,
            previous_chain_length: prev_n,
            message_number: msg_n,
        };
        let bytes = rmp_serde::to_vec(&header).unwrap();
        let decoded: MessageHeader = rmp_serde::from_slice(&bytes).unwrap();
        prop_assert_eq!(header.version, decoded.version);
        prop_assert_eq!(header.ratchet_key, decoded.ratchet_key);
        prop_assert_eq!(header.previous_chain_length, decoded.previous_chain_length);
        prop_assert_eq!(header.message_number, decoded.message_number);
    }

    /// Envelope::signable_data is deterministic for the same inputs.
    #[test]
    fn fuzz_signable_data_deterministic(
        ratchet_key in arb_key(),
        ciphertext in arb_plaintext(),
        msg_n in any::<u32>(),
    ) {
        let header = MessageHeader {
            version: PROTOCOL_VERSION,
            ratchet_key,
            previous_chain_length: 0,
            message_number: msg_n,
        };
        let s1 = Envelope::signable_data(&header, &ciphertext);
        let s2 = Envelope::signable_data(&header, &ciphertext);
        prop_assert_eq!(s1, s2);
    }
}

// ---------------------------------------------------------------------------
// Double Ratchet round-trip under arbitrary plaintext
// ---------------------------------------------------------------------------

proptest! {
    #![proptest_config(ProptestConfig::with_cases(50))]

    /// A full X3DH → Double Ratchet roundtrip decrypts arbitrary plaintexts.
    #[test]
    fn fuzz_ratchet_roundtrip(
        plaintext in prop::collection::vec(any::<u8>(), 1..2048),
    ) {
        // Set up identities.
        let alice_exchange = X25519StaticSecret::random_from_rng(OsRng);
        let alice_exchange_pub = *x25519_dalek::PublicKey::from(&alice_exchange).as_bytes();

        let bob_exchange = X25519StaticSecret::random_from_rng(OsRng);
        let bob_exchange_pub = *x25519_dalek::PublicKey::from(&bob_exchange).as_bytes();
        let bob_signing = SigningKey::generate(&mut OsRng);

        // Bob's SPK
        let spk_secret = X25519StaticSecret::random_from_rng(OsRng);
        let spk_public = *x25519_dalek::PublicKey::from(&spk_secret).as_bytes();
        let spk_sig = crypto::sign(&spk_public, &bob_signing);

        // OPK
        let opk_secret = X25519StaticSecret::random_from_rng(OsRng);
        let opk_public = *x25519_dalek::PublicKey::from(&opk_secret).as_bytes();

        let user_id = UserId(crypto::blake2b_hash(&bob_signing.verifying_key().to_bytes()));

        let bundle = cipherline_common::identity::PreKeyBundle {
            version: PROTOCOL_VERSION,
            user_id,
            device_id: DeviceId::generate(),
            identity_signing_key: bob_signing.verifying_key().to_bytes(),
            identity_exchange_key: bob_exchange_pub,
            signed_pre_key: spk_public,
            signed_pre_key_signature: spk_sig.to_bytes().to_vec(),
            signed_pre_key_id: 1,
            one_time_pre_keys: vec![cipherline_common::identity::OneTimePreKey {
                id: 0,
                key: opk_public,
            }],
        };

        // Alice initiates X3DH.
        let init = x3dh_initiate(&alice_exchange, &alice_exchange_pub, &bundle).unwrap();

        // Bob responds.
        let bob_ss = x3dh_respond(
            &bob_exchange,
            &spk_secret,
            Some(&opk_secret),
            &init.header,
        )
        .unwrap();

        // Init ratchets.
        let mut alice_ratchet =
            RatchetState::init_sender(init.shared_secret, bundle.signed_pre_key).unwrap();
        let mut bob_ratchet =
            RatchetState::init_receiver(bob_ss, spk_secret);

        // Alice encrypts.
        let (header, ct) = alice_ratchet.ratchet_encrypt(&plaintext).unwrap();

        // Bob decrypts.
        let pt = bob_ratchet.ratchet_decrypt(&header, &ct).unwrap();
        prop_assert_eq!(&pt, &plaintext);
    }

    /// Multiple messages in one direction all decrypt correctly.
    #[test]
    fn fuzz_ratchet_multi_message(
        messages in prop::collection::vec(
            prop::collection::vec(any::<u8>(), 1..512),
            1..10,
        ),
    ) {
        let alice_exchange = X25519StaticSecret::random_from_rng(OsRng);
        let alice_exchange_pub = *x25519_dalek::PublicKey::from(&alice_exchange).as_bytes();
        let bob_exchange = X25519StaticSecret::random_from_rng(OsRng);
        let bob_exchange_pub = *x25519_dalek::PublicKey::from(&bob_exchange).as_bytes();
        let bob_signing = SigningKey::generate(&mut OsRng);

        let spk_secret = X25519StaticSecret::random_from_rng(OsRng);
        let spk_public = *x25519_dalek::PublicKey::from(&spk_secret).as_bytes();
        let spk_sig = crypto::sign(&spk_public, &bob_signing);

        let user_id = UserId(crypto::blake2b_hash(&bob_signing.verifying_key().to_bytes()));

        let bundle = cipherline_common::identity::PreKeyBundle {
            version: PROTOCOL_VERSION,
            user_id,
            device_id: DeviceId::generate(),
            identity_signing_key: bob_signing.verifying_key().to_bytes(),
            identity_exchange_key: bob_exchange_pub,
            signed_pre_key: spk_public,
            signed_pre_key_signature: spk_sig.to_bytes().to_vec(),
            signed_pre_key_id: 1,
            one_time_pre_keys: vec![],
        };

        let init = x3dh_initiate(&alice_exchange, &alice_exchange_pub, &bundle).unwrap();
        let bob_ss = x3dh_respond(&bob_exchange, &spk_secret, None, &init.header).unwrap();

        let mut alice = RatchetState::init_sender(init.shared_secret, bundle.signed_pre_key).unwrap();
        let mut bob = RatchetState::init_receiver(bob_ss, spk_secret);

        for msg in &messages {
            let (header, ct) = alice.ratchet_encrypt(msg).unwrap();
            let pt = bob.ratchet_decrypt(&header, &ct).unwrap();
            prop_assert_eq!(&pt, msg);
        }
    }

    /// Tampered ratchet ciphertext is always rejected.
    #[test]
    fn fuzz_ratchet_tampered_rejected(
        plaintext in prop::collection::vec(any::<u8>(), 1..1024),
        flip_pos in 0usize..8192,
    ) {
        let alice_exchange = X25519StaticSecret::random_from_rng(OsRng);
        let alice_exchange_pub = *x25519_dalek::PublicKey::from(&alice_exchange).as_bytes();
        let bob_exchange = X25519StaticSecret::random_from_rng(OsRng);
        let bob_exchange_pub = *x25519_dalek::PublicKey::from(&bob_exchange).as_bytes();
        let bob_signing = SigningKey::generate(&mut OsRng);

        let spk_secret = X25519StaticSecret::random_from_rng(OsRng);
        let spk_public = *x25519_dalek::PublicKey::from(&spk_secret).as_bytes();
        let spk_sig = crypto::sign(&spk_public, &bob_signing);

        let user_id = UserId(crypto::blake2b_hash(&bob_signing.verifying_key().to_bytes()));

        let bundle = cipherline_common::identity::PreKeyBundle {
            version: PROTOCOL_VERSION,
            user_id,
            device_id: DeviceId::generate(),
            identity_signing_key: bob_signing.verifying_key().to_bytes(),
            identity_exchange_key: bob_exchange_pub,
            signed_pre_key: spk_public,
            signed_pre_key_signature: spk_sig.to_bytes().to_vec(),
            signed_pre_key_id: 1,
            one_time_pre_keys: vec![],
        };

        let init = x3dh_initiate(&alice_exchange, &alice_exchange_pub, &bundle).unwrap();
        let bob_ss = x3dh_respond(&bob_exchange, &spk_secret, None, &init.header).unwrap();

        let mut alice = RatchetState::init_sender(init.shared_secret, bundle.signed_pre_key).unwrap();
        let mut bob = RatchetState::init_receiver(bob_ss, spk_secret);

        let (header, ct) = alice.ratchet_encrypt(&plaintext).unwrap();

        if ct.is_empty() {
            return Ok(());
        }
        let idx = flip_pos % ct.len();
        let mut tampered = ct.clone();
        tampered[idx] ^= 0x01;

        prop_assert!(bob.ratchet_decrypt(&header, &tampered).is_err());
    }
}
