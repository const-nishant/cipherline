//! Challenge-response authentication for WebSocket connections.
//!
//! # Flow
//!
//! 1. Server sends a 32-byte random challenge on WebSocket connect.
//! 2. Client signs `challenge || timestamp` with its device Ed25519 key.
//! 3. Client sends `AuthResponse { user_id, device_id, device_public_key, signature, timestamp }`.
//! 4. Server verifies: valid signature, timestamp within tolerance, no replay.
//! 5. On success, the connection is associated with `(UserId, DeviceId)`.
//!
//! # Replay Prevention
//!
//! Server maintains a short-lived set of used challenge nonces (TTL = 2× tolerance).
//! A used challenge is rejected on resubmission.

use std::collections::HashMap;
use std::time::{Duration, Instant};

use ed25519_dalek::{Signature, VerifyingKey};
use rand::RngCore;
use tracing::{debug, warn};

use cipherline_common::types::{DeviceId, UserId};

/// A pending authentication challenge.
#[derive(Debug, Clone)]
pub struct PendingChallenge {
    pub challenge: [u8; 32],
    pub created_at: Instant,
}

/// Result of a successful authentication.
#[derive(Debug, Clone)]
pub struct AuthenticatedPeer {
    pub user_id: UserId,
    pub device_id: DeviceId,
    #[allow(dead_code)] // Used in later phases for per-message signature checks
    pub verifying_key: VerifyingKey,
}

/// Manages authentication challenges and replay prevention.
pub struct AuthManager {
    /// Used challenge nonces with their creation time, for replay prevention.
    used_challenges: HashMap<[u8; 32], Instant>,
    /// How long a timestamp can differ from server time.
    timestamp_tolerance: Duration,
    /// How long to keep used challenges before pruning.
    challenge_ttl: Duration,
}

impl AuthManager {
    pub fn new(timestamp_tolerance_secs: u64) -> Self {
        let tolerance = Duration::from_secs(timestamp_tolerance_secs);
        Self {
            used_challenges: HashMap::new(),
            timestamp_tolerance: tolerance,
            // Keep used challenges for 2× tolerance to catch replays.
            challenge_ttl: tolerance * 2,
        }
    }

    /// Generate a fresh 32-byte challenge.
    pub fn generate_challenge(&self) -> PendingChallenge {
        let mut challenge = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut challenge);
        PendingChallenge {
            challenge,
            created_at: Instant::now(),
        }
    }

    /// Verify an authentication response.
    ///
    /// Returns the authenticated peer on success.
    pub fn verify_response(
        &mut self,
        challenge: &[u8; 32],
        challenge_created: Instant,
        user_id: UserId,
        device_id: DeviceId,
        device_public_key: &[u8; 32],
        signature_bytes: &[u8],
        client_timestamp: u64,
    ) -> Result<AuthenticatedPeer, AuthError> {
        // 1. Check challenge hasn't expired (generous timeout: 2× tolerance).
        if challenge_created.elapsed() > self.challenge_ttl {
            warn!("auth: challenge expired");
            return Err(AuthError::ChallengeExpired);
        }

        // 2. Check for replay — challenge must not have been used before.
        if self.used_challenges.contains_key(challenge) {
            warn!("auth: replayed challenge");
            return Err(AuthError::ReplayDetected);
        }

        // 3. Verify client timestamp is within tolerance of server time.
        let server_time = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64;
        let tolerance_ms = self.timestamp_tolerance.as_millis() as u64;
        let diff = if server_time > client_timestamp {
            server_time - client_timestamp
        } else {
            client_timestamp - server_time
        };
        if diff > tolerance_ms {
            warn!("auth: timestamp out of range (diff={diff}ms, tolerance={tolerance_ms}ms)");
            return Err(AuthError::TimestampOutOfRange);
        }

        // 4. Reconstruct the signed payload: challenge || timestamp (LE bytes).
        let mut payload = Vec::with_capacity(32 + 8);
        payload.extend_from_slice(challenge);
        payload.extend_from_slice(&client_timestamp.to_le_bytes());

        // 5. Verify the Ed25519 signature.
        let verifying_key =
            VerifyingKey::from_bytes(device_public_key).map_err(|_| AuthError::InvalidPublicKey)?;

        let sig_bytes: [u8; 64] = signature_bytes
            .try_into()
            .map_err(|_| AuthError::InvalidSignature)?;
        let signature = Signature::from_bytes(&sig_bytes);

        verifying_key
            .verify_strict(&payload, &signature)
            .map_err(|_| AuthError::SignatureVerificationFailed)?;

        // 6. Mark challenge as used (replay prevention).
        self.used_challenges.insert(*challenge, Instant::now());

        debug!(
            "auth: device {:?} authenticated for user {:?}",
            device_id, user_id
        );

        Ok(AuthenticatedPeer {
            user_id,
            device_id,
            verifying_key,
        })
    }

    /// Prune expired used-challenge entries.
    pub fn cleanup_expired_challenges(&mut self) {
        let cutoff = self.challenge_ttl;
        self.used_challenges
            .retain(|_, created| created.elapsed() < cutoff);
    }
}

/// Authentication errors.
#[derive(Debug, thiserror::Error)]
pub enum AuthError {
    #[error("authentication challenge expired")]
    ChallengeExpired,

    #[error("replay detected: challenge already used")]
    ReplayDetected,

    #[error("client timestamp out of acceptable range")]
    TimestampOutOfRange,

    #[error("invalid public key bytes")]
    InvalidPublicKey,

    #[error("invalid signature format")]
    InvalidSignature,

    #[error("signature verification failed")]
    SignatureVerificationFailed,

    #[error("device not registered for user")]
    #[allow(dead_code)] // Used when device registration checks are enforced
    DeviceNotRegistered,
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};
    use rand::rngs::OsRng;

    fn make_auth_response(challenge: &[u8; 32]) -> (UserId, DeviceId, [u8; 32], Vec<u8>, u64) {
        let signing_key = SigningKey::generate(&mut OsRng);
        let verifying_key = signing_key.verifying_key();
        let user_id = UserId(cipherline_common::crypto::blake2b_hash(
            verifying_key.as_bytes(),
        ));
        let device_id = DeviceId::generate();
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64;

        let mut payload = Vec::with_capacity(40);
        payload.extend_from_slice(challenge);
        payload.extend_from_slice(&timestamp.to_le_bytes());
        let signature = signing_key.sign(&payload);

        (
            user_id,
            device_id,
            verifying_key.to_bytes(),
            signature.to_bytes().to_vec(),
            timestamp,
        )
    }

    #[test]
    fn test_successful_auth() {
        let mut auth = AuthManager::new(60);
        let pending = auth.generate_challenge();
        let (user_id, device_id, pubkey, sig, ts) = make_auth_response(&pending.challenge);

        let result = auth.verify_response(
            &pending.challenge,
            pending.created_at,
            user_id,
            device_id,
            &pubkey,
            &sig,
            ts,
        );
        assert!(result.is_ok());
        let peer = result.unwrap();
        assert_eq!(peer.user_id, user_id);
        assert_eq!(peer.device_id, device_id);
    }

    #[test]
    fn test_replay_detected() {
        let mut auth = AuthManager::new(60);
        let pending = auth.generate_challenge();
        let (user_id, device_id, pubkey, sig, ts) = make_auth_response(&pending.challenge);

        // First attempt succeeds.
        let _ = auth
            .verify_response(
                &pending.challenge,
                pending.created_at,
                user_id,
                device_id,
                &pubkey,
                &sig,
                ts,
            )
            .unwrap();

        // Second attempt with same challenge → replay.
        let result = auth.verify_response(
            &pending.challenge,
            pending.created_at,
            user_id,
            device_id,
            &pubkey,
            &sig,
            ts,
        );
        assert!(matches!(result, Err(AuthError::ReplayDetected)));
    }

    #[test]
    fn test_wrong_signature_fails() {
        let mut auth = AuthManager::new(60);
        let pending = auth.generate_challenge();
        let (user_id, device_id, pubkey, _sig, ts) = make_auth_response(&pending.challenge);

        // Use a different (wrong) signature.
        let wrong_sig = vec![0u8; 64];
        let result = auth.verify_response(
            &pending.challenge,
            pending.created_at,
            user_id,
            device_id,
            &pubkey,
            &wrong_sig,
            ts,
        );
        assert!(matches!(
            result,
            Err(AuthError::SignatureVerificationFailed)
        ));
    }

    #[test]
    fn test_cleanup_expired_challenges() {
        let mut auth = AuthManager::new(60);
        // Manually insert an old challenge.
        let old_challenge = [42u8; 32];
        auth.used_challenges
            .insert(old_challenge, Instant::now() - Duration::from_secs(300));
        assert_eq!(auth.used_challenges.len(), 1);

        auth.cleanup_expired_challenges();
        assert_eq!(auth.used_challenges.len(), 0);
    }
}
