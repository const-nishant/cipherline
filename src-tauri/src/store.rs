//! Encrypted local storage using SQLCipher.
//!
//! - Master key: read from OS keychain via the `keystore` module (which uses
//!   platform-appropriate backends: keyring on desktop, file-based on Android,
//!   iOS Keychain on iOS). If absent, generate 32 random bytes, store via
//!   keystore, derive SQLCipher passphrase via Argon2id with domain string
//!   `"CipherLine_DBKey_v1"`.
//! - Schema includes: identity, contacts, sessions, messages, prekeys, devices,
//!   contact_devices.
//!
//! All operations run through a single `Store` handle wrapping a `rusqlite::Connection`.

use argon2::{Argon2, Params, Version};
use base64::Engine as _;
use rand::RngCore;
use rusqlite::{params, Connection, OptionalExtension};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use tracing::{debug, info};
use zeroize::Zeroize;

use cipherline_common::types::{DeviceId, Timestamp, UserId};

use crate::keystore;

/// Domain string for DB key derivation.
const DB_KEY_DOMAIN: &str = "CipherLine_DBKey_v1";

// ---------------------------------------------------------------------------
// Error
// ---------------------------------------------------------------------------

/// Store-level errors.
#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    #[error("database error: {0}")]
    Database(#[from] rusqlite::Error),

    #[error("keystore error: {0}")]
    Keystore(String),

    #[error("key derivation error: {0}")]
    KeyDerivation(String),

    #[error("serialization error: {0}")]
    Serialization(String),

    #[error("not found: {0}")]
    NotFound(String),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
}

impl From<rmp_serde::encode::Error> for StoreError {
    fn from(e: rmp_serde::encode::Error) -> Self {
        StoreError::Serialization(e.to_string())
    }
}

impl From<rmp_serde::decode::Error> for StoreError {
    fn from(e: rmp_serde::decode::Error) -> Self {
        StoreError::Serialization(e.to_string())
    }
}

// ---------------------------------------------------------------------------
// Stored types
// ---------------------------------------------------------------------------

/// Identity record persisted to the store.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct StoredIdentity {
    pub user_id: UserId,
    pub device_id: DeviceId,
    /// Ed25519 signing key bytes (private, 32 bytes).
    pub signing_key: Vec<u8>,
    /// X25519 static secret bytes (private, 32 bytes).
    pub exchange_secret: Vec<u8>,
    /// Root Ed25519 signing key bytes (private, 32 bytes).
    pub root_signing_key: Vec<u8>,
    /// Root X25519 static secret bytes (private, 32 bytes).
    pub root_exchange_secret: Vec<u8>,
    /// Device certificate (MessagePack).
    pub certificate: Vec<u8>,
    pub created_at: u64,
}

/// Contact record.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct StoredContact {
    pub user_id: UserId,
    pub display_name: String,
    /// Ed25519 verifying key bytes.
    pub signing_key: [u8; 32],
    /// X25519 public key bytes.
    pub exchange_key: [u8; 32],
    pub added_at: u64,
}

/// Message record.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct StoredMessage {
    pub id: String,
    pub conversation_id: String,
    pub sender_id: Vec<u8>,
    pub sender_device_id: Vec<u8>,
    pub timestamp: u64,
    /// Plaintext content.
    pub content: String,
    pub is_outgoing: bool,
    pub read: bool,
}

/// Device record.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct StoredDevice {
    pub device_id: DeviceId,
    pub signing_key: [u8; 32],
    pub exchange_key: [u8; 32],
    pub is_current: bool,
    pub active: bool,
    pub created_at: u64,
}

// ---------------------------------------------------------------------------
// Store
// ---------------------------------------------------------------------------

/// Encrypted local database backed by SQLCipher.
pub struct Store {
    conn: Connection,
}

impl Store {
    /// Open (or create) the encrypted database at the given path.
    ///
    /// The master key is read from the OS keychain. If absent, a new one is
    /// generated, stored in the keychain, and used to derive the SQLCipher passphrase.
    pub fn open(db_path: &PathBuf) -> Result<Self, StoreError> {
        // Ensure parent directory exists.
        if let Some(parent) = db_path.parent() {
            std::fs::create_dir_all(parent)?;
        }

        // Load or generate per-installation salt.
        let salt = Self::get_or_create_salt(db_path)?;

        let passphrase = Self::get_or_create_passphrase(&salt)?;
        let conn = Connection::open(db_path)?;

        // Apply SQLCipher encryption key.
        conn.pragma_update(None, "key", &passphrase)?;

        // Verify the database is accessible (SQLCipher will fail here if key is wrong).
        conn.execute_batch("SELECT count(*) FROM sqlite_master;")?;

        let store = Self { conn };
        store.initialize_schema()?;

        info!("Store opened at {}", db_path.display());
        Ok(store)
    }

    /// Open an in-memory encrypted database (for testing).
    #[cfg(test)]
    pub fn open_in_memory() -> Result<Self, StoreError> {
        let conn = Connection::open_in_memory()?;
        let store = Self { conn };
        store.initialize_schema()?;
        Ok(store)
    }

    /// Derive the SQLCipher passphrase from the master key.
    fn get_or_create_passphrase(salt: &[u8; 16]) -> Result<String, StoreError> {
        match keystore::get_master_key().map_err(|e| StoreError::Keystore(e.to_string()))? {
            Some(existing) => {
                debug!("Master key found in secure store");
                Self::derive_passphrase_from_b64(&existing, salt)
            }
            None => {
                info!("No master key found — generating new one");
                let mut master_key = [0u8; 32];
                rand::rngs::OsRng.fill_bytes(&mut master_key);
                let b64 = base64::engine::general_purpose::STANDARD.encode(master_key);
                master_key.zeroize();
                keystore::set_master_key(&b64).map_err(|e| StoreError::Keystore(e.to_string()))?;
                Self::derive_passphrase_from_b64(&b64, salt)
            }
        }
    }

    /// Load or create the per-installation random salt file.
    fn get_or_create_salt(db_path: &PathBuf) -> Result<[u8; 16], StoreError> {
        let salt_path = db_path.with_extension("salt");
        if salt_path.exists() {
            let data = std::fs::read(&salt_path)?;
            let salt: [u8; 16] = data
                .try_into()
                .map_err(|_| StoreError::KeyDerivation("corrupt salt file".into()))?;
            Ok(salt)
        } else {
            let mut salt = [0u8; 16];
            rand::rngs::OsRng.fill_bytes(&mut salt);
            std::fs::write(&salt_path, &salt)?;
            Ok(salt)
        }
    }

    /// Derive passphrase from base64-encoded master key using Argon2id.
    fn derive_passphrase_from_b64(b64_key: &str, salt: &[u8; 16]) -> Result<String, StoreError> {
        let mut master_key = base64::engine::general_purpose::STANDARD
            .decode(b64_key)
            .map_err(|e| StoreError::KeyDerivation(e.to_string()))?;

        // Argon2id with moderate params (suitable for client-side).
        let params = Params::new(65536, 3, 1, Some(32))
            .map_err(|e| StoreError::KeyDerivation(e.to_string()))?;
        let argon2 = Argon2::new(argon2::Algorithm::Argon2id, Version::V0x13, params);

        let mut derived = [0u8; 32];
        // Use domain-separated input: domain || master_key.
        let mut input = Vec::with_capacity(DB_KEY_DOMAIN.len() + master_key.len());
        input.extend_from_slice(DB_KEY_DOMAIN.as_bytes());
        input.extend_from_slice(&master_key);

        // Zeroize the decoded master key as soon as it's been consumed.
        master_key.zeroize();

        argon2
            .hash_password_into(&input, salt, &mut derived)
            .map_err(|e| StoreError::KeyDerivation(e.to_string()))?;

        // Zeroize the input buffer.
        input.zeroize();

        // SQLCipher expects a hex-encoded key prefixed with "x'"
        let hex_key = derived
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>();
        derived.zeroize();
        Ok(format!("x'{hex_key}'"))
    }

    /// Create all tables if they don't exist.
    fn initialize_schema(&self) -> Result<(), StoreError> {
        self.conn.execute_batch(
            "
            CREATE TABLE IF NOT EXISTS identity (
                id          INTEGER PRIMARY KEY CHECK (id = 1),
                user_id     BLOB NOT NULL,
                device_id   BLOB NOT NULL,
                signing_key BLOB NOT NULL,
                exchange_secret BLOB NOT NULL,
                root_signing_key BLOB NOT NULL,
                root_exchange_secret BLOB NOT NULL,
                certificate BLOB NOT NULL,
                created_at  INTEGER NOT NULL
            );

            CREATE TABLE IF NOT EXISTS contacts (
                user_id      BLOB PRIMARY KEY,
                display_name TEXT NOT NULL,
                signing_key  BLOB NOT NULL,
                exchange_key BLOB NOT NULL,
                added_at     INTEGER NOT NULL
            );

            CREATE TABLE IF NOT EXISTS sessions (
                contact_user_id   BLOB NOT NULL,
                contact_device_id BLOB NOT NULL,
                ratchet_state     BLOB NOT NULL,
                updated_at        INTEGER NOT NULL,
                PRIMARY KEY (contact_user_id, contact_device_id)
            );

            CREATE TABLE IF NOT EXISTS messages (
                id              TEXT PRIMARY KEY,
                conversation_id TEXT NOT NULL,
                sender_id       BLOB NOT NULL,
                sender_device_id BLOB NOT NULL,
                timestamp       INTEGER NOT NULL,
                content         TEXT NOT NULL,
                is_outgoing     INTEGER NOT NULL DEFAULT 0,
                read            INTEGER NOT NULL DEFAULT 0
            );
            CREATE INDEX IF NOT EXISTS idx_messages_conversation
                ON messages(conversation_id, timestamp);

            CREATE TABLE IF NOT EXISTS prekeys (
                id     INTEGER PRIMARY KEY,
                secret BLOB NOT NULL
            );

            CREATE TABLE IF NOT EXISTS signed_prekeys (
                id     INTEGER PRIMARY KEY,
                secret BLOB NOT NULL
            );

            CREATE TABLE IF NOT EXISTS devices (
                device_id    BLOB PRIMARY KEY,
                signing_key  BLOB NOT NULL,
                exchange_key BLOB NOT NULL,
                is_current   INTEGER NOT NULL DEFAULT 0,
                active       INTEGER NOT NULL DEFAULT 1,
                created_at   INTEGER NOT NULL
            );

            CREATE TABLE IF NOT EXISTS metadata (
                key   TEXT PRIMARY KEY,
                value BLOB NOT NULL
            );

            CREATE TABLE IF NOT EXISTS contact_devices (
                user_id      BLOB NOT NULL,
                device_id    BLOB NOT NULL,
                signing_key  BLOB NOT NULL,
                exchange_key BLOB NOT NULL,
                active       INTEGER NOT NULL DEFAULT 1,
                added_at     INTEGER NOT NULL,
                PRIMARY KEY (user_id, device_id)
            );
            ",
        )?;
        Ok(())
    }

    // -----------------------------------------------------------------------
    // Identity
    // -----------------------------------------------------------------------

    /// Store the local identity (root + device keys).
    pub fn save_identity(&self, identity: &StoredIdentity) -> Result<(), StoreError> {
        self.conn.execute(
            "INSERT OR REPLACE INTO identity
                (id, user_id, device_id, signing_key, exchange_secret,
                 root_signing_key, root_exchange_secret, certificate, created_at)
             VALUES (1, ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            params![
                identity.user_id.0.to_vec(),
                identity.device_id.0.to_vec(),
                identity.signing_key,
                identity.exchange_secret,
                identity.root_signing_key,
                identity.root_exchange_secret,
                identity.certificate,
                identity.created_at,
            ],
        )?;
        Ok(())
    }

    /// Load the local identity.
    pub fn load_identity(&self) -> Result<Option<StoredIdentity>, StoreError> {
        let mut stmt = self.conn.prepare(
            "SELECT user_id, device_id, signing_key, exchange_secret,
                    root_signing_key, root_exchange_secret, certificate, created_at
             FROM identity WHERE id = 1",
        )?;

        let result = stmt
            .query_row([], |row| {
                let uid_bytes: Vec<u8> = row.get(0)?;
                let did_bytes: Vec<u8> = row.get(1)?;
                let mut uid = [0u8; 32];
                let mut did = [0u8; 16];
                uid.copy_from_slice(&uid_bytes);
                did.copy_from_slice(&did_bytes);

                Ok(StoredIdentity {
                    user_id: UserId(uid),
                    device_id: DeviceId(did),
                    signing_key: row.get(2)?,
                    exchange_secret: row.get(3)?,
                    root_signing_key: row.get(4)?,
                    root_exchange_secret: row.get(5)?,
                    certificate: row.get(6)?,
                    created_at: row.get(7)?,
                })
            })
            .optional()?;

        Ok(result)
    }

    // -----------------------------------------------------------------------
    // Contacts
    // -----------------------------------------------------------------------

    /// Add or update a contact.
    pub fn save_contact(&self, contact: &StoredContact) -> Result<(), StoreError> {
        self.conn.execute(
            "INSERT OR REPLACE INTO contacts
                (user_id, display_name, signing_key, exchange_key, added_at)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![
                contact.user_id.0.to_vec(),
                contact.display_name,
                contact.signing_key.to_vec(),
                contact.exchange_key.to_vec(),
                contact.added_at,
            ],
        )?;
        Ok(())
    }

    /// List all contacts.
    pub fn list_contacts(&self) -> Result<Vec<StoredContact>, StoreError> {
        let mut stmt = self
            .conn
            .prepare("SELECT user_id, display_name, signing_key, exchange_key, added_at FROM contacts ORDER BY display_name")?;

        let contacts = stmt
            .query_map([], |row| {
                let uid_bytes: Vec<u8> = row.get(0)?;
                let sk_bytes: Vec<u8> = row.get(2)?;
                let ek_bytes: Vec<u8> = row.get(3)?;
                let mut uid = [0u8; 32];
                let mut sk = [0u8; 32];
                let mut ek = [0u8; 32];
                uid.copy_from_slice(&uid_bytes);
                sk.copy_from_slice(&sk_bytes);
                ek.copy_from_slice(&ek_bytes);

                Ok(StoredContact {
                    user_id: UserId(uid),
                    display_name: row.get(1)?,
                    signing_key: sk,
                    exchange_key: ek,
                    added_at: row.get(4)?,
                })
            })?
            .collect::<Result<Vec<_>, _>>()?;

        Ok(contacts)
    }

    /// Get a single contact by UserId.
    pub fn get_contact(&self, user_id: &UserId) -> Result<Option<StoredContact>, StoreError> {
        let mut stmt = self.conn.prepare(
            "SELECT user_id, display_name, signing_key, exchange_key, added_at
             FROM contacts WHERE user_id = ?1",
        )?;

        let result = stmt
            .query_row(params![user_id.0.to_vec()], |row| {
                let uid_bytes: Vec<u8> = row.get(0)?;
                let sk_bytes: Vec<u8> = row.get(2)?;
                let ek_bytes: Vec<u8> = row.get(3)?;
                let mut uid = [0u8; 32];
                let mut sk = [0u8; 32];
                let mut ek = [0u8; 32];
                uid.copy_from_slice(&uid_bytes);
                sk.copy_from_slice(&sk_bytes);
                ek.copy_from_slice(&ek_bytes);

                Ok(StoredContact {
                    user_id: UserId(uid),
                    display_name: row.get(1)?,
                    signing_key: sk,
                    exchange_key: ek,
                    added_at: row.get(4)?,
                })
            })
            .optional()?;

        Ok(result)
    }

    // -----------------------------------------------------------------------
    // Sessions (Double Ratchet state)
    // -----------------------------------------------------------------------

    /// Save a serialized ratchet session for a (contact, device) pair.
    pub fn save_session(
        &self,
        contact_user_id: &UserId,
        contact_device_id: &DeviceId,
        ratchet_state: &[u8],
    ) -> Result<(), StoreError> {
        let now = Timestamp::now().0;
        self.conn.execute(
            "INSERT OR REPLACE INTO sessions
                (contact_user_id, contact_device_id, ratchet_state, updated_at)
             VALUES (?1, ?2, ?3, ?4)",
            params![
                contact_user_id.0.to_vec(),
                contact_device_id.0.to_vec(),
                ratchet_state,
                now,
            ],
        )?;
        Ok(())
    }

    /// Load a ratchet session for a (contact, device) pair.
    pub fn load_session(
        &self,
        contact_user_id: &UserId,
        contact_device_id: &DeviceId,
    ) -> Result<Option<Vec<u8>>, StoreError> {
        let mut stmt = self.conn.prepare(
            "SELECT ratchet_state FROM sessions
             WHERE contact_user_id = ?1 AND contact_device_id = ?2",
        )?;

        let result = stmt
            .query_row(
                params![contact_user_id.0.to_vec(), contact_device_id.0.to_vec(),],
                |row| row.get(0),
            )
            .optional()?;

        Ok(result)
    }

    /// Find any session for a contact user (returns first device_id + ratchet state).
    pub fn find_any_session(
        &self,
        contact_user_id: &UserId,
    ) -> Result<Option<(DeviceId, Vec<u8>)>, StoreError> {
        let mut stmt = self.conn.prepare(
            "SELECT contact_device_id, ratchet_state FROM sessions
             WHERE contact_user_id = ?1 LIMIT 1",
        )?;

        let result = stmt
            .query_row(params![contact_user_id.0.to_vec()], |row| {
                let did_bytes: Vec<u8> = row.get(0)?;
                let ratchet: Vec<u8> = row.get(1)?;
                let mut did = [0u8; 16];
                did.copy_from_slice(&did_bytes);
                Ok((DeviceId(did), ratchet))
            })
            .optional()?;

        Ok(result)
    }

    /// Find all sessions for a contact user (returns vec of device_id + ratchet state).
    pub fn find_all_sessions(
        &self,
        contact_user_id: &UserId,
    ) -> Result<Vec<(DeviceId, Vec<u8>)>, StoreError> {
        let mut stmt = self.conn.prepare(
            "SELECT contact_device_id, ratchet_state FROM sessions
             WHERE contact_user_id = ?1",
        )?;

        let results = stmt
            .query_map(params![contact_user_id.0.to_vec()], |row| {
                let did_bytes: Vec<u8> = row.get(0)?;
                let ratchet: Vec<u8> = row.get(1)?;
                let mut did = [0u8; 16];
                did.copy_from_slice(&did_bytes);
                Ok((DeviceId(did), ratchet))
            })?
            .collect::<Result<Vec<_>, _>>()?;

        Ok(results)
    }

    /// Delete a session (e.g. after device revocation).
    pub fn delete_session(
        &self,
        contact_user_id: &UserId,
        contact_device_id: &DeviceId,
    ) -> Result<(), StoreError> {
        self.conn.execute(
            "DELETE FROM sessions WHERE contact_user_id = ?1 AND contact_device_id = ?2",
            params![contact_user_id.0.to_vec(), contact_device_id.0.to_vec(),],
        )?;
        Ok(())
    }

    /// Delete all sessions for a contact user.
    pub fn delete_all_sessions(&self, contact_user_id: &UserId) -> Result<u64, StoreError> {
        let count = self.conn.execute(
            "DELETE FROM sessions WHERE contact_user_id = ?1",
            params![contact_user_id.0.to_vec()],
        )? as u64;
        Ok(count)
    }

    // -----------------------------------------------------------------------
    // Contact Devices (remote devices for contacts)
    // -----------------------------------------------------------------------

    /// Store a contact's device record.
    pub fn save_contact_device(
        &self,
        user_id: &UserId,
        device_id: &DeviceId,
        signing_key: &[u8; 32],
        exchange_key: &[u8; 32],
    ) -> Result<(), StoreError> {
        let now = Timestamp::now().0;
        self.conn.execute(
            "INSERT OR REPLACE INTO contact_devices
                (user_id, device_id, signing_key, exchange_key, active, added_at)
             VALUES (?1, ?2, ?3, ?4, 1, ?5)",
            params![
                user_id.0.to_vec(),
                device_id.0.to_vec(),
                signing_key.to_vec(),
                exchange_key.to_vec(),
                now,
            ],
        )?;
        Ok(())
    }

    /// List active devices for a contact.
    pub fn list_contact_devices(
        &self,
        user_id: &UserId,
    ) -> Result<Vec<(DeviceId, [u8; 32], [u8; 32])>, StoreError> {
        let mut stmt = self.conn.prepare(
            "SELECT device_id, signing_key, exchange_key FROM contact_devices
             WHERE user_id = ?1 AND active = 1",
        )?;

        let results = stmt
            .query_map(params![user_id.0.to_vec()], |row| {
                let did_bytes: Vec<u8> = row.get(0)?;
                let sk_bytes: Vec<u8> = row.get(1)?;
                let ek_bytes: Vec<u8> = row.get(2)?;
                let mut did = [0u8; 16];
                let mut sk = [0u8; 32];
                let mut ek = [0u8; 32];
                did.copy_from_slice(&did_bytes);
                sk.copy_from_slice(&sk_bytes);
                ek.copy_from_slice(&ek_bytes);
                Ok((DeviceId(did), sk, ek))
            })?
            .collect::<Result<Vec<_>, _>>()?;

        Ok(results)
    }

    /// Revoke a contact's device.
    pub fn revoke_contact_device(
        &self,
        user_id: &UserId,
        device_id: &DeviceId,
    ) -> Result<(), StoreError> {
        self.conn.execute(
            "UPDATE contact_devices SET active = 0 WHERE user_id = ?1 AND device_id = ?2",
            params![user_id.0.to_vec(), device_id.0.to_vec()],
        )?;
        Ok(())
    }

    /// Replace all contact devices from a signed device list.
    pub fn replace_contact_devices(
        &self,
        user_id: &UserId,
        devices: &[(DeviceId, [u8; 32], [u8; 32], bool)],
    ) -> Result<(), StoreError> {
        // Mark all existing as inactive.
        self.conn.execute(
            "UPDATE contact_devices SET active = 0 WHERE user_id = ?1",
            params![user_id.0.to_vec()],
        )?;
        let now = Timestamp::now().0;
        // Insert/update from the list.
        for (device_id, signing_key, exchange_key, active) in devices {
            self.conn.execute(
                "INSERT OR REPLACE INTO contact_devices
                    (user_id, device_id, signing_key, exchange_key, active, added_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                params![
                    user_id.0.to_vec(),
                    device_id.0.to_vec(),
                    signing_key.to_vec(),
                    exchange_key.to_vec(),
                    *active as i32,
                    now,
                ],
            )?;
        }
        Ok(())
    }

    // -----------------------------------------------------------------------
    // Messages
    // -----------------------------------------------------------------------

    /// Store a decrypted message.
    pub fn save_message(&self, msg: &StoredMessage) -> Result<(), StoreError> {
        self.conn.execute(
            "INSERT OR REPLACE INTO messages
                (id, conversation_id, sender_id, sender_device_id,
                 timestamp, content, is_outgoing, read)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            params![
                msg.id,
                msg.conversation_id,
                msg.sender_id,
                msg.sender_device_id,
                msg.timestamp,
                msg.content,
                msg.is_outgoing as i32,
                msg.read as i32,
            ],
        )?;
        Ok(())
    }

    /// Get messages for a conversation, ordered by timestamp.
    pub fn get_messages(
        &self,
        conversation_id: &str,
        limit: u32,
        offset: u32,
    ) -> Result<Vec<StoredMessage>, StoreError> {
        let mut stmt = self.conn.prepare(
            "SELECT id, conversation_id, sender_id, sender_device_id,
                    timestamp, content, is_outgoing, read
             FROM messages
             WHERE conversation_id = ?1
             ORDER BY timestamp ASC
             LIMIT ?2 OFFSET ?3",
        )?;

        let messages = stmt
            .query_map(params![conversation_id, limit, offset], |row| {
                Ok(StoredMessage {
                    id: row.get(0)?,
                    conversation_id: row.get(1)?,
                    sender_id: row.get(2)?,
                    sender_device_id: row.get(3)?,
                    timestamp: row.get(4)?,
                    content: row.get(5)?,
                    is_outgoing: row.get::<_, i32>(6)? != 0,
                    read: row.get::<_, i32>(7)? != 0,
                })
            })?
            .collect::<Result<Vec<_>, _>>()?;

        Ok(messages)
    }

    /// Mark all messages in a conversation as read.
    pub fn mark_conversation_read(&self, conversation_id: &str) -> Result<(), StoreError> {
        self.conn.execute(
            "UPDATE messages SET read = 1 WHERE conversation_id = ?1 AND read = 0",
            params![conversation_id],
        )?;
        Ok(())
    }

    /// Get unread count per conversation.
    pub fn unread_counts(&self) -> Result<Vec<(String, u32)>, StoreError> {
        let mut stmt = self.conn.prepare(
            "SELECT conversation_id, COUNT(*) FROM messages
             WHERE read = 0 AND is_outgoing = 0
             GROUP BY conversation_id",
        )?;
        let counts = stmt
            .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(counts)
    }

    // -----------------------------------------------------------------------
    // Pre-keys
    // -----------------------------------------------------------------------

    /// Store a one-time pre-key secret.
    pub fn save_prekey(&self, id: u32, secret: &[u8]) -> Result<(), StoreError> {
        self.conn.execute(
            "INSERT OR REPLACE INTO prekeys (id, secret) VALUES (?1, ?2)",
            params![id, secret],
        )?;
        Ok(())
    }

    /// Load and delete a one-time pre-key secret (consumed on use).
    pub fn consume_prekey(&self, id: u32) -> Result<Option<Vec<u8>>, StoreError> {
        let mut stmt = self
            .conn
            .prepare("SELECT secret FROM prekeys WHERE id = ?1")?;
        let result: Option<Vec<u8>> = stmt.query_row(params![id], |row| row.get(0)).optional()?;

        if result.is_some() {
            self.conn
                .execute("DELETE FROM prekeys WHERE id = ?1", params![id])?;
        }
        Ok(result)
    }

    /// Count remaining pre-keys.
    pub fn prekey_count(&self) -> Result<u32, StoreError> {
        let count: u32 = self
            .conn
            .query_row("SELECT COUNT(*) FROM prekeys", [], |row| row.get(0))?;
        Ok(count)
    }

    /// Store a signed pre-key secret.
    pub fn save_signed_prekey(&self, id: u32, secret: &[u8]) -> Result<(), StoreError> {
        self.conn.execute(
            "INSERT OR REPLACE INTO signed_prekeys (id, secret) VALUES (?1, ?2)",
            params![id, secret],
        )?;
        Ok(())
    }

    /// Load a signed pre-key secret.
    pub fn load_signed_prekey(&self, id: u32) -> Result<Option<Vec<u8>>, StoreError> {
        let mut stmt = self
            .conn
            .prepare("SELECT secret FROM signed_prekeys WHERE id = ?1")?;
        let result = stmt.query_row(params![id], |row| row.get(0)).optional()?;
        Ok(result)
    }

    // -----------------------------------------------------------------------
    // Devices
    // -----------------------------------------------------------------------

    /// Store a device record.
    pub fn save_device(&self, device: &StoredDevice) -> Result<(), StoreError> {
        self.conn.execute(
            "INSERT OR REPLACE INTO devices
                (device_id, signing_key, exchange_key, is_current, active, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![
                device.device_id.0.to_vec(),
                device.signing_key.to_vec(),
                device.exchange_key.to_vec(),
                device.is_current as i32,
                device.active as i32,
                device.created_at,
            ],
        )?;
        Ok(())
    }

    /// List all devices.
    pub fn list_devices(&self) -> Result<Vec<StoredDevice>, StoreError> {
        let mut stmt = self.conn.prepare(
            "SELECT device_id, signing_key, exchange_key, is_current, active, created_at
             FROM devices ORDER BY created_at",
        )?;

        let devices = stmt
            .query_map([], |row| {
                let did_bytes: Vec<u8> = row.get(0)?;
                let sk_bytes: Vec<u8> = row.get(1)?;
                let ek_bytes: Vec<u8> = row.get(2)?;
                let mut did = [0u8; 16];
                let mut sk = [0u8; 32];
                let mut ek = [0u8; 32];
                did.copy_from_slice(&did_bytes);
                sk.copy_from_slice(&sk_bytes);
                ek.copy_from_slice(&ek_bytes);

                Ok(StoredDevice {
                    device_id: DeviceId(did),
                    signing_key: sk,
                    exchange_key: ek,
                    is_current: row.get::<_, i32>(3)? != 0,
                    active: row.get::<_, i32>(4)? != 0,
                    created_at: row.get(5)?,
                })
            })?
            .collect::<Result<Vec<_>, _>>()?;

        Ok(devices)
    }

    /// Mark a device as revoked.
    pub fn revoke_device(&self, device_id: &DeviceId) -> Result<(), StoreError> {
        self.conn.execute(
            "UPDATE devices SET active = 0 WHERE device_id = ?1",
            params![device_id.0.to_vec()],
        )?;
        Ok(())
    }

    /// Get next available prekey ID.
    pub fn next_prekey_id(&self) -> Result<u32, StoreError> {
        let max_id: Option<u32> = self
            .conn
            .query_row("SELECT MAX(id) FROM prekeys", [], |row| row.get(0))
            .optional()?
            .flatten();
        Ok(max_id.map(|id| id + 1).unwrap_or(0))
    }

    /// Get next available signed prekey ID.
    pub fn next_signed_prekey_id(&self) -> Result<u32, StoreError> {
        let max_id: Option<u32> = self
            .conn
            .query_row("SELECT MAX(id) FROM signed_prekeys", [], |row| row.get(0))
            .optional()?
            .flatten();
        Ok(max_id.map(|id| id + 1).unwrap_or(0))
    }

    // -----------------------------------------------------------------------
    // Metadata (key-value store for misc state)
    // -----------------------------------------------------------------------

    /// Store a metadata value.
    pub fn set_metadata(&self, key: &str, value: &[u8]) -> Result<(), StoreError> {
        self.conn.execute(
            "INSERT OR REPLACE INTO metadata (key, value) VALUES (?1, ?2)",
            params![key, value],
        )?;
        Ok(())
    }

    /// Load a metadata value.
    pub fn get_metadata(&self, key: &str) -> Result<Option<Vec<u8>>, StoreError> {
        let mut stmt = self
            .conn
            .prepare("SELECT value FROM metadata WHERE key = ?1")?;
        let result = stmt.query_row(params![key], |row| row.get(0)).optional()?;
        Ok(result)
    }

    /// Delete a metadata value.
    pub fn delete_metadata(&self, key: &str) -> Result<(), StoreError> {
        self.conn
            .execute("DELETE FROM metadata WHERE key = ?1", params![key])?;
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn test_store() -> Store {
        Store::open_in_memory().expect("failed to open in-memory store")
    }

    #[test]
    fn test_schema_creation() {
        let _store = test_store();
    }

    #[test]
    fn test_identity_save_load() {
        let store = test_store();

        let identity = StoredIdentity {
            user_id: UserId([1u8; 32]),
            device_id: DeviceId([2u8; 16]),
            signing_key: vec![3u8; 32],
            exchange_secret: vec![4u8; 32],
            root_signing_key: vec![5u8; 32],
            root_exchange_secret: vec![6u8; 32],
            certificate: vec![7u8; 100],
            created_at: 12345,
        };

        store.save_identity(&identity).unwrap();
        let loaded = store.load_identity().unwrap().unwrap();

        assert_eq!(loaded.user_id, identity.user_id);
        assert_eq!(loaded.device_id, identity.device_id);
        assert_eq!(loaded.signing_key, identity.signing_key);
        assert_eq!(loaded.created_at, identity.created_at);
    }

    #[test]
    fn test_identity_none_before_creation() {
        let store = test_store();
        assert!(store.load_identity().unwrap().is_none());
    }

    #[test]
    fn test_contacts_crud() {
        let store = test_store();

        let contact = StoredContact {
            user_id: UserId([10u8; 32]),
            display_name: "Alice".into(),
            signing_key: [11u8; 32],
            exchange_key: [12u8; 32],
            added_at: 1000,
        };

        store.save_contact(&contact).unwrap();

        let contacts = store.list_contacts().unwrap();
        assert_eq!(contacts.len(), 1);
        assert_eq!(contacts[0].display_name, "Alice");

        let found = store.get_contact(&UserId([10u8; 32])).unwrap();
        assert!(found.is_some());

        let not_found = store.get_contact(&UserId([99u8; 32])).unwrap();
        assert!(not_found.is_none());
    }

    #[test]
    fn test_sessions_save_load_delete() {
        let store = test_store();

        let uid = UserId([20u8; 32]);
        let did = DeviceId([21u8; 16]);
        let state = vec![0xAB; 512];

        store.save_session(&uid, &did, &state).unwrap();
        let loaded = store.load_session(&uid, &did).unwrap().unwrap();
        assert_eq!(loaded, state);

        store.delete_session(&uid, &did).unwrap();
        assert!(store.load_session(&uid, &did).unwrap().is_none());
    }

    #[test]
    fn test_messages_save_query() {
        let store = test_store();

        for i in 0..5 {
            let msg = StoredMessage {
                id: format!("msg-{i}"),
                conversation_id: "conv-1".into(),
                sender_id: vec![30u8; 32],
                sender_device_id: vec![31u8; 16],
                timestamp: 1000 + i,
                content: format!("Hello {i}"),
                is_outgoing: i % 2 == 0,
                read: false,
            };
            store.save_message(&msg).unwrap();
        }

        let messages = store.get_messages("conv-1", 100, 0).unwrap();
        assert_eq!(messages.len(), 5);
        assert_eq!(messages[0].content, "Hello 0");
        assert_eq!(messages[4].content, "Hello 4");
    }

    #[test]
    fn test_messages_unread_counts() {
        let store = test_store();

        // 3 unread incoming in conv-1, 2 in conv-2
        for i in 0..3 {
            store
                .save_message(&StoredMessage {
                    id: format!("a-{i}"),
                    conversation_id: "conv-1".into(),
                    sender_id: vec![1; 32],
                    sender_device_id: vec![1; 16],
                    timestamp: i,
                    content: "hi".into(),
                    is_outgoing: false,
                    read: false,
                })
                .unwrap();
        }
        for i in 0..2 {
            store
                .save_message(&StoredMessage {
                    id: format!("b-{i}"),
                    conversation_id: "conv-2".into(),
                    sender_id: vec![2; 32],
                    sender_device_id: vec![2; 16],
                    timestamp: i,
                    content: "hi".into(),
                    is_outgoing: false,
                    read: false,
                })
                .unwrap();
        }

        let counts = store.unread_counts().unwrap();
        assert_eq!(counts.len(), 2);
    }

    #[test]
    fn test_mark_conversation_read() {
        let store = test_store();

        store
            .save_message(&StoredMessage {
                id: "m1".into(),
                conversation_id: "conv-x".into(),
                sender_id: vec![1; 32],
                sender_device_id: vec![1; 16],
                timestamp: 100,
                content: "test".into(),
                is_outgoing: false,
                read: false,
            })
            .unwrap();

        store.mark_conversation_read("conv-x").unwrap();

        let counts = store.unread_counts().unwrap();
        // No unread left.
        let conv_x_count = counts
            .iter()
            .find(|(cid, _)| cid == "conv-x")
            .map(|(_, c)| *c)
            .unwrap_or(0);
        assert_eq!(conv_x_count, 0);
    }

    #[test]
    fn test_prekeys_save_consume() {
        let store = test_store();

        store.save_prekey(0, &[0xAA; 32]).unwrap();
        store.save_prekey(1, &[0xBB; 32]).unwrap();

        assert_eq!(store.prekey_count().unwrap(), 2);

        let consumed = store.consume_prekey(0).unwrap().unwrap();
        assert_eq!(consumed, vec![0xAA; 32]);

        assert_eq!(store.prekey_count().unwrap(), 1);

        // Double consume returns None.
        assert!(store.consume_prekey(0).unwrap().is_none());
    }

    #[test]
    fn test_devices_crud() {
        let store = test_store();

        let dev = StoredDevice {
            device_id: DeviceId([50u8; 16]),
            signing_key: [51u8; 32],
            exchange_key: [52u8; 32],
            is_current: true,
            active: true,
            created_at: 9999,
        };

        store.save_device(&dev).unwrap();

        let devices = store.list_devices().unwrap();
        assert_eq!(devices.len(), 1);
        assert!(devices[0].is_current);
        assert!(devices[0].active);

        store.revoke_device(&DeviceId([50u8; 16])).unwrap();
        let devices = store.list_devices().unwrap();
        assert!(!devices[0].active);
    }

    #[test]
    fn test_next_prekey_id() {
        let store = test_store();
        assert_eq!(store.next_prekey_id().unwrap(), 0);

        store.save_prekey(0, &[0; 32]).unwrap();
        store.save_prekey(1, &[0; 32]).unwrap();
        store.save_prekey(2, &[0; 32]).unwrap();

        assert_eq!(store.next_prekey_id().unwrap(), 3);
    }
}
