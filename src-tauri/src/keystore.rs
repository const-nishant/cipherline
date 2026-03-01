//! Platform-abstracted secure key storage.
//!
//! On **desktop** (Windows, macOS, Linux) this delegates to the OS keychain
//! via the `keyring` crate.
//!
//! On **Android** the master key is stored in the app-private files directory.
//! Android's file-based encryption (FBE) provides at-rest protection, and the
//! directory is sandboxed per-app.
//!
//! On **iOS** the `keyring` crate with `apple-native` delegates to the iOS
//! Keychain which is hardware-backed.

use tracing::{debug, info};

/// Service / account identifiers.
const SERVICE: &str = "com.cipherline.app";
const ACCOUNT: &str = "master_key";

/// Errors from key storage operations.
#[derive(Debug, thiserror::Error)]
pub enum KeystoreError {
    #[error("keystore error: {0}")]
    Backend(String),
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
}

// ---------------------------------------------------------------------------
// Desktop: keyring-backed (Windows / macOS / Linux)
// ---------------------------------------------------------------------------
#[cfg(not(any(target_os = "android", target_os = "ios")))]
mod platform {
    use super::*;
    use keyring::Entry;

    /// Read the stored master key, or return `None` if no entry exists.
    pub fn get_master_key() -> Result<Option<String>, KeystoreError> {
        let entry =
            Entry::new(SERVICE, ACCOUNT).map_err(|e| KeystoreError::Backend(e.to_string()))?;

        match entry.get_password() {
            Ok(existing) => {
                debug!("Master key found in keychain");
                Ok(Some(existing))
            }
            Err(keyring::Error::NoEntry) => Ok(None),
            Err(e) => Err(KeystoreError::Backend(e.to_string())),
        }
    }

    /// Store the master key.
    pub fn set_master_key(value: &str) -> Result<(), KeystoreError> {
        let entry =
            Entry::new(SERVICE, ACCOUNT).map_err(|e| KeystoreError::Backend(e.to_string()))?;
        entry
            .set_password(value)
            .map_err(|e| KeystoreError::Backend(e.to_string()))?;
        info!("Master key stored in keychain");
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Android: file-backed in app-private directory
// ---------------------------------------------------------------------------
#[cfg(target_os = "android")]
mod platform {
    use super::*;
    use std::fs;
    use std::path::PathBuf;

    /// The app-private files directory on Android.
    /// Tauri sets DATA_DIR; we derive the key file path from it.
    fn key_file_path() -> PathBuf {
        // On Android, std::env::var("HOME") or the data dir can be used.
        // Android app private dir is typically /data/data/<pkg>/files/
        // We use a well-known subdirectory.
        let base = if let Ok(home) = std::env::var("HOME") {
            PathBuf::from(home)
        } else {
            // Fallback: use Android app's internal storage
            PathBuf::from("/data/data/com.cipherline.app/files")
        };
        let dir = base.join(".cipherline_keys");
        let _ = fs::create_dir_all(&dir);
        dir.join("master.key")
    }

    pub fn get_master_key() -> Result<Option<String>, KeystoreError> {
        let path = key_file_path();
        if path.exists() {
            let content = fs::read_to_string(&path)?;
            debug!("Master key loaded from app-private file");
            Ok(Some(content.trim().to_string()))
        } else {
            Ok(None)
        }
    }

    pub fn set_master_key(value: &str) -> Result<(), KeystoreError> {
        let path = key_file_path();
        fs::write(&path, value)?;
        // Restrict permissions (best-effort; Android's sandbox is the main guard).
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let perms = fs::Permissions::from_mode(0o600);
            let _ = fs::set_permissions(&path, perms);
        }
        info!("Master key stored in app-private file");
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// iOS: keyring with apple-native (Keychain)
// ---------------------------------------------------------------------------
#[cfg(target_os = "ios")]
mod platform {
    use super::*;
    use keyring::Entry;

    pub fn get_master_key() -> Result<Option<String>, KeystoreError> {
        let entry =
            Entry::new(SERVICE, ACCOUNT).map_err(|e| KeystoreError::Backend(e.to_string()))?;

        match entry.get_password() {
            Ok(existing) => {
                debug!("Master key found in iOS Keychain");
                Ok(Some(existing))
            }
            Err(keyring::Error::NoEntry) => Ok(None),
            Err(e) => Err(KeystoreError::Backend(e.to_string())),
        }
    }

    pub fn set_master_key(value: &str) -> Result<(), KeystoreError> {
        let entry =
            Entry::new(SERVICE, ACCOUNT).map_err(|e| KeystoreError::Backend(e.to_string()))?;
        entry
            .set_password(value)
            .map_err(|e| KeystoreError::Backend(e.to_string()))?;
        info!("Master key stored in iOS Keychain");
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Public API — delegates to the active platform module
// ---------------------------------------------------------------------------

/// Read the stored master key, or return `None` if no entry exists.
pub fn get_master_key() -> Result<Option<String>, KeystoreError> {
    platform::get_master_key()
}

/// Store the master key.
pub fn set_master_key(value: &str) -> Result<(), KeystoreError> {
    platform::set_master_key(value)
}
