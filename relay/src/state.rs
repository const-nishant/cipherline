//! Shared relay state.
//!
//! Contains all server-wide data structures (message queue, pre-key store,
//! device registry, online connections) behind concurrent-safe wrappers.

use std::collections::HashSet;
use std::sync::Arc;

use axum::extract::ws::{Message, WebSocket};
use dashmap::DashMap;
use futures::stream::SplitSink;
use tokio::sync::Mutex;

use cipherline_common::identity::{PreKeyBundle, SignedDeviceList};
use cipherline_common::types::{DeviceId, UserId};

use crate::auth::AuthManager;
use crate::config::RelayConfig;
use crate::queue::MessageQueue;

/// Composite key for device identification.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
struct DeviceKey {
    user_id: UserId,
    device_id: DeviceId,
}

/// The global relay state, shared across all connections.
pub struct RelayState {
    pub config: RelayConfig,
    pub auth: Mutex<AuthManager>,
    pub queue: MessageQueue,

    /// Online WebSocket senders, keyed by (UserId, DeviceId).
    online: DashMap<DeviceKey, Arc<Mutex<SplitSink<WebSocket, Message>>>>,

    /// Pre-key bundles stored for devices.
    prekey_bundles: DashMap<DeviceKey, PreKeyBundle>,

    /// Registered devices per user.
    devices: DashMap<UserId, HashSet<DeviceId>>,

    /// Signed device lists per user.
    device_lists: DashMap<UserId, SignedDeviceList>,
}

impl RelayState {
    pub fn new(config: RelayConfig) -> Self {
        let auth = AuthManager::new(config.auth_timestamp_tolerance_secs);
        let queue = MessageQueue::new(config.max_queued_per_device, config.message_ttl_secs);

        Self {
            config,
            auth: Mutex::new(auth),
            queue,
            online: DashMap::new(),
            prekey_bundles: DashMap::new(),
            devices: DashMap::new(),
            device_lists: DashMap::new(),
        }
    }

    // --- Online connection management ---

    /// Register a device as online with its WebSocket sender.
    pub fn register_online(
        &self,
        user_id: UserId,
        device_id: DeviceId,
        sender: Arc<Mutex<SplitSink<WebSocket, Message>>>,
    ) {
        let key = DeviceKey { user_id, device_id };
        self.online.insert(key, sender);

        // Also ensure the device is in the registered set.
        self.devices.entry(user_id).or_default().insert(device_id);
    }

    /// Unregister a device as online.
    pub fn unregister_online(&self, user_id: &UserId, device_id: &DeviceId) {
        let key = DeviceKey {
            user_id: *user_id,
            device_id: *device_id,
        };
        self.online.remove(&key);
    }

    /// Get the WebSocket sender for an online device.
    pub fn get_online_sender(
        &self,
        user_id: &UserId,
        device_id: &DeviceId,
    ) -> Option<Arc<Mutex<SplitSink<WebSocket, Message>>>> {
        let key = DeviceKey {
            user_id: *user_id,
            device_id: *device_id,
        };
        self.online.get(&key).map(|entry| entry.value().clone())
    }

    /// Get number of online connections.
    pub fn online_count(&self) -> usize {
        self.online.len()
    }

    // --- Pre-key bundle management ---

    /// Store (or replace) a pre-key bundle for a device.
    pub fn store_prekey_bundle(&self, user_id: UserId, device_id: DeviceId, bundle: PreKeyBundle) {
        let key = DeviceKey { user_id, device_id };
        self.prekey_bundles.insert(key, bundle);
    }

    /// Get a pre-key bundle for a specific device, consuming one OPK.
    pub fn get_prekey_bundle(
        &self,
        user_id: &UserId,
        device_id: &DeviceId,
    ) -> Option<PreKeyBundle> {
        let key = DeviceKey {
            user_id: *user_id,
            device_id: *device_id,
        };

        self.prekey_bundles.get_mut(&key).map(|mut entry| {
            let mut bundle = entry.value().clone();
            // Consume one OPK (first available).
            if !bundle.one_time_pre_keys.is_empty() {
                bundle.one_time_pre_keys.remove(0);
                // Update stored bundle with remaining OPKs.
                *entry.value_mut() = bundle.clone();
            }
            bundle
        })
    }

    /// Get a pre-key bundle for any device of a user.
    pub fn get_any_prekey_bundle(&self, user_id: &UserId) -> Option<PreKeyBundle> {
        // Find any device for this user that has a pre-key bundle.
        if let Some(devices) = self.devices.get(user_id) {
            for device_id in devices.iter() {
                if let Some(bundle) = self.get_prekey_bundle(user_id, device_id) {
                    return Some(bundle);
                }
            }
        }
        None
    }

    /// Consume a specific one-time pre-key.
    pub fn consume_opk(&self, user_id: &UserId, device_id: &DeviceId, opk_id: u32) {
        let key = DeviceKey {
            user_id: *user_id,
            device_id: *device_id,
        };
        if let Some(mut entry) = self.prekey_bundles.get_mut(&key) {
            entry
                .value_mut()
                .one_time_pre_keys
                .retain(|opk| opk.id != opk_id);
        }
    }

    // --- Device management ---

    /// Register a device for a user.
    pub fn register_device(&self, user_id: UserId, device_id: DeviceId) {
        self.devices.entry(user_id).or_default().insert(device_id);
    }

    /// Revoke a device.
    pub fn revoke_device(&self, user_id: &UserId, device_id: &DeviceId) {
        if let Some(mut devices) = self.devices.get_mut(user_id) {
            devices.remove(device_id);
        }
        // Also remove pre-key bundle and online connection.
        let key = DeviceKey {
            user_id: *user_id,
            device_id: *device_id,
        };
        self.prekey_bundles.remove(&key);
        self.online.remove(&key);
    }

    /// Get number of devices registered for a user.
    pub fn device_count(&self, user_id: &UserId) -> usize {
        self.devices.get(user_id).map(|d| d.len()).unwrap_or(0)
    }

    /// Get all registered device IDs for a user.
    #[allow(dead_code)] // Used in Phase 5 multi-device fan-out
    pub fn get_device_ids(&self, user_id: &UserId) -> Vec<DeviceId> {
        self.devices
            .get(user_id)
            .map(|d| d.iter().cloned().collect())
            .unwrap_or_default()
    }

    // --- Device list management ---

    /// Store a signed device list for a user.
    #[allow(dead_code)] // Used in Phase 5 multi-device
    pub fn store_device_list(&self, user_id: UserId, list: SignedDeviceList) {
        self.device_lists.insert(user_id, list);
    }

    /// Get the signed device list for a user.
    pub fn get_device_list(&self, user_id: &UserId) -> Option<SignedDeviceList> {
        self.device_lists.get(user_id).map(|entry| entry.clone())
    }
}
