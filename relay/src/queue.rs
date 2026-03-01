//! Encrypted message queue for the relay.
//!
//! # Design
//!
//! All enqueued data is opaque ciphertext — the relay never decrypts.
//! Messages are stored per `(UserId, DeviceId)` so each device gets
//! its own copy (sender-side fan-out happens at the client, but the relay
//! stores per-device to support offline delivery).
//!
//! # Expiry
//!
//! A background task calls `cleanup_expired()` periodically to purge old messages.

use std::collections::VecDeque;
use std::sync::Arc;
use std::time::{Duration, Instant};

use dashmap::DashMap;
use tracing::{debug, trace, warn};

use cipherline_common::protocol::Envelope;
use cipherline_common::types::{DeviceId, UserId};

/// Composite key for per-device queues.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct DeviceQueueKey {
    pub user_id: UserId,
    pub device_id: DeviceId,
}

/// A message stored in the queue with metadata.
#[derive(Clone, Debug)]
pub struct StoredEnvelope {
    pub envelope: Envelope,
    pub stored_at: Instant,
}

/// Thread-safe message queue backed by `DashMap`.
#[derive(Clone)]
pub struct MessageQueue {
    queues: Arc<DashMap<DeviceQueueKey, VecDeque<StoredEnvelope>>>,
    max_per_device: usize,
    message_ttl: Duration,
}

impl MessageQueue {
    pub fn new(max_per_device: usize, message_ttl_secs: u64) -> Self {
        Self {
            queues: Arc::new(DashMap::new()),
            max_per_device,
            message_ttl: Duration::from_secs(message_ttl_secs),
        }
    }

    /// Enqueue an envelope for a specific device.
    ///
    /// Returns `Err` if the device's queue is full.
    pub fn enqueue(
        &self,
        user_id: UserId,
        device_id: DeviceId,
        envelope: Envelope,
    ) -> Result<(), QueueError> {
        let key = DeviceQueueKey { user_id, device_id };
        let mut queue = self.queues.entry(key).or_insert_with(VecDeque::new);

        if queue.len() >= self.max_per_device {
            warn!("queue full for device {:?}", device_id);
            return Err(QueueError::QueueFull {
                device_id,
                max: self.max_per_device,
            });
        }

        queue.push_back(StoredEnvelope {
            envelope,
            stored_at: Instant::now(),
        });

        trace!("enqueued message for device {:?}", device_id);
        Ok(())
    }

    /// Drain all queued messages for a device.
    ///
    /// Returns an empty vec if no messages are queued.
    pub fn drain(&self, user_id: &UserId, device_id: &DeviceId) -> Vec<Envelope> {
        let key = DeviceQueueKey {
            user_id: *user_id,
            device_id: *device_id,
        };

        if let Some(mut queue) = self.queues.get_mut(&key) {
            let envelopes: Vec<Envelope> = queue.drain(..).map(|se| se.envelope).collect();
            debug!(
                "drained {} messages for device {:?}",
                envelopes.len(),
                device_id
            );
            envelopes
        } else {
            Vec::new()
        }
    }

    /// Remove a specific message by ID from a device's queue.
    ///
    /// Used when a client ACKs a delivered message.
    pub fn remove_by_id(
        &self,
        user_id: &UserId,
        device_id: &DeviceId,
        message_id: &cipherline_common::types::MessageId,
    ) -> bool {
        let key = DeviceQueueKey {
            user_id: *user_id,
            device_id: *device_id,
        };

        if let Some(mut queue) = self.queues.get_mut(&key) {
            let before = queue.len();
            queue.retain(|se| se.envelope.message_id != *message_id);
            let removed = queue.len() < before;
            if removed {
                trace!("removed ACKed message {:?}", message_id);
            }
            removed
        } else {
            false
        }
    }

    /// Purge all messages older than the configured TTL.
    ///
    /// Returns the number of messages purged.
    pub fn cleanup_expired(&self) -> usize {
        let mut total_purged = 0;

        self.queues.iter_mut().for_each(|mut entry| {
            let before = entry.value().len();
            entry
                .value_mut()
                .retain(|se| se.stored_at.elapsed() < self.message_ttl);
            let purged = before - entry.value().len();
            total_purged += purged;
        });

        // Remove empty queues to avoid unbounded map growth.
        self.queues.retain(|_, queue| !queue.is_empty());

        if total_purged > 0 {
            debug!("cleanup: purged {total_purged} expired messages");
        }

        total_purged
    }

    /// Get the number of queued messages for a device.
    #[allow(dead_code)] // Used by monitoring / admin endpoints in later phases
    pub fn queue_len(&self, user_id: &UserId, device_id: &DeviceId) -> usize {
        let key = DeviceQueueKey {
            user_id: *user_id,
            device_id: *device_id,
        };
        self.queues.get(&key).map(|q| q.len()).unwrap_or(0)
    }

    /// Get total number of messages across all queues.
    pub fn total_messages(&self) -> usize {
        self.queues.iter().map(|entry| entry.value().len()).sum()
    }
}

/// Queue errors.
#[derive(Debug, thiserror::Error)]
pub enum QueueError {
    #[error("queue full for device {device_id:?} (max {max})")]
    QueueFull { device_id: DeviceId, max: usize },
}

#[cfg(test)]
mod tests {
    use super::*;
    use cipherline_common::types::{MessageId, Timestamp};

    fn make_test_envelope(
        sender_id: UserId,
        recipient_id: UserId,
        recipient_device_id: DeviceId,
    ) -> Envelope {
        Envelope {
            version: 1,
            sender_id,
            sender_device_id: DeviceId::generate(),
            recipient_id,
            recipient_device_id,
            message_id: MessageId::generate(),
            timestamp: Timestamp::now(),
            header: cipherline_common::types::MessageHeader {
                version: 1,
                ratchet_key: [0u8; 32],
                previous_chain_length: 0,
                message_number: 0,
            },
            ciphertext: vec![1, 2, 3],
            signature: vec![4, 5, 6],
        }
    }

    #[test]
    fn test_enqueue_and_drain() {
        let queue = MessageQueue::new(100, 3600);
        let user = UserId([1u8; 32]);
        let device = DeviceId::generate();
        let env = make_test_envelope(UserId([2u8; 32]), user, device);

        queue.enqueue(user, device, env.clone()).unwrap();
        assert_eq!(queue.queue_len(&user, &device), 1);

        let messages = queue.drain(&user, &device);
        assert_eq!(messages.len(), 1);
        assert_eq!(messages[0].message_id, env.message_id);
        assert_eq!(queue.queue_len(&user, &device), 0);
    }

    #[test]
    fn test_queue_full() {
        let queue = MessageQueue::new(2, 3600);
        let user = UserId([1u8; 32]);
        let device = DeviceId::generate();

        queue
            .enqueue(
                user,
                device,
                make_test_envelope(UserId([2u8; 32]), user, device),
            )
            .unwrap();
        queue
            .enqueue(
                user,
                device,
                make_test_envelope(UserId([2u8; 32]), user, device),
            )
            .unwrap();
        let result = queue.enqueue(
            user,
            device,
            make_test_envelope(UserId([2u8; 32]), user, device),
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_remove_by_id() {
        let queue = MessageQueue::new(100, 3600);
        let user = UserId([1u8; 32]);
        let device = DeviceId::generate();
        let env = make_test_envelope(UserId([2u8; 32]), user, device);
        let msg_id = env.message_id;

        queue.enqueue(user, device, env).unwrap();
        assert!(queue.remove_by_id(&user, &device, &msg_id));
        assert_eq!(queue.queue_len(&user, &device), 0);
    }

    #[test]
    fn test_cleanup_expired() {
        let queue = MessageQueue::new(100, 0); // TTL = 0 seconds → everything expires immediately
        let user = UserId([1u8; 32]);
        let device = DeviceId::generate();

        queue
            .enqueue(
                user,
                device,
                make_test_envelope(UserId([2u8; 32]), user, device),
            )
            .unwrap();

        // Wait a tiny bit so the message is definitely past TTL=0.
        std::thread::sleep(std::time::Duration::from_millis(10));

        let purged = queue.cleanup_expired();
        assert_eq!(purged, 1);
        assert_eq!(queue.queue_len(&user, &device), 0);
    }

    #[test]
    fn test_total_messages() {
        let queue = MessageQueue::new(100, 3600);
        let user1 = UserId([1u8; 32]);
        let user2 = UserId([2u8; 32]);
        let dev1 = DeviceId::generate();
        let dev2 = DeviceId::generate();

        queue
            .enqueue(user1, dev1, make_test_envelope(user2, user1, dev1))
            .unwrap();
        queue
            .enqueue(user1, dev1, make_test_envelope(user2, user1, dev1))
            .unwrap();
        queue
            .enqueue(user2, dev2, make_test_envelope(user1, user2, dev2))
            .unwrap();

        assert_eq!(queue.total_messages(), 3);
    }
}
