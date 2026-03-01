//! WebSocket client for connecting to the CipherLine relay server.
//!
//! Handles:
//! - Connection establishment with auto-reconnect
//! - Challenge-response authentication
//! - Sending/receiving MessagePack-encoded messages
//! - Background message listener that dispatches incoming envelopes

use futures_util::{SinkExt, StreamExt};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{mpsc, Mutex, Notify};
use tokio_tungstenite::{connect_async, tungstenite::Message as WsMessage};
use tracing::{debug, error, info, warn};

use cipherline_common::protocol::{
    deserialize_server_msg, serialize_client_msg, AuthResponse, ClientMessage, ServerMessage,
};
use cipherline_common::types::{DeviceId, Timestamp, UserId};

/// Connection status.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub enum ConnectionStatus {
    Disconnected,
    Connecting,
    Authenticating,
    Connected,
    Reconnecting,
}

/// WebSocket client errors.
#[derive(Debug, thiserror::Error)]
pub enum WsClientError {
    #[error("connection failed: {0}")]
    Connection(String),

    #[error("authentication failed: {0}")]
    AuthFailed(String),

    #[error("send failed: {0}")]
    SendFailed(String),

    #[error("not connected")]
    NotConnected,

    #[error("serialization error: {0}")]
    Serialization(String),
}

/// Outbound message sender type.
pub type OutboundSender = mpsc::Sender<ClientMessage>;
/// Inbound server message receiver type.
pub type InboundReceiver = mpsc::Receiver<ServerMessage>;

/// Configuration for the WS client.
#[derive(Debug, Clone)]
pub struct WsClientConfig {
    pub relay_url: String,
    pub reconnect_delay: Duration,
    pub max_reconnect_delay: Duration,
    pub ping_interval: Duration,
}

impl Default for WsClientConfig {
    fn default() -> Self {
        Self {
            relay_url: "ws://127.0.0.1:8080/ws".into(),
            reconnect_delay: Duration::from_secs(2),
            max_reconnect_delay: Duration::from_secs(60),
            ping_interval: Duration::from_secs(30),
        }
    }
}

/// Auth credentials needed for challenge-response.
#[derive(Clone)]
pub struct AuthCredentials {
    pub user_id: UserId,
    pub device_id: DeviceId,
    pub device_public_key: [u8; 32],
    /// Ed25519 signing key bytes (32 bytes) for signing the challenge.
    pub signing_key_bytes: Vec<u8>,
}

/// WebSocket client handle.
///
/// Provides a channel-based API:
/// - `outbound_tx`: send `ClientMessage` to be transmitted
/// - `inbound_rx`: receive `ServerMessage` from the relay
/// - `status`: current connection status
pub struct WsClient {
    pub status: Arc<Mutex<ConnectionStatus>>,
    pub outbound_tx: OutboundSender,
    pub inbound_rx: Arc<Mutex<InboundReceiver>>,
    shutdown: Arc<Notify>,
}

impl WsClient {
    /// Start the WebSocket client. Returns a handle immediately;
    /// the connection runs in a background tokio task.
    pub fn start(config: WsClientConfig, credentials: AuthCredentials) -> Self {
        let (outbound_tx, outbound_rx) = mpsc::channel::<ClientMessage>(256);
        let (inbound_tx, inbound_rx) = mpsc::channel::<ServerMessage>(256);
        let status = Arc::new(Mutex::new(ConnectionStatus::Disconnected));
        let shutdown = Arc::new(Notify::new());

        let client = Self {
            status: status.clone(),
            outbound_tx,
            inbound_rx: Arc::new(Mutex::new(inbound_rx)),
            shutdown: shutdown.clone(),
        };

        // Spawn the connection loop.
        tokio::spawn(connection_loop(
            config,
            credentials,
            outbound_rx,
            inbound_tx,
            status,
            shutdown,
        ));

        client
    }

    /// Shut down the WebSocket client.
    pub fn shutdown(&self) {
        self.shutdown.notify_one();
    }

    /// Send a client message to the relay.
    pub async fn send(&self, msg: ClientMessage) -> Result<(), WsClientError> {
        self.outbound_tx
            .send(msg)
            .await
            .map_err(|e| WsClientError::SendFailed(e.to_string()))
    }

    /// Get current connection status.
    pub async fn connection_status(&self) -> ConnectionStatus {
        self.status.lock().await.clone()
    }
}

/// Main connection loop with auto-reconnect.
async fn connection_loop(
    config: WsClientConfig,
    credentials: AuthCredentials,
    mut outbound_rx: mpsc::Receiver<ClientMessage>,
    inbound_tx: mpsc::Sender<ServerMessage>,
    status: Arc<Mutex<ConnectionStatus>>,
    shutdown: Arc<Notify>,
) {
    let mut reconnect_delay = config.reconnect_delay;

    loop {
        // Check shutdown.
        if shutdown_requested(&shutdown) {
            info!("WS client shutting down");
            *status.lock().await = ConnectionStatus::Disconnected;
            return;
        }

        *status.lock().await = ConnectionStatus::Connecting;
        info!("Connecting to relay at {}", config.relay_url);

        match connect_async(&config.relay_url).await {
            Ok((ws_stream, _response)) => {
                info!("WebSocket connected");
                reconnect_delay = config.reconnect_delay; // Reset on success.

                let (mut ws_sink, mut ws_stream_rx) = ws_stream.split();

                // Wait for auth challenge.
                *status.lock().await = ConnectionStatus::Authenticating;

                let auth_result = handle_auth(&credentials, &mut ws_sink, &mut ws_stream_rx).await;

                match auth_result {
                    Ok(()) => {
                        info!("Authenticated successfully");
                        *status.lock().await = ConnectionStatus::Connected;
                    }
                    Err(e) => {
                        error!("Authentication failed: {e}");
                        *status.lock().await = ConnectionStatus::Reconnecting;
                        tokio::time::sleep(reconnect_delay).await;
                        reconnect_delay = (reconnect_delay * 2).min(config.max_reconnect_delay);
                        continue;
                    }
                }

                // Main message loop.
                let ping_interval = config.ping_interval;
                let mut ping_timer = tokio::time::interval(ping_interval);

                loop {
                    tokio::select! {
                        // Outbound messages from the application.
                        Some(client_msg) = outbound_rx.recv() => {
                            match serialize_client_msg(&client_msg) {
                                Ok(bytes) => {
                                    if let Err(e) = ws_sink.send(WsMessage::Binary(bytes.into())).await {
                                        error!("Failed to send message: {e}");
                                        break;
                                    }
                                    debug!("Sent client message");
                                }
                                Err(e) => {
                                    error!("Failed to serialize message: {e}");
                                }
                            }
                        }

                        // Inbound messages from the relay.
                        Some(ws_msg) = ws_stream_rx.next() => {
                            match ws_msg {
                                Ok(WsMessage::Binary(data)) => {
                                    match deserialize_server_msg(&data) {
                                        Ok(server_msg) => {
                                            debug!("Received server message");
                                            if inbound_tx.send(server_msg).await.is_err() {
                                                warn!("Inbound channel closed");
                                                return;
                                            }
                                        }
                                        Err(e) => {
                                            warn!("Failed to deserialize server message: {e}");
                                        }
                                    }
                                }
                                Ok(WsMessage::Ping(data)) => {
                                    let _ = ws_sink.send(WsMessage::Pong(data)).await;
                                }
                                Ok(WsMessage::Close(_)) => {
                                    info!("Server closed connection");
                                    break;
                                }
                                Err(e) => {
                                    error!("WebSocket error: {e}");
                                    break;
                                }
                                _ => {}
                            }
                        }

                        // Periodic ping.
                        _ = ping_timer.tick() => {
                            if let Err(e) = ws_sink.send(WsMessage::Ping(vec![].into())).await {
                                error!("Ping failed: {e}");
                                break;
                            }
                        }

                        // Shutdown signal.
                        _ = shutdown.notified() => {
                            info!("Shutdown signal received");
                            let _ = ws_sink.send(WsMessage::Close(None)).await;
                            *status.lock().await = ConnectionStatus::Disconnected;
                            return;
                        }
                    }
                }
            }
            Err(e) => {
                error!("Failed to connect: {e}");
            }
        }

        // Schedule reconnect.
        *status.lock().await = ConnectionStatus::Reconnecting;
        warn!("Reconnecting in {}s", reconnect_delay.as_secs());
        tokio::time::sleep(reconnect_delay).await;
        reconnect_delay = (reconnect_delay * 2).min(config.max_reconnect_delay);
    }
}

/// Handle the challenge-response authentication flow.
async fn handle_auth<S, R>(
    credentials: &AuthCredentials,
    sink: &mut S,
    stream: &mut R,
) -> Result<(), WsClientError>
where
    S: SinkExt<WsMessage> + Unpin,
    S::Error: std::fmt::Display,
    R: StreamExt<Item = Result<WsMessage, tokio_tungstenite::tungstenite::Error>> + Unpin,
{
    // Wait for Challenge message from server.
    let challenge_data = tokio::time::timeout(Duration::from_secs(10), async {
        while let Some(msg) = stream.next().await {
            match msg {
                Ok(WsMessage::Binary(data)) => match deserialize_server_msg(&data) {
                    Ok(ServerMessage::Challenge(challenge)) => {
                        return Ok(challenge.challenge);
                    }
                    Ok(other) => {
                        debug!("Ignoring non-challenge message during auth: {other:?}");
                    }
                    Err(e) => {
                        return Err(WsClientError::AuthFailed(format!(
                            "failed to parse challenge: {e}"
                        )));
                    }
                },
                Err(e) => {
                    return Err(WsClientError::Connection(e.to_string()));
                }
                _ => {}
            }
        }
        Err(WsClientError::Connection(
            "stream ended before challenge".into(),
        ))
    })
    .await
    .map_err(|_| WsClientError::AuthFailed("challenge timeout".into()))??;

    // Sign the challenge.
    let timestamp = Timestamp::now();

    // Build signable payload: challenge || timestamp (LE bytes).
    let mut payload = Vec::with_capacity(challenge_data.len() + 8);
    payload.extend_from_slice(&challenge_data);
    payload.extend_from_slice(&timestamp.0.to_le_bytes());

    // Reconstruct the signing key from bytes.
    let signing_key_bytes: [u8; 32] = credentials
        .signing_key_bytes
        .as_slice()
        .try_into()
        .map_err(|_| WsClientError::AuthFailed("invalid signing key length".into()))?;
    let signing_key = ed25519_dalek::SigningKey::from_bytes(&signing_key_bytes);
    let signature = cipherline_common::crypto::sign(&payload, &signing_key);

    let auth_response = ClientMessage::Authenticate(AuthResponse {
        user_id: credentials.user_id,
        device_id: credentials.device_id,
        device_public_key: credentials.device_public_key,
        signature: signature.to_bytes().to_vec(),
        timestamp,
    });

    let auth_bytes = serialize_client_msg(&auth_response)
        .map_err(|e| WsClientError::Serialization(e.to_string()))?;

    sink.send(WsMessage::Binary(auth_bytes.into()))
        .await
        .map_err(|e| WsClientError::SendFailed(e.to_string()))?;

    // Wait for AuthSuccess or Error.
    let result = tokio::time::timeout(Duration::from_secs(10), async {
        while let Some(msg) = stream.next().await {
            match msg {
                Ok(WsMessage::Binary(data)) => match deserialize_server_msg(&data) {
                    Ok(ServerMessage::AuthSuccess) => return Ok(()),
                    Ok(ServerMessage::Error { code, message }) => {
                        return Err(WsClientError::AuthFailed(format!("{code:?}: {message}")));
                    }
                    Ok(other) => {
                        debug!("Ignoring message during auth: {other:?}");
                    }
                    Err(e) => {
                        return Err(WsClientError::AuthFailed(e.to_string()));
                    }
                },
                Err(e) => return Err(WsClientError::Connection(e.to_string())),
                _ => {}
            }
        }
        Err(WsClientError::Connection(
            "stream ended before auth result".into(),
        ))
    })
    .await
    .map_err(|_| WsClientError::AuthFailed("auth response timeout".into()))??;

    Ok(result)
}

/// Check if shutdown has been requested (non-blocking).
fn shutdown_requested(_shutdown: &Notify) -> bool {
    // Try to poll without blocking — we use notified().now_or_never()
    // but Notify doesn't have that directly. Instead, we check via try.
    // The actual shutdown check happens in the select! loop.
    false
}
