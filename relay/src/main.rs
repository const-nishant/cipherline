//! CipherLine blind relay server.
//!
//! A zero-knowledge relay that stores and forwards encrypted messages.
//! The relay never has access to plaintext or encryption keys.
//!
//! # Usage
//!
//! ```text
//! cipherline-relay [--bind-addr 0.0.0.0:8080] [--message-ttl 604800] ...
//! ```

mod auth;
mod config;
mod queue;
mod state;
mod ws;

use std::sync::Arc;

use axum::{
    extract::{ws::WebSocketUpgrade, State},
    response::IntoResponse,
    routing::get,
    Router,
};
use clap::Parser;
use tokio::signal;
use tracing::info;

use config::RelayConfig;
use state::RelayState;

#[tokio::main]
async fn main() {
    // Initialize tracing.
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "cipherline_relay=info".into()),
        )
        .init();

    let config = RelayConfig::parse();
    let bind_addr = config.bind_addr;
    let cleanup_interval = config.cleanup_interval_secs;

    info!("CipherLine relay starting on {}", bind_addr);
    info!(
        "Config: TTL={}s, max_msg={}B, max_conn={}, rate_limit={}/s",
        config.message_ttl_secs,
        config.max_message_size,
        config.max_connections,
        config.rate_limit_per_sec
    );

    let state = Arc::new(RelayState::new(config));

    // Spawn background cleanup task.
    let cleanup_state = state.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(cleanup_interval));
        loop {
            interval.tick().await;
            let purged = cleanup_state.queue.cleanup_expired();
            if purged > 0 {
                info!("cleanup: purged {purged} expired messages");
            }
            // Also clean up expired auth challenges.
            cleanup_state.auth.lock().await.cleanup_expired_challenges();
        }
    });

    // Build axum router.
    let app = Router::new()
        .route("/ws", get(ws_handler))
        .route("/health", get(health_handler))
        .with_state(state);

    // Start server with graceful shutdown.
    let listener = tokio::net::TcpListener::bind(bind_addr).await.unwrap();
    info!("relay listening on {}", bind_addr);

    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await
        .unwrap();

    info!("relay shut down");
}

/// WebSocket upgrade handler.
async fn ws_handler(
    ws: WebSocketUpgrade,
    State(state): State<Arc<RelayState>>,
) -> impl IntoResponse {
    ws.on_upgrade(|socket| ws::handle_connection(socket, state))
}

/// Health check endpoint.
async fn health_handler(State(state): State<Arc<RelayState>>) -> impl IntoResponse {
    let online = state.online_count();
    let queued = state.queue.total_messages();
    format!("OK\nonline_connections: {online}\nqueued_messages: {queued}\n")
}

/// Wait for shutdown signal (Ctrl+C or SIGTERM).
async fn shutdown_signal() {
    let ctrl_c = async {
        signal::ctrl_c()
            .await
            .expect("failed to install Ctrl+C handler");
    };

    #[cfg(unix)]
    let terminate = async {
        signal::unix::signal(signal::unix::SignalKind::terminate())
            .expect("failed to install SIGTERM handler")
            .recv()
            .await;
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {
            info!("received Ctrl+C, shutting down");
        }
        _ = terminate => {
            info!("received SIGTERM, shutting down");
        }
    }
}
