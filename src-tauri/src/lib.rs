pub mod commands;
pub mod keystore;
pub mod state;
pub mod store;
pub mod ws_client;

use tauri::Manager;
use tracing::info;
use tracing_subscriber::EnvFilter;

use state::AppState;

/// Default relay URL.
const DEFAULT_RELAY_URL: &str = "ws://127.0.0.1:8080/ws";

/// Initialize and run the Tauri application.
#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    // Initialize tracing.
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();

    info!("CipherLine starting");

    tauri::Builder::default()
        .plugin(tauri_plugin_os::init())
        .plugin(tauri_plugin_notification::init())
        .setup(|app| {
            // Determine database path in app data directory.
            let app_data_dir = app
                .path()
                .app_data_dir()
                .expect("failed to resolve app data dir");
            let db_path = app_data_dir.join("cipherline.db");

            info!("Database path: {}", db_path.display());

            // Read relay URL from environment or use default.
            let relay_url = std::env::var("CIPHERLINE_RELAY_URL")
                .unwrap_or_else(|_| DEFAULT_RELAY_URL.to_string());

            // Create application state.
            let app_state =
                AppState::new(db_path, relay_url).expect("failed to initialize application state");

            app.manage(app_state);

            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            commands::create_identity,
            commands::get_identity,
            commands::connect_relay,
            commands::get_status,
            commands::add_contact,
            commands::get_contacts,
            commands::send_message,
            commands::get_messages,
            commands::mark_read,
            commands::list_devices,
            commands::revoke_device,
            commands::upload_prekeys,
            commands::unread_counts,
            commands::fetch_prekeys,
            commands::disconnect,
        ])
        .run(tauri::generate_context!())
        .expect("error while running CipherLine");
}
