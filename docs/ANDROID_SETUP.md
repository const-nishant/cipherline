# CipherLine — Android Build Setup

## Prerequisites

- Android SDK (API 24+, target SDK 36)
- Android NDK 28.x
- JDK 17 (OpenJDK or Oracle JDK)
- Rust Android targets (already installed):
  - `aarch64-linux-android`
  - `armv7-linux-androideabi`
  - `i686-linux-android`
  - `x86_64-linux-android`

## Environment Variables

Set these before building:

```powershell
# Windows
$env:ANDROID_HOME = "$env:LOCALAPPDATA\Android\Sdk"
$env:NDK_HOME = "$env:LOCALAPPDATA\Android\Sdk\ndk\28.2.13676358"
$env:JAVA_HOME = "C:\Program Files\RedHat\java-17-openjdk-17.0.17.0.10-1"
```

```bash
# macOS / Linux
export ANDROID_HOME="$HOME/Android/Sdk"
export NDK_HOME="$ANDROID_HOME/ndk/28.2.13676358"
export JAVA_HOME="/usr/lib/jvm/java-17-openjdk"
```

## Building

```bash
# Development build (connected device or emulator)
cargo tauri android dev

# Release build
cargo tauri android build
```

## Key Storage

On Android, the master key for SQLCipher is stored in the app's private
files directory (`/data/data/com.cipherline.app/files/.cipherline_keys/`).
Android's file-based encryption (FBE) provides at-rest protection, and the
directory is sandboxed per-app by the Android OS.

## Permissions

The AndroidManifest.xml includes:
- `INTERNET` — WebSocket relay connection
- `ACCESS_NETWORK_STATE` — connection monitoring
- `POST_NOTIFICATIONS` — push notification display
- `FOREGROUND_SERVICE` — background message listener
- `RECEIVE_BOOT_COMPLETED` — reconnect after device restart

## Push Notifications (FCM)

1. Create a Firebase project at https://console.firebase.google.com
2. Add your Android app (package: `com.cipherline.app`)
3. Download `google-services.json` into `src-tauri/gen/android/app/`
4. Add FCM dependencies to `build.gradle.kts` (see docs)
5. Configure the push relay endpoint

## Troubleshooting

- **NDK not found**: Ensure `NDK_HOME` points to the exact NDK version directory
- **SQLCipher build fails**: The `bundled-sqlcipher` feature compiles from source;
  ensure the NDK toolchain includes a working C compiler
- **Emulator**: Use an x86_64 system image for faster builds during development
