# Usage Guide

This guide covers installing and running CipherLine on all supported platforms.

---

## Desktop Installation

### Download

Download the latest installer for your platform from [GitHub Releases](https://github.com/const-nishant/cipherline/releases):

| Platform | File Type |
|----------|-----------|
| Windows x64 | `.msi` (recommended) or `.exe` (NSIS installer) |
| macOS x64 (Intel) | `.dmg` |
| macOS ARM64 (Apple Silicon) | `.dmg` |
| Linux x64 | `.deb` / `.rpm` / `.AppImage` |

### Install

- **Windows**: Run the `.msi` or `.exe` installer. Follow the on-screen prompts.
- **macOS**: Open the `.dmg` and drag CipherLine to Applications.
- **Linux (Debian/Ubuntu)**: `sudo dpkg -i cipherline_*.deb`
- **Linux (Fedora/RHEL)**: `sudo rpm -i cipherline-*.rpm`
- **Linux (AppImage)**: `chmod +x CipherLine-*.AppImage && ./CipherLine-*.AppImage`

### First Launch

1. Open CipherLine
2. Create your account — this generates your cryptographic identity (Ed25519 identity key, X25519 signed pre-key)
3. Your keys are stored locally in an encrypted SQLCipher database
4. Connect to a relay server (default or custom URL)
5. Add contacts by their user ID and start messaging

---

## Android Installation

1. Download the APK from [GitHub Releases](https://github.com/const-nishant/cipherline/releases)
2. On your device, enable **Settings → Security → Install from unknown sources** (or per-app permission)
3. Open the APK and install
4. Follow the same first launch steps as desktop

---

## Building from Source

### Prerequisites

| Tool | Version |
|------|---------|
| Rust | stable (latest) |
| Node.js | 20+ |
| Tauri CLI | 2.x (`cargo install tauri-cli --version "^2" --locked`) |
| OpenSSL | 3.x |

### Desktop

```sh
# Install frontend dependencies
npm ci --prefix ui

# Development mode (hot-reload)
cargo tauri dev

# Production build
cargo tauri build
```

Output is in `src-tauri/target/release/bundle/`.

### Relay Server

```sh
# Dev
cargo run -p cipherline-relay

# Production
cargo build -p cipherline-relay --release
```

See [RELAY.md](RELAY.md) for configuration and deployment details.

### Android

See [ANDROID.md](ANDROID.md) for the full Android build and signing guide.

---

## Relay Server Setup

If you want to self-host a relay:

```sh
# Option 1: Binary
cargo build -p cipherline-relay --release
./target/release/cipherline-relay

# Option 2: Docker
docker run -d -p 8080:8080 ghcr.io/const-nishant/cipherline-relay:0.1.0
```

Configure your clients to connect to your relay URL.

---

## Troubleshooting

| Problem | Solution |
|---------|----------|
| OpenSSL not found during build | Install OpenSSL 3.x. On macOS: `brew install openssl@3`. On Ubuntu: `sudo apt install libssl-dev`. On Windows: `choco install openssl`. |
| SQLCipher build fails | Ensure `libsqlite3-sys` has the `bundled-sqlcipher` feature and OpenSSL headers are available. |
| WebSocket connection refused | Check that the relay is running and the URL/port are correct. Verify firewall rules. |
| Android build fails | Verify Android SDK is installed, `ANDROID_HOME` is set, and the correct NDK version is available. See [ANDROID.md](ANDROID.md). |
| macOS "damaged" or "unidentified developer" | Right-click → Open, or run `xattr -cr /Applications/CipherLine.app`. |
| Linux AppImage won't run | `chmod +x CipherLine-*.AppImage` |

---

## Updating

Download the latest release from GitHub and install over the existing version. Your local data (keys, messages) is preserved in the SQLCipher database.
