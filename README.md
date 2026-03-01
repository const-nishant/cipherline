# CipherLine

[![CI](https://github.com/const-nishant/cipherline/actions/workflows/ci.yml/badge.svg)](https://github.com/const-nishant/cipherline/actions/workflows/ci.yml)
[![Release](https://github.com/const-nishant/cipherline/actions/workflows/release.yml/badge.svg)](https://github.com/const-nishant/cipherline/actions/workflows/release.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

**CipherLine** is a cross-platform, end-to-end encrypted messaging application built entirely in Rust. It implements the **Signal Double Ratchet** protocol with X3DH key agreement, providing forward secrecy and post-compromise security for every message.

| Component | Technology |
|-----------|------------|
| Client (Desktop) | Tauri v2 · Rust · React 19 · TypeScript |
| Client (Mobile) | Tauri Mobile (Android) |
| Relay Server | Axum · Tokio · WebSocket |
| Cryptography | X25519 · Ed25519 · ChaCha20-Poly1305 · BLAKE2b |
| Local Storage | SQLCipher (encrypted SQLite) |
| Serialization | MessagePack (`rmp-serde`) |

---

## Table of Contents

- [Features](#features)
- [Prerequisites](#prerequisites)
- [Quick Start](#quick-start)
- [Project Structure](#project-structure)
- [Security](#security)
- [Documentation](#documentation)
- [Contributing](#contributing)
- [License](#license)

---

## Features

**Cryptography**
- X3DH key agreement with identity, signed pre-key, and one-time pre-keys
- Signal Double Ratchet with symmetric-key ratchet and DH ratchet
- ChaCha20-Poly1305 authenticated encryption (single-use keys, fixed nonce)
- Ed25519 signatures on every envelope
- BLAKE2b KDF chains with domain separation
- Constant-time MAC/signature comparisons via `subtle`
- Automatic key zeroization via `zeroize`

**Client**
- Cross-platform desktop: Windows (.msi/.exe), macOS (.dmg), Linux (.deb/.rpm/.AppImage)
- Android APK
- SQLCipher-encrypted local database
- Offline message queuing with store-and-forward

**Relay Server**
- Stateless blind relay — cannot read message contents
- WebSocket-based real-time delivery
- Public-key authentication with challenge-response
- Configurable rate limiting, connection caps, and message TTL
- Docker multi-arch images (amd64/arm64)
- Horizontally scalable

**DevOps**
- GitHub Actions CI (clippy, fmt, tests, fuzz, cargo-audit)
- Automated releases triggered by version tags
- Conventional Commits with auto-versioning
- Multi-platform binary artifacts
- GHCR container registry for relay Docker images

---

## Prerequisites

| Tool | Version | Purpose |
|------|---------|---------|
| Rust | stable (latest) | Build all crates |
| Node.js | 20+ | Build frontend (`ui/`) |
| npm | 10+ | Frontend dependency management |
| Tauri CLI | 2.x | Desktop/mobile build tooling |
| OpenSSL | 3.x | Required by `libsqlite3-sys` (bundled SQLCipher) |
| Android SDK | API 24+ | Mobile builds only |

Install Tauri CLI:
```sh
cargo install tauri-cli --version "^2" --locked
```

---

## Quick Start

### Desktop Client

```sh
# Install frontend dependencies
npm ci --prefix ui

# Development mode (hot-reload)
cargo tauri dev

# Production build
cargo tauri build
```

Installers are written to `src-tauri/target/release/bundle/`.

### Relay Server

```sh
# Development
cargo run -p cipherline-relay

# Production build
cargo build -p cipherline-relay --release

# With custom config
CIPHERLINE_BIND_ADDR=0.0.0.0:9090 \
CIPHERLINE_RATE_LIMIT=50 \
./target/release/cipherline-relay
```

### Docker (Relay)

```sh
docker build -t cipherline-relay .
docker run -d -p 8080:8080 \
  -e CIPHERLINE_MAX_CONNECTIONS=20000 \
  cipherline-relay
```

Pre-built images are available from GHCR:
```sh
docker pull ghcr.io/const-nishant/cipherline-relay:0.1.0
```

### Android APK

```sh
cargo tauri android build --apk
```

---

## Project Structure

```
cipherline/
├── common/              # Shared Rust library
│   └── src/
│       ├── crypto.rs    # X25519, ChaCha20-Poly1305, Ed25519, BLAKE2b
│       ├── identity.rs  # Device identity, certificates, pre-key bundles
│       ├── protocol.rs  # Wire protocol (ClientMessage / ServerMessage)
│       ├── ratchet.rs   # X3DH key agreement + Double Ratchet sessions
│       └── types.rs     # Shared types, errors, constants
├── relay/               # Relay server binary
│   └── src/
│       ├── auth.rs      # Public-key challenge-response authentication
│       ├── config.rs    # CLI/env configuration (clap)
│       ├── queue.rs     # Per-device message queue
│       ├── state.rs     # Shared server state
│       └── ws.rs        # WebSocket handler
├── src-tauri/           # Desktop client (Tauri)
│   └── src/
│       ├── commands.rs  # Tauri IPC commands
│       ├── keystore.rs  # Local key storage
│       ├── store.rs     # SQLCipher database layer
│       └── ws_client.rs # WebSocket relay client
├── ui/                  # React frontend
│   └── src/
│       ├── App.tsx      # Root component
│       ├── api.ts       # Tauri invoke bindings
│       └── components/  # UI components
├── Dockerfile           # Multi-stage relay build
├── Cargo.toml           # Workspace manifest
└── .github/workflows/   # CI + Release pipelines
```

---

## Security

CipherLine's cryptographic design follows the Signal protocol specification:

- **Forward secrecy**: Compromising long-term keys does not reveal past messages
- **Post-compromise security**: Sessions self-heal after key compromise via DH ratchet
- **Zero-knowledge relay**: The server sees only opaque ciphertext and routing metadata
- **Bounded skip**: Skipped message keys are capped to prevent DoS attacks

See [docs/SECURITY.md](docs/SECURITY.md) for the full security model, threat analysis, and responsible disclosure policy.

---

## Documentation

| Document | Description |
|----------|-------------|
| [docs/SECURITY.md](docs/SECURITY.md) | Security model, cryptography details, threat model |
| [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) | System architecture, data flow, module design |
| [docs/RELAY.md](docs/RELAY.md) | Relay server API, configuration, deployment |
| [docs/USAGE.md](docs/USAGE.md) | End-user guide, installation, troubleshooting |
| [docs/ANDROID.md](docs/ANDROID.md) | Android build, signing, and release process |

---

## Contributing

Contributions are welcome. Please follow these guidelines:

1. **Conventional Commits** — All commit messages must follow [Conventional Commits](https://www.conventionalcommits.org/) (`feat:`, `fix:`, `chore:`, etc.)
2. **Code quality** — Run `cargo clippy` and `cargo fmt` before submitting
3. **Tests** — Add or update tests for any logic changes
4. **Security** — Never commit private keys, keystores, or secrets. See [docs/SECURITY.md](docs/SECURITY.md)
5. **Documentation** — Update relevant docs for new features

---

## License

This project is licensed under the MIT License. See [LICENSE](LICENSE).

## Maintainers

- [Nishant Patil](https://github.com/const-nishant)
