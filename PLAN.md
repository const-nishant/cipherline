
# CipherLine — Build Plan & Security Guide

> **Version:** 1.0  
> **Date:** March 1, 2026  
> **Status:** Approved for implementation

---

## Table of Contents

1. [System Overview](#1-system-overview)
2. [Architecture](#2-architecture)
3. [Project Structure](#3-project-structure)
4. [Technology Decisions](#4-technology-decisions)
5. [Phase 1 — Core Crypto](#5-phase-1--core-crypto)
6. [Phase 2 — Protocol](#6-phase-2--protocol)
7. [Phase 3 — Relay Server](#7-phase-3--relay-server)
8. [Phase 4 — Desktop Client](#8-phase-4--desktop-client)
9. [Phase 5 — Multi-Device](#9-phase-5--multi-device)
10. [Phase 6 — Mobile](#10-phase-6--mobile)
11. [Phase 7 — Hardening](#11-phase-7--hardening)
12. [Security Guidance](#12-security-guidance)
    - [Double Ratchet Safety](#121-double-ratchet-safety)
    - [Pre-Key Handling](#122-pre-key-handling)
    - [Multi-Device Messaging](#123-multi-device-messaging)
    - [Relay Server Behavior](#124-relay-server-behavior)
    - [Cryptographic Hygiene](#125-cryptographic-hygiene)
    - [Mobile-Specific Concerns](#126-mobile-specific-concerns)
    - [Operational Hardening](#127-operational-hardening)
    - [Threat Model Clarity](#128-threat-model-clarity)
13. [Verification](#13-verification)

---

## 1. System Overview

CipherLine is a zero-knowledge encrypted chat system with blind relay servers. All cryptography happens on client devices. The relay server stores and forwards only encrypted ciphertext — it never sees keys or plaintext.

### Guarantees

- End-to-end encrypted messaging
- Offline message delivery (store-and-forward)
- Multi-device identity (from day one)
- No server access to plaintext
- Minimal metadata exposure
- Single core codebase for all platforms
- Free to use, free to host
- Public + self-hosted relay support

### Non-Guarantees

- Not "unhackable"
- Not "undetectable" or "untraceable"
- No protection against compromised devices or malware

---

## 2. Architecture

```
┌────────────┐        Encrypted        ┌──────────────┐
│  Client A  │ ────────────────────►  │   Relay      │
│ (Any OS)   │                        │   Server     │
└────────────┘        Encrypted        └──────────────┘
        │                                     │
        │        Encrypted                    │
        └────────────────────────────────►   │
                                ┌──────────────┐
                                │  Client B    │
                                │ (Any OS)     │
                                └──────────────┘
```

**Relay server is blind. Clients do all cryptography.**

---

## 3. Project Structure

```
cipherline/
├── Cargo.toml                  # [workspace] members = ["common", "relay", "src-tauri"]
├── common/
│   ├── Cargo.toml              # cipherline-common
│   └── src/
│       ├── lib.rs
│       ├── crypto.rs           # Key generation, encrypt/decrypt, sign/verify
│       ├── identity.rs         # Root identity, device keys, key bundles
│       ├── ratchet.rs          # Double Ratchet + X3DH
│       ├── protocol.rs         # Message envelope, wire types, ACK
│       └── types.rs            # UserId, DeviceId, MessageId, Timestamp newtypes
├── relay/
│   ├── Cargo.toml              # cipherline-relay
│   └── src/
│       ├── main.rs             # Entry point, axum router
│       ├── ws.rs               # WebSocket upgrade, connection handler
│       ├── queue.rs            # Encrypted message queue (in-memory + optional disk)
│       ├── auth.rs             # Challenge-response device authentication
│       └── config.rs           # TTL, rate limits, bind address
├── src-tauri/
│   ├── Cargo.toml              # depends on cipherline-common
│   ├── tauri.conf.json
│   ├── capabilities/
│   │   └── default.json
│   └── src/
│       ├── main.rs             # Desktop entry
│       ├── lib.rs              # Mobile entry (run())
│       ├── commands.rs         # #[tauri::command] IPC handlers
│       ├── state.rs            # AppState: DB, identity, sessions
│       └── store.rs            # SQLCipher read/write, keychain access
├── ui/                         # React frontend
│   ├── package.json
│   ├── vite.config.ts
│   ├── tsconfig.json
│   ├── index.html
│   └── src/
│       ├── main.tsx
│       ├── App.tsx
│       ├── components/
│       │   ├── ChatView.tsx
│       │   ├── MessageBubble.tsx
│       │   ├── ContactList.tsx
│       │   ├── DeviceLinkDialog.tsx
│       │   └── SettingsPanel.tsx
│       ├── hooks/
│       │   ├── useChat.ts
│       │   ├── useIdentity.ts
│       │   └── useWebSocket.ts
│       ├── lib/
│       │   └── tauri.ts        # invoke() wrappers, typed IPC
│       └── styles/
├── docs/
│   └── threat-model.md
└── .github/
    └── workflows/
        └── ci.yml              # Build + test for all crates
```

### Key Design Constraint

`common/` has **no Tauri dependency** — pure logic only, usable by both client and relay. The workspace `Cargo.toml` at root declares all three members. Tauri's build tools work natively with this workspace layout.

---

## 4. Technology Decisions

| Decision | Choice | Rationale |
|---|---|---|
| Crypto library | **RustCrypto crates** (pure Rust) | `sodiumoxide` is archived. Pure Rust eliminates C cross-compilation for 5 platforms. Same algorithms as libsodium. |
| Key pairs | **Separate Ed25519 + X25519** | No key conversion. Cleaner key hygiene, directly supported by dalek crates. |
| Wire format | **MessagePack** (`rmp-serde`) | Compact binary, serde-native, good balance of debuggability and efficiency. |
| Frontend | **React** (Vite + TypeScript) | User's choice. Paired with `@tauri-apps/api` for IPC. |
| Multi-device | **From day one** (sender-side fan-out) | Every wire type includes `DeviceId`. All DR sessions are per-device. No architectural refactoring later. |
| Local storage | **SQLCipher** via `rusqlite` | Full DB encryption at rest. Master key stored in OS keychain. |
| Relay framework | **axum** 0.8.x | Dominant Rust web framework, first-class WebSocket, `tower` middleware ecosystem. |
| Double Ratchet | **Custom implementation** | No existing crate matches the exact primitive set. ~500-800 lines. Must be carefully tested. |
| Cloud backup | **Disabled** | Messages exist only on devices and (temporarily encrypted) on relay. |

### Crate Versions

| Crate | Version | Feature Flags |
|---|---|---|
| `tauri` | 2.2.x | — |
| `tauri-build` | 2.0.x | — |
| `serde` | 1.x | `derive` |
| `serde_json` | 1.x | — |
| `tokio` | 1.x | `full` |
| `axum` | 0.8.x | `ws` |
| `x25519-dalek` | 2.x | — |
| `ed25519-dalek` | 2.x | `serde`, `rand_core` |
| `chacha20poly1305` | 0.10.x | — |
| `blake2` | 0.10.x | — |
| `rusqlite` | 0.32.x | `bundled-sqlcipher-vendored-openssl` |
| `keyring` | 3.x | — |
| `rmp-serde` | 1.x | — |
| `uuid` | 1.x | `v4`, `serde` |
| `chrono` | 0.4.x | `serde` |
| `tracing` | 0.1.x | — |
| `tracing-subscriber` | 0.3.x | — |
| `argon2` | 0.5.x | — |
| `rand` | 0.8.x | — |
| `base64` | 0.22.x | — |
| `thiserror` | 2.x | — |
| `zeroize` | 1.8.x | `derive` |
| `secrecy` | 0.8.x | — |
| `subtle` | 2.6.x | — |
| `dashmap` | 6.x | — |
| `clap` | 4.x | `derive` |

---

## 5. Phase 1 — Core Crypto

**Files:** `common/src/crypto.rs`, `common/src/identity.rs`

### Step 1: Initialize Workspace

Create root `Cargo.toml` with `[workspace]` declaring members `common`, `relay`, `src-tauri`. Set `resolver = "2"`.

### Step 2: Create `common` Crate

Add all RustCrypto dependencies, `serde`, `rmp-serde`, `thiserror`, `zeroize`, `base64`, `rand`.

### Step 3: Implement `crypto.rs`

| Function | Purpose |
|---|---|
| `generate_ed25519_keypair()` | Returns `(SigningKey, VerifyingKey)` |
| `generate_x25519_keypair()` | Returns `(StaticSecret, PublicKey)` |
| `encrypt(plaintext, key, nonce)` | ChaCha20-Poly1305 AEAD encryption |
| `decrypt(ciphertext, key, nonce)` | ChaCha20-Poly1305 AEAD decryption |
| `sign(message, signing_key)` | Ed25519 signature |
| `verify(message, signature, verifying_key)` | Ed25519 verification |
| `blake2b_hash(data)` | BLAKE2b-256 digest |
| `kdf_derive(ikm, context, subkey_id)` | BLAKE2b keyed mode for chain key derivation |

### Step 4: Implement `identity.rs`

- `RootIdentity`: Ed25519 signing key + X25519 static key, `UserId` (BLAKE2b hash of Ed25519 public key)
- `DeviceIdentity`: Ed25519 + X25519 per-device keys, `DeviceId`, signature from root key
- `PreKeyBundle`: signed pre-key (X25519) + signature + one-time pre-keys (batch of X25519)
- Functions: `generate_root_identity()`, `generate_device_identity()`, `generate_prekey_bundle()`, `verify_device_signature()`
- All private key wrappers derive `Zeroize + ZeroizeOnDrop`

### Step 5: Unit Tests

Round-trip encrypt/decrypt, sign/verify, KDF determinism, key generation uniqueness.

---

## 6. Phase 2 — Protocol

**Files:** `common/src/ratchet.rs`, `common/src/protocol.rs`, `common/src/types.rs`

### Step 6: Implement `types.rs`

- Newtype wrappers: `UserId([u8; 32])`, `DeviceId([u8; 16])`, `MessageId(Uuid)`, `Timestamp(u64)`
- `PublicKeyBundle` — serializable public key set for a device
- All types derive `Serialize`, `Deserialize`, `Clone`, `Debug`
- Include `version: u8` field in all serializable protocol types

### Step 7: Implement X3DH

In `ratchet.rs`:

- `X3DHInitiator::perform(our_identity, our_ephemeral, their_bundle)` → `(SharedSecret, X3DHHeader)`
- `X3DHResponder::perform(our_identity, our_signed_prekey, our_one_time_prekey, their_header)` → `SharedSecret`
- Uses X25519 for DH operations, BLAKE2b-KDF with domain string `"CipherLine_X3DH_v1"` for combining DH outputs
- Consumes one-time pre-keys (mark used)
- **Validation:** Initiator must verify SPK signature. Reject all-zero DH outputs (low-order point check).

### Step 8: Implement Double Ratchet

In `ratchet.rs`:

- `RatchetState` struct: `root_key`, `sending_chain_key`, `receiving_chain_key`, `our_ratchet_keypair` (X25519), `their_ratchet_public`, `sending_chain_n`, `receiving_chain_n`, `previous_chain_n`, `skipped_message_keys` (HashMap)
- `RatchetState::init_sender(shared_secret, their_ratchet_pub)` → `RatchetState`
- `RatchetState::init_receiver(shared_secret, our_ratchet_keypair)` → `RatchetState`
- `ratchet_encrypt(&mut self, plaintext)` → `(MessageHeader, CipherText)`
- `ratchet_decrypt(&mut self, header, ciphertext)` → `Result<Vec<u8>>`
- `MAX_SKIP = 2000` per chain step. Global skipped key cap: 5000.
- Fixed nonce `[0u8; 12]` — safe because each message key is single-use.
- KDF domain strings:
  - Root chain: `"CipherLine_DR_Root_v1"`
  - Chain key → message key: `"CipherLine_DR_MsgKey_v1"`
  - Chain key → next chain key: `"CipherLine_DR_ChainKey_v1"`
- `RatchetState` derives `Serialize`/`Deserialize` for persistence, `Zeroize` for cleanup.

### Step 9: Implement `protocol.rs`

```
Envelope {
    version: u8,
    sender_id: UserId,
    sender_device_id: DeviceId,
    recipient_id: UserId,
    recipient_device_id: DeviceId,
    message_id: MessageId,
    timestamp: Timestamp,
    header: MessageHeader,        // DR ratchet public key + chain indices
    ciphertext: Vec<u8>,          // ChaCha20-Poly1305 output
    signature: Vec<u8>,           // Ed25519 over (header || ciphertext)
}
```

- `AckMessage { message_id, device_id }`
- `ClientMessage` enum: `SendEnvelope`, `Ack`, `FetchPreKeys`, `UploadPreKeys`, `RegisterDevice`, `Authenticate`
- `ServerMessage` enum: `Deliver`, `PreKeys`, `Ack`, `Error`, `Challenge`
- Serialization via `rmp-serde` (MessagePack)

### Step 10: Extensive Tests

- X3DH key agreement between two parties
- Full DR session: Alice ↔ Bob 100+ message exchange with random interleaving
- Out-of-order messages within MAX_SKIP
- Exceeding MAX_SKIP → error
- Skipped key handling and deletion after use
- Serialization round-trips for all protocol types

---

## 7. Phase 3 — Relay Server

**Files:** `relay/src/`

### Step 11: Create `relay` Crate

Dependencies: `cipherline-common`, `axum` 0.8.x, `tokio`, `tower-http`, `dashmap` 6.x, `tracing`, `clap` 4.x.

### Step 12: Implement `config.rs`

CLI args + env vars:

| Config | Default | Description |
|---|---|---|
| `bind_addr` | `0.0.0.0:8080` | Server bind address |
| `message_ttl_secs` | `604800` (7 days) | Time before undelivered messages expire |
| `max_message_size` | `65536` (64 KB) | Maximum envelope size |
| `max_connections` | `10000` | Maximum concurrent WebSocket connections |
| `rate_limit_per_sec` | `30` | Per-IP request rate limit |

### Step 13: Implement `auth.rs`

Challenge-response authentication without accounts:

1. Server sends 32-byte random challenge on WebSocket connect
2. Client signs `challenge || server_identity || timestamp` with device Ed25519 key
3. Client sends `{ user_id, device_id, device_public_key, signature, timestamp }`
4. Server verifies: valid signature, timestamp within 60 seconds, device registered for user
5. Replay prevention: server maintains short-lived set (TTL = 120s) of used challenge nonces

### Step 14: Implement `queue.rs`

- `MessageQueue`: `DashMap<(UserId, DeviceId), VecDeque<StoredEnvelope>>`
- `StoredEnvelope`: `Envelope` + `stored_at: Timestamp`
- `enqueue()` — adds to queue, enforces max 2000 queued messages per device
- `dequeue()` — drains queued messages for a device
- `cleanup_expired()` — periodic task removes messages past TTL
- Fan-out: when a message arrives for `UserId`, enqueue for each of that user's registered `DeviceId`s
- Optional: disk-backed mode using append-only log for persistence across restarts

### Step 15: Implement `ws.rs`

Per-connection event loop handling `ClientMessage` variants:

| Message | Action |
|---|---|
| `SendEnvelope` | Validate size → enqueue for all recipient devices → acknowledge sender → push to online devices |
| `Ack` | Remove delivered message from queue |
| `FetchPreKeys` | Return stored pre-key bundle (rate-limited: 10/hour) |
| `UploadPreKeys` | Store/replace device's pre-key bundle |
| `RegisterDevice` | Register `(UserId, DeviceId)` mapping, verify device cert signed by root identity |
| `Authenticate` | Challenge-response flow from Step 13 |

Heartbeat: ping/pong every 30s, disconnect after 90s silence.

### Step 16: Implement `main.rs`

Axum router with single `/ws` route. Spawn TTL cleanup task (every 60s). Graceful shutdown on SIGTERM.

### Step 17: Pre-Key Storage

`DashMap<(UserId, DeviceId), PreKeyBundle>` on the relay. Clients upload on registration; other clients fetch to initiate X3DH. OPK deleted immediately after serving. Max 200 OPKs + 2 SPKs stored per device.

### Step 18: Integration Tests

Spin up relay in-process, connect two mock clients via `tokio-tungstenite`, exchange messages through relay, verify delivery, ACK, and TTL expiry cleanup.

---

## 8. Phase 4 — Desktop Client

**Files:** `src-tauri/`, `ui/`

### Step 19: Initialize Tauri Project

Configure `tauri.conf.json`: window title "CipherLine", default size 900×650, disable devtools in release. Set `frontendDist` to `../ui/dist`.

### Step 20: Set Up React UI

Vite + React + TypeScript in `ui/`. Install `@tauri-apps/api` for IPC.

### Step 21: Implement `store.rs`

- SQLCipher database in `app_data_dir()/cipherline.db`
- Master key: read from OS keychain (`keyring` crate). If absent, generate 32 random bytes, store in keychain, derive SQLCipher passphrase via Argon2id with domain string `"CipherLine_DBKey_v1"`
- Database schema:

| Table | Columns |
|---|---|
| `identity` | Root keys (encrypted), device keys |
| `contacts` | UserId, display name, public keys |
| `sessions` | Serialized `RatchetState` per (contact UserId, contact DeviceId) |
| `messages` | id, conversation_id, sender, timestamp, plaintext (encrypted), read status |
| `prekeys` | Our unused one-time pre-keys |
| `devices` | Our linked devices, public keys, status |

### Step 22: Implement `commands.rs`

Tauri IPC commands (all registered in `invoke_handler`):

| Command | Purpose |
|---|---|
| `create_identity()` | Generate root + first device, store in DB, upload pre-keys to relay |
| `get_identity()` | Return public identity info for display |
| `add_contact(user_id)` | Fetch pre-key bundle, perform X3DH, create DR session |
| `send_message(contact_id, text)` | Load DR session, encrypt, sign, send envelope for each recipient device |
| `get_messages(contact_id)` | Load decrypted messages from DB |
| `get_contacts()` | List all contacts |
| `link_device(qr_data)` | Device linking flow |
| `list_devices()` | Show linked devices |
| `revoke_device(device_id)` | Mark device revoked, notify contacts |

### Step 23: Implement `state.rs`

- `AppState`: DB connection pool, WebSocket connection to relay, identity cache
- Managed via `tauri::Manager::manage()`
- Background task: WebSocket listener receives `ServerMessage::Deliver(envelope)` → verify signature → load DR session → decrypt → store plaintext in DB → emit Tauri event `"new-message"` to UI

### Step 24: Configure Capabilities

Whitelist all IPC commands in `src-tauri/capabilities/default.json`. Tauri v2 silently rejects commands not declared here.

### Step 25: Build React UI

| Component/Hook | Purpose |
|---|---|
| `useIdentity` | Calls `get_identity()` on mount, handles first-run `create_identity()` |
| `useChat` | Calls `get_messages(contactId)`, listens to `"new-message"` Tauri event |
| `useWebSocket` | Connection status indicator (connected/reconnecting/offline) |
| `ContactList` | Sidebar with contact list, unread badges |
| `ChatView` | Message list + input box, calls `send_message` on submit |
| `DeviceLinkDialog` | QR code display/scan for device linking |
| `SettingsPanel` | Identity fingerprint, device management, auto-delete timer |

Styling: Tailwind CSS, dark mode default.

---

## 9. Phase 5 — Multi-Device

### Step 26: Device Registration Protocol

1. New device generates its own Ed25519 + X25519 keys
2. Existing device displays QR: `{ user_id, root_public_key, approval_token, relay_url }`
3. New device scans QR, connects to relay, sends `RegisterDevice` with public keys + approval_token
4. Relay forwards to existing device(s) for approval
5. Existing device signs new device's public key with root Ed25519 → creates `DeviceCertificate`
6. Certificate stored on relay + new device. Now trusted by contacts.

### Step 27: Device Revocation

- Revocation = signed message: `{ revoked_device_id, timestamp, signature_by_root_identity }`
- Relay immediately removes device registration, pre-key bundles, and queued messages
- Other devices broadcast `DeviceRevocation` to all contacts via existing DR sessions
- Contacts delete all DR sessions with revoked device, stop encrypting to it
- **Race window:** Up to ~6 hours of messages may still be encrypted for revoked device (due to cached device lists). Documented as known limitation.

### Step 28: Sender-Side Fan-Out

- Sender queries relay for all active `DeviceId`s of recipient (signed device list, verified against root identity)
- Sender maintains one DR session per `(recipient_user, recipient_device)`
- Message encrypted N times (once per device), all N envelopes sent to relay
- Relay delivers each to corresponding device
- Each device ACKs independently; envelope deleted when all devices ACK

### Step 29: Own-Device Sync

When sending a message, also encrypt to each of the user's own other devices. This syncs sent message history across devices.

---

## 10. Phase 6 — Mobile

### Step 30: Android Setup

- `cargo tauri android init` → generates Android project in `src-tauri/gen/android/`
- Verify RustCrypto crates compile for `aarch64-linux-android` and `armv7-linux-androideabi`
- Verify `rusqlite` with `bundled-sqlcipher-vendored-openssl` cross-compiles
- Test with `cargo tauri android dev` on emulator
- Key storage: Android Keystore (hardware-backed, StrongBox if available)

### Step 31: iOS Setup

- `cargo tauri ios init` (requires macOS)
- Configure Xcode signing
- Verify builds for `aarch64-apple-ios`
- Key storage: iOS Keychain with `kSecAttrAccessibleAfterFirstUnlock`

### Step 32: UI Adaptation

- Responsive CSS: single-column layout on mobile viewports
- Touch-friendly tap targets (min 44px)
- Handle mobile keyboard pushing content up
- Bottom navigation bar for mobile (Chats, Contacts, Settings)

### Step 33: Mobile Keychain

- **Android:** Android Keystore → generate random AES-256 key → encrypt SQLCipher key → store encrypted blob in app-private storage
- **iOS:** `security-framework` crate or Tauri plugin wrapping iOS Keychain Services

### Step 34: Push Notifications

- Push payloads contain **zero message content** — only a wake-up signal
- App wakes, connects to relay over its own TLS WebSocket, fetches encrypted messages
- Requires: Firebase account (Android FCM), Apple Developer account (APNs)
- Support WebSocket-only mode on Android for de-Googled devices
- iOS: Use Notification Service Extension (NSE) for background message fetch and decryption

---

## 11. Phase 7 — Hardening

### Step 35: Disable Debug Logging

`tracing` default level = `WARN` in release builds. Remove all `dbg!()` and `println!()`. Strip `Debug` impl from key types. Use `secrecy::Secret<T>` for auto-redaction.

### Step 36: Rate Limiting

| Layer | Mechanism | Limit |
|---|---|---|
| IP-level | `tower` middleware | 30 req/sec per IP |
| User-level | Per-authenticated-user counter | 10 msg/sec |
| Pre-key fetch | Per-requester throttle | 10 fetches/hour |
| Registration | Per-IP throttle | 5 new devices/hour |
| WebSocket connect | Per-IP | 10 connections/min |
| Envelope size | Hard reject | > 64 KB |

### Step 37: Fuzzing

- `cargo-fuzz` targets:
  - `ratchet_decrypt` with random header + ciphertext → must never panic
  - `Envelope` deserialization from random MessagePack bytes
  - `crypto::decrypt` with random key/nonce/ciphertext
- Run for ≥24 hours in CI

### Step 38: Panic Safety

- All crypto/protocol functions return `Result<T, CipherlineError>` — never panic on bad input
- `catch_unwind` at Tauri command boundary as last resort
- Relay: isolate per-connection panics via `tokio::task::spawn` so one bad client can't crash the server

### Step 39: Memory Safety

- `zeroize` all key material on drop (`Zeroize + ZeroizeOnDrop` derives)
- `memsec::mlock()` on pages containing keys (fall back gracefully if unavailable)
- Wrap sensitive data in `secrecy::SecretVec<u8>` / `secrecy::SecretString`

### Step 40: Message Padding

Pad all ciphertexts to fixed-size buckets: 256B, 1KB, 4KB, 16KB, 64KB. Padding is random bytes appended before encryption, with length prefix inside the plaintext.

### Step 41: Security Audit Preparation

- Write `docs/threat-model.md` with exact guarantees and known limitations
- Document all crypto choices and rationale
- Prepare for third-party code review of the `common/` crate

---

## 12. Security Guidance

### 12.1 Double Ratchet Safety

**Pitfalls to avoid:**

1. **Message key reuse.** Each message key must be used exactly once for encryption, then immediately deleted from memory and storage. After `ratchet_decrypt()` succeeds, delete the key before returning. Retaining it breaks forward secrecy.

2. **Fixed nonce is correct.** Use `[0u8; 12]` nonce for ChaCha20-Poly1305 since each DR message key is single-use. This matches Signal's approach. If a key were ever reused with the same nonce, ChaCha20-Poly1305 completely breaks.

3. **Skipped key DoS.** An attacker sends a message with counter `N = 1,000,000`, forcing expensive derivation. Enforce `MAX_SKIP = 2000` per chain step. Also enforce a global cap of ~5000 total skipped keys. Reject messages exceeding either limit.

4. **Timing side-channels.** Never compare MAC tags or signatures with `==`. Rust's `PartialEq` for `[u8]` short-circuits on first differing byte. Use `subtle::ConstantTimeEq` for all secret-dependent comparisons.

5. **State rollback.** A restored database snapshot restores old chain keys, breaking forward secrecy and causing ratchet divergence. Write DR state atomically (SQLite transaction) after every encrypt/decrypt. Exclude the database from cloud backups.

6. **Chain stall.** If one party never replies, the sending chain never gets fresh DH material. Consider a protocol-level "silent ratchet tick" if no reply after ~100 messages on one chain without a DH step.

7. **Re-initialization detection.** When a session already exists, treat a new X3DH initial message as suspicious. Archive the old session (capped at 40 archives) and alert the user.

**Skip header encryption initially.** Document this as a known limitation. TLS on the relay transport provides partial protection.

**Testing strategies:**

- **Property-based tests** (`proptest` / `quickcheck`): generate random send/receive sequences. Assert: every encrypted message decrypts to original; out-of-order within MAX_SKIP succeeds; exceeding MAX_SKIP fails; key deletion prevents re-decryption.
- **Fuzzing** (`cargo-fuzz`): fuzz `ratchet_decrypt` with arbitrary header + ciphertext. Must never panic. Run ≥24 hours in CI.
- **Deterministic test vectors:** seed `rand` with fixed value, run scripted conversation, assert exact ciphertext/key outputs. Pin as regression tests.
- **Session divergence test:** 200+ messages with random ordering, including gaps, verify both sides stay in sync.

**Keeping ratchet auditable:**

- Entire DR + X3DH implementation in a single file (`common/src/ratchet.rs`), targeted at 500-800 lines.
- No trait abstractions, no generics over crypto backends. Hardcode primitives.
- Zero `unsafe` in the ratchet module.
- Every public function has a doc comment stating security invariants.
- Run `cargo audit` in CI.

---

### 12.2 Pre-Key Handling

**Exhaustion safeguards:**

- Upload **100 OPKs** on initial registration.
- On every WebSocket connect, relay reports OPK count. If below **25**, client uploads a fresh batch of 100.
- Relay enforces max **200 OPKs** stored per device.

**Fallback when OPKs unavailable:**

- X3DH degrades to 3-DH (omitting OPK DH). Explicitly allowed by the spec but has weaker properties:
  - No replay detection via OPK uniqueness.
  - Weaker forward secrecy — SPK compromise before rotation allows decryption of initial messages.
- Log client-side when a session is initiated without OPK. Consider surfacing as reduced-security indicator.

**Signed pre-key rotation:**

- Rotate SPK every **48 hours**.
- Keep previous SPK for **30 days** (in-flight messages may reference it).
- Maximum 2 SPKs stored per device on relay.

**Bundle validation (initiator MUST verify):**

1. SPK signature is valid Ed25519 from the claimed identity key.
2. Identity key matches previously trusted key (TOFU) or verified out-of-band.
3. All public keys are valid Curve25519 points. Check DH output is not all-zeros.

**Server-side abuse prevention:**

- Delete OPK from storage immediately after serving it. Never serve the same OPK twice.
- Rate-limit pre-key bundle fetches: max 10 per hour per requester identity.

---

### 12.3 Multi-Device Messaging

**Risks of sender-side fan-out:**

- Encryption cost scales linearly. 50 contacts × 5 devices = 250 encryptions per message. Mitigate later with Sender Keys for groups.
- Session state: ~1-2 KB per DR session. 500 contacts × 5 devices ≈ 3-5 MB. Manageable.
- Metadata amplification: relay sees N envelopes where N = device count. Mitigate with batching.

**Device-count abuse prevention:**

- **Hard cap: 6 devices per user.** Relay rejects `RegisterDevice` beyond this.
- **Device list signing:** User's root identity signs a `DeviceList` manifest. Sender verifies root signature when fetching device lists. Prevents relay from injecting phantom devices.
- **Cache device lists with 6-hour TTL.** Never trust a device list older than 24 hours for first contact.

**Device revocation propagation:**

- Revocation is a signed timestamped message from root identity.
- Relay immediately removes device registration, pre-keys, and queued messages.
- Other devices broadcast revocation to all contacts via existing DR sessions.
- Contacts delete all DR sessions with revoked device.
- **Known limitation:** ~6 hour race window for cached device lists.

---

### 12.4 Relay Server Behavior

**Hard limits:**

| Limit | Value | Rationale |
|---|---|---|
| Max envelope size | 64 KB | Real messages are < 10 KB |
| Max queued messages per device | 2,000 | Prevents mailbombing |
| Max connections per IP | 10 | Limits DoS |
| Max devices per user | 6 | Prevents phantom devices |
| Max OPKs per device | 200 + 2 SPKs | Prevents storage abuse |
| Message TTL | 7 days (configurable) | Limits exposure window |
| Max message rate per user | 10 msg/sec | Prevents flooding |

**Metadata minimization:**

- Do not log sender/recipient pairs, message IDs, or timestamps.
- Pad relay-to-client transmissions to fixed-size blocks (1 KB, 4 KB, 16 KB, 64 KB).
- No presence/online-status API. Users cannot query if someone is online.

**Authentication:**

1. Client opens WebSocket. Relay sends 32-byte random challenge.
2. Client signs `challenge || server_identity || timestamp` with device Ed25519 key.
3. Relay verifies signature, checks timestamp within 60s, verifies device registration.
4. Replay prevention: short-lived set (TTL = 120s) of used challenge nonces.

**Store-and-forward semantics:**

- Enqueue: store encrypted envelope for each recipient device. Return `Ack` to sender after storage.
- Deliver: push all queued envelopes in FIFO on recipient connect.
- ACK: recipient sends `Ack(message_id, device_id)` after decryption and local storage. Relay removes from that device's queue.
- All-device ACK: envelope fully deleted when all registered devices have ACKed.
- TTL cleanup: background sweep every 60s. Expired envelopes deleted silently.
- **No delivery guarantee after TTL.** Document explicitly.

---

### 12.5 Cryptographic Hygiene

**Key separation and domain separation:**

- Separate Ed25519 (signing) and X25519 (key exchange) key pairs. Never convert between them.
- All KDF calls include a domain separation string:
  - X3DH: `"CipherLine_X3DH_v1"`
  - DR root chain: `"CipherLine_DR_Root_v1"`
  - DR chain key → message key: `"CipherLine_DR_MsgKey_v1"`
  - DR chain key → next chain key: `"CipherLine_DR_ChainKey_v1"`
  - SQLCipher key derivation: `"CipherLine_DBKey_v1"`
- Version suffix (`_v1`) enables non-ambiguous protocol upgrades.

**Memory zeroization:**

- All private keys, chain keys, message keys, shared secrets: `Zeroize + ZeroizeOnDrop`.
- Wrap sensitive data in `secrecy::SecretVec<u8>` (auto-zeroize, redacted Debug/Display).
- `memsec::mlock()` on key-material pages to prevent swapping. Fall back gracefully.
- Accept `zeroize` cannot zero register copies or compiler temporaries. Compensate with short key lifetimes.

**Protocol versioning:**

- Every serialized type includes `version: u8` as first field.
- Receivers reject unknown versions with clear error.
- `PROTOCOL_VERSION` constant in `common/src/types.rs`.
- KDF domain strings include version (`_v1`) to prevent cross-version key collisions.

---

### 12.6 Mobile-Specific Concerns

**Push notification privacy:**

- Apple/Google see: device token, app bundle ID, payload size, timestamp.
- **Mandatory:** push payloads contain zero message content. Wake-up signal only.
- On Android: support WebSocket-only mode (no FCM) for de-Googled devices.
- On iOS: APNs is mandatory — no alternative. Document this privacy tradeoff in threat model.
- Store device tokens encrypted at rest. Allow users to opt out of push (at cost of delayed delivery).

**Background execution:**

- **iOS:** Background WebSocket killed within seconds. Use Notification Service Extension (NSE, ~30s execution window) on push arrival to fetch + decrypt + present local notification. NSE shares DB via Keychain access group.
- **Android:** Background services restricted on Android 8+. Use `WorkManager` or FCM wake-up only.
- **Shared DB access:** iOS NSE and main app share SQLCipher DB. Use WAL mode + careful locking.

**Key storage:**

- **Android:** Keystore with StrongBox (Pixel 3+). `setUserAuthenticationRequired(true)` for biometric gating. `setInvalidatedByBiometricEnrollment(true)` for enrollment change protection. Handle `KeyPermanentlyInvalidatedException` → re-generate + re-encrypt.
- **iOS:** Keychain with `kSecAttrAccessibleAfterFirstUnlock` for DB key (allows background decryption). `kSecAttrAccessibleWhenUnlocked` for identity signing key. `.biometryCurrentSet` for biometric gating.
- **Device PIN/password change:** Android 12+ does not invalidate Keystore keys on PIN change. iOS Keychain items survive passcode changes. Biometric enrollment changes invalidate keys with `biometryCurrentSet` / `invalidatedByBiometricEnrollment`.
- Never store raw keys in SharedPreferences (Android) or UserDefaults (iOS).
- Exclude database from cloud backups on both platforms.

---

### 12.7 Operational Hardening

**Rate limiting:**

| Layer | Mechanism | Limit |
|---|---|---|
| IP-level | `tower` middleware | 30 req/sec per IP |
| User-level | Per-user counter | 10 msg/sec |
| Pre-key fetch | Per-requester throttle | 10/hour |
| Registration | Per-IP throttle | 5 devices/hour |
| WebSocket connect | Per-IP | 10/minute |
| Envelope size | Hard reject | > 64 KB |

On limit violation: return `ServerMessage::Error(RateLimited)`, close WebSocket with code `4029` after 3 violations in 60 seconds.

**Crash-only server:**

- Kill at any point, restart, and recover.
- In-memory queue: accept that undelivered messages are lost on crash. Clients retry. Document this.
- Disk-backed queue (optional): append-only log or SQLite WAL. On startup, replay and discard expired entries.
- No startup migration or initialization ceremony. Read config, bind, serve.
- One bad message must never crash the server. Per-connection panic isolation via `tokio::task::spawn`.

**Safe logging:**

- **Never log:** message content, keys, nonces, full user IDs, full device IDs, IP addresses, pre-key material.
- **Allowed to log:** connection count, message throughput (count only), error categories, TTL cleanup count, memory usage.
- Use `tracing` with structured logging. Release default: `WARN`.
- `INFO` level: zero PII.
- Strip `Debug` from key types. Use `secrecy::Secret<T>` for auto-redaction.
- For abuse investigation: log truncated hash of user ID (first 8 hex chars of BLAKE2b), not raw ID.

---

### 12.8 Threat Model Clarity

**Must be documented explicitly in `docs/threat-model.md`:**

1. **Relay trust model.** The relay is honest-but-curious. It routes faithfully but may read metadata. CipherLine prevents content access. CipherLine reduces but does not eliminate metadata leakage (relay knows who talks to whom and when).

2. **No protection against compromised endpoints.** Malware on device defeats all encryption. Root identity key is in memory during app execution.

3. **TOFU limitation.** First contact trusts the relay for correct pre-key bundles. Malicious relay can MITM first session. Safety number verification detects this. Document as optional but strongly recommended.

4. **Replay window without OPKs.** When OPKs exhausted, initial messages can be replayed. Display a warning.

5. **Device revocation race.** Up to ~6 hours of messages may be encrypted for a revoked device.

6. **Push notification metadata.** Apple/Google learn that a CipherLine notification was sent to a specific device at a specific time.

7. **Forward secrecy boundaries.** Forward secrecy applies per-message after the first DR ratchet step. Between X3DH and first reply, SPK compromise (without OPK) breaks secrecy of initial message.

8. **Storage at rest.** SQLCipher encrypted, but key is in OS keychain. Unlocked keychain exposes DB key. Biometric gating adds a layer but is not impenetrable.

**Guarantees that must NEVER be claimed:**

| Claim | Why it's false |
|---|---|
| "Untraceable" | Relay sees connection metadata, IPs, timing |
| "Cannot be monitored" | Compromised devices, keyloggers, screen capture defeat encryption |
| "Government-proof" | Legal compulsion reveals metadata; device seizure reveals everything if unlocked |
| "Perfect forward secrecy" (unqualified) | PFS applies to DR but not to X3DH under OPK exhaustion/SPK compromise |
| "Zero metadata" | Relay knows sender, recipient, timestamp, message size |
| "Trustless" | TOFU requires trusting relay for first contact |

---

## 13. Verification

| Phase | How to Verify |
|---|---|
| **Phase 1** | `cargo test -p cipherline-common` — all crypto tests pass (round-trip encrypt/decrypt, sign/verify, key generation) |
| **Phase 2** | `cargo test -p cipherline-common` — X3DH agreement, DR session with 100+ messages interleaved, out-of-order delivery, skipped key limits, serialization round-trips |
| **Phase 3** | Integration test: two in-process clients exchange messages through relay, verify delivery, ACK, TTL expiry. Manual smoke test with `websocat` |
| **Phase 4** | `cargo tauri dev` — app launches, create identity, add contact, send/receive messages. Verify persistence across restart. Verify SQLCipher DB is unreadable without key |
| **Phase 5** | Link two desktop instances as same user. Send message from contact → both devices receive. Revoke one → messages no longer delivered to it |
| **Phase 6** | `cargo tauri android dev` / `cargo tauri ios dev` — full chat flow on mobile. Verify push notification wake-up |
| **Phase 7** | `cargo fuzz run fuzz_decrypt` for 10 min with no crashes. `cargo clippy` clean. Release build has no debug output. Rate limiter rejects flood test |

---