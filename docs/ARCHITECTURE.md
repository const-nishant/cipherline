# Architecture

CipherLine is a Rust workspace with three crates and a React frontend, communicating over a WebSocket-based wire protocol serialized with MessagePack.

---

## System Overview

```
┌─────────────────┐         WebSocket (MessagePack)         ┌─────────────────┐
│  Desktop Client │ ◄──────────────────────────────────────► │  Relay Server   │
│  (Tauri + React)│                                          │  (Axum + Tokio) │
└─────────────────┘                                          └────────┬────────┘
                                                                      │
┌─────────────────┐         WebSocket (MessagePack)                   │
│  Android Client │ ◄─────────────────────────────────────────────────┘
│  (Tauri Mobile) │
└─────────────────┘
```

- Clients encrypt messages locally using the Double Ratchet, then send opaque `Envelope` payloads to the relay
- The relay authenticates clients, stores/forwards envelopes, and manages pre-key bundles
- The relay **never** has access to plaintext message content

---

## Workspace Crates

### `common/` — Shared Library

The core cryptographic and protocol logic, used by both client and relay.

| File | Responsibility |
|------|---------------|
| `crypto.rs` | Low-level primitives: X25519 DH, ChaCha20-Poly1305 encrypt/decrypt, Ed25519 sign/verify, BLAKE2b KDF chains |
| `identity.rs` | Device identity, certificates, signed device lists, pre-key bundles |
| `protocol.rs` | Wire protocol types: `ClientMessage`, `ServerMessage`, `Envelope`, `InitialMessage` |
| `ratchet.rs` | X3DH key agreement, Double Ratchet session (`DoubleRatchetSession`), skipped key management |
| `types.rs` | Shared types (`UserId`, `DeviceId`, `MessageId`, `MessageHeader`), error types, constants |

### `relay/` — Relay Server

A stateless blind relay built on Axum.

| File | Responsibility |
|------|---------------|
| `main.rs` | Server startup, route registration (`/ws`, `/health`), CORS |
| `config.rs` | CLI/env configuration via `clap` (bind addr, rate limits, TTL, etc.) |
| `auth.rs` | Ed25519 challenge-response authentication |
| `ws.rs` | WebSocket handler: message routing, pre-key management, envelope delivery |
| `queue.rs` | Per-device message queue with TTL expiration |
| `state.rs` | Shared server state: connection registry, pre-key store, device lists |

### `src-tauri/` — Desktop Client

Tauri v2 application bridging the Rust backend to the React frontend.

| File | Responsibility |
|------|---------------|
| `main.rs` | Tauri application entry point |
| `lib.rs` | Plugin registration and setup |
| `commands.rs` | Tauri IPC commands exposed to the frontend |
| `keystore.rs` | Local key generation and storage |
| `store.rs` | SQLCipher database layer (contacts, messages, sessions) |
| `ws_client.rs` | WebSocket client connecting to the relay |
| `state.rs` | Application state management |

### `ui/` — React Frontend

| File | Responsibility |
|------|---------------|
| `App.tsx` | Root component, routing |
| `api.ts` | TypeScript bindings to Tauri `invoke()` commands |
| `components/` | UI components (chat, contacts, settings) |
| `notifications.ts` | Desktop notification integration |

---

## Wire Protocol

All client ↔ relay communication uses MessagePack over WebSocket.

```
Client → Relay:
  - Authenticate          (Ed25519 signed challenge response)
  - RegisterDevice        (upload device certificate)
  - UploadPreKeys         (identity key, signed pre-key, one-time pre-keys)
  - FetchPreKeys          (request pre-key bundle for a recipient)
  - SendEnvelope          (encrypted message envelope)
  - Ack                   (acknowledge receipt of a message)

Relay → Client:
  - Challenge             (random bytes for authentication)
  - Ack                   (confirmation of received message)
  - Deliver               (incoming encrypted envelope)
  - PreKeys               (requested pre-key bundle)
  - DeviceListResponse    (signed device list for a user)
  - Error                 (error code + description)
```

---

## Data Flow: Sending a Message

```
1. Sender looks up recipient's pre-key bundle (or uses existing session)
2. If new session: X3DH key agreement → seed Double Ratchet
3. Double Ratchet encrypts plaintext → (header, ciphertext)
4. Sender signs (header || ciphertext) with Ed25519
5. Envelope { routing, header, ciphertext, signature } → relay via WebSocket
6. Relay authenticates sender, validates envelope, queues for recipient
7. Relay delivers envelope to recipient (or stores until online)
8. Recipient verifies signature, decrypts via Double Ratchet
9. Message key is zeroized immediately after decryption
```

---

## Scalability

- **Relay is stateless** — no persistent storage; all state is in-memory. Multiple relay instances can run behind a load balancer.
- **WebSocket connections** are bounded by `CIPHERLINE_MAX_CONNECTIONS` (default: 10,000)
- **Message queues** are bounded per-device (`CIPHERLINE_MAX_QUEUED`, default: 2,000)
- **Expired messages** are swept at configurable intervals (`CIPHERLINE_CLEANUP_INTERVAL`)
- **Docker multi-arch images** (amd64/arm64) enable deployment on any infrastructure
