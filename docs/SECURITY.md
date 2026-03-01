# Security Model

> **Disclaimer:** CipherLine is designed for strong privacy using well-studied cryptographic protocols. However, no software can guarantee absolute security. This software has not undergone a formal security audit. Always keep your keys safe and keep your software up to date.

---

## Cryptographic Algorithms

CipherLine uses a locked set of cryptographic primitives. These are intentionally fixed and must not be changed without a full protocol version bump.

| Purpose | Algorithm | Library |
|---------|-----------|---------|
| Key exchange | X25519 | `x25519-dalek` |
| Authenticated encryption | ChaCha20-Poly1305 | `chacha20poly1305` |
| Digital signatures | Ed25519 | `ed25519-dalek` |
| KDF / Hashing | BLAKE2b (keyed, 256-bit) | `blake2` |
| Constant-time comparison | `subtle` | `subtle` |
| Key zeroization | `zeroize` | `zeroize` |
| Random number generation | OS CSPRNG | `OsRng` via `rand` |

---

## Protocol Design

### X3DH Key Agreement

CipherLine implements Extended Triple Diffie-Hellman (X3DH) for initial session establishment:

1. Each device publishes an **identity key** (Ed25519), a **signed pre-key** (X25519), and a batch of **one-time pre-keys** (X25519)
2. The initiator performs three (or four, if a one-time pre-key is available) DH operations to derive a shared secret
3. The shared secret seeds the Double Ratchet

### Double Ratchet

After X3DH, all messages use the Signal Double Ratchet:

- **DH Ratchet**: Each reply rotates the DH key pair, providing post-compromise security
- **Symmetric Ratchet**: A KDF chain (BLAKE2b, domain-separated) derives per-message keys
- **Fixed Nonce**: ChaCha20-Poly1305 uses a zero nonce because each message key is used exactly once and then zeroized
- **Skipped Keys**: Out-of-order messages are handled by storing bounded skipped message keys (`MAX_SKIP` per step, `MAX_TOTAL_SKIPPED_KEYS` globally)

### Envelope Signing

Every `Envelope` on the wire is signed:

```
signature = Ed25519_Sign(sender_signing_key, serialize(header) || ciphertext)
```

The relay and recipients verify this signature to ensure message authenticity and integrity.

---

## Key Management

- **Key generation**: All keys are generated on-device using the OS CSPRNG (`OsRng`). No keys are ever generated server-side.
- **Private key storage**: Private keys are stored in the local SQLCipher-encrypted database. They never leave the device.
- **Key zeroization**: All secret key material implements `Zeroize` and is wiped from memory when no longer needed.
- **Pre-key rotation**: One-time pre-keys are consumed on use. Clients should periodically upload fresh batches.
- **Device certificates**: Each device holds a `DeviceCertificate` signed by the identity key, binding the device ID to its signing and pre-key public keys.

---

## Threat Model

### What CipherLine protects against

| Threat | Mitigation |
|--------|------------|
| Relay server compromise | Server sees only opaque ciphertext and routing metadata. Cannot decrypt messages. |
| Past message exposure after key compromise | Forward secrecy via DH ratchet — past message keys are irrecoverable |
| Future message exposure after key compromise | Post-compromise security — DH ratchet heals the session on the next reply |
| Message tampering | Ed25519 signature on every envelope; ChaCha20-Poly1305 authenticated encryption |
| Replay attacks | Message IDs and timestamps; bounded skipped-key window |
| Timing side-channels | Constant-time MAC/signature comparisons via `subtle` |
| Memory forensics | Secret keys are zeroized on drop |

### What CipherLine does NOT protect against

- Compromised endpoint devices (keyloggers, screen capture, rooted devices)
- Traffic analysis (message timing, sizes, sender/recipient IDs are visible to the relay)
- Social engineering attacks
- Bugs in dependencies or the Rust compiler itself
- Lack of formal verification

### Trust Assumptions

- The OS CSPRNG (`/dev/urandom`, `CryptGenRandom`, etc.) is trustworthy
- The user's device is not compromised at the time of key generation
- The `x25519-dalek`, `ed25519-dalek`, `chacha20poly1305`, `blake2`, and `subtle` crates are correctly implemented

---

## Relay Server Security

- The relay authenticates clients via **Ed25519 challenge-response**: it sends a random challenge, and the client signs `challenge || timestamp` with its identity key
- **Timestamp tolerance** is configurable (`CIPHERLINE_AUTH_TOLERANCE`, default 60s) to prevent replay
- **Rate limiting** caps messages per second per IP (`CIPHERLINE_RATE_LIMIT`)
- **Connection limit** caps total concurrent WebSocket connections (`CIPHERLINE_MAX_CONNECTIONS`)
- **Message TTL** automatically purges undelivered messages after a configurable period (`CIPHERLINE_MESSAGE_TTL`)

---

## Local Storage

Client data is stored in an SQLCipher-encrypted SQLite database (`rusqlite` with `bundled-sqlcipher` feature). The database key is derived from user credentials and stored securely on the device.

---

## Responsible Disclosure

If you discover a security vulnerability in CipherLine:

1. **Do not** open a public GitHub issue
2. Contact the maintainer directly at [const-nishant](https://github.com/const-nishant) via GitHub
3. Include a clear description of the vulnerability and steps to reproduce
4. Allow reasonable time for a fix before public disclosure

We take all security reports seriously and will respond promptly.
