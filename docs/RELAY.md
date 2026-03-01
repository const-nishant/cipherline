# Relay Server

The CipherLine relay is a stateless, blind message-forwarding server built with Axum and Tokio. It authenticates clients via Ed25519 challenge-response, stores/forwards encrypted envelopes, and manages pre-key bundles — without ever accessing plaintext message content.

---

## Endpoints

| Route | Method | Description |
|-------|--------|-------------|
| `/ws` | GET (WebSocket upgrade) | Primary client connection. All protocol messages flow over this WebSocket. |
| `/health` | GET | Health check. Returns `200 OK` when the server is running. |

---

## Configuration

All options can be set via CLI flags or environment variables (via `clap`).

| Environment Variable | CLI Flag | Default | Description |
|---------------------|----------|---------|-------------|
| `CIPHERLINE_BIND_ADDR` | `--bind-addr` | `0.0.0.0:8080` | Address and port to bind |
| `CIPHERLINE_MESSAGE_TTL` | `--message-ttl` | `604800` (7 days) | TTL for undelivered messages (seconds) |
| `CIPHERLINE_MAX_MSG_SIZE` | `--max-msg-size` | `65536` (64 KB) | Maximum envelope size in bytes |
| `CIPHERLINE_MAX_CONNECTIONS` | `--max-connections` | `10000` | Maximum concurrent WebSocket connections |
| `CIPHERLINE_RATE_LIMIT` | `--rate-limit` | `30` | Per-IP rate limit (messages/second) |
| `CIPHERLINE_CLEANUP_INTERVAL` | `--cleanup-interval` | `60` | Expired message sweep interval (seconds) |
| `CIPHERLINE_MAX_QUEUED` | `--max-queued` | `2000` | Maximum queued messages per device |
| `CIPHERLINE_MAX_OPKS` | `--max-opks` | `200` | Maximum one-time pre-keys stored per device |
| `CIPHERLINE_PING_INTERVAL` | `--ping-interval` | `30` | WebSocket ping interval (seconds) |
| `CIPHERLINE_IDLE_TIMEOUT` | `--idle-timeout` | `90` | WebSocket idle timeout (seconds) |
| `CIPHERLINE_AUTH_TOLERANCE` | `--auth-tolerance` | `60` | Auth challenge timestamp tolerance (seconds) |

---

## Running

### Local Development

```sh
cargo run -p cipherline-relay
```

### Production Binary

```sh
cargo build -p cipherline-relay --release
./target/release/cipherline-relay \
  --bind-addr 0.0.0.0:8080 \
  --max-connections 20000 \
  --rate-limit 50
```

### Docker

Build locally:
```sh
docker build -t cipherline-relay .
```

Or pull from GHCR:
```sh
docker pull ghcr.io/const-nishant/cipherline-relay:0.1.0
```

Run with custom config:
```sh
docker run -d \
  -p 8080:8080 \
  -e CIPHERLINE_MAX_CONNECTIONS=20000 \
  -e CIPHERLINE_RATE_LIMIT=50 \
  -e CIPHERLINE_MESSAGE_TTL=86400 \
  --name cipherline-relay \
  ghcr.io/const-nishant/cipherline-relay:0.1.0
```

Multi-arch images are published for `linux/amd64` and `linux/arm64`.

---

## Authentication Flow

1. Client connects via WebSocket to `/ws`
2. Relay sends a `Challenge` message containing random bytes
3. Client signs `challenge_bytes || timestamp` with its Ed25519 identity key
4. Client sends `Authenticate` response with the signature, public key, device ID, and timestamp
5. Relay verifies the signature and checks timestamp is within `CIPHERLINE_AUTH_TOLERANCE` seconds
6. On success, the device is registered as connected

---

## Deployment Recommendations

- **Always use TLS** — Place the relay behind a reverse proxy (nginx, Caddy, Traefik) with TLS termination, or use a cloud load balancer
- **Monitor `/health`** — Use the health endpoint for liveness/readiness probes in Kubernetes or Docker health checks
- **Set resource limits** — Tune `CIPHERLINE_MAX_CONNECTIONS` and `CIPHERLINE_RATE_LIMIT` for your expected load
- **Log monitoring** — The relay uses `tracing` with `env-filter`. Set `RUST_LOG=info` (or `debug` for troubleshooting)
- **Horizontal scaling** — The relay is stateless. Run multiple instances behind a load balancer for high availability

---

## Security Notes

- The relay **never** decrypts message content — it forwards opaque ciphertext
- Authentication prevents unauthorized devices from sending messages
- Rate limiting and connection caps mitigate DoS attacks
- Message TTL ensures undelivered messages are automatically purged
- See [SECURITY.md](SECURITY.md) for the full threat model
