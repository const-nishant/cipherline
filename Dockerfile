# ---------- Build stage ----------
FROM rust:1.87-slim AS builder

RUN apt-get update && apt-get install -y --no-install-recommends \
    pkg-config libssl-dev && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /build

# Copy workspace manifests first for layer caching
COPY Cargo.toml Cargo.lock ./
COPY common/Cargo.toml common/Cargo.toml
COPY relay/Cargo.toml  relay/Cargo.toml
COPY src-tauri/Cargo.toml src-tauri/Cargo.toml

# Stub out source files so cargo can resolve the workspace
RUN mkdir -p common/src relay/src src-tauri/src && \
    echo "// stub" > common/src/lib.rs && \
    echo "fn main() {}" > relay/src/main.rs && \
    echo "fn main() {}" > src-tauri/src/main.rs && \
    echo "// stub" > src-tauri/src/lib.rs && \
    echo "fn main() -> Result<(), Box<dyn std::error::Error>> { tauri::Builder::default().run(tauri::generate_context!()).expect(\"error\"); Ok(()) }" > src-tauri/src/lib.rs || true

# Pre-build dependencies (cached unless Cargo.toml/lock change)
RUN cargo build --release --package cipherline-relay 2>/dev/null || true

# Copy real source
COPY common/ common/
COPY relay/  relay/

# Touch main.rs so cargo knows it changed
RUN touch relay/src/main.rs common/src/lib.rs

# Final release build
RUN cargo build --release --package cipherline-relay && \
    strip /build/target/release/cipherline-relay

# ---------- Runtime stage ----------
FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates libssl3 && \
    rm -rf /var/lib/apt/lists/*

RUN groupadd -r cipherline && useradd -r -g cipherline cipherline

COPY --from=builder /build/target/release/cipherline-relay /usr/local/bin/cipherline-relay

USER cipherline

# Default relay port
EXPOSE 8080

ENV RUST_LOG=cipherline_relay=info

ENTRYPOINT ["cipherline-relay"]
CMD ["--bind", "0.0.0.0:8080"]
