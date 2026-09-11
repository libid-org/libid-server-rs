# Build stage.
FROM rust:1.97-slim-bookworm AS builder

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        ca-certificates git pkg-config libssl-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build
COPY . .
RUN cargo build --release --locked

# Runtime stage. No CA bundle: the binary's TLS trust anchors are compiled in
# (`webpki_root_certs`), the notary link is plain TCP, and the healthcheck is
# plaintext loopback. curl serves the healthcheck.
FROM debian:bookworm-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        curl \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /build/target/release/libid-server-rs /usr/local/bin/libid-server-rs

# Bind on all interfaces inside the container.
ENV HOST=0.0.0.0 \
    PORT=8722

EXPOSE 8722

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD curl -fsS "http://127.0.0.1:${PORT}/health" || exit 1

ENTRYPOINT ["libid-server-rs"]
