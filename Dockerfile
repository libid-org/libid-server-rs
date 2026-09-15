# Build stage.
FROM rust:1.97-slim-bookworm AS builder

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build
COPY . .
RUN cargo build --release --locked

# Runtime stage. No CA bundle: the trust anchors for retrieving the callback
# artifact are compiled in (`webpki-root-certs`), and the healthcheck is
# plaintext loopback. curl serves the healthcheck.
FROM debian:bookworm-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        curl \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /build/target/release/libid-server-rs /usr/local/bin/libid-server-rs

# Where the process listens inside the container. The mounted configuration
# file carries no bind address: HOST and PORT are the only way to set one.
ENV HOST=0.0.0.0 \
    PORT=8722

EXPOSE 8722

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD curl -fsS "http://127.0.0.1:${PORT}/health" || exit 1

ENTRYPOINT ["libid-server-rs"]
