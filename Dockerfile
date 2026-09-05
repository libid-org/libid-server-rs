# Build stage. git + ca-certificates are needed because the libid-rs and
# tlsn dependencies are git dependencies; pkg-config/libssl-dev cover any
# transitive native-TLS probe (the binary itself uses rustls).
FROM rust:1.97-slim-bookworm AS builder

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        ca-certificates git pkg-config libssl-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build
COPY . .
RUN cargo build --release --locked

# Runtime stage: slim Debian + curl for the container healthcheck below.
#
# No CA bundle. The binary's only outbound TLS is the MPC-TLS session to
# github.com, and its trust anchors are compiled in — libid-tlsn builds its
# root store from `webpki_root_certs`, never from /etc/ssl. The notary link is
# raw TCP and the healthcheck is plaintext loopback, so nothing in the image
# reads a system root; shipping one would only widen what a compromised
# process could trust.
#
# libssl3 is no longer installed explicitly, because the binary links neither
# it nor any other OpenSSL (`ldd` shows libgcc, libm and libc, and there is no
# openssl-sys in the dependency graph). It is still IN the image: curl pulls it
# in for the healthcheck. Dropping it would mean dropping curl.
FROM debian:bookworm-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        curl \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /build/target/release/libid-server-rs /usr/local/bin/libid-server-rs

# Bind on all interfaces inside the container; everything else comes from
# the environment (see README for the full table).
ENV HOST=0.0.0.0 \
    PORT=8722

EXPOSE 8722

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD curl -fsS "http://127.0.0.1:${PORT}/health" || exit 1

ENTRYPOINT ["libid-server-rs"]
