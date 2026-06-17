# Alpine-based multi-stage build (supports amd64 and arm64)
FROM alpine:3.21 AS builder

# Install build dependencies
# linux-headers: provides <linux/futex.h> used by mp-queue.c and jobs.c
# DEBUG_TOOLS=1: adds libunwind for stack traces in crash dumps (test/CI only)
ARG DEBUG_TOOLS=0
RUN apk add --no-cache build-base openssl-dev zlib-dev linux-headers git cmake curl \
    $([ "$DEBUG_TOOLS" = "1" ] && echo "libunwind-dev")

# Set working directory
WORKDIR /src

# Download libteleproto3 from its GitHub Release (ankuper/teleproto3).
# Pinned for reproducibility; the v0.6.0+ archive layout is lib/{include,libteleproto3.a}.
ARG T3_LIB_VERSION=v0.6.0
RUN ARCH=$(uname -m) && \
    curl -fsSL "https://github.com/ankuper/teleproto3/releases/download/${T3_LIB_VERSION}/libteleproto3-linux-${ARCH}.tar.gz" \
      -o /tmp/libteleproto3.tar.gz && \
    mkdir -p teleproto3 && \
    tar xzf /tmp/libteleproto3.tar.gz -C teleproto3 && \
    rm /tmp/libteleproto3.tar.gz

# Copy source code
COPY . .

# Build the application (links against libteleproto3 via T3_LIB_DIR)
ARG VERSION=unknown
ARG EXTRA_CFLAGS=
ARG EXTRA_LDFLAGS=
ARG T3_SERVER_SOCKS5_CONNECT=0
RUN make clean && make -j$(nproc) \
    EXTRA_VERSION="${VERSION}" \
    EXTRA_CFLAGS="${EXTRA_CFLAGS}" \
    EXTRA_LDFLAGS="${EXTRA_LDFLAGS}" \
    T3_SERVER_SOCKS5_CONNECT="${T3_SERVER_SOCKS5_CONNECT}" \
    T3_LIB_DIR=teleproto3/lib

# Runtime image
FROM alpine:3.21

# OCI labels — ghcr.io reads these for the package page
LABEL org.opencontainers.image.source="https://github.com/teleproxy/teleproxy"
LABEL org.opencontainers.image.description="High-performance MTProto proxy for Telegram with DPI resistance and fake-TLS camouflage"
LABEL org.opencontainers.image.licenses="GPL-2.0-only"
LABEL org.opencontainers.image.url="https://teleproxy.github.io"
LABEL org.opencontainers.image.documentation="https://teleproxy.github.io"
LABEL org.opencontainers.image.vendor="teleproxy"

# Install runtime dependencies
# curl: config downloads + health check
# openssl: runtime libs (libssl3/libcrypto3) + CLI for secret generation
# zlib: required by teleproxy (-lz)
# iproute2: ip command for local IP detection in NAT setup
# ca-certificates: TLS certificate verification
ARG DEBUG_TOOLS=0
RUN apk add --no-cache curl ca-certificates openssl zlib iproute2 \
    $([ "$DEBUG_TOOLS" = "1" ] && echo "libunwind")

# Create user for running the proxy
RUN adduser -D -H -s /sbin/nologin teleproxy

# Create directory for the application
WORKDIR /opt/teleproxy

# Copy binary from builder stage
COPY --from=builder /src/objs/bin/teleproxy /opt/teleproxy/

# Make binary executable
RUN chmod +x /opt/teleproxy/teleproxy \
    && ln -s teleproxy /opt/teleproxy/mtproto-proxy

# proxy-secret is a static public 128-byte blob used for MTProto key exchange.
# Baking it at build time eliminates the most critical runtime network dependency.
RUN curl --connect-timeout 10 --max-time 30 --retry 3 --retry-delay 2 \
    -fsSL https://core.telegram.org/getProxySecret -o /opt/teleproxy/proxy-secret

# Create data directory for persistent config (proxy-multi.conf)
RUN mkdir -p /opt/teleproxy/data

# Install cron job to refresh proxy-multi.conf from Telegram servers every 6 hours.
# Prevents proxy from becoming unavailable due to stale DC configuration.
# Output is redirected to PID 1's stdout so it appears in `docker logs`.
# busybox crond reads /etc/crontabs/<user> (no user field in entry, unlike Ubuntu cron.d)
COPY teleproxy-config-refresh.sh /opt/teleproxy/config-refresh.sh
RUN chmod +x /opt/teleproxy/config-refresh.sh \
    && echo '0 */6 * * * /opt/teleproxy/config-refresh.sh >> /proc/1/fd/1 2>> /proc/1/fd/2' >> /etc/crontabs/root

# Expose ports
EXPOSE 443 8888

# Add startup script (POSIX sh — no bash dependency)
COPY start.sh /opt/teleproxy/start.sh
RUN chmod +x /opt/teleproxy/start.sh

HEALTHCHECK --interval=30s --timeout=10s --retries=3 --start-period=60s \
    CMD curl -f http://localhost:${STATS_PORT:-8888}/stats || exit 1

# Set entrypoint
ENTRYPOINT ["/opt/teleproxy/start.sh"]
