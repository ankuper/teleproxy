# Installation

## One-Liner Install (Recommended)

The install script downloads the binary, creates a systemd service, generates a secret, and prints the connection link:

```bash
curl -sSL https://raw.githubusercontent.com/teleproxy/teleproxy/main/install.sh | sh
```

Customize with environment variables:

```bash
PORT=8443 EE_DOMAIN=www.google.com curl -sSL https://raw.githubusercontent.com/teleproxy/teleproxy/main/install.sh | sh
```

After installation, manage with:

```bash
systemctl status teleproxy       # check status
systemctl reload teleproxy       # reload config after editing
nano /etc/teleproxy/config.toml  # edit config (secrets, ports, etc.)
```

To uninstall:

```bash
curl -sSL https://raw.githubusercontent.com/teleproxy/teleproxy/main/install.sh | sh -s -- --uninstall
```

## Static Binary (Any Linux)

Pre-built static binaries are published with every release — statically linked against musl libc, zero runtime dependencies. Download and run.

=== "amd64"

    ```bash
    curl -Lo teleproxy https://github.com/teleproxy/teleproxy/releases/latest/download/teleproxy-linux-amd64
    chmod +x teleproxy
    ```

=== "arm64"

    ```bash
    curl -Lo teleproxy https://github.com/teleproxy/teleproxy/releases/latest/download/teleproxy-linux-arm64
    chmod +x teleproxy
    ```

SHA256 checksums are published alongside each release for verification.

## Docker

See [Docker Quick Start](../docker/index.md) for the simplest way to run Teleproxy — a single `docker run` command with auto-generated secrets.

## Building from Source

Install build dependencies:

=== "Debian / Ubuntu"

    ```bash
    apt install git curl build-essential libssl-dev zlib1g-dev
    ```

=== "CentOS / RHEL"

    ```bash
    yum groupinstall "Development Tools"
    yum install openssl-devel zlib-devel
    ```

=== "macOS (development)"

    ```bash
    brew install epoll-shim openssl
    ```

    macOS builds use [epoll-shim](https://github.com/jiixyj/epoll-shim) to wrap kqueue behind the Linux epoll API, and Homebrew OpenSSL (keg-only). This is intended for local development — production deployments should use Linux.

Clone and build:

```bash
git clone https://github.com/teleproxy/teleproxy
cd teleproxy
make
```

The compiled binary will be at `objs/bin/teleproxy`.

!!! note
    If the build fails, run `make clean` before retrying.
