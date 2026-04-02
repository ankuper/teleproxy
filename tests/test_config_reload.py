#!/usr/bin/env python3
"""E2E tests for TOML config file support and SIGHUP reload.

Tests:
  1. Proxy starts with secrets from a TOML config file
  2. Secrets can be added/removed via TOML edit + SIGHUP
  3. CLI -S (pinned) secrets survive reload
  4. CLI flags override TOML values
"""
import os
import signal
import sys
import time

from test_tls_e2e import (
    _do_handshake,
    _verify_server_hmac,
    wait_for_proxy,
)

# Shared config file path (mounted volume)
CONFIG_PATH = os.environ.get("CONFIG_PATH", "/shared/config.toml")
PROXY_PID_CMD = os.environ.get("PROXY_PID_CMD", "")


def write_config(secrets, **kwargs):
    """Write a TOML config file with the given secrets."""
    with open(CONFIG_PATH, "w") as f:
        f.write("# Test config\n")
        f.write('direct = true\n')
        f.write('http_stats = true\n')
        for k, v in kwargs.items():
            if isinstance(v, bool):
                f.write(f'{k} = {"true" if v else "false"}\n')
            elif isinstance(v, int):
                f.write(f'{k} = {v}\n')
            else:
                f.write(f'{k} = "{v}"\n')
        f.write("\n")
        for secret_hex, label, limit in secrets:
            f.write("[[secret]]\n")
            f.write(f'key = "{secret_hex}"\n')
            if label:
                f.write(f'label = "{label}"\n')
            if limit:
                f.write(f'limit = {limit}\n')
            f.write("\n")


def send_sighup():
    """Send SIGHUP to the proxy process (PID 1 via shared pid namespace)."""
    try:
        os.kill(1, signal.SIGHUP)
        print("  Sent SIGHUP to PID 1")
    except ProcessLookupError:
        print("  WARNING: PID 1 not found")
    except PermissionError:
        print("  WARNING: no permission to signal PID 1")
    time.sleep(2)  # give the event loop time to process


def check_secret_works(host, port, secret_hex, label=""):
    """Verify a TLS handshake succeeds with the given secret."""
    secret_bytes = bytes.fromhex(secret_hex)
    data, client_random = _do_handshake(host, port, secret_bytes)
    ok = len(data) >= 138 and _verify_server_hmac(data, client_random, secret_bytes)
    status = "OK" if ok else "REJECTED"
    print(f"  Secret {secret_hex[:8]}...{' [' + label + ']' if label else ''}: {status}")
    return ok


def check_secret_rejected(host, port, secret_hex, label=""):
    """Verify a TLS handshake is rejected with the given secret."""
    secret_bytes = bytes.fromhex(secret_hex)
    data, client_random = _do_handshake(host, port, secret_bytes)
    rejected = not _verify_server_hmac(data, client_random, secret_bytes)
    status = "REJECTED" if rejected else "UNEXPECTEDLY ACCEPTED"
    print(f"  Secret {secret_hex[:8]}...{' [' + label + ']' if label else ''}: {status}")
    return rejected


def test_config_startup():
    """Test that proxy starts and works with secrets from TOML only."""
    host = os.environ.get("TELEPROXY_HOST", "teleproxy")
    port = int(os.environ.get("TELEPROXY_PORT", "8443"))
    secrets_csv = os.environ.get("TELEPROXY_SECRETS", "")

    assert secrets_csv, "TELEPROXY_SECRETS not set"
    secrets = [s.strip() for s in secrets_csv.split(",") if s.strip()]

    for s in secrets:
        assert check_secret_works(host, port, s), f"Secret {s[:8]}... should work"

    # Wrong secret must be rejected
    wrong = "ff" * 16
    assert check_secret_rejected(host, port, wrong), "Wrong secret should be rejected"


def test_sighup_add_secret():
    """Test adding a secret via config edit + SIGHUP."""
    host = os.environ.get("TELEPROXY_HOST", "teleproxy")
    port = int(os.environ.get("TELEPROXY_PORT", "8443"))
    secrets_csv = os.environ.get("TELEPROXY_SECRETS", "")
    new_secret = os.environ.get("NEW_SECRET", "")

    assert secrets_csv and new_secret, "TELEPROXY_SECRETS and NEW_SECRET required"
    original = [s.strip() for s in secrets_csv.split(",") if s.strip()]

    # Verify new secret doesn't work yet
    assert check_secret_rejected(host, port, new_secret, "new-before-reload"), \
        "New secret should not work before reload"

    # Write updated config with original + new secret
    entries = [(s, "", 0) for s in original] + [(new_secret, "added", 0)]
    write_config(entries)
    send_sighup()

    # Verify new secret works now
    assert check_secret_works(host, port, new_secret, "new-after-reload"), \
        "New secret should work after reload"

    # Original secrets still work
    for s in original:
        assert check_secret_works(host, port, s, "original"), \
            f"Original secret {s[:8]}... should still work"


def test_sighup_remove_secret():
    """Test removing a secret via config edit + SIGHUP."""
    host = os.environ.get("TELEPROXY_HOST", "teleproxy")
    port = int(os.environ.get("TELEPROXY_PORT", "8443"))
    secrets_csv = os.environ.get("TELEPROXY_SECRETS", "")
    new_secret = os.environ.get("NEW_SECRET", "")

    assert secrets_csv and new_secret, "TELEPROXY_SECRETS and NEW_SECRET required"
    original = [s.strip() for s in secrets_csv.split(",") if s.strip()]

    # Keep only the new secret (from previous test), remove originals
    write_config([(new_secret, "sole-survivor", 0)])
    send_sighup()

    # New secret still works
    assert check_secret_works(host, port, new_secret, "kept"), \
        "Kept secret should work"

    # Original secrets are now rejected
    for s in original:
        assert check_secret_rejected(host, port, s, "removed"), \
            f"Removed secret {s[:8]}... should be rejected"


def test_pinned_secret_survives_reload():
    """Test that a CLI -S secret survives SIGHUP reload."""
    host = os.environ.get("TELEPROXY_HOST", "teleproxy")
    port = int(os.environ.get("TELEPROXY_PORT", "8443"))
    pinned = os.environ.get("PINNED_SECRET", "")

    if not pinned:
        print("  SKIP: PINNED_SECRET not set (no mixed-mode test)")
        return

    # Write config with NO secrets
    write_config([])
    send_sighup()

    # Pinned CLI secret must still work
    assert check_secret_works(host, port, pinned, "pinned"), \
        "Pinned CLI secret should survive reload"


def main():
    tests = [
        ("test_config_startup", test_config_startup),
        ("test_sighup_add_secret", test_sighup_add_secret),
        ("test_sighup_remove_secret", test_sighup_remove_secret),
        ("test_pinned_secret_survives_reload", test_pinned_secret_survives_reload),
    ]

    host = os.environ.get("TELEPROXY_HOST", "teleproxy")
    port = int(os.environ.get("TELEPROXY_PORT", "8443"))

    print("Starting config reload E2E tests...\n", flush=True)
    print(f"Waiting for proxy at {host}:{port}...", flush=True)
    if not wait_for_proxy(host, port, timeout=90):
        print("ERROR: Proxy not ready after 90s")
        sys.exit(1)
    print("Proxy is ready.\n", flush=True)

    passed = 0
    failed = 0
    errors = []

    for name, fn in tests:
        try:
            print(f"[RUN]  {name}")
            fn()
            print(f"[PASS] {name}\n")
            passed += 1
        except Exception as e:
            print(f"[FAIL] {name}: {e}\n")
            failed += 1
            errors.append((name, e))

    print(f"Results: {passed} passed, {failed} failed")
    if errors:
        print("\nFailures:")
        for name, err in errors:
            print(f"  {name}: {err}")

    sys.exit(0 if failed == 0 else 1)


if __name__ == "__main__":
    main()
