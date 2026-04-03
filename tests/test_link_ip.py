#!/usr/bin/env python3
"""Test that /link substitutes Docker-internal and loopback IPs with the external IP."""
import os
import re
import socket
import sys

import requests

host = os.environ.get("TELEPROXY_HOST", "teleproxy")
stats_port = os.environ.get("TELEPROXY_STATS_PORT", "8888")
expected_ip = os.environ.get("EXPECTED_IP", "198.51.100.1")

passed = 0
failed = 0


def check(name, condition, detail=""):
    global passed, failed
    if condition:
        passed += 1
        print(f"  PASS  {name}")
    else:
        failed += 1
        msg = f"  FAIL  {name}"
        if detail:
            msg += f"\n        {detail}"
        print(msg)


print("=== /link endpoint IP substitution tests ===")

# Resolve the container's Docker-internal IP (172.x.x.x)
container_ip = socket.gethostbyname(host)
print(f"Container IP: {container_ip}")

# Access via Docker-internal IP — should be substituted by nat_translate_ip
resp = requests.get(
    f"http://{container_ip}:{stats_port}/link",
    headers={"Host": f"{container_ip}:{stats_port}"},
    timeout=5,
)
check("/link returns 200", resp.status_code == 200, f"got {resp.status_code}")

html = resp.text
check("container IP substituted with external IP",
      f"server={expected_ip}" in html,
      f"expected server={expected_ip}, got HTML snippet: "
      + re.search(r"server=[^&]+", html).group(0) if re.search(r"server=[^&]+", html) else "no server= found")

internal_ips = re.findall(r"server=(172\.\d+\.\d+\.\d+)", html)
check("no Docker-internal IPs in URLs",
      len(internal_ips) == 0,
      f"found internal IPs: {internal_ips}")

# Access via hostname — should pass through unchanged (hostname is not loopback/NAT)
resp2 = requests.get(f"http://{host}:{stats_port}/link", timeout=5)
html2 = resp2.text
check("hostname access passes through",
      f"server={host}" in html2,
      f"expected server={host} in HTML")

print(f"\n{'=' * 40}")
print(f"Results: {passed} passed, {failed} failed")

if failed > 0:
    sys.exit(1)
print("All tests passed!")
