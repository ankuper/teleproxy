/* net-socks5-tunnel.h — server-side SOCKS5/CONNECT tunnel (Story 9-1).
 *
 * Build-flag-gated: compiled only when T3_SERVER_SOCKS5_CONNECT=1.
 * When a Type3 WS connection presents DC sentinel 0x5353 in the obfs2
 * random header, the connection is handed off to socks5_tunnel_start()
 * instead of direct_connect_to_dc().
 *
 * The tunnel runs in a detached POSIX thread per connection, performing
 * the SOCKS5/CONNECT handshake and splicing bidirectionally between the
 * shim and the upstream TCP target.
 *
 * Dogfood-only (≤5 users, Story 9-1 AC #4).
 */
#pragma once

#include "net/net-connections.h"

/* DC field sentinel in the obfs2 random header that signals SOCKS5 mode.
 * Chosen outside the valid Telegram DC range (1–5 / ±1–20). The shim
 * patches random_header[60:62] to decrypt to this value on the server. */
#define SOCKS5_TUNNEL_DC_SENTINEL  0x5353  /* 21331 decimal */

/* Guard against future DC-range expansion silently colliding with the
 * sentinel — pinned at a single site per D1-amend (Winston). */
_Static_assert (
    SOCKS5_TUNNEL_DC_SENTINEL >  5 || SOCKS5_TUNNEL_DC_SENTINEL < -5,
    "SOCKS5_TUNNEL_DC_SENTINEL must lie outside the valid Telegram DC range (-5..-1, 1..5)");

/* Hard cap on concurrent server-side tunnels (D4). Calls v1 is dogfood
 * scope ≤5 users; the cap protects the server against accidental
 * thread-count blow-out and gives an oncall signal via the rejected
 * counter when something is misbehaving. */
#define SOCKS5_TUNNEL_MAX_CONCURRENT 32

/* Counters — exported for stats aggregation */
extern long long socks5_connect_tunnels_active;
extern long long socks5_connect_tunnels_total;
extern long long socks5_connect_tunnels_bytes_up;
extern long long socks5_connect_tunnels_bytes_down;
extern long long socks5_connect_tunnels_rejected;  /* D4: tunnels refused (cap or other guard) */

/* Called from tcp_rpcs_compact_parse_execute when DC sentinel is detected.
 * Spawns a detached relay thread, then calls fail_connection() to release
 * the connection object.  Returns 0. */
int socks5_tunnel_start (connection_job_t C);
