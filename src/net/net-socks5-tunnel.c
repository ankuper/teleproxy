/* net-socks5-tunnel.c — server-side SOCKS5/CONNECT tunnel (Story 9-1).
 *
 * Dogfood implementation for ≤5 users.  One detached thread per tunnel.
 * Each thread:
 *   1. Reads SOCKS5 auth greeting + CONNECT request from the shim via the
 *      existing Type3 WS+AES-CTR channel (relay_fd = dup of c->fd).
 *   2. Opens a TCP connection to the requested target host:port.
 *   3. Sends SOCKS5 success/failure response back through the tunnel.
 *   4. Splices bidirectionally (poll loop) until either side closes.
 *
 * Thread lifecycle: spawn → splice → close relay_fd + target_fd → free.
 * The connection system concurrently closes c->fd (via fail_connection);
 * relay_fd = dup(c->fd) keeps the socket alive until the thread closes it.
 *
 * WS framing:  client→server frames are masked binary (RFC 6455 §5.3).
 *              server→client frames are unmasked binary.
 * AES-CTR:     contexts copied from c->crypto before fail_connection.
 *              EVP_EncryptUpdate used for both directions (CTR mode).
 */

#define _GNU_SOURCE 1
#define _FILE_OFFSET_BITS 64

#include "net/net-socks5-tunnel.h"
#include "net/net-connections.h"
#include "net/net-crypto-aes.h"
#include "common/kprintf.h"

#include <arpa/inet.h>
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <openssl/evp.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

/* ── counters ─────────────────────────────────────────────────────────── */

long long socks5_connect_tunnels_active;
long long socks5_connect_tunnels_total;
long long socks5_connect_tunnels_bytes_up;
long long socks5_connect_tunnels_bytes_down;
long long socks5_connect_tunnels_rejected;  /* D4: refused (cap or guard) */

/* ── relay thread state ───────────────────────────────────────────────── */

struct relay_args {
  int relay_fd;           /* dup'd connection fd; owns WS+AES-CTR channel */
  EVP_CIPHER_CTX *enc;    /* write (encrypt plaintext → shim) */
  EVP_CIPHER_CTX *dec;    /* read  (decrypt ciphertext ← shim) */
};

/* ── I/O helpers ──────────────────────────────────────────────────────── */

static int recv_all (int fd, uint8_t *buf, int len) {
  int got = 0;
  while (got < len) {
    int n = (int)recv (fd, buf + got, (size_t)(len - got), 0);
    if (n < 0 && errno == EINTR) continue;  /* P3: retry on signal */
    if (n <= 0) return -1;
    got += n;
  }
  return got;
}

static int send_all (int fd, const uint8_t *buf, int len) {
  int sent = 0;
  while (sent < len) {
    /* P4: MSG_NOSIGNAL — SIGPIPE on broken pipe would tear down the process. */
    int n = (int)send (fd, buf + sent, (size_t)(len - sent), MSG_NOSIGNAL);
    if (n < 0 && errno == EINTR) continue;  /* P3 */
    if (n <= 0) return -1;
    sent += n;
  }
  return sent;
}

/* ── WS frame helpers ─────────────────────────────────────────────────── */

/* Read one complete WS frame from relay_fd. Handles RFC 6455 control frames
 * inline (PING→PONG, PONG→discard, CLOSE→terminate) so the caller only ever
 * receives a binary data frame's decrypted plaintext. AES-CTR is applied
 * ONLY to binary data — control frames are not encrypted on the wire.
 * Caller must free() the returned buffer. Returns NULL on error/teardown. */
static uint8_t *ws_read_decrypt (int fd, EVP_CIPHER_CTX *dec, int *out_len) {
  for (;;) {
    uint8_t h2[2];
    if (recv_all (fd, h2, 2) < 0) return NULL;
    int fin    = !!(h2[0] & 0x80);
    int op     =   h2[0] & 0x0F;
    int masked = !!(h2[1] & 0x80);
    int plen   =   h2[1] & 0x7F;
    if (plen == 126) {
      uint8_t ext[2];
      if (recv_all (fd, ext, 2) < 0) return NULL;
      plen = ((int)ext[0] << 8) | (int)ext[1];
    } else if (plen == 127) {
      return NULL;  /* 64-bit length not supported (deferred MEDIUM P6) */
    }
    uint8_t mask[4] = {0};
    if (masked && recv_all (fd, mask, 4) < 0) return NULL;
    if (plen < 0 || plen > 1 << 20) return NULL;  /* sanity cap 1 MiB */
    uint8_t *buf = NULL;
    if (plen > 0) {
      buf = malloc ((size_t)plen);
      if (!buf) return NULL;
      if (recv_all (fd, buf, plen) < 0) { free (buf); return NULL; }
      if (masked) {
        for (int i = 0; i < plen; i++) buf[i] ^= mask[i & 3];
      }
    }

    /* P2: dispatch on opcode. Control frames (≥0x8) bypass AES. */
    if (op == 0x9) {                    /* PING — reply unmasked PONG echoing payload */
      uint8_t hdr[4]; int hi = 0;
      hdr[hi++] = 0x8A;                 /* FIN + PONG */
      if (plen < 126) {
        hdr[hi++] = (uint8_t)plen;
      } else {
        hdr[hi++] = 126;
        hdr[hi++] = (uint8_t)(plen >> 8);
        hdr[hi++] = (uint8_t)(plen & 0xFF);
      }
      int r = send_all (fd, hdr, hi);
      if (r >= 0 && plen > 0) r = send_all (fd, buf, plen);
      free (buf);
      if (r < 0) return NULL;
      continue;
    }
    if (op == 0xA) { free (buf); continue; }       /* PONG — discard */
    if (op == 0x8) { free (buf); return NULL; }    /* CLOSE — tear down */
    if (op != 0x2) {                                /* continuation/text/reserved — reject */
      free (buf);
      return NULL;
    }
    /* Binary data frame */
    if (!fin || plen <= 0) { free (buf); return NULL; }
    int olen = plen;
    if (EVP_EncryptUpdate (dec, buf, &olen, buf, plen) != 1) {  /* P5 */
      free (buf);
      return NULL;
    }
    *out_len = plen;
    return buf;
  }
}

/* Encrypt plaintext and send as an unmasked binary WS frame to relay_fd.
 * Returns 0 on success, -1 on error. */
static int ws_write_encrypt (int fd, EVP_CIPHER_CTX *enc, const uint8_t *plain, int len) {
  if (len <= 0 || len > 1 << 20) return -1;
  uint8_t *ct = malloc ((size_t)len);
  if (!ct) return -1;
  int olen = len;
  if (EVP_EncryptUpdate (enc, ct, &olen, plain, len) != 1) {  /* P5 */
    free (ct);
    return -1;
  }

  uint8_t hdr[4]; int hi = 0;
  hdr[hi++] = 0x82;  /* FIN + binary */
  if (len < 126) {
    hdr[hi++] = (uint8_t)len;
  } else {
    hdr[hi++] = 126;
    hdr[hi++] = (uint8_t)(len >> 8);
    hdr[hi++] = (uint8_t)(len & 0xFF);
  }
  int r = 0;
  if (send_all (fd, hdr, hi) < 0 || send_all (fd, ct, len) < 0) r = -1;
  free (ct);
  return r;
}

/* ── SOCKS5 handshake ─────────────────────────────────────────────────── */

/* Perform auth negotiation (NO-AUTH only).  Returns 0 on success. */
static int socks5_auth (int fd, EVP_CIPHER_CTX *enc, EVP_CIPHER_CTX *dec) {
  int len;
  uint8_t *pkt = ws_read_decrypt (fd, dec, &len);
  if (!pkt) return -1;
  int ok = 0;
  if (len >= 3 && pkt[0] == 0x05) {
    int nm = pkt[1];
    if (len >= 2 + nm) {
      for (int i = 0; i < nm; i++) {
        if (pkt[2 + i] == 0x00) { ok = 1; break; }
      }
    }
  }
  free (pkt);
  uint8_t resp[2] = { 0x05, ok ? (uint8_t)0x00 : (uint8_t)0xFF };
  if (ws_write_encrypt (fd, enc, resp, 2) < 0) return -1;
  return ok ? 0 : -1;
}

/* Parse CONNECT request, fill host/port.  Returns 0 on success. */
static int socks5_connect_req (int fd, EVP_CIPHER_CTX *enc, EVP_CIPHER_CTX *dec,
                               char *host, uint16_t *port) {
  int len;
  uint8_t *pkt = ws_read_decrypt (fd, dec, &len);
  if (!pkt) return -1;

  int rc = -1;
  do {
    if (len < 5 || pkt[0] != 0x05) break;
    if (pkt[1] != 0x01) {           /* not CONNECT */
      uint8_t err[10] = { 0x05, 0x07, 0x00, 0x01, 0,0,0,0, 0,0 };
      ws_write_encrypt (fd, enc, err, 10);
      break;
    }
    uint8_t atyp = pkt[3];
    if (atyp == 0x01) {             /* IPv4 */
      if (len < 10) break;
      snprintf (host, 256, "%u.%u.%u.%u", pkt[4], pkt[5], pkt[6], pkt[7]);
      uint16_t p; memcpy (&p, pkt + 8, 2); *port = (uint16_t)ntohs (p);
      rc = 0;
    } else if (atyp == 0x03) {      /* domain */
      int dlen = (int)(uint8_t)pkt[4];
      if (len < 5 + dlen + 2) break;
      memcpy (host, pkt + 5, (size_t)dlen); host[dlen] = '\0';
      uint16_t p; memcpy (&p, pkt + 5 + dlen, 2); *port = (uint16_t)ntohs (p);
      rc = 0;
    } else if (atyp == 0x04) {      /* IPv6 */
      if (len < 22) break;
      struct in6_addr a6; memcpy (&a6, pkt + 4, 16);
      inet_ntop (AF_INET6, &a6, host, 256);
      uint16_t p; memcpy (&p, pkt + 20, 2); *port = (uint16_t)ntohs (p);
      rc = 0;
    } else {
      uint8_t err[10] = { 0x05, 0x08, 0x00, 0x01, 0,0,0,0, 0,0 };
      ws_write_encrypt (fd, enc, err, 10);
    }
  } while (0);

  free (pkt);
  return rc;
}

/* ── target TCP connect ───────────────────────────────────────────────── */

/* D3 SSRF block-list helper. Filter applied AFTER getaddrinfo() on resolved
 * sockaddrs (defeats DNS-rebinding); checks BOTH AF_INET and AF_INET6.
 * Returns 1 to reject, 0 to allow. */
static int v4_blocked (uint32_t ip /* host byte order */) {
  if ((ip >> 24) == 127) return 1;            /* 127/8     loopback        */
  if ((ip >> 24) == 10)  return 1;            /* 10/8      private         */
  if ((ip >> 24) == 0)   return 1;            /* 0/8       "this network"  */
  if ((ip & 0xFFF00000u) == 0xAC100000u) return 1; /* 172.16/12 private */
  if ((ip >> 16) == 0xC0A8) return 1;         /* 192.168/16 private        */
  if ((ip >> 16) == 0xA9FE) return 1;         /* 169.254/16 link-local     */
  if ((ip >> 28) == 0xE)    return 1;         /* 224/4     multicast       */
  return 0;
}

static int sockaddr_blocked (const struct sockaddr *sa) {
  if (sa->sa_family == AF_INET) {
    const struct sockaddr_in *a = (const struct sockaddr_in *)sa;
    return v4_blocked (ntohl (a->sin_addr.s_addr));
  }
  if (sa->sa_family == AF_INET6) {
    const struct sockaddr_in6 *a = (const struct sockaddr_in6 *)sa;
    const uint8_t *b = a->sin6_addr.s6_addr;
    static const uint8_t loopback[16] = {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1};
    static const uint8_t v4mapped[12] = {0,0,0,0,0,0,0,0,0,0,0xFF,0xFF};
    if (memcmp (b, loopback, 16) == 0) return 1;          /* ::1                  */
    if ((b[0] & 0xFE) == 0xFC) return 1;                  /* fc00::/7 ULA         */
    if (b[0] == 0xFE && (b[1] & 0xC0) == 0x80) return 1;  /* fe80::/10 link-local */
    if (b[0] == 0xFF) return 1;                           /* ff00::/8 multicast   */
    if (memcmp (b, v4mapped, 12) == 0) {                  /* ::ffff:0:0/96        */
      uint32_t ip = ((uint32_t)b[12] << 24) | ((uint32_t)b[13] << 16)
                  | ((uint32_t)b[14] <<  8) |  (uint32_t)b[15];
      return v4_blocked (ip);
    }
    return 0;
  }
  return 1;  /* unknown family — block */
}

static int tcp_connect_target (const char *host, uint16_t port) {
  char ps[8]; snprintf (ps, sizeof (ps), "%u", (unsigned)port);
  struct addrinfo hints = { .ai_family = AF_UNSPEC, .ai_socktype = SOCK_STREAM };
  struct addrinfo *res = NULL;
  if (getaddrinfo (host, ps, &hints, &res) != 0 || !res) return -1;

  /* D3: walk all resolver results, skipping any that hit the SSRF block-list.
   * If every result is blocked or fails to connect, return -1. */
  int tfd = -1;
  for (struct addrinfo *p = res; p; p = p->ai_next) {
    if (sockaddr_blocked (p->ai_addr)) {
      vkprintf (1, "socks5_tunnel: SSRF block-list rejected resolved addr (af=%d)\n",
                p->ai_family);
      continue;
    }
    tfd = socket (p->ai_family, p->ai_socktype, p->ai_protocol);
    if (tfd < 0) continue;
    if (connect (tfd, p->ai_addr, p->ai_addrlen) == 0) break;
    close (tfd);
    tfd = -1;
  }
  freeaddrinfo (res);
  return tfd;
}

/* ── bidirectional poll splice ────────────────────────────────────────── */

static void relay_splice (struct relay_args *a, int tfd) {
  struct pollfd pfds[2];
  pfds[0].fd = a->relay_fd; pfds[0].events = POLLIN;
  pfds[1].fd = tfd;          pfds[1].events = POLLIN;

  for (;;) {
    pfds[0].revents = pfds[1].revents = 0;
    int rc = poll (pfds, 2, 120000);
    if (rc < 0 && errno == EINTR) continue;  /* P3: retry on signal */
    if (rc <= 0) break;

    /* shim → target */
    if (pfds[0].revents & POLLIN) {
      int plen;
      uint8_t *plain = ws_read_decrypt (a->relay_fd, a->dec, &plen);
      if (!plain) break;
      int sent = 0;
      while (sent < plen) {
        int n = (int)send (tfd, plain + sent, (size_t)(plen - sent), MSG_NOSIGNAL);  /* P4 */
        if (n < 0 && errno == EINTR) continue;  /* P3 */
        if (n <= 0) { free (plain); goto done; }
        sent += n;
      }
      __sync_fetch_and_add (&socks5_connect_tunnels_bytes_up, plen);
      free (plain);
    }

    /* target → shim */
    if (pfds[1].revents & POLLIN) {
      uint8_t buf[16384];
      int n = (int)recv (tfd, buf, sizeof (buf), 0);
      if (n <= 0) break;
      if (ws_write_encrypt (a->relay_fd, a->enc, buf, n) < 0) break;
      __sync_fetch_and_add (&socks5_connect_tunnels_bytes_down, n);
    }

    if ((pfds[0].revents | pfds[1].revents) & (POLLHUP | POLLERR)) break;
  }
done:;
}

/* ── relay thread entry ───────────────────────────────────────────────── */

static void *relay_thread (void *arg) {
  struct relay_args *a = arg;
  int tfd = -1;
  char host[256] = {0}; uint16_t port = 0;

  /* P4: belt-and-braces with MSG_NOSIGNAL — block SIGPIPE on the relay
   * thread so a partial write to a closed peer can never tear down the
   * process even if a send() site is missed. */
  sigset_t sigp;
  sigemptyset (&sigp);
  sigaddset (&sigp, SIGPIPE);
  pthread_sigmask (SIG_BLOCK, &sigp, NULL);

  if (socks5_auth (a->relay_fd, a->enc, a->dec) < 0) goto done;
  if (socks5_connect_req (a->relay_fd, a->enc, a->dec, host, &port) < 0) goto done;

  vkprintf (1, "socks5_tunnel: CONNECT %s:%u\n", host, (unsigned)port);
  tfd = tcp_connect_target (host, port);

  uint8_t resp[10] = { 0x05, tfd >= 0 ? 0x00 : 0x04, 0x00, 0x01,
                        0,0,0,0, 0,0 };
  if (ws_write_encrypt (a->relay_fd, a->enc, resp, 10) < 0) goto done;
  if (tfd < 0) {
    vkprintf (1, "socks5_tunnel: connect to %s:%u failed\n", host, (unsigned)port);
    goto done;
  }

  relay_splice (a, tfd);

done:
  close (a->relay_fd);
  if (tfd >= 0) close (tfd);
  EVP_CIPHER_CTX_free (a->enc);
  EVP_CIPHER_CTX_free (a->dec);
  free (a);
  __sync_fetch_and_sub (&socks5_connect_tunnels_active, 1);
  return NULL;
}

/* ── public API ───────────────────────────────────────────────────────── */

int socks5_tunnel_start (connection_job_t C) {
  struct connection_info *c = CONN_INFO (C);
  struct aes_crypto *T = (struct aes_crypto *)c->crypto;

  if (c->in.total_bytes != 0) {
    vkprintf (0, "socks5_tunnel: %d byte(s) already in c->in — ordering violation, aborting\n",
              c->in.total_bytes);
    fail_connection (C, -1);
    return 0;
  }

  /* D4: concurrent-tunnel cap. Calls v1 = dogfood ≤5; SOCKS5_TUNNEL_MAX_CONCURRENT=32
   * gives ample headroom while protecting the server against runaway spawn.
   * Counter bump is the oncall signal that something hit the cap. */
  long long active_now = __sync_fetch_and_add (&socks5_connect_tunnels_active, 0);
  if (active_now >= SOCKS5_TUNNEL_MAX_CONCURRENT) {
    __sync_fetch_and_add (&socks5_connect_tunnels_rejected, 1);
    vkprintf (0, "socks5_tunnel: cap %d reached (active=%lld), rejecting connection\n",
              SOCKS5_TUNNEL_MAX_CONCURRENT, active_now);
    fail_connection (C, -1);
    return 0;
  }

  struct relay_args *a = malloc (sizeof (*a));
  if (!a) goto fail_conn;

  a->enc = EVP_CIPHER_CTX_new ();
  a->dec = EVP_CIPHER_CTX_new ();
  a->relay_fd = -1;

  if (!a->enc || !a->dec
      || EVP_CIPHER_CTX_copy (a->enc, T->write_aeskey) != 1
      || EVP_CIPHER_CTX_copy (a->dec, T->read_aeskey)  != 1) {
    vkprintf (0, "socks5_tunnel: EVP_CIPHER_CTX_copy failed\n");
    goto fail_args;
  }

  a->relay_fd = dup (c->fd);
  if (a->relay_fd < 0) {
    vkprintf (0, "socks5_tunnel: dup(c->fd) failed: %s\n", strerror (errno));
    goto fail_args;
  }

  /* P1 BLOCKER: c->fd is non-blocking (event-loop fd); dup() inherits the
   * O_NONBLOCK flag. Our relay thread uses blocking recv/send semantics
   * (recv_all loops until len or EOF); without this clear, the very first
   * partial frame trips EAGAIN → -1 → tunnel collapses. Strip O_NONBLOCK. */
  int fl = fcntl (a->relay_fd, F_GETFL, 0);
  if (fl < 0 || fcntl (a->relay_fd, F_SETFL, fl & ~O_NONBLOCK) < 0) {
    vkprintf (0, "socks5_tunnel: clearing O_NONBLOCK on relay_fd failed: %s\n", strerror (errno));
    goto fail_args;
  }

  pthread_t tid;
  pthread_attr_t attr;
  pthread_attr_init (&attr);
  /* D4: 256 KiB stack (default ~8 MiB × 32-tunnel cap is wasteful). */
  pthread_attr_setstacksize (&attr, 256 * 1024);
  pthread_attr_setdetachstate (&attr, PTHREAD_CREATE_DETACHED);
  int cr = pthread_create (&tid, &attr, relay_thread, a);
  pthread_attr_destroy (&attr);

  if (cr != 0) {
    vkprintf (0, "socks5_tunnel: pthread_create failed: %s\n", strerror (cr));
    close (a->relay_fd);
    goto fail_args;
  }

  __sync_fetch_and_add (&socks5_connect_tunnels_active, 1);
  __sync_fetch_and_add (&socks5_connect_tunnels_total, 1);
  vkprintf (1, "socks5_tunnel: relay thread spawned for fd=%d (relay_fd=%d)\n",
            c->fd, a->relay_fd);
  fail_connection (C, -1);
  return 0;

fail_args:
  if (a) {
    EVP_CIPHER_CTX_free (a->enc);
    EVP_CIPHER_CTX_free (a->dec);
    if (a->relay_fd >= 0) close (a->relay_fd);
    free (a);
  }
fail_conn:
  fail_connection (C, -1);
  return 0;
}
