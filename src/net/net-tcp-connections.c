/*
    This file is part of Mtproto-proxy Library.

    Mtproto-proxy Library is free software: you can redistribute it and/or modify
    it under the terms of the GNU Lesser General Public License as published by
    the Free Software Foundation, either version 2 of the License, or
    (at your option) any later version.

    Mtproto-proxy Library is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU Lesser General Public License for more details.

    You should have received a copy of the GNU Lesser General Public License
    along with Mtproto-proxy Library.  If not, see <http://www.gnu.org/licenses/>.

    Copyright 2009-2013 Vkontakte Ltd
              2008-2013 Nikolai Durov
              2008-2013 Andrey Lopatin
                   2013 Vitaliy Valtman
    
    Copyright 2014-2016 Telegram Messenger Inc                 
              2015-2016 Vitaly Valtman     
*/

#include <errno.h>
#include <sys/uio.h>
#include <stdlib.h>
#include <assert.h>
#include <stdio.h>
#include <unistd.h>
#include <openssl/rand.h>

#include "net/net-connections.h"
#include "net/net-msg.h"
#include "net/net-msg-buffers.h"
#include "crypto/aesni256.h"
#include "net/net-crypto-aes.h"
#include "net/net-websocket.h"
#include "kprintf.h"

extern double server_padding_probability;
extern int server_ws_max_frame_size;


int cpu_tcp_free_connection_buffers (connection_job_t C) /* {{{ */ {
  struct connection_info *c = CONN_INFO (C);
  assert_net_cpu_thread ();
  rwm_free (&c->in);
  rwm_free (&c->in_u);
  rwm_free (&c->out);
  rwm_free (&c->out_p);
  return 0;
}
/* }}} */


int cpu_tcp_server_writer (connection_job_t C) /* {{{ */ {
  assert_net_cpu_thread ();

  struct connection_info *c = CONN_INFO (C);
  
  int stop = 0;
  if (c->status == conn_write_close) {
    stop = 1;
  }
  
  while (1) {
    struct raw_message *raw = mpq_pop_nw (c->out_queue, 4);
    if (!raw) { break; }
    //rwm_union (out, raw);
    c->type->write_packet (C, raw);
    free (raw);
  }
  
  c->type->flush (C);

  struct raw_message *raw = malloc (sizeof (*raw));

  if (c->type->crypto_encrypt_output && c->crypto) {
    if (c->type->crypto_encrypt_output (C) < 0) {
      free (raw);
      return -1;
    }
    *raw = c->out_p;
    rwm_init (&c->out_p, 0);
  } else {
    *raw = c->out;
    rwm_init (&c->out, 0);
  }
 
  if (raw->total_bytes && c->io_conn) {        
    mpq_push_w (SOCKET_CONN_INFO(c->io_conn)->out_packet_queue, raw, 0);
    if (stop) {
      __sync_fetch_and_or (&SOCKET_CONN_INFO(c->io_conn)->flags, C_STOPWRITE);
    }
    job_signal (JOB_REF_CREATE_PASS (c->io_conn), JS_RUN);
  } else {
    rwm_free (raw);
    free (raw);
  }

  return 0;
}
/* }}} */

int cpu_tcp_server_reader (connection_job_t C) /* {{{ */ {
  assert_net_cpu_thread ();
  struct connection_info *c = CONN_INFO(C);

  while (1) {
    struct raw_message *raw = mpq_pop_nw (c->in_queue, 4);
    if (!raw) { break; }

    if (c->crypto) {
      rwm_union (&c->in_u, raw);
    } else {
      rwm_union (&c->in, raw);
    }
    free (raw);
  }
        
  if (c->crypto) {
    if (c->type->crypto_decrypt_input (C) < 0) {
      return -1;
    }
  }

  int r = c->in.total_bytes;
        
  int s = c->skip_bytes;

  if (c->type->data_received) {
    c->type->data_received (C, r);
  }

  if (c->flags & (C_FAILED | C_ERROR | C_NET_FAILED)) {
    return -1;
  }
  if (c->flags & C_STOPREAD) {
    return 0;
  }

  int r1 = r;

  if (s < 0) {
    // have to skip s more bytes
    if (r1 > -s) {
      r1 = -s;
    }
    rwm_skip_data (&c->in, r1);
    c->skip_bytes = s += r1;

    vkprintf (2, "skipped %d bytes, %d more to skip\n", r1, -s);
      
    if (s) {
      return 0;
    }
  }

  if (s > 0) {
    // need to read s more bytes before invoking parse_execute()
    if (r1 >= s) {
      c->skip_bytes = s = 0;
    }

    vkprintf (1, "fetched %d bytes, %d available bytes, %d more to load\n", r, r1, s ? s - r1 : 0);
    if (s) {
      return 0;
    }
  }


  while (!c->skip_bytes && !(c->flags & (C_ERROR | C_FAILED | C_NET_FAILED | C_STOPREAD)) && c->status != conn_error) {
    int bytes = c->in.total_bytes;
    if (!bytes) {
      break;
    }

    int res = c->type->parse_execute (C);
    
    // 0 - ok/done, >0 - need that much bytes, <0 - skip bytes, or NEED_MORE_BYTES
    if (!res) {
    } else if (res != NEED_MORE_BYTES) {
      bytes = (c->crypto ? c->in.total_bytes : c->in_u.total_bytes);
      // have to load or skip abs(res) bytes before invoking parse_execute
      if (res < 0) {
        res -= bytes;
      } else {
        res += bytes;
      }
      c->skip_bytes = res;
      break;
    } else {
      break;
    }
  }

  return 0;
}
/* }}} */

int cpu_tcp_aes_crypto_encrypt_output (connection_job_t C) /* {{{ */ {
  assert_net_cpu_thread ();
  struct connection_info *c = CONN_INFO (C);

  struct aes_crypto *T = c->crypto;
  assert (c->crypto);
  struct raw_message *out = &c->out;

  int l = out->total_bytes;
  l &= ~15;
  if (l) {
    if (rwm_encrypt_decrypt_to (&c->out, &c->out_p, l, T->write_aeskey, 16) != l) {
      fail_connection (C, -1);
      return -1;
    }
  }

  return (-out->total_bytes) & 15;
}
/* }}} */

int cpu_tcp_aes_crypto_decrypt_input (connection_job_t C) /* {{{ */ {
  assert_net_cpu_thread ();
  struct connection_info *c = CONN_INFO (C);
  struct aes_crypto *T = c->crypto;
  assert (c->crypto);
  struct raw_message *in = &c->in_u;

  int l = in->total_bytes;
  l &= ~15;
  if (l) {
    if (rwm_encrypt_decrypt_to (&c->in_u, &c->in, l, T->read_aeskey, 16) != l) {
      fail_connection (C, -1);
      return -1;
    }
  }

  return (-in->total_bytes) & 15;
}
/* }}} */

int cpu_tcp_aes_crypto_needed_output_bytes (connection_job_t C) /* {{{ */ {
  struct connection_info *c = CONN_INFO (C);
  assert (c->crypto);
  return -c->out.total_bytes & 15;
}
/* }}} */

int cpu_tcp_aes_crypto_ctr128_encrypt_output (connection_job_t C) /* {{{ */ {
  assert_net_cpu_thread ();
  struct connection_info *c = CONN_INFO (C);

  struct aes_crypto *T = c->crypto;
  assert (c->crypto);

  if (c->ws_state == WS_STATE_ACTIVE && (c->ws_flags & T3_FLAG_PADDING)) {
    int remaining = c->out.total_bytes;
    if (remaining > 0) {
      int n_frags = 2 + (lrand48() % 4); // 2–5 fragments
      while (remaining > 0 && n_frags > 0) {
        int frag_size;
        if (n_frags == 1) {
          frag_size = remaining;
        } else {
          int min_frag = remaining / (n_frags * 2);
          if (min_frag < 1) min_frag = 1;
          int max_frag = remaining - (n_frags - 1);
          if (max_frag < min_frag) max_frag = min_frag;
          frag_size = min_frag + (lrand48() % (max_frag - min_frag + 1));
        }
        ws_write_frame_header (&c->out_p, frag_size);
        vkprintf (2, "WS_OUTPUT_SPLIT: sending split fragment len=%d (remaining=%d, n_frags=%d)\n", frag_size, remaining - frag_size, n_frags - 1);
        if (rwm_encrypt_decrypt_to (&c->out, &c->out_p, frag_size, T->write_aeskey, 1) != frag_size) {
          fail_connection (C, -1);
          return -1;
        }
        remaining -= frag_size;
        n_frags--;
      }

      // Inject padding frame with probability P
      double p = server_padding_probability;
      if (p > 0.0 && drand48() < p) {
        int pad_len = 32 + (lrand48() % 257); // [32, 288]
        unsigned char pad_buf[288];
        pad_buf[0] = T3_PADDING_MARKER; // 0xFE
        if (RAND_bytes (pad_buf + 1, pad_len - 1) != 1) {
          /* CSPRNG failure: skip padding this frame rather than sending stack garbage */
          vkprintf (1, "WS_PADDING: RAND_bytes failed, skipping padding frame\n");
        } else {
          struct raw_message pad_msg;
          rwm_create (&pad_msg, pad_buf, pad_len);
          ws_write_frame_header (&c->out_p, pad_len);
          vkprintf (2, "WS_PADDING: injecting %d-byte padding frame\n", pad_len);
          if (rwm_encrypt_decrypt_to (&pad_msg, &c->out_p, pad_len, T->write_aeskey, 1) != pad_len) {
            rwm_free (&pad_msg);
            fail_connection (C, -1);
            return -1;
          }
          rwm_free (&pad_msg);
        }
      }
    }
  } else {
    while (c->out.total_bytes) {
      int len = c->out.total_bytes;
      if (c->ws_state == WS_STATE_ACTIVE) {
        // Type3 WS transport: wrap outgoing (server→client) payloads in
        // unmasked RFC 6455 binary frames. Randomize size between 4 KiB
        // and ws_max_frame_size for DPI resistance (fixed frame sizes
        // are a fingerprint).
        const int WS_MIN_FRAME = 4096;
        int ws_max = server_ws_max_frame_size;
        if (ws_max < WS_MIN_FRAME) ws_max = WS_MIN_FRAME;
        int ws_frame = WS_MIN_FRAME + (lrand48 () % (ws_max - WS_MIN_FRAME + 1));
        if (len > ws_frame) {
          len = ws_frame;
        }
        ws_write_frame_header (&c->out_p, len);
        vkprintf (2, "WS_OUTPUT: send binary frame len=%d\n", len);
      } else if (c->flags & C_IS_TLS) {
        assert (c->left_tls_packet_length >= 0);
        const int MAX_PACKET_LENGTH = 1425;
        if (MAX_PACKET_LENGTH < len) {
          len = MAX_PACKET_LENGTH;
        }

        unsigned char header[5] = {0x17, 0x03, 0x03, len >> 8, len & 255};
        rwm_push_data (&c->out_p, header, 5);
        vkprintf (2, "Send TLS-packet of length %d\n", len);
      }

      if (rwm_encrypt_decrypt_to (&c->out, &c->out_p, len, T->write_aeskey, 1) != len) {
        fail_connection (C, -1);
        return -1;
      }
    }
  }

  return 0;
}
/* }}} */

int cpu_tcp_aes_crypto_ctr128_decrypt_input (connection_job_t C) /* {{{ */ {
  assert_net_cpu_thread ();
  struct connection_info *c = CONN_INFO (C);
  struct aes_crypto *T = c->crypto;
  assert (c->crypto);

  while (c->in_u.total_bytes) {
    int len = c->in_u.total_bytes;
    if (c->ws_state == WS_STATE_ACTIVE) {
      // Type3 WS transport: unwrap incoming (client→server, masked) frames.
      // Each frame is: [2..14 byte header] [masked payload]. Parse header
      // once per frame, then unmask and pass payload through the AES-CTR
      // decryptor in fixed-size chunks of up to 16 KiB (stack buffer).
      if (c->ws_frame_remaining == 0) {
        int payload_len = ws_parse_frame_header (c, &c->in_u);
        if (payload_len < 0) {
          vkprintf (1, "WS frame parse error\n");
          fail_connection (C, -1);
          return 0;
        }
        if (payload_len == 0) {
          return 0; // need more data to parse the next frame header
        }
        len = c->in_u.total_bytes;
      }

      if (c->ws_frame_remaining < len) {
        len = c->ws_frame_remaining;
      }
      c->ws_frame_remaining -= len;

      if (len > 0) {
        unsigned char stack_buf[16384];
        unsigned char *tmp = (len <= (int)sizeof(stack_buf)) ? stack_buf : malloc (len);
        assert (rwm_fetch_data (&c->in_u, tmp, len) == len);
        ws_unmask_data (c, tmp, len);
        struct raw_message tmp_msg;
        rwm_create (&tmp_msg, tmp, len);

        struct raw_message dec_msg;
        rwm_init (&dec_msg, 0);

        int r = rwm_encrypt_decrypt_to (&tmp_msg, &dec_msg, len, T->read_aeskey, 1);
        rwm_free (&tmp_msg);
        if (tmp != stack_buf) free (tmp);
        if (r != len) {
          rwm_free (&dec_msg);
          fail_connection (C, -1);
          return -1;
        }

        int is_padding = 0;
        if (c->ws_flags & T3_FLAG_PADDING) {
          unsigned char first_byte;
          if (rwm_fetch_lookup (&dec_msg, &first_byte, 1) == 1 && first_byte == T3_PADDING_MARKER) {
            is_padding = 1;
          }
        }

        if (is_padding) {
          vkprintf (2, "WS_PADDING: dropped %d-byte padding frame\n", len);
          rwm_free (&dec_msg);
        } else {
          rwm_union (&c->in, &dec_msg);
        }
        vkprintf (2, "WS_INPUT: decrypted %d bytes, %d remaining in frame\n", len, c->ws_frame_remaining);
      }
      continue;
    } else if (c->flags & C_IS_TLS) {
      assert (c->left_tls_packet_length >= 0);
      if (c->left_tls_packet_length == 0) {
        if (len < 5) {
          vkprintf (2, "Need %d more bytes to parse TLS header\n", 5 - len);
          return 5 - len;
        }

        unsigned char header[5];
        assert (rwm_fetch_lookup (&c->in_u, header, 5) == 5);
        if (memcmp (header, "\x17\x03\x03", 3) != 0) {
          vkprintf (1, "error while parsing packet: expect TLS header\n");
          fail_connection (C, -1);
          return 0;
        }
        c->left_tls_packet_length = 256 * header[3] + header[4];
        vkprintf (2, "Receive TLS-packet of length %d\n", c->left_tls_packet_length);
        assert (rwm_skip_data (&c->in_u, 5) == 5);
        len -= 5;
      }

      if (c->left_tls_packet_length < len) {
        len = c->left_tls_packet_length;
      }
      c->left_tls_packet_length -= len;
    }
    vkprintf (2, "Read %d bytes out of %d available\n", len, c->in_u.total_bytes);
    if (rwm_encrypt_decrypt_to (&c->in_u, &c->in, len, T->read_aeskey, 1) != len) {
      fail_connection (C, -1);
      return -1;
    }
  }

  return 0;
}
/* }}} */

int cpu_tcp_aes_crypto_ctr128_needed_output_bytes (connection_job_t C) /* {{{ */ {
  struct connection_info *c = CONN_INFO (C);
  assert (c->crypto);
  return 0;
}
/* }}} */
