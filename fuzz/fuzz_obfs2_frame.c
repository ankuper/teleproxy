/* Fuzz harness for obfs2_parse_frame_length().
   Tests: medium/compact length parsing, QUICKACK handling, alignment checks.
   Input: 4 bytes (raw stream head) + 1 byte (flags selector). */

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "net/net-obfs2-parse.h"
#include "net/net-tcp-rpc-common.h"

int LLVMFuzzerTestOneInput (const uint8_t *data, size_t size) {
  if (size < 4) {
    return 0;
  }

  int raw4;
  memcpy (&raw4, data, 4);

  struct obfs2_frame_result result;

  /* Test all flag combinations */
  int flag_combos[] = {
    RPC_F_MEDIUM,
    RPC_F_MEDIUM | RPC_F_PAD,
    0,          /* compact mode */
    RPC_F_PAD,  /* compact + pad */
  };

  for (int i = 0; i < 4; i++) {
    memset (&result, 0, sizeof (result));
    obfs2_parse_frame_length (raw4, flag_combos[i], 0, &result);
    obfs2_parse_frame_length (raw4, flag_combos[i], 1 << 20, &result);
  }

  return 0;
}
