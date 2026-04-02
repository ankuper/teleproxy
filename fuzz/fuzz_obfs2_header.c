/* Fuzz harness for obfs2_parse_header().
   Tests: key derivation, AES-CTR decryption, tag validation, DC extraction.
   Input: 64-byte header + optional 16-byte secret appended. */

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "net/net-obfs2-parse.h"

int LLVMFuzzerTestOneInput (const uint8_t *data, size_t size) {
  if (size < 64 || size > 64 + 16) {
    return 0;
  }

  unsigned char header[64];
  memcpy (header, data, 64);

  struct obfs2_parse_result result;
  memset (&result, 0, sizeof (result));

  if (size >= 64 + 16) {
    /* Fuzz with a secret */
    unsigned char secret[1][16];
    memcpy (secret[0], data + 64, 16);
    obfs2_parse_header (header, secret, 1, 0, &result);

    /* Also test rand_pad_only mode */
    memcpy (header, data, 64);
    obfs2_parse_header (header, secret, 1, 1, &result);
  } else {
    /* Fuzz without secrets */
    obfs2_parse_header (header, NULL, 0, 0, &result);
  }

  return 0;
}
