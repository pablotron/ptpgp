#include "internal.h"

static char *lut = "0123456789abcdef";

ptpgp_err_t ptpgp_to_hex(u8 *src, size_t src_len, u8 *dst, size_t dst_len) {
  size_t i;

  /* check output buffer */
  if (src_len * 2 > dst_len)
    return PTPGP_ERR_HEX_DEST_BUF_TOO_SMALL;

  /* convert buffer */
  for (i = 0; i < src_len; i++) {
    dst[i * 2] = lut[src[i] >> 4];
    dst[i * 2 + 1] = lut[src[i] & 15];
  }

  /* return success */
  return PTPGP_OK;
}
