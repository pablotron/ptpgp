#include "internal.h"

#define CRC24_INIT 0xB704CEL
#define CRC24_POLY 0x1864CFBL

ptpgp_err_t
ptpgp_crc24_init(ptpgp_crc24_t *r) {
  memset(r, 0, sizeof(ptpgp_crc24_t));
  r->crc = CRC24_INIT;
  return PTPGP_OK;
}

ptpgp_err_t
ptpgp_crc24_push(ptpgp_crc24_t *r, u8 *src, size_t src_len) {
  size_t i;

  if (r->last_err)
    return r->last_err;

  if (r->done)
    return r->last_err = PTPGP_ERR_CRC24_ALREADY_DONE;

  if (!src || !src_len) {
    r->done = 1;
    return PTPGP_OK;
  }

  while (src_len--) {
    r->crc ^= (*src++) << 16;

    for (i = 0; i < 8; i++) {
      r->crc <<= 1;
      if (r->crc & 0x1000000)
        r->crc ^= CRC24_POLY;
    }
  }

  /* mask out high bits */
  r->crc &= 0xFFFFFFL;

  /* return success */
  return PTPGP_OK;
}

ptpgp_err_t
ptpgp_crc24_done(ptpgp_crc24_t *r) {
  return ptpgp_crc24_push(r, 0, 0);
}
