#include "internal.h"

/* 
 * typedef union {
 *   uint32_t i;
 *   char     c[4];
 * } packed;
 * 
 * static packed crc24_init = {
 *   .c = {0x00, 0xB7, 0x04, 0xCE}
 * };
 * 
 * static packed crc24_poly = {
 *   .c = {0x01, 0x86, 0x4C, 0xFB}
 * };
 */ 

#if 0 /* mine */
#define CRC24_INIT 0xCE04B700L
#define CRC24_POLY 0xFB4C8601L
#endif /* 0 */

#define CRC24_INIT 0x00B704CEL
#define CRC24_POLY 0x01864CFBL

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

    /* mask out high bits */
    r->crc &= 0x00FFFFFFL;

    return PTPGP_OK;
  }

  while (src_len--) {
    r->crc ^= (*(src++)) << 16;

    for (i = 0; i < 8; i++) {
      r->crc <<= 1;
      if (r->crc & 0x01000000L)
        r->crc ^= CRC24_POLY;
    }
  }

  /* return success */
  return PTPGP_OK;
}

ptpgp_err_t
ptpgp_crc24_done(ptpgp_crc24_t *r) {
  return ptpgp_crc24_push(r, 0, 0);
}

long crc_octets(unsigned char *octets, size_t len)
{
  long crc = CRC24_INIT;
  int i;
  while (len--) {
    crc ^= (*octets++) << 16;
    for (i = 0; i < 8; i++) {
      crc <<= 1;
      if (crc & 0x1000000)
        crc ^= CRC24_POLY;
    }
  }
  return crc & 0xFFFFFFL;
}
