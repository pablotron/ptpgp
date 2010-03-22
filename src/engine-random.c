#include "internal.h"

/* FIXME: should we wrap RAND_status() here too (as .ready)? */

ptpgp_err_t
ptpgp_engine_random_strong(ptpgp_engine_t *e, u8 *dst, size_t dst_len) {
  return e->random.strong(e, dst, dst_len);
}

ptpgp_err_t
ptpgp_engine_random_nonce(ptpgp_engine_t *e, u8 *dst, size_t dst_len) {
  return e->random.nonce(e, dst, dst_len);
}
