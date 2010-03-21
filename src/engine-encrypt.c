#include "internal.h"

ptpgp_err_t
ptpgp_engine_encrypt_init(ptpgp_encrypt_context_t *c,
                          ptpgp_encrypt_options_t *o) {
  /* clear context */
  memset(c, 0, sizeof(ptpgp_encrypt_context_t));

  /* save options */
  c->options = *o;

  /* init and return result */
  return c->options.engine->encrypt.init(c);
}

ptpgp_err_t
ptpgp_engine_encrypt_push(ptpgp_encrypt_context_t *c,
                          u8 *src,
                          size_t src_len) {
  return c->options.engine->encrypt.push(c, src, src_len);
}

ptpgp_err_t
ptpgp_engine_encrypt_done(ptpgp_encrypt_context_t *c) {
  return c->options.engine->encrypt.done(c);
}
