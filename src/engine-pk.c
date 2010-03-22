#include "internal.h"

ptpgp_err_t
ptpgp_engine_pk_generate_key(ptpgp_pk_genkey_context_t *c, 
                             ptpgp_pk_genkey_options_t *o) {
  /* clear context */
  memset(c, 0, sizeof(ptpgp_pk_genkey_context_t));

  /* save options */
  c->options = *o;

  /* call engine */
  return c->options.engine->pk.genkey(c);
}
