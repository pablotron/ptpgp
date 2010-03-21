#include "internal.h"

ptpgp_err_t
ptpgp_engine_hash_init(ptpgp_hash_context_t *c,
                       ptpgp_engine_t *e,
                       ptpgp_hash_type_t a) {
  memset(c, 0, sizeof(ptpgp_hash_context_t));

  c->engine    = e;
  c->algorithm = a;

  return c->engine->hash.init(c);
}

ptpgp_err_t
ptpgp_engine_hash_push(ptpgp_hash_context_t *c,
                       u8 *src,
                       size_t src_len) {
  if (c->done)
    return PTPGP_ERR_ENGINE_HASH_CONTEXT_ALREADY_DONE;

  return c->engine->hash.push(c, src, src_len);
}

ptpgp_err_t
ptpgp_engine_hash_done(ptpgp_hash_context_t *c) {
  if (c->done)
    return PTPGP_ERR_ENGINE_HASH_CONTEXT_ALREADY_DONE;

  TRY(c->engine->hash.done(c));

  c->done = 1;
  return PTPGP_OK;
}

ptpgp_err_t
ptpgp_engine_hash_read(ptpgp_hash_context_t *c, 
                       u8 *dst,
                       size_t dst_len,
                       size_t *out_len) {
  if (!c->done)
    return PTPGP_ERR_ENGINE_HASH_CONTEXT_NOT_DONE;

  if (dst_len < c->hash_len)
    return PTPGP_ERR_ENGINE_HASH_OUTPUT_BUFFER_TOO_SMALL;

  memcpy(dst, c->hash, c->hash_len);

  if (out_len)
    *out_len = c->hash_len;

  return PTPGP_OK;
}

ptpgp_err_t
ptpgp_engine_hash_once(ptpgp_engine_t *e,
                       ptpgp_hash_type_t a,
                       u8 *src, size_t src_len,
                       u8 *dst, size_t dst_len, 
                       size_t *out_len) {
  ptpgp_hash_context_t c;

  TRY(ptpgp_engine_hash_init(&c, e, a));
  TRY(ptpgp_engine_hash_push(&c, src, src_len));
  TRY(ptpgp_engine_hash_done(&c));

  TRY(ptpgp_engine_hash_read(&c, dst, dst_len, out_len));

  return PTPGP_OK;
}
