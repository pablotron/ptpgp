#ifdef PTPGP_USE_GCRYPT
#include "internal.h"
#include <gcrypt.h>

/****************/
/* hash methods */
/****************/
static int
get_hash_algorithm(ptpgp_hash_algorithm_type_t t) {
  switch (t) {
  case PTPGP_HASH_ALGORITHM_TYPE_MD5:
    return GCRY_MD_MD5;
  case PTPGP_HASH_ALGORITHM_TYPE_SHA1:
    return GCRY_MD_SHA1;
  case PTPGP_HASH_ALGORITHM_TYPE_RIPEMD160:
    return GCRY_MD_RMD160;
  case PTPGP_HASH_ALGORITHM_TYPE_SHA256:
    return GCRY_MD_SHA256;
  case PTPGP_HASH_ALGORITHM_TYPE_SHA384:
    return GCRY_MD_SHA384;
  case PTPGP_HASH_ALGORITHM_TYPE_SHA512:
    return GCRY_MD_SHA512;
  default:
    return -1;
  }
}

static ptpgp_err_t
hash_init(ptpgp_hash_context_t *c) {
  int a = get_hash_algorithm(c->algorithm);
  gcry_md_hd_t h;

  /* XXX: should we try and allocate with secure memory here? */

  /* init hash context, check for error */
  if (gcry_md_open(&h, a, 0) != GPG_ERR_NO_ERROR)
    return PTPGP_ERR_ENGINE_HASH_INIT_FAILED;

  /* save hash context */
  c->engine_data = (void*) h;

  /* return success */
  return PTPGP_OK;
}

static ptpgp_err_t
hash_push(ptpgp_hash_context_t *c, u8 *src, size_t src_len) {
  gcry_md_write((gcry_md_hd_t) c->engine_data, src, src_len);
  return PTPGP_OK;
}

static ptpgp_err_t
hash_done(ptpgp_hash_context_t *c) {
  gcry_md_hd_t h = (gcry_md_hd_t) c->engine_data;
  unsigned char *hash = gcry_md_read(h, 0);
  int len = gcry_md_get_algo_dlen(get_hash_algorithm(c->algorithm));

  /* check hash */
  if (!hash)
    return PTPGP_ERR_ENGINE_HASH_DONE_FAILED;

  /* copy hash data */
  if (len > 0)
    memcpy(c->hash, hash, len);

  /* save hash len */
  c->hash_len = len;

  /* close digest handle */
  gcry_md_close(h);

  /* return success */
  return PTPGP_OK;
}

/********************************/
/* symmetric encryption methods */
/********************************/

static ptpgp_err_t 
encrypt_init(ptpgp_encrypt_context_t *c) {
  UNUSED(c);

  /* TODO */

  return PTPGP_OK;
}

static ptpgp_err_t 
encrypt_push(ptpgp_encrypt_context_t *c, 
             u8 *src,
             size_t src_len) {
  UNUSED(c);
  UNUSED(src);
  UNUSED(src_len);

  /* TODO */

  return PTPGP_OK;
}

static ptpgp_err_t 
encrypt_done(ptpgp_encrypt_context_t *c) {
  UNUSED(c);

  /* TODO */

  return PTPGP_OK;
}

static ptpgp_engine_t 
engine = {
  /* hash methods */
  .hash = {
    .init = hash_init,
    .push = hash_push,
    .done = hash_done
  },

  /* symmetric encryption methods */
  .encrypt = {
    .init = encrypt_init,
    .push = encrypt_push,
    .done = encrypt_done
  }
};

ptpgp_err_t 
ptpgp_gcrypt_engine_init(ptpgp_engine_t *r) {
  /* make sure gcrypt was properly initialized by the application */
  if (!gcry_control(GCRYCTL_INITIALIZATION_FINISHED_P))
    return PTPGP_ERR_ENGINE_INIT_FAILED;

  /* copy gcrypt settings */
  memcpy(r, &engine, sizeof(ptpgp_engine_t));

  /* return success */
  return PTPGP_OK;
}

#endif /* PTPGP_USE_GCRYPT */
