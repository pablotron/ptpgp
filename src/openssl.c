#ifdef PTPGP_USE_OPENSSL
#include "internal.h"

/****************/
/* hash methods */
/****************/
static const EVP_MD *
get_hash_algorithm(ptpgp_hash_type_t t) {
  switch (t) {
  case PTPGP_HASH_TYPE_MD5:
    return EVP_md5();
  case PTPGP_HASH_TYPE_SHA1:
    return EVP_sha1();
  case PTPGP_HASH_TYPE_RIPEMD160:
    return EVP_ripemd160();
  case PTPGP_HASH_TYPE_SHA256:
    return EVP_sha256();
  case PTPGP_HASH_TYPE_SHA384:
    return EVP_sha384();
  case PTPGP_HASH_TYPE_SHA512:
    return EVP_sha512();
  default:
    return NULL;
  }
}

static ptpgp_err_t
hash_init(ptpgp_hash_context_t *c) {
  const EVP_MD *a = get_hash_algorithm(c->algorithm);
  EVP_MD_CTX *h;

  /* alloc hash context, check for error */
  if ((h = EVP_MD_CTX_create()) == NULL)
    return PTPGP_ERR_ENGINE_HASH_INIT_FAILED;

  /* TODO: non-default engine support */

  /* init hash context, check for error */
  if (!EVP_DigestInit_ex(h, a, NULL))
    return PTPGP_ERR_ENGINE_HASH_INIT_FAILED;

  /* save hash context */
  c->engine_data = (void*) h;

  /* return success */
  return PTPGP_OK;
}

static ptpgp_err_t
hash_push(ptpgp_hash_context_t *c, u8 *src, size_t src_len) {
  if (!EVP_DigestUpdate((EVP_MD_CTX*) c->engine_data, src, src_len))
    return PTPGP_ERR_ENGINE_HASH_PUSH_FAILED;
  return PTPGP_OK;
}

static ptpgp_err_t
hash_done(ptpgp_hash_context_t *c) {
  EVP_MD_CTX *h = (EVP_MD_CTX*) c->engine_data;
  unsigned int len;

  /* FIXME: need to check for possible overflow here */
  if (!EVP_DigestFinal_ex(h, c->hash, &len))
    return PTPGP_ERR_ENGINE_HASH_DONE_FAILED;

  /* save hash length */
  c->hash_len = len;

  /* free digest handle */
  EVP_MD_CTX_destroy(h);

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
ptpgp_openssl_engine_init(ptpgp_engine_t *r) {
  /* FIXME: is this the right place for this? */
  OpenSSL_add_all_digests();

  /* copy engine settings */
  memcpy(r, &engine, sizeof(ptpgp_engine_t));

  /* return success */
  return PTPGP_OK;
}

#endif /* PTPGP_USE_OPENSSL */
