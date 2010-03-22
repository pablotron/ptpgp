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
static const EVP_CIPHER *
get_cipher_type(ptpgp_encrypt_context_t *c) {
  switch (c->options.algorithm) {
  case PTPGP_SYMMETRIC_TYPE_PLAINTEXT:
    return EVP_enc_null();
  case PTPGP_SYMMETRIC_TYPE_IDEA:
#ifdef OPENSSL_NO_IDEA
    /* no idea in this ssl build */
    return NULL;
#else /* !OPENSSL_NO_IDEA */
    switch (c->options.mode) {
    case PTPGP_SYMMETRIC_MODE_TYPE_ECB:
      return EVP_idea_ecb();
    case PTPGP_SYMMETRIC_MODE_TYPE_CFB:
      return EVP_idea_cfb();
    case PTPGP_SYMMETRIC_MODE_TYPE_CBC:
      return EVP_idea_cbc();
    case PTPGP_SYMMETRIC_MODE_TYPE_OFB:
      return EVP_idea_ofb();
    default:
      return NULL;
    }
#endif /* OPENSSL_NO_IDEA */
  case PTPGP_SYMMETRIC_TYPE_TRIPLEDES:
    switch (c->options.mode) {
    case PTPGP_SYMMETRIC_MODE_TYPE_ECB:
      return EVP_des_ede3();
    case PTPGP_SYMMETRIC_MODE_TYPE_CFB:
      return EVP_des_ede3_cfb();
    case PTPGP_SYMMETRIC_MODE_TYPE_CBC:
      return EVP_des_ede3_cbc();
    case PTPGP_SYMMETRIC_MODE_TYPE_OFB:
      return EVP_des_ede3_ofb();
    default:
      return NULL;
    }
  case PTPGP_SYMMETRIC_TYPE_CAST5:
    switch (c->options.mode) {
    case PTPGP_SYMMETRIC_MODE_TYPE_ECB:
      return EVP_cast5_ecb();
    case PTPGP_SYMMETRIC_MODE_TYPE_CFB:
      return EVP_cast5_cfb();
    case PTPGP_SYMMETRIC_MODE_TYPE_CBC:
      return EVP_cast5_cbc();
    case PTPGP_SYMMETRIC_MODE_TYPE_OFB:
      return EVP_cast5_ofb();
    default:
      return NULL;
    }
  case PTPGP_SYMMETRIC_TYPE_BLOWFISH:
    switch (c->options.mode) {
    case PTPGP_SYMMETRIC_MODE_TYPE_ECB:
      return EVP_bf_ecb();
    case PTPGP_SYMMETRIC_MODE_TYPE_CFB:
      return EVP_bf_cfb();
    case PTPGP_SYMMETRIC_MODE_TYPE_CBC:
      return EVP_bf_cbc();
    case PTPGP_SYMMETRIC_MODE_TYPE_OFB:
      return EVP_bf_ofb();
    default:
      return NULL;
    }
  case PTPGP_SYMMETRIC_TYPE_AES_128:
    switch (c->options.mode) {
    case PTPGP_SYMMETRIC_MODE_TYPE_ECB:
      return EVP_aes_128_ecb();
    case PTPGP_SYMMETRIC_MODE_TYPE_CFB:
      return EVP_aes_128_cfb();
    case PTPGP_SYMMETRIC_MODE_TYPE_CBC:
      return EVP_aes_128_cbc();
    case PTPGP_SYMMETRIC_MODE_TYPE_OFB:
      return EVP_aes_128_ofb();
    default:
      return NULL;
    }
  case PTPGP_SYMMETRIC_TYPE_AES_192:
    switch (c->options.mode) {
    case PTPGP_SYMMETRIC_MODE_TYPE_ECB:
      return EVP_aes_192_ecb();
    case PTPGP_SYMMETRIC_MODE_TYPE_CFB:
      return EVP_aes_192_cfb();
    case PTPGP_SYMMETRIC_MODE_TYPE_CBC:
      return EVP_aes_192_cbc();
    case PTPGP_SYMMETRIC_MODE_TYPE_OFB:
      return EVP_aes_192_ofb();
    default:
      return NULL;
    }
  case PTPGP_SYMMETRIC_TYPE_AES_256:
    switch (c->options.mode) {
    case PTPGP_SYMMETRIC_MODE_TYPE_ECB:
      return EVP_aes_256_ecb();
    case PTPGP_SYMMETRIC_MODE_TYPE_CFB:
      return EVP_aes_256_cfb();
    case PTPGP_SYMMETRIC_MODE_TYPE_CBC:
      return EVP_aes_256_cbc();
    case PTPGP_SYMMETRIC_MODE_TYPE_OFB:
      return EVP_aes_256_ofb();
    default:
      return NULL;
    }
  case PTPGP_SYMMETRIC_TYPE_TWOFISH:
    return NULL;
  case PTPGP_SYMMETRIC_TYPE_CAMELLIA_128:
#ifdef OPENSSL_NO_CAMELLIA
    /* no camellia included, return NULL */
    return NULL;
#else /* !OPENSSL_NO_CAMELLIA */
    switch (c->options.mode) {
    case PTPGP_SYMMETRIC_MODE_TYPE_ECB:
      return EVP_camellia_128_ecb();
    case PTPGP_SYMMETRIC_MODE_TYPE_CFB:
      return EVP_camellia_128_cfb();
    case PTPGP_SYMMETRIC_MODE_TYPE_CBC:
      return EVP_camellia_128_cbc();
    case PTPGP_SYMMETRIC_MODE_TYPE_OFB:
      return EVP_camellia_128_ofb();
    default:
      return NULL;
    }
#endif /* OPENSSL_NO_CAMELLIA */
  case PTPGP_SYMMETRIC_TYPE_CAMELLIA_192:
#ifdef OPENSSL_NO_CAMELLIA
    /* no camellia included, return NULL */
    return NULL;
#else /* !OPENSSL_NO_CAMELLIA */
    switch (c->options.mode) {
    case PTPGP_SYMMETRIC_MODE_TYPE_ECB:
      return EVP_camellia_192_ecb();
    case PTPGP_SYMMETRIC_MODE_TYPE_CFB:
      return EVP_camellia_192_cfb();
    case PTPGP_SYMMETRIC_MODE_TYPE_CBC:
      return EVP_camellia_192_cbc();
    case PTPGP_SYMMETRIC_MODE_TYPE_OFB:
      return EVP_camellia_192_ofb();
    default:
      return NULL;
    }
#endif /* OPENSSL_NO_CAMELLIA */
  case PTPGP_SYMMETRIC_TYPE_CAMELLIA_256:
#ifdef OPENSSL_NO_CAMELLIA
    /* no camellia included, return NULL */
    return NULL;
#else /* !OPENSSL_NO_CAMELLIA */
    switch (c->options.mode) {
    case PTPGP_SYMMETRIC_MODE_TYPE_ECB:
      return EVP_camellia_256_ecb();
    case PTPGP_SYMMETRIC_MODE_TYPE_CFB:
      return EVP_camellia_256_cfb();
    case PTPGP_SYMMETRIC_MODE_TYPE_CBC:
      return EVP_camellia_256_cbc();
    case PTPGP_SYMMETRIC_MODE_TYPE_OFB:
      return EVP_camellia_256_ofb();
    default:
      return NULL;
    }
#endif /* OPENSSL_NO_CAMELLIA */
  default:
    return NULL;
  }
}

static ptpgp_err_t
encrypt_init(ptpgp_encrypt_context_t *c) {
  EVP_CIPHER_CTX *h = malloc(sizeof(EVP_CIPHER_CTX));
  const EVP_CIPHER *type  = get_cipher_type(c);
  int ok;

  /* couldn't allocate openssl cipher context */
  if (!h)
    return PTPGP_ERR_ENGINE_ENCRYPT_INIT_FAILED;

  if (!type) {
    free(h);
    return PTPGP_ERR_ENGINE_ENCRYPT_INIT_UNSUPPORTED_ALGORITHM;
  }

  /* init cipher context */
  EVP_CIPHER_CTX_init(h);

  /* configure cipher context */
  ok = EVP_CipherInit_ex(h, type, NULL,
                         c->options.key,
                         c->options.iv,
                         c->options.encrypt);

  if (!ok) {
    /* free cipher context handle */
    EVP_CIPHER_CTX_cleanup(h);
    free(h);

    /* this error message isn't strictly accurate, but it lets us
     * distinguish between a malloc() error above and and an init error
     * here */
    return PTPGP_ERR_ENGINE_ENCRYPT_INIT_KEY_FAILED;
  }

  /* save cipher context */
  c->engine_data = (void*) h;

  /* return success */
  return PTPGP_OK;
}

#define BUF_SIZE PTPGP_ENCRYPT_CONTEXT_BUFFER_SIZE

static ptpgp_err_t
encrypt_push(ptpgp_encrypt_context_t *c,
             u8 *src,
             size_t src_len) {
  EVP_CIPHER_CTX *h = (EVP_CIPHER_CTX*) c->engine_data;
  int len, buf_len;

  /* check for NULL cipher context (previous error occurred) */
  if (!h)
    return PTPGP_ERR_ENGINE_ENCRYPT_PUSH_FAILED;

  while (src_len > 0) {
    /* calculate input length */
    /* FIXME: should leave room for one extra block */
    len = (src_len < BUF_SIZE) ? src_len : BUF_SIZE;

    /* reset to size of output buffer; after call to EVP_CipherUpdate
     * this will contain the number of output bytes */
    buf_len = BUF_SIZE;

    /* encrypt/decrypt data */
    if (!EVP_CipherUpdate(h, c->buf, &buf_len, src, len)) {
      /* free cipher context handle */
      EVP_CIPHER_CTX_cleanup(h);
      free(h);
      c->engine_data = NULL;

      /* return failure */
      return PTPGP_ERR_ENGINE_ENCRYPT_PUSH_FAILED;
    }

    /* pass data to callback */
    if (buf_len > 0)
      TRY(c->options.cb(c, c->buf, buf_len));

    /* shift input */
    src += len;
    src_len -= len;
  }

  /* return success */
  return PTPGP_OK;
}

static ptpgp_err_t
encrypt_done(ptpgp_encrypt_context_t *c) {
  EVP_CIPHER_CTX *h = (EVP_CIPHER_CTX*) c->engine_data;
  int len = BUF_SIZE;
  ptpgp_err_t r;

  /* check for NULL cipher context (previous error occurred) */
  if (!h)
    return PTPGP_ERR_ENGINE_ENCRYPT_DONE_FAILED;

  /* finalize cipher context */
  if (EVP_CipherFinal_ex(h, c->buf, &len)) {
    /* success, pass remaining data to callback */

    /* pass data to callback */
    if (len > 0)
      TRY(c->options.cb(c, c->buf, len));

    /* return success */
    r = PTPGP_OK;
  } else {
    /* return failure :( */
    r = PTPGP_ERR_ENGINE_ENCRYPT_DONE_FAILED;
  }

  /* regardless of the result, free cipher context handle */
  EVP_CIPHER_CTX_cleanup(h);
  free(h);
  c->engine_data = NULL;

  /* return result */
  return r;
}

/******************/
/* random methods */
/******************/

static ptpgp_err_t
random_strong(ptpgp_engine_t *e, u8 *dst, size_t dst_len) {
  int err = RAND_bytes(dst, dst_len);

  UNUSED(e);

  /* handle response */
  switch (err) {
  case 1:
    /* return success */
    return PTPGP_OK;
  case -1:
    /* return success */
    return PTPGP_ERR_ENGINE_RANDOM_UNSUPPORTED;
  default:
    return PTPGP_ERR_ENGINE_RANDOM_FAILED;
  }
}

static ptpgp_err_t
random_nonce(ptpgp_engine_t *e, u8 *dst, size_t dst_len) {
  int err = RAND_bytes(dst, dst_len);

  UNUSED(e);

  /* FIXME: should we warn if err == 0 (e.g., random number is not
   * cryptographically secure? */

  /* check for error */
  if (err == -1)
    return PTPGP_ERR_ENGINE_RANDOM_UNSUPPORTED;

  /* return success */
  return PTPGP_OK;
}

/**********************/
/* public key methods */
/**********************/
static void
dump_bn(char *name, BIGNUM *bn) {
  char *s;

  if (bn && (s = BN_bn2hex(bn)) != NULL) {
    D("%s = %s", name, s);
    OPENSSL_free(s);
  }
}

static void
dump_rsa(RSA *rsa) {
  dump_bn("n", rsa->n);
  dump_bn("e", rsa->e);
  dump_bn("d", rsa->d);
  dump_bn("p", rsa->p);
  dump_bn("q", rsa->q);
  dump_bn("dmp1", rsa->dmp1);
  dump_bn("dmq1", rsa->dmq1);
  dump_bn("iqmp", rsa->iqmp);
}

static void
pk_genkey_rsa_cb(int step, int n, void *cb_data) {
  ptpgp_pk_genkey_context_t *c = (ptpgp_pk_genkey_context_t*) cb_data;
  UNUSED(c);

  /* D("step = %d, n = %d", step, n); */

  switch (step) {
  case 0:
    D("generating prime %d", n + 1);
    break;
  case 1:
    D("testing for primality (test #%d)", n + 1);
    break;
  case 2:
    D("rejecting prime %d (not suitable for key)", n + 1);
    break;
  case 3:
    D("found suitable prime for %s", n ? "q" : "p");
    break;
  default:
    W("unknown rsa keygen step: %d", step);
  }

  /* TODO: map to pk_genkey_cb_t */
}

static ptpgp_err_t
pk_genkey_rsa(ptpgp_pk_genkey_context_t *c) {
  RSA *rsa;

  /* generate key */
  rsa = RSA_generate_key(c->options.num_bits,
                         c->options.params.rsa.e, 
                         pk_genkey_rsa_cb, c);

  /* check for error */
  if (!rsa)
    return PTPGP_ERR_ENGINE_PK_GENKEY_FAILED;

  /* dump rsa structure */
  dump_rsa(rsa);

  /* populate key structure */
  /* TODO */

  /* free rsa structure */
  RSA_free(rsa);

  /* return success */
  return PTPGP_OK;
}

static ptpgp_err_t
pk_genkey(ptpgp_pk_genkey_context_t *c) {
  switch(c->options.algorithm) {
  case PTPGP_PUBLIC_KEY_TYPE_RSA:
  case PTPGP_PUBLIC_KEY_TYPE_RSA_ENCRYPT_ONLY:
  case PTPGP_PUBLIC_KEY_TYPE_RSA_SIGN_ONLY:
    return pk_genkey_rsa(c);
  default:
    return PTPGP_ERR_ENGINE_PK_GENKEY_UNSUPPORTED_ALGORITHM;
  }
}

/****************/
/* init methods */
/****************/

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
    .init   = encrypt_init,
    .push   = encrypt_push,
    .done   = encrypt_done
  },

  /* random number methods */
  .random = {
    .strong = random_strong,
    .nonce  = random_nonce
  },

  /* public key methods */
  .pk = {
    .genkey = pk_genkey
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
