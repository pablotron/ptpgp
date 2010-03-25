#ifdef PTPGP_USE_GCRYPT
#include "internal.h"
#include <gcrypt.h>
#include <math.h>

#define GCRYPT_OK GPG_ERR_NO_ERROR

/****************/
/* hash methods */
/****************/
static int
get_hash_algorithm(ptpgp_hash_type_t t) {
  switch (t) {
  case PTPGP_HASH_TYPE_MD5:
    return GCRY_MD_MD5;
  case PTPGP_HASH_TYPE_SHA1:
    return GCRY_MD_SHA1;
  case PTPGP_HASH_TYPE_RIPEMD160:
    return GCRY_MD_RMD160;
  case PTPGP_HASH_TYPE_SHA256:
    return GCRY_MD_SHA256;
  case PTPGP_HASH_TYPE_SHA384:
    return GCRY_MD_SHA384;
  case PTPGP_HASH_TYPE_SHA512:
    return GCRY_MD_SHA512;
  default:
    return -1;
  }
}

static ptpgp_err_t
hash_init(ptpgp_hash_context_t *c) {
  int a = get_hash_algorithm(c->algorithm);
  gcry_md_hd_t h;

  /* TODO: handle secure memory */

  /* init hash context, check for error */
  if (gcry_md_open(&h, a, 0) != GCRYPT_OK)
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
static int
get_symmetric_algorithm(ptpgp_symmetric_type_t t) {
  switch (t) {
  case PTPGP_SYMMETRIC_TYPE_PLAINTEXT:
    return GCRY_CIPHER_NONE;
  case PTPGP_SYMMETRIC_TYPE_IDEA:
    return GCRY_CIPHER_IDEA;
  case PTPGP_SYMMETRIC_TYPE_TRIPLEDES:
    return GCRY_CIPHER_3DES;
  case PTPGP_SYMMETRIC_TYPE_CAST5:
    return GCRY_CIPHER_CAST5;
  case PTPGP_SYMMETRIC_TYPE_BLOWFISH:
    return GCRY_CIPHER_BLOWFISH;
  case PTPGP_SYMMETRIC_TYPE_AES_128:
    return GCRY_CIPHER_AES128;
  case PTPGP_SYMMETRIC_TYPE_AES_192:
    return GCRY_CIPHER_AES192;
  case PTPGP_SYMMETRIC_TYPE_AES_256:
    return GCRY_CIPHER_AES256;
  case PTPGP_SYMMETRIC_TYPE_TWOFISH:
    return GCRY_CIPHER_TWOFISH;
  case PTPGP_SYMMETRIC_TYPE_CAMELLIA_128:
    return GCRY_CIPHER_CAMELLIA128;
  case PTPGP_SYMMETRIC_TYPE_CAMELLIA_192:
    return GCRY_CIPHER_CAMELLIA192;
  case PTPGP_SYMMETRIC_TYPE_CAMELLIA_256:
    return GCRY_CIPHER_CAMELLIA256;
  default:
    return -1;
  }
}

static int
get_symmetric_mode(ptpgp_symmetric_mode_type_t t) {
  switch (t) {
  case PTPGP_SYMMETRIC_MODE_TYPE_NONE:
    return GCRY_CIPHER_MODE_NONE;
  case PTPGP_SYMMETRIC_MODE_TYPE_ECB:
    return GCRY_CIPHER_MODE_ECB;
  case PTPGP_SYMMETRIC_MODE_TYPE_CFB:
    return GCRY_CIPHER_MODE_CFB;
  case PTPGP_SYMMETRIC_MODE_TYPE_CBC:
    return GCRY_CIPHER_MODE_CBC;
  case PTPGP_SYMMETRIC_MODE_TYPE_OFB:
    return GCRY_CIPHER_MODE_OFB;
  case PTPGP_SYMMETRIC_MODE_TYPE_CTR:
    return GCRY_CIPHER_MODE_CTR;
  case PTPGP_SYMMETRIC_MODE_TYPE_STREAM:
    return GCRY_CIPHER_MODE_STREAM;
  case PTPGP_SYMMETRIC_MODE_TYPE_LAST:
  default:
    return -1;
  }
}

static ptpgp_err_t
encrypt_init(ptpgp_encrypt_context_t *c) {
  int a = get_symmetric_algorithm(c->options.algorithm),
      m = get_symmetric_mode(c->options.mode);
  gcry_cipher_hd_t h;

  /* TODO: handle secure memory */

  /* init cipher context */
  if (gcry_cipher_open(&h, a, m, 0) != GCRYPT_OK)
    return PTPGP_ERR_ENGINE_ENCRYPT_INIT_FAILED;

  /* set iv */
  if (gcry_cipher_setiv(h, c->options.iv, c->options.iv_len) != GCRYPT_OK)
    return PTPGP_ERR_ENGINE_ENCRYPT_INIT_IV_FAILED;


  /* set key */
  if (gcry_cipher_setkey(h, c->options.key, c->options.key_len) != GCRYPT_OK)
    return PTPGP_ERR_ENGINE_ENCRYPT_INIT_KEY_FAILED;

  /* TODO: handle counter for ctr mode */

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
  gcry_cipher_hd_t h = (gcry_cipher_hd_t) c->engine_data;
  gcry_error_t err;
  size_t len;

  while (src_len > 0) {
    /* get length */
    /* XXX: should we enforce block constraints here? */
    len = (src_len < BUF_SIZE) ? src_len : BUF_SIZE;

    /* encrypt/decrypt data */
    if (c->options.encrypt)
      err = gcry_cipher_encrypt(h, c->buf, BUF_SIZE, src, len);
    else
      err = gcry_cipher_decrypt(h, c->buf, BUF_SIZE, src, len);

    /* check for gcrypt error */
    if (err != GCRYPT_OK)
      return PTPGP_ERR_ENGINE_ENCRYPT_PUSH_FAILED;

    /* pass data to callback */
    TRY(c->options.cb(c, c->buf, len));

    /* shift input */
    src += len;
    src_len -= len;
  }

  /* return success */
  return PTPGP_OK;
}

static ptpgp_err_t
encrypt_done(ptpgp_encrypt_context_t *c) {
  gcry_cipher_close((gcry_cipher_hd_t) c->engine_data);
  return PTPGP_OK;
}

/******************/
/* random methods */
/******************/
static ptpgp_err_t
random_strong(ptpgp_engine_t *e, u8 *dst, size_t dst_len) {
  UNUSED(e);

  gcry_randomize(dst, dst_len, GCRY_VERY_STRONG_RANDOM);

  /* return success */
  return PTPGP_OK;
}

static ptpgp_err_t
random_nonce(ptpgp_engine_t *e, u8 *dst, size_t dst_len) {
  UNUSED(e);

  gcry_create_nonce(dst, dst_len);

  /* return success */
  return PTPGP_OK;
}

/**********************/
/* public key methods */
/**********************/

static void
pk_genkey_progress_cb(void *cb_data,
                      const char *what,
                      int p,
                      int current,
                      int total) {
  ptpgp_pk_genkey_context_t *c = (ptpgp_pk_genkey_context_t*) cb_data;

  UNUSED(c);
  UNUSED(current);

  if (!strncmp(what, "primegen", 9)) {
    switch (p) {
    case '\n':
      D("prime generated");
      break;
    case '!':
      D("need to refresh prime number pool");
      break;
    case '<':
    case '>':
      D("number of bits adjusted (%c)", p);
      break;
    case '^':
      D("searching for a generator");
      break;
    case '.':
      D("fermat test on 10 candidates failed");
      break;
    case ':':
      D("restart with new random value");
      break;
    case '+':
      D("rabin miller test passed");
      break;
    default:
      W("unknown progress state: %c", p);
    }
  } else if (!strncmp(what, "need_entropy", 13)) {
    W("need entropy: %d bytes remaining", total);
  }
}

static void
dump_key_piece_value(gcry_sexp_t v, char *name) {
  char *s;
  u8 buf[4096];
  gcry_mpi_t n;
  size_t len;
  int err;

  /* get name */
  if ((s = gcry_sexp_nth_string(v, 0)) == NULL) {
    W("couldn't get value name");
    return;
  }

  /* get mpi and convert it to hex */
  if ((n = gcry_sexp_nth_mpi(v, 1, GCRYMPI_FMT_STD)) == NULL) {
    W("couldn't get value mpi");
    gcry_free(s);
    return;
  }

  /* convert mpi to hex */
  err = gcry_mpi_print(GCRYMPI_FMT_HEX, buf, sizeof(buf), &len, n);

  /* check for error */
  if (err != GCRYPT_OK) {
    W("couldn't convert mpi to hex");
    gcry_free(s);
    gcry_mpi_release(n);
    return;
  }

  D("%s %s = %s", name, s, buf);

  gcry_free(s);
  gcry_mpi_release(n);
}

static void
dump_key_piece(gcry_sexp_t p, char *name) {
  gcry_sexp_t v;
  size_t i, l;

  /* get length of s-exp */
  l = gcry_sexp_length(p);

  for (i = 1; i < l; i++) {
    /* get value */
    if ((v = gcry_sexp_nth(p, i)) == NULL) {
      W("couldn't get value %ld", i);
      continue;
    }

    /* print value */
    dump_key_piece_value(v, name);

    /* release value */
    gcry_sexp_release(v);
  }
}

static char *key_pieces[] = {
  "public-key",
  "private-key",
  NULL
};

static void
dump_key(gcry_sexp_t *k) {
  gcry_sexp_t t, b;
  size_t i;

  for (i = 0; key_pieces[i]; i++) {
    if ((t = gcry_sexp_find_token(*k, key_pieces[i], 0)) != NULL) {
      /* get body */
      if ((b = gcry_sexp_nth(t, 1)) == NULL) {
        W("couldn't get %s sublist body", key_pieces[i]);
        gcry_sexp_release(t);
        continue;
      }

      /* print body */
      dump_key_piece(b, key_pieces[i]);

      /* free s-exps */
      gcry_sexp_release(t);
      gcry_sexp_release(b);
    }
  }
}

static ptpgp_err_t
pk_set_rsa_key_value(ptpgp_pk_key_t *dst,
                     char *s,
                     u8 *src,
                     size_t src_len) {
  ptpgp_mpi_t *n;
  size_t i;

  switch (s[0]) {
  case 'n':
    n = &(dst->rsa.n);
    break;
  case 'e':
    n = &(dst->rsa.e);
    break;
  case 'd':
    n = &(dst->rsa.d);
    break;
  case 'p':
    /* store these values in OpenSSL order */
    n = &(dst->rsa.q);
    break;
  case 'q':
    /* store these values in OpenSSL order */
    n = &(dst->rsa.p);
    break;
  case 'u':
    /* 
     * We deliberately ignore this, because it ca be computed from
     * p and q.  from the gcrypt documentation:
     *
     *   For signing and decryption the parameters (p, q, u) are
     *   optional but greatly improve the performance. Either all of
     *   these optional parameters must be given
     *   or none of them. They are mandatory for gcry_pk_testkey.
     *
     *   Note that OpenSSL uses slighly different parameters: q < p and
     *   u = q^-1 \bmod p. To use these parameters you will need to swap
     *   the values and recompute u. Here is example code to do this:
     *
     *     if (gcry_mpi_cmp(p, q) > 0) {
     *       gcry_mpi_swap(p, q);
     *       gcry_mpi_invm(u, p, q);
     *     }
     *
     */

    /* return success */
    return PTPGP_OK;
  default:
    W("unknown rsa key parameter name: %s", s);
    return PTPGP_ERR_ENGINE_PK_GENKEY_UNKNOWN_KEY_PARAMETER_NAME;
  }

  /* set approximate bit count */
  n->num_bits = (src[0] << 8 | src[1]) * 8;

  /* determine exact bit count */
  for (i = 0; i < 8; i++) {
    if (src[2] & (1 << (7 - i))) {
      n->num_bits -= i;
      break;
    }
  }

  /* check buffer size */
  if (src_len - 2 > PTPGP_MPI_BUF_SIZE)
    return PTPGP_ERR_ENGINE_PK_GENKEY_MPI_TOO_LARGE;

  /* copy data */
  memcpy(n->data, src + 2, src_len - 2);

  /* return success */
  return PTPGP_OK;
}

static ptpgp_err_t
pk_decode_rsa_key_value_pair_sexp(ptpgp_pk_key_t *dst,
                                  gcry_sexp_t src,
                                  char *list_name) {
  char *s;
  u8 buf[8194]; /* 8192 + 2 (for length header) */
  gcry_mpi_t n;
  size_t len;
  int err;
  ptpgp_err_t r;

  /* get name */
  if ((s = gcry_sexp_nth_string(src, 0)) == NULL) {
    W("couldn't get value name");
    return PTPGP_ERR_ENGINE_PK_GENKEY_MISSING_KEY_PARAMETER_NAME;
  }

  /* get mpi (FIXME: should the format be _USG?) */
  if ((n = gcry_sexp_nth_mpi(src, 1, GCRYMPI_FMT_USG)) == NULL) {
    W("couldn't get value mpi");
    gcry_free(s);
    return PTPGP_ERR_ENGINE_PK_GENKEY_MISSING_KEY_PARAMETER_VALUE;
  }

  /* decode mpi to buffer */
  err = gcry_mpi_scan(&n, GCRYMPI_FMT_PGP, buf, sizeof(buf), &len);

  /* check for error */
  if (err == GCRYPT_OK) {
    /* save value */
    r = pk_set_rsa_key_value(dst, s, buf, len);
  } else {
    /* warn about error, set result */
    W("couldn't decode mpi %s.%s", list_name, s);

    /* return error */
    r = PTPGP_ERR_ENGINE_PK_GENKEY_CONVERT_MPI_FAILED;
  }

  /* free name and value */
  gcry_free(s);
  gcry_mpi_release(n);

  /* return result */
  return r;
}

static ptpgp_err_t
pk_decode_rsa_key_value_list_sexp(ptpgp_pk_key_t *dst,
                                  gcry_sexp_t src,
                                  char *list_name) {
  gcry_sexp_t v;
  size_t i, l;
  ptpgp_err_t err;

  /* get length of s-exp */
  l = gcry_sexp_length(src);

  for (i = 1; i < l; i++) {
    /* get value pair */
    if ((v = gcry_sexp_nth(src, i)) == NULL) {
      W("couldn't get value %ld for token %s", i, list_name);
      return PTPGP_ERR_ENGINE_PK_GENKEY_INCOMPLETE_KEY_PARAMETER;
    }

    /* decode value pair */
    err = pk_decode_rsa_key_value_pair_sexp(dst, v, list_name);

    /* release value pair */
    gcry_sexp_release(v);

    /* check for error */
    if (err != PTPGP_OK)
      return err;
  }

  /* return success */
  return PTPGP_OK;
}

static char *
rsa_key_tokens[] = {
  "public-key",
  "private-key",
  NULL
};

ptpgp_err_t
pk_decode_rsa_key_sexp(ptpgp_pk_key_t *dst, gcry_sexp_t src) {
  gcry_sexp_t t, b;
  size_t i;
  ptpgp_err_t err;

  for (i = 0; key_pieces[i]; i++) {
    /* find token */
    if ((t = gcry_sexp_find_token(src, key_pieces[i], 0)) == NULL) {
      W("couldn't find token %s", rsa_key_tokens[i]);
      return PTPGP_ERR_ENGINE_PK_GENKEY_INCOMPLETE_KEY;
    }

    /* get body */
    b = gcry_sexp_nth(t, 1);

    /* unconditionally release token s-exp */
    gcry_sexp_release(t);

    /* check for error */
    if (b == NULL) {
      W("couldn't get sublist body for token %s", rsa_key_tokens[i]);
      return PTPGP_ERR_ENGINE_PK_GENKEY_INCOMPLETE_KEY;
    }

    /* decode value list */
    err = pk_decode_rsa_key_value_list_sexp(dst, b, rsa_key_tokens[i]);

    /* unconditionally release body exp */
    gcry_sexp_release(b);

    /* check for error */
    if (err != PTPGP_OK) 
      return err;
  }

  /* return success */
  return PTPGP_OK;
}

static void
dump_sexp(char *name, gcry_sexp_t *s) {
  char buf[4096];
  size_t len;

#ifdef PTPGP_DEBUG
  /* dump parameter s-exp */
  len = gcry_sexp_sprint(*s, GCRYSEXP_FMT_CANON, buf, sizeof(buf));
  D("%s = %s", name, buf);
#else /* !PTPGP_DEBUG */
  UNUSED(name);
  UNUSED(s);
#endif /* PTPGP_DEBUG */
}

static ptpgp_err_t
pk_genkey_rsa(ptpgp_pk_genkey_context_t *c) {
  gcry_sexp_t r, p;
  size_t err_ofs;
  ptpgp_err_t ptpgp_err;
  int err;

  /* generate parameter s-exp */
  /* FIXME: remove transient-key */
  err = gcry_sexp_build(&p, &err_ofs,
    "(genkey (rsa (nbits %d) (transient-key)))",
    c->options.num_bits
  );

  /* check for error */
  if (err != GCRYPT_OK)
    return PTPGP_ERR_ENGINE_PK_GENKEY_FAILED; /* TODO: better error? */

  /* dump parameter s-exp */
  dump_sexp("param s-exp", &p);

  /* set progress handler */
  gcry_set_progress_handler(pk_genkey_progress_cb, c);

  /* generate public keypair */
  err = gcry_pk_genkey(&r, p);

  /* clear progress handler and release parameter s-exp
   * (regardless of genkey result) */
  gcry_set_progress_handler(NULL, NULL);
  gcry_sexp_release(p);

  /* check for error */
  if (err != GCRYPT_OK)
    return PTPGP_ERR_ENGINE_PK_GENKEY_FAILED; /* TODO: better error? */

  /* dump rsa s-exp */
  dump_sexp("rsa s-exp", &r);
  dump_key(&r);

  /* decode and save key */
  ptpgp_err = pk_decode_rsa_key_sexp(&(c->key), r);

  /* free rsa s-exp */
  gcry_sexp_release(r);

  /* TODO: */
  /* dump_decoded_key(&(c->key)); */

  /* return result */
  return ptpgp_err;
}

static ptpgp_err_t
pk_genkey(ptpgp_pk_genkey_context_t *c) {
  /* clear output key */
  memset(&(c->key), 0, sizeof(ptpgp_pk_key_t));

  /* save algorithm */
  c->key.algorithm = c->options.algorithm;

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
    .init   = hash_init,
    .push   = hash_push,
    .done   = hash_done
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
