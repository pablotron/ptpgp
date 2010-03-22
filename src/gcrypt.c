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

/* get lenght of number in base 10 */
static int
decimal_size(size_t num) {
  return (int) (0.5 + log(num + 1.0));
}

static void
pk_genkey_progress_cb(void *cb_data, 
                      const char *what,
                      int p,
                      int current,
                      int total) {
  ptpgp_pk_genkey_context_t *c = (ptpgp_pk_genkey_context_t*) cb_data;

  UNUSED(c);
  UNUSED(current);
  UNUSED(total);

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
    case '\'':
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
  }
}

static void
dump_sexp(char *name, gcry_sexp_t *s) {
  char buf[4096];
  size_t len;

#ifdef PTPGP_DEBUG
  /* dump parameter s-exp */
  len = gcry_sexp_sprint(*s, GCRYSEXP_FMT_DEFAULT, buf, sizeof(buf));
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
  int err;

  /* generate parameter s-exp */
  err = gcry_sexp_build(&p, &err_ofs,
    "(genkey (rsa (nbits %d:%d)))",
    decimal_size(c->options.num_bits),
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

  /* free rsa s-exp */
  gcry_sexp_release(r);

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
