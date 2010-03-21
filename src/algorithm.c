#include "internal.h"

#define T(s) PTPGP_TYPE_##s
#define R(s) PTPGP_REQUIREMENT_##s

#define F(k) \
  { A(k), R(MUST_NOT), R(MUST_NOT), "Private/Experimental", 0, 0, 0, 0 }

#define FOOTER \
  F(PRIVATE_100), \
  F(PRIVATE_101), \
  F(PRIVATE_102), \
  F(PRIVATE_103), \
  F(PRIVATE_104), \
  F(PRIVATE_105), \
  F(PRIVATE_106), \
  F(PRIVATE_107), \
  F(PRIVATE_108), \
  F(PRIVATE_109), \
  F(PRIVATE_110)

static ptpgp_type_info_t algos[] = {{
/* algorithm types */
#define A(a) T(TYPE), PTPGP_TYPE_##a
  A(TYPE),                      R(MUST),      R(MUST),
  "Type",                       "type",         
  0,                            0, 0
}, {
  A(PUBLIC_KEY),                R(MUST),      R(MUST),
  "Public Key Algorithm",       "public-key", 
  0,                            0, 0
}, {
  A(SYMMETRIC),                 R(MUST),      R(MUST),
  "Symmetric Algorithm",        "symmetric",
  0,                            0, 0
}, {
  A(COMPRESSION),               R(MUST),      R(MUST),
  "Compression Algorithm",      "compression",
  0,                            0, 0
}, {
  A(HASH),                      R(MUST),      R(MUST),
  "Hash Algorithm",             "hash",
  0,                            0, 0
}, {
  A(S2K),                       R(MUST),      R(MUST),
  "String-to-Key Specifier",    "s2k",
  0,                            0, 0
}, {
#undef A
/* public key algorithms (rfc4880 9.1) */
#define A(a) T(PUBLIC_KEY), PTPGP_PUBLIC_KEY_TYPE_##a
  A(RESERVED_0),                R(MUST_NOT),  R(MUST_NOT),
  "Reserved",                   NULL,
  0,                            0, 0
}, {
  A(RSA),                       R(SHOULD),    R(SHOULD),
  "RSA",                        "rsa",
  0,                            2, 4
}, {
  A(RSA_ENCRYPT_ONLY),          R(MAY),       R(SHOULD_NOT),
  "RSA (Encrypt-Only)",         "rsa-encrypt-only",
  0,                            2, 4
}, {
  A(RSA_SIGN_ONLY),             R(MAY),       R(SHOULD_NOT),
  "RSA (Sign-Only)",            "rsa-sign-only",
  0,                            2, 4
}, {
  A(ELGAMEL_ENCRYPT_ONLY),      R(MUST),      R(MUST),
  "Elgamal (Encrypt-Only)",     "elgamal-encrypt-only",
  0,                            3, 1
}, {
  A(DSA),                       R(MUST),      R(MUST),
  "DSA",                        "dsa",
  0,                            4, 1
}, {
  A(EC),                        R(MUST_NOT),  R(MUST_NOT),
  "Elliptic Curve (Reserved)",  "elliptic-curve",
  0,                            0, 0
}, {
  A(ECDSA),                     R(MUST_NOT),  R(MUST_NOT),
  "ECDSA (Reserved)",           "ecdsa",
  0,                            0, 0
}, {
  A(ELGAMAL_ENCRYPT_OR_SIGN),   R(MAY),       R(MUST_NOT),
  "Elgamal (Deprecated)",       "elgamal-deprecated",
  0,                            3, 1
}, {
  A(DH),                        R(MUST_NOT),  R(MUST_NOT),
  "Diffie-Hellman",             "dh",
  0,                            0, 0
}, FOOTER, {
#undef A


/* symmetric key algorithms (rfc4880 9.2) */
#define A(a) T(SYMMETRIC), PTPGP_SYMMETRIC_TYPE_##a
  A(PLAINTEXT),                 R(MUST),      R(MUST),
  "Plaintext",                  "plaintext",
  0,                            0, 0
}, {
  A(IDEA),                      R(SHOULD),    R(SHOULD_NOT),
  "IDEA",                       "idea",
  64,                           0, 0
}, {
  A(TRIPLEDES),                 R(MUST),      R(MUST),
  "TripleDES (DES-EDE)",        "tripledes",
  64,                           0, 0
}, {
  A(CAST5),                     R(SHOULD),    R(SHOULD),
  "CAST5 (128-bit)",            "cast5",
  64,                           0, 0
}, {
  A(BLOWFISH),                  R(MAY),       R(MAY),
  "Blowfish (128-bit)",         "blowfish",
  64,                           0, 0
}, {
  A(RESERVED_5),                R(MUST_NOT),  R(MUST_NOT),
  "Reserved",                   NULL,
  0,                            0, 0
}, {
  A(RESERVED_6),                R(MUST_NOT),  R(MUST_NOT),
  "Reserved",                   NULL,
  0,                            0, 0
}, {
  A(AES_128),                   R(SHOULD),    R(SHOULD),
  "AES (128-bit)",              "aes-128",
  128,                          0, 0
}, {
  A(AES_192),                   R(MAY),       R(MAY),
  "AES (192-bit)",              "aes-192",
  128,                          0, 0
}, {
  A(AES_256),                   R(MAY),       R(MAY),
  "AES (256-bit)",              "aes-256",
  128,                          0, 0
}, {
  A(TWOFISH),                   R(MAY),       R(MAY),
  "Twofish (256-bit)",          "twofish",
  128,                          0, 0
}, {
  A(CAMELLIA_128),              R(MAY),       R(MAY),
  "Camellia (128-bit)",         "camellia-128",
  128,                          0, 0
}, {
  A(CAMELLIA_192),              R(MAY),       R(MAY),
  "Camellia (192-bit)",         "camellia-192",
  128,                          0, 0
}, {
  A(CAMELLIA_256),              R(MAY),       R(MAY),
  "Camellia (256-bit)",         "camellia-256",
  128,                          0, 0
}, FOOTER, {
#undef A


/* compression algorithms (rfc4880 9.3) */
#define A(a) T(COMPRESSION), PTPGP_COMPRESSION_TYPE_##a
  A(NONE),                      R(MUST),      R(MUST),
  "Uncompressed",               "none",
  0,                            0, 0
}, {
  A(ZIP),                       R(SHOULD),    R(SHOULD),
  "ZIP (RFC1951)",              "zip",
  0,                            0, 0
}, {
  A(ZLIB),                      R(MAY),       R(MAY),
  "ZLIB (RFC1950)",             "zlib",
  0,                            0, 0
}, {
  A(BZIP2),                     R(MAY),       R(MAY),
  "BZip2",                      "bzip2",
  0,                            0, 0
}, FOOTER, {
#undef A


/* hash algorithms (rfc4880 9.4) */
#define A(a) T(HASH), PTPGP_HASH_TYPE_##a
  A(RESERVED_0),                R(MUST_NOT),  R(MUST_NOT),
  "Reserved",                   NULL,
  0,                            0, 0
}, {
  A(MD5),                       R(SHOULD),    R(SHOULD_NOT),
  "MD5 (Deprecated)",           "md5",
  128,                          0, 0
}, {
  A(SHA1),                      R(MUST),      R(MUST),
  "SHA-1",                      "sha1",
  160,                          0, 0
}, {
  A(RIPEMD160),                 R(MAY),       R(MAY),
  "RIPE-MD/160",                "ripemd160",
  160,                          0, 0
}, {
  A(RESERVED_4),                R(MUST_NOT),  R(MUST_NOT),
  "Reserved",                   NULL,
  0,                            0, 0
}, {
  A(RESERVED_5),                R(MUST_NOT),  R(MUST_NOT),
  "Reserved",                   NULL,
  0,                            0, 0
}, {
  A(RESERVED_6),                R(MUST_NOT),  R(MUST_NOT),
  "Reserved",                   NULL,
  0,                            0, 0
}, {
  A(RESERVED_7),                R(MUST_NOT),  R(MUST_NOT),
  "Reserved",                   NULL,
  0,                            0, 0
}, {
  A(SHA256),                    R(MAY),       R(MAY),
  "SHA-256",                    "sha256",
  256,                          0, 0
}, {
  A(SHA384),                    R(MAY),       R(MAY),
  "SHA-384",                    "sha384",
  384,                          0, 0
}, {
  A(SHA512),                    R(MAY),       R(MAY),
  "SHA-512",                    "sha512",
  512,                          0, 0
}, FOOTER, {
#undef A

/* s2k algorithms (rfc4880 3.7) */
#define A(a) T(S2K), PTPGP_S2K_TYPE_##a
  A(SIMPLE),                    R(MUST),      R(SHOULD_NOT),
  "Simple",                     "simple",
  0,                            0, 0
}, {
  A(SALTED),                    R(MUST),      R(MUST),
  "Salted",                     "salted",
  0,                            0, 0
}, {
  A(RESERVED),                  R(MUST_NOT),  R(MUST_NOT),
  "Reserved",                   NULL,
  0,                            0, 0
}, {
  A(ITERATED_AND_SALTED),       R(MUST),      R(MUST),
  "Iterated and Salted",        "iterated",
  0,                            0, 0
}, FOOTER, {
#undef A

  /* sentinel */
  0, 0, 0, 0, 
  0, 0,
  0, 0, 0
}};

ptpgp_err_t
ptpgp_type_info(ptpgp_type_t t,
                uint32_t a,
                ptpgp_type_info_t **r) {
  size_t i;

  if (!r)
    return PTPGP_OK;

  /* could bsearch() this to speed things up, but hey */
  for (i = 0; algos[i].name; i++) {
    if (algos[i].type == t && algos[i].algorithm == a) {
      *r = algos + i;

      /* return success */
      return PTPGP_OK;
    }
  }

  /* return failure */
  return PTPGP_ERR_TYPE_UNKNOWN;
}

ptpgp_err_t
ptpgp_type_to_s(ptpgp_type_t t,
                uint32_t a,
                u8 *dst,
                size_t dst_len,
                size_t *out_len) {
  ptpgp_type_info_t *info;
  ptpgp_err_t err;
  size_t l;

  /* get algorithm info */
  if ((err = ptpgp_type_info(t, a, &info)) != PTPGP_OK)
    return err;

  /* get name length */
  l = strlen(info->name) + 1;

  /* check output buffer */
  if (l > dst_len)
    return PTPGP_ERR_TYPE_DEST_BUFFER_TOO_SMALL;

  /* copy string */
  memcpy(dst, info->name, l);

  if (out_len)
    *out_len = l;

  /* return success */
  return PTPGP_OK;
}

ptpgp_err_t 
ptpgp_type_find(ptpgp_type_t t,
                char *key,
                uint32_t *r) {
  size_t i, l;

  /* could bsearch() this to speed things up, but hey */
  for (i = 0; algos[i].name; i++) {
    /* make sure this is the right type and that the type has a key */
    if (algos[i].type != t || !algos[i].key)
      continue;

    /* get length of key */
    l = strlen(algos[i].key);

    if (!strncasecmp(algos[i].key, key, l)) {
      if (r)
        *r = algos[i].algorithm;

      /* return success */
      return PTPGP_OK;
    }
  }

  /* return failure */
  return PTPGP_ERR_TYPE_UNKNOWN;
}
