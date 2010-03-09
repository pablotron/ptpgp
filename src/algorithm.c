#include "internal.h"

#define T(s) PTPGP_ALGORITHM_TYPE_##s
#define R(s) PTPGP_REQUIREMENT_##s

#define F(k) { A(k), R(MUST_NOT), R(MUST_NOT), "Private/Experimental", 0, 0 }

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

static ptpgp_algorithm_info_t algos[] = {{
/* public key algorithms (rfc4880 9.1) */
#define A(a) T(PUBLIC_KEY), PTPGP_PUBLIC_KEY_ALGORITHM_TYPE_##a
  A(RESERVED_0),                R(MUST_NOT),  R(MUST_NOT), 
  "Reserved",                   NULL,         NULL
}, {
  A(RSA),                       R(SHOULD),    R(SHOULD),
  "RSA",                        NULL,         NULL
}, {
  A(RSA_ENCRYPT_ONLY),          R(MAY),       R(SHOULD_NOT),
  "RSA (Encrypt-Only)",         NULL,         NULL
}, {
  A(RSA_SIGN_ONLY),             R(MAY),       R(SHOULD_NOT),
  "RSA (Sign-Only)",            NULL,         NULL
}, {
  A(ELGAMEL_ENCRYPT_ONLY),      R(MUST),      R(MUST),  
  "Elgamal (Encrypt-Only)",     NULL,         NULL
}, {
  A(DSA),                       R(MUST),      R(MUST),
  "DSA",                        NULL,         NULL
}, {
  A(EC),                        R(MUST_NOT),  R(MUST_NOT),
  "Elliptic Curve (Reserved)",  NULL,         NULL
}, {
  A(ECDSA),                     R(MUST_NOT),  R(MUST_NOT),
  "ECDSA (Reserved)",           NULL,         NULL
}, {
  A(ELGAMAL_ENCRYPT_OR_SIGN),   R(MAY),       R(MUST_NOT),
  "Elgamal (Deprecated)",       NULL,         NULL
}, {
  A(DH),                        R(MUST_NOT),  R(MUST_NOT),
  "Diffie-Hellman",             NULL,         NULL
}, FOOTER, {
#undef A


/* symmetric key algorithms (rfc4880 9.2) */
#define A(a) T(SYMMETRIC_KEY), PTPGP_SYMMETRIC_KEY_ALGORITHM_TYPE_##a
  A(PLAINTEXT),                 R(MUST),      R(MUST),
  "Plaintext",                   NULL,         NULL
}, {
  A(IDEA),                      R(SHOULD),    R(SHOULD_NOT),
  "IDEA",                       NULL,         NULL
}, {
  A(TRIPLEDES),                 R(MUST),      R(MUST),
  "TripleDES (DES-EDE)",        NULL,         NULL
}, {
  A(CAST5),                     R(SHOULD),    R(SHOULD),
  "CAST5 (128-bit)",            NULL,         NULL
}, {
  A(BLOWFISH),                  R(MAY),       R(MAY),
  "Blowfish (128-bit)",         NULL,         NULL
}, {
  A(RESERVED_5),                R(MUST_NOT),  R(MUST_NOT),
  "Reserved",                   NULL,         NULL
}, {
  A(RESERVED_6),                R(MUST_NOT),  R(MUST_NOT),
  "Reserved",                   NULL,         NULL
}, {
  A(AES_128),                   R(SHOULD),    R(SHOULD),
  "AES (128-bit)",              NULL,         NULL
}, {
  A(AES_192),                   R(MAY),       R(MAY),
  "AES (192-bit)",              NULL,         NULL
}, {
  A(AES_256),                   R(MAY),       R(MAY),
  "AES (256-bit)",              NULL,         NULL
}, {
  A(TWOFISH),                   R(MAY),       R(MAY),
  "Twofish (256-bit)",          NULL,         NULL
}, FOOTER, {
#undef A


/* compression algorithms (rfc4880 9.3) */
#define A(a) T(COMPRESSION), PTPGP_COMPRESSION_ALGORITHM_TYPE_##a
  A(NONE),                      R(MUST),      R(MUST),
  "Uncompressed",               NULL,         NULL
}, {
  A(ZIP),                       R(SHOULD),    R(SHOULD),
  "ZIP (RFC1951)",              NULL,         NULL
}, {
  A(ZLIB),                      R(MAY),       R(MAY),
  "ZLIB (RFC1950)",             NULL,         NULL
}, {
  A(BZIP2),                     R(MAY),       R(MAY),
  "BZip2",                      NULL,         NULL
}, FOOTER, {
#undef A


/* hash algorithms (rfc4880 9.4) */
#define A(a) T(HASH), PTPGP_HASH_ALGORITHM_TYPE_##a
  A(RESERVED_0),                R(MUST_NOT),  R(MUST_NOT),
  "Reserved",                   NULL,         NULL
}, {
  A(MD5),                       R(SHOULD),    R(SHOULD_NOT),
  "MD5 (Deprecated)",           NULL,         NULL
}, {
  A(SHA1),                      R(MUST),      R(MUST),
  "SHA-1",                      NULL,         NULL
}, {
  A(RIPEMD160),                 R(MAY),       R(MAY),
  "RIPE-MD/160",                NULL,         NULL
}, {
  A(RESERVED_4),                R(MUST_NOT),  R(MUST_NOT),
  "Reserved",                   NULL,         NULL
}, {
  A(RESERVED_5),                R(MUST_NOT),  R(MUST_NOT),
  "Reserved",                   NULL,         NULL
}, {
  A(RESERVED_6),                R(MUST_NOT),  R(MUST_NOT),
  "Reserved",                   NULL,         NULL
}, {
  A(RESERVED_7),                R(MUST_NOT),  R(MUST_NOT),
  "Reserved",                   NULL,         NULL
}, {
  A(SHA256),                    R(MAY),       R(MAY),
  "SHA-256",                    NULL,         NULL
}, {
  A(SHA384),                    R(MAY),       R(MAY),
  "SHA-384",                    NULL,         NULL
}, {
  A(SHA512),                    R(MAY),       R(MAY),
  "SHA-512",                    NULL,         NULL
}, FOOTER, {
#undef A

  /* sentinel */
  0, 0, 0, 0, 0, 0, 0
}};

ptpgp_err_t
ptpgp_algorithm_info(ptpgp_algorithm_type_t t, 
                     uint32_t a, 
                     ptpgp_algorithm_info_t **r) {
  size_t i;

  if (!r)
    return PTPGP_OK;

  /* could bsearch() this to speed things up, but hey */
  for (i = 0; algos[i].name; i++) {
    if (algos[i].type == t && algos[i].algorithm == a) {
      *r = algos + i;
      return PTPGP_OK;
    }
  }

  /* return success */
  return PTPGP_ERR_ALGORITHM_UNKNOWN;
}


ptpgp_err_t
ptpgp_algorithm_to_s(ptpgp_algorithm_type_t, 
                     uint32_t, u8 *,
                     size_t,
                     size_t *);
