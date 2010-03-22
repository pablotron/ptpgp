#define FOOTER \
  H(PRIVATE_100) = 100, \
  H(PRIVATE_101) = 101, \
  H(PRIVATE_102) = 102, \
  H(PRIVATE_103) = 103, \
  H(PRIVATE_104) = 104, \
  H(PRIVATE_105) = 105, \
  H(PRIVATE_106) = 106, \
  H(PRIVATE_107) = 107, \
  H(PRIVATE_108) = 108, \
  H(PRIVATE_109) = 109, \
  H(PRIVATE_110) = 110, \
  H(LAST) = 127


/***************/
/* ptpgp types */
/***************/

#define H(a) PTPGP_TYPE_##a
typedef enum {
  /* algorithm types */
  H(TYPE),

  /* public key algorithms (rfc4880 9.1) */
  H(PUBLIC_KEY),

  /* symmetric algorithms (rfc4880 9.2) */
  H(SYMMETRIC),

  /* symmetric modes */
  H(SYMMETRIC_MODE),

  /* compression algorithms (rfc4880 9.3) */
  H(COMPRESSION),

  /* hash algorithms (rfc4880 9.4) */
  H(HASH),

  /* s2k algorithms (rfc4880 3.7) */
  H(S2K),

  /* sentinel */
  H(LAST)
} ptpgp_type_t;
#undef H


/****************/
/* requirements */
/****************/

#define H(a) PTPGP_REQUIREMENT_##a
typedef enum {
  H(MUST),
  H(MUST_NOT),
  H(SHOULD),
  H(SHOULD_NOT),
  H(MAY),

  /* sentinel */
  H(LAST)
} ptpgp_requirement_t;
#undef H

typedef struct {
  ptpgp_type_t           type;
  uint32_t               algorithm;

  ptpgp_requirement_t    interpret,
                         generate;

  char                  *name, 
                        *key;

  /* algorithm-specific numbers */
  uint32_t               a, b;
} ptpgp_type_info_t;


/***************************************/
/* public key algorithms (rfc4880 9.1) */
/***************************************/

#define PTPGP_INFO_PUBLIC_KEY_NUM_PUBLIC_MPIS(info) ((info)->a)
#define PTPGP_INFO_PUBLIC_KEY_NUM_PRIVATE_MPIS(info) ((info)->b)

/* algorithms */
#define H(a) PTPGP_PUBLIC_KEY_TYPE_##a
typedef enum {
  H(RESERVED_0)               = 0,
  H(RSA)                      = 1,
  H(RSA_ENCRYPT_ONLY)         = 2,
  H(RSA_SIGN_ONLY)            = 3,
  H(ELGAMAL_ENCRYPT_ONLY)     = 16,
  H(DSA)                      = 17,
  H(EC)                       = 18,
  H(ECDSA)                    = 19,
  H(ELGAMAL_ENCRYPT_OR_SIGN)  = 20,
  H(DH)                       = 21,

  FOOTER
} ptpgp_public_key_type_t;
#undef H


/******************************************/
/* symmetric key algorithms (rfc4880 9.2) */
/******************************************/

#define PTPGP_INFO_SYMMETRIC_BLOCK_SIZE(info) ((info)->a)
#define PTPGP_INFO_SYMMETRIC_KEY_SIZE(info) ((info)->b)

/* algorithms */
#define H(a) PTPGP_SYMMETRIC_TYPE_##a
typedef enum {
  H(PLAINTEXT)                = 0,
  H(IDEA)                     = 1,
  H(TRIPLEDES)                = 2,
  H(CAST5)                    = 3,
  H(BLOWFISH)                 = 4,
  H(RESERVED_5)               = 5,
  H(RESERVED_6)               = 6,
  H(AES_128)                  = 7,
  H(AES_192)                  = 8,
  H(AES_256)                  = 9,
  H(TWOFISH)                  = 10,

  /* rfc5581 */
  H(CAMELLIA_128)             = 11,
  H(CAMELLIA_192)             = 12,
  H(CAMELLIA_256)             = 13,

  FOOTER
} ptpgp_symmetric_type_t;
#undef H


/*****************************/
/* symmetric algorithm modes */
/*****************************/

/* modes */
#define H(a) PTPGP_SYMMETRIC_MODE_TYPE_##a
typedef enum {
  H(NONE),
  H(ECB),
  H(CFB),
  H(CBC),
  H(OFB),
  H(CTR),
  H(STREAM),

  /* sentinel */
  H(LAST)
} ptpgp_symmetric_mode_type_t;
#undef H


/**************************/
/* compression algorithms */
/**************************/

#define H(a) PTPGP_COMPRESSION_TYPE_##a
typedef enum {
  H(NONE),
  H(ZIP),
  H(ZLIB),
  H(BZIP2),

  FOOTER
} ptpgp_compression_type_t;
#undef H


/*******************/
/* hash algorithms */
/*******************/

#define H(a) PTPGP_HASH_TYPE_##a
typedef enum {
  H(RESERVED_0),
  H(MD5),
  H(SHA1),
  H(RIPEMD160),
  H(RESERVED_4),
  H(RESERVED_5),
  H(RESERVED_6),
  H(RESERVED_7),
  H(SHA256),
  H(SHA384),
  H(SHA512),

  FOOTER
} ptpgp_hash_type_t;
#undef H


/******************/
/* s2k specifiers */
/******************/

#define H(a) PTPGP_S2K_TYPE_##a
typedef enum {
  H(SIMPLE)               = 0,
  H(SALTED)               = 1,
  H(RESERVED)             = 2,
  H(ITERATED_AND_SALTED)  = 3,

  FOOTER
} ptpgp_s2k_type_t;
#undef H


ptpgp_err_t
ptpgp_type_to_s(ptpgp_type_t, 
                uint32_t, u8 *,
                size_t,
                size_t *);

ptpgp_err_t
ptpgp_type_info(ptpgp_type_t, 
                uint32_t, 
                ptpgp_type_info_t **);

ptpgp_err_t 
ptpgp_type_find(ptpgp_type_t,
                char *,
                uint32_t *);

#undef FOOTER
