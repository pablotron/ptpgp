typedef enum {
  PTPGP_TAG_RESERVED                                    =  0,
  PTPGP_TAG_PUBLIC_KEY_ENCRYPTED_SESSION_KEY            =  1,
  PTPGP_TAG_SIGNATURE                                   =  2,
  PTPGP_TAG_SYMMETRIC_KEY_ENCRYPTED_SESSION_KEY         =  3,
  PTPGP_TAG_ONE_PASS_SIGNATURE                          =  4,
  PTPGP_TAG_SECRET_KEY                                  =  5,
  PTPGP_TAG_PUBLIC_KEY                                  =  6,
  PTPGP_TAG_SECRET_SUBKEY                               =  7,
  PTPGP_TAG_COMPRESSED_DATA                             =  8,
  PTPGP_TAG_SYMMETRICALLY_ENCRYPTED_DATA                =  9,
  PTPGP_TAG_MARKER                                      = 10,
  PTPGP_TAG_LITERAL_DATA                                = 11,
  PTPGP_TAG_TRUST                                       = 12,
  PTPGP_TAG_USER_ID                                     = 13,
  PTPGP_TAG_PUBLIC_SUBKEY                               = 14,

  PTPGP_TAG_USER_ATTRIBUTE                              = 17,
  PTPGP_TAG_SYM_ENCRYPTED_INTEGRITY_PROTECTED_DATA      = 18,
  PTPGP_TAG_MODIFICATION_DETECTION_CODE                 = 19,

  PTPGP_TAG_PRIVATE_OR_EXPERIMENTAL_60                  = 60,
  PTPGP_TAG_PRIVATE_OR_EXPERIMENTAL_61                  = 61,
  PTPGP_TAG_PRIVATE_OR_EXPERIMENTAL_62                  = 62,
  PTPGP_TAG_PRIVATE_OR_EXPERIMENTAL_63                  = 63,

  PTPGP_TAG_LAST                                        = 64
} ptpgp_tag_t;

ptpgp_err_t
ptpgp_tag_to_s(ptpgp_tag_t tag,
               char *buf,
               size_t buf_len,
               size_t *out_len);
