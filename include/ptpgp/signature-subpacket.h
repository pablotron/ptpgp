typedef enum {
  PTPGP_SIGNATURE_SUBPACKET_TYPE_RESERVED_0                              =   0,
  PTPGP_SIGNATURE_SUBPACKET_TYPE_RESERVED_1                              =   1,
  PTPGP_SIGNATURE_SUBPACKET_TYPE_SIGNATURE_CREATION_TIME                 =   2,
  PTPGP_SIGNATURE_SUBPACKET_TYPE_SIGNATURE_EXPIRATION_TIME               =   3,
  PTPGP_SIGNATURE_SUBPACKET_TYPE_EXPORTABLE_CERTIFICATION                =   4,
  PTPGP_SIGNATURE_SUBPACKET_TYPE_TRUST_SIGNATURE                         =   5,
  PTPGP_SIGNATURE_SUBPACKET_TYPE_REGULAR_EXPRESSION                      =   6,
  PTPGP_SIGNATURE_SUBPACKET_TYPE_REVOCABLE                               =   7,
  PTPGP_SIGNATURE_SUBPACKET_TYPE_RESERVED_8                              =   8,
  PTPGP_SIGNATURE_SUBPACKET_TYPE_KEY_EXPIRATION_TIME                     =   9,
  PTPGP_SIGNATURE_SUBPACKET_TYPE_PLACEHOLDER_FOR_BACKWARD_COMPATIBILITY  =  10,
  PTPGP_SIGNATURE_SUBPACKET_TYPE_PREFERRED_SYMMETRIC_ALGORITHMS          =  11,
  PTPGP_SIGNATURE_SUBPACKET_TYPE_REVOCATION_KEY                          =  12,
  PTPGP_SIGNATURE_SUBPACKET_TYPE_RESERVED_13                             =  13,
  PTPGP_SIGNATURE_SUBPACKET_TYPE_RESERVED_14                             =  14,
  PTPGP_SIGNATURE_SUBPACKET_TYPE_RESERVED_15                             =  15,
  PTPGP_SIGNATURE_SUBPACKET_TYPE_ISSUER                                  =  16,
  PTPGP_SIGNATURE_SUBPACKET_TYPE_RESERVED_16                             =  17,
  PTPGP_SIGNATURE_SUBPACKET_TYPE_RESERVED_17                             =  18,
  PTPGP_SIGNATURE_SUBPACKET_TYPE_RESERVED_18                             =  19,
  PTPGP_SIGNATURE_SUBPACKET_TYPE_NOTATION_DATA                           =  20,
  PTPGP_SIGNATURE_SUBPACKET_TYPE_PREFERRED_HASH_ALGORITHMS               =  21,
  PTPGP_SIGNATURE_SUBPACKET_TYPE_PREFERRED_COMPRESSION_ALGORITHMS        =  22,
  PTPGP_SIGNATURE_SUBPACKET_TYPE_KEY_SERVER_PREFERENCES                  =  23,
  PTPGP_SIGNATURE_SUBPACKET_TYPE_PREFERRED_KEY_SERVER                    =  24,
  PTPGP_SIGNATURE_SUBPACKET_TYPE_PRIMARY_USER_ID                         =  25,
  PTPGP_SIGNATURE_SUBPACKET_TYPE_POLICY_URI                              =  26,
  PTPGP_SIGNATURE_SUBPACKET_TYPE_KEY_FLAGS                               =  27,
  PTPGP_SIGNATURE_SUBPACKET_TYPE_SIGNERS_USER_ID                         =  28,
  PTPGP_SIGNATURE_SUBPACKET_TYPE_REASON_FOR_REVOCATION                   =  29,
  PTPGP_SIGNATURE_SUBPACKET_TYPE_FEATURES                                =  30,
  PTPGP_SIGNATURE_SUBPACKET_TYPE_SIGNATURE_TARGET                        =  31,
  PTPGP_SIGNATURE_SUBPACKET_TYPE_EMBEDDED_SIGNATURE                      =  32,
  PTPGP_SIGNATURE_SUBPACKET_TYPE_PRIVATE_OR_EXPERIMENTAL_100             = 100,
  PTPGP_SIGNATURE_SUBPACKET_TYPE_PRIVATE_OR_EXPERIMENTAL_101             = 101,
  PTPGP_SIGNATURE_SUBPACKET_TYPE_PRIVATE_OR_EXPERIMENTAL_102             = 102,
  PTPGP_SIGNATURE_SUBPACKET_TYPE_PRIVATE_OR_EXPERIMENTAL_103             = 103,
  PTPGP_SIGNATURE_SUBPACKET_TYPE_PRIVATE_OR_EXPERIMENTAL_104             = 104,
  PTPGP_SIGNATURE_SUBPACKET_TYPE_PRIVATE_OR_EXPERIMENTAL_105             = 105,
  PTPGP_SIGNATURE_SUBPACKET_TYPE_PRIVATE_OR_EXPERIMENTAL_106             = 106,
  PTPGP_SIGNATURE_SUBPACKET_TYPE_PRIVATE_OR_EXPERIMENTAL_107             = 107,
  PTPGP_SIGNATURE_SUBPACKET_TYPE_PRIVATE_OR_EXPERIMENTAL_108             = 108,
  PTPGP_SIGNATURE_SUBPACKET_TYPE_PRIVATE_OR_EXPERIMENTAL_109             = 109,
  PTPGP_SIGNATURE_SUBPACKET_TYPE_PRIVATE_OR_EXPERIMENTAL_110             = 110,

  /* sentinel */
  PTPGP_SIGNATURE_SUBPACKET_TYPE_LAST                                    = 127
} ptpgp_signature_subpacket_type_t;

typedef struct {
  ptpgp_signature_subpacket_type_t type;
  size_t size;
  char   critical;
} ptpgp_signature_subpacket_header_t;

ptpgp_err_t
ptpgp_signature_subpacket_type_to_s(ptpgp_signature_subpacket_type_t, 
                                    char *, 
                                    size_t,
                                    size_t *);
