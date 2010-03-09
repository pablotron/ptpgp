typedef enum {
  PTPGP_SIGNATURE_TYPE_DOCUMENT_BINARY          = 0x00,
  PTPGP_SIGNATURE_TYPE_DOCUMENT_TEXT            = 0x01,
  PTPGP_SIGNATURE_TYPE_STANDALONE               = 0x02,
  PTPGP_SIGNATURE_TYPE_CERTIFICATION_GENERIC    = 0x10,
  PTPGP_SIGNATURE_TYPE_CERTIFICATION_PERSONA    = 0x11,
  PTPGP_SIGNATURE_TYPE_CERTIFICATION_CASUAL     = 0x12,
  PTPGP_SIGNATURE_TYPE_CERTIFICATION_POSITIVE   = 0x13,
  PTPGP_SIGNATURE_TYPE_BINDING_SUBKEY           = 0x18,
  PTPGP_SIGNATURE_TYPE_BINDING_PRIMARY_KEY      = 0x19,
  PTPGP_SIGNATURE_TYPE_KEY                      = 0x1F,
  PTPGP_SIGNATURE_TYPE_REVOKATION_KEY           = 0x20,
  PTPGP_SIGNATURE_TYPE_REVOKATION_SUBKEY        = 0x28,
  PTPGP_SIGNATURE_TYPE_REVOKATION_CERTIFICATION = 0x30,
  PTPGP_SIGNATURE_TYPE_TIMESTAMP                = 0x40,
  PTPGP_SIGNATURE_TYPE_THIRD_PARTY_CONFIRMATION = 0x50,

  /* sentinel */
  PTPGP_SIGNATURE_TYPE_LAST                     = 0xff
} ptpgp_signature_type_t;

ptpgp_err_t
ptpgp_signature_type_to_s(ptpgp_signature_type_t, 
                          u8 *dst,
                          size_t dst_len,
                          size_t *out_len);
ptpgp_err_t
ptpgp_signature_type_description(ptpgp_signature_type_t, 
                                 u8 *dst,
                                 size_t dst_len,
                                 size_t *out_len);
