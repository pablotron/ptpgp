#define H(a) PTPGP_KEY_FLAG_##a
typedef enum {
  H(CERTIFY)                = 0x01,
  H(SIGN_DATA)              = 0x02,
  H(ENCRYPT_COMMUNICATION)  = 0x04,
  H(ENCRYPT_STORAGE)        = 0x08,
  H(SPLIT_PRIVATE_KEY)      = 0x10,
  H(AUTHENTICATION)         = 0x20,
  H(SHARED_PRIVATE_KEY)     = 0x80,

  /* sentinel */
  H(LAST)                   = 0xff
} ptpgp_key_flag_t;
#undef H

typedef struct {
  ptpgp_key_flag_t flag;
  char *name,
       *description;
} ptpgp_key_flag_info_t;

ptpgp_err_t
ptpgp_key_flag_info(ptpgp_key_flag_t,
                    ptpgp_key_flag_info_t **);

ptpgp_err_t
ptpgp_key_flag_to_s(ptpgp_key_flag_t,
                    char *,
                    size_t, 
                    size_t *);
