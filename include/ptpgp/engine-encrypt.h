/* symmetric encryption/decryption */

/* FIXME: move this elsewhere */
typedef enum {
  PTPGP_SYMMETRIC_MODE_NONE,
  PTPGP_SYMMETRIC_MODE_ECB,
  PTPGP_SYMMETRIC_MODE_CFB,
  PTPGP_SYMMETRIC_MODE_CBC,
  PTPGP_SYMMETRIC_MODE_OFB,

  /* XXX: do i need this? */
  PTPGP_SYMMETRIC_MODE_STREAM,

  PTPGP_SYMMETRIC_MODE_LAST
} ptpgp_symmetric_mode_type_t;

typedef ptpgp_err_t (*ptpgp_encrypt_context_cb_t)(ptpgp_encrypt_context_t *,
                                                  u8 *, size_t);

typedef struct {
  ptpgp_engine_t                       *engine;

  bool                                  encrypt,
                                        padding;

  ptpgp_symmetric_key_algorithm_type_t  algorithm;
  ptpgp_symmetric_mode_type_t           mode;

  u8                                   *iv,
                                       *key;

  /* XXX: do i need these? */
  size_t                                iv_len,
                                        key_len;

  ptpgp_encrypt_context_cb_t            cb;
  void                                 *user_data;
} ptpgp_encrypt_options_t;

struct ptpgp_encrypt_context_t_ {
  void                    *engine_data;
  ptpgp_encrypt_options_t  options;
};

ptpgp_err_t
ptpgp_engine_encrypt_init(ptpgp_encrypt_context_t *,
                          ptpgp_encrypt_options_t *);

ptpgp_err_t
ptpgp_engine_encrypt_push(ptpgp_encrypt_context_t *,
                          u8 *,
                          size_t);

ptpgp_err_t
ptpgp_engine_encrypt_done(ptpgp_encrypt_context_t *);
