/* symmetric encryption/decryption */

#define PTPGP_ENCRYPT_CONTEXT_BUFFER_SIZE 1024

typedef ptpgp_err_t (*ptpgp_encrypt_context_cb_t)(ptpgp_encrypt_context_t *,
                                                  u8 *, size_t);

typedef struct {
  ptpgp_engine_t                       *engine;

  bool                                  encrypt,
                                        padding;

  ptpgp_symmetric_type_t                algorithm;
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
  void *engine_data;
  u8 buf[PTPGP_ENCRYPT_CONTEXT_BUFFER_SIZE];
  size_t buf_len;
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
