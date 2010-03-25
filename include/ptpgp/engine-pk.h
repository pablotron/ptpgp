typedef enum {
  PTPGP_PK_GENKEY_STATE_INIT,
  PTPGP_PK_GENKEY_STATE_LAST
} ptpgp_pk_genkey_state_t;

/* TODO: add paramteres to context callback */
typedef ptpgp_err_t (*ptpgp_pk_genkey_cb_t)(ptpgp_pk_genkey_context_t *,    
                                            ptpgp_pk_genkey_state_t);

typedef struct {
  ptpgp_engine_t          *engine;

  ptpgp_public_key_type_t  algorithm; 
  size_t                   num_bits;

  ptpgp_pk_genkey_cb_t     cb;
  void                    *user_data;

  /* algorithm-specific parameters */
  union {
    struct {
      uint32_t e;
    } rsa;

    struct {
      /* TODO */ 
      uint32_t placeholder;
    } dsa;
  } params;

  /* output key */
  ptpgp_pk_key_t key;
} ptpgp_pk_genkey_options_t;

struct ptpgp_pk_genkey_context_t_ {
  void                     *engine_data;
  ptpgp_pk_key_t            key;
  ptpgp_pk_genkey_options_t options;
};

ptpgp_err_t
ptpgp_engine_pk_generate_key(ptpgp_pk_genkey_context_t *, 
                             ptpgp_pk_genkey_options_t *);
