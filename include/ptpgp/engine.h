/* 
 * typedef struct {
 *   ptpgp_context_init_cb_t init, 
 *                           done;
 *   ptpgp_context_push_cb_t push;
 * } ptpgp_engine_cb_set_t;
 * 
 */ 

/* forward-reference typedef in engine-structs.h */
struct ptpgp_engine_t_ {
  /* internal engine data */
  void *engine_data;

  /* symmetric encryption handlers */
  struct {
    ptpgp_err_t (*init)(ptpgp_encrypt_context_t *);
    ptpgp_err_t (*push)(ptpgp_encrypt_context_t *, 
                        u8 *, size_t);
    ptpgp_err_t (*done)(ptpgp_encrypt_context_t *);
  } encrypt;

/* 
 *   struct {
 *     ptpgp_err_t (*init)(ptpgp_hash_context_t *, 
 *                         ptpgp_hash_options_t *);
 *     ptpgp_err_t (*push)(ptpgp_hash_context_t *, 
 *                         u8 *, size_t);
 *     ptpgp_err_t (*done)(ptpgp_hash_context_t *);
 *   } hash;
 */ 

  /* crypto callbacks for this engine */
  /* ptpgp_engine_cb_set_t sign,
                        verify,
                        encrypt,
                        genkey,
                        hash,
                        random; */
};
