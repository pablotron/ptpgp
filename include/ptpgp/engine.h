/* 
 * typedef struct {
 *   ptpgp_context_init_cb_t init, 
 *                           done;
 *   ptpgp_context_push_cb_t push;
 * } ptpgp_engine_cb_set_t;
 * 
 */ 

/* symmetric encryption handlers */
typedef struct {
  ptpgp_err_t (*init)(ptpgp_encrypt_context_t *);
  ptpgp_err_t (*push)(ptpgp_encrypt_context_t *, 
                      u8 *, size_t);
  ptpgp_err_t (*done)(ptpgp_encrypt_context_t *);
} ptpgp_engine_encrypt_handlers_t;

/* hash (message digest) handlers */
typedef struct {
  ptpgp_err_t (*init)(ptpgp_hash_context_t *);
  ptpgp_err_t (*push)(ptpgp_hash_context_t *, 
                      u8 *, size_t);
  ptpgp_err_t (*done)(ptpgp_hash_context_t *);
} ptpgp_engine_hash_handlers_t;

/* random handlers */
typedef struct {
  ptpgp_err_t (*strong)(ptpgp_engine_t *, u8*, size_t);
  ptpgp_err_t (*nonce)(ptpgp_engine_t *, u8*, size_t);
} ptpgp_engine_random_handlers_t;

/* forward-reference typedef in engine-structs.h */
struct ptpgp_engine_t_ {
  /* internal engine data */
  void *engine_data;

  ptpgp_engine_encrypt_handlers_t encrypt;
  ptpgp_engine_hash_handlers_t    hash;
  ptpgp_engine_random_handlers_t  random;

  /* crypto callbacks for this engine */
  /* ptpgp_engine_cb_set_t sign,
                        verify,
                        encrypt,
                        genkey,
                        hash,
                        random; */
};
