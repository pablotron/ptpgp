
struct ptpgp_hash_context_t_ {
  ptpgp_engine_t               *engine;
  void                         *engine_data;

  ptpgp_hash_type_t             algorithm;

  bool                          done;

  u8                            hash[128];
  size_t                        hash_len;
};

ptpgp_err_t
ptpgp_engine_hash_init(ptpgp_hash_context_t *,
                       ptpgp_engine_t *,
                       ptpgp_hash_type_t);

ptpgp_err_t
ptpgp_engine_hash_push(ptpgp_hash_context_t *,
                       u8 *,
                       size_t);

ptpgp_err_t
ptpgp_engine_hash_done(ptpgp_hash_context_t *);

ptpgp_err_t
ptpgp_engine_hash_read(ptpgp_hash_context_t *, 
                       u8 *,
                       size_t,
                       size_t *);

ptpgp_err_t
ptpgp_engine_hash_once(ptpgp_engine_t *engine,
                       ptpgp_hash_type_t algorithm,
                       u8 *src, size_t src_len,
                       u8 *dst, size_t dst_len, 
                       size_t *out_len);
