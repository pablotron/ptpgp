typedef struct {
  ptpgp_err_t last_err;
  bool done;
  uint32_t crc;
} ptpgp_crc24_t;

ptpgp_err_t ptpgp_crc24_init(ptpgp_crc24_t *);
ptpgp_err_t ptpgp_crc24_push(ptpgp_crc24_t *, u8 *, size_t);
ptpgp_err_t ptpgp_crc24_done(ptpgp_crc24_t *);
