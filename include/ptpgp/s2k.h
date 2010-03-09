
typedef struct {
  ptpgp_s2k_algorithm_type_t type;
  ptpgp_hash_algorithm_type_t algorithm;
  u8 salt[8];

  uint32_t count;
} ptpgp_s2k_t;

#define PTPGP_S2K_COUNT_DECODE(c) (               \
  ((uint32_t) (16 + (c & 15))) << ((c >> 4) + 6)  \
)

ptpgp_err_t
ptpgp_s2k_init(ptpgp_s2k_t *s2k,
               ptpgp_s2k_algorithm_type_t type,
               ptpgp_hash_algorithm_type_t algo,
               u8 *salt,
               uint32_t count);

ptpgp_err_t
ptpgp_s2k_to_s(ptpgp_s2k_t *, 
               char *,
               size_t,
               size_t *);
