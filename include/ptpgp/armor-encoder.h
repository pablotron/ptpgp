#define PTPGP_ARMOR_ENCODER_ENVELOPE_NAME_SIZE  70
#define PTPGP_ARMOR_ENCODER_HEADER_VALUE_SIZE   70
#define PTPGP_ARMOR_ENCODER_OUT_BUF_SIZE        512

typedef struct ptpgp_armor_encoder_t_ ptpgp_armor_encoder_t;

typedef ptpgp_err_t (*ptpgp_armor_encoder_cb_t)(ptpgp_armor_encoder_t *,
                                                u8 *, size_t);

struct ptpgp_armor_encoder_t_ {
  ptpgp_err_t last_err;

  bool is_done;
  char envelope_name[PTPGP_ARMOR_ENCODER_ENVELOPE_NAME_SIZE];

  u8 buf[PTPGP_ARMOR_ENCODER_OUT_BUF_SIZE];
  size_t buf_len;

  ptpgp_armor_encoder_cb_t cb;
  void *user_data;

  ptpgp_base64_t base64;
  ptpgp_crc24_t  crc24;
};

ptpgp_err_t
ptpgp_armor_encoder_init(ptpgp_armor_encoder_t *p,
                         char *envelope_name,
                         char **headers,
                         ptpgp_armor_encoder_cb_t cb,
                         void *user_data);

ptpgp_err_t
ptpgp_armor_encoder_push(ptpgp_armor_encoder_t *p,
                         u8 *src,
                         size_t src_len);

ptpgp_err_t
ptpgp_armor_encoder_done(ptpgp_armor_encoder_t *p);
