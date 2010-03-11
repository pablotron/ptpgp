#define PTPGP_ARMOR_PARSER_BUFFER_SIZE          1024
#define PTPGP_ARMOR_PARSER_OUTPUT_BUFFER_SIZE   1024

typedef struct ptpgp_armor_parser_t_ ptpgp_armor_parser_t;

typedef enum {
  PTPGP_ARMOR_PARSER_TOKEN_START_ARMOR,
  PTPGP_ARMOR_PARSER_TOKEN_HEADER_NAME,
  PTPGP_ARMOR_PARSER_TOKEN_HEADER_VALUE,
  PTPGP_ARMOR_PARSER_TOKEN_BODY,
  PTPGP_ARMOR_PARSER_TOKEN_CRC24,
  PTPGP_ARMOR_PARSER_TOKEN_END_ARMOR,
  PTPGP_ARMOR_PARSER_TOKEN_DONE,
  PTPGP_ARMOR_PARSER_TOKEN_LAST
} ptpgp_armor_parser_token_t;

typedef ptpgp_err_t (*ptpgp_armor_parser_cb_t)(ptpgp_armor_parser_t *,
                                      ptpgp_armor_parser_token_t,
                                      u8 *, size_t);

typedef enum {
  PTPGP_ARMOR_PARSER_STATE_NONE,
  PTPGP_ARMOR_PARSER_STATE_LINE_START,
  PTPGP_ARMOR_PARSER_STATE_MAYBE_ENVELOPE,
  PTPGP_ARMOR_PARSER_STATE_HEADERS,
  PTPGP_ARMOR_PARSER_STATE_BODY,
  PTPGP_ARMOR_PARSER_STATE_DONE,
  PTPGP_ARMOR_PARSER_STATE_LAST
} ptpgp_armor_parser_state_t;

struct ptpgp_armor_parser_t_ {
  ptpgp_err_t last_err;

  ptpgp_armor_parser_state_t state;

  ptpgp_armor_parser_cb_t cb;
  void *user_data;

  u8 buf[PTPGP_ARMOR_PARSER_BUFFER_SIZE];
  size_t buf_len;

  u8 out_buf[PTPGP_ARMOR_PARSER_OUTPUT_BUFFER_SIZE];
  size_t out_buf_len;
};

ptpgp_err_t
ptpgp_armor_parser_init(ptpgp_armor_parser_t *p, ptpgp_armor_parser_cb_t cb, void *user_data);

ptpgp_err_t
ptpgp_armor_parser_push(ptpgp_armor_parser_t *p, u8 *src, size_t src_len);

ptpgp_err_t
ptpgp_armor_parser_done(ptpgp_armor_parser_t *p);
