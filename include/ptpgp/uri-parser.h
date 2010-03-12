/* 
 * typedef struct {
 *   u8 scheme[32],
 *      auth[128],
 *      host[256],
 *      port[32],
 *      path[1024],
 *      query[1024];
 * } ptpgp_uri_t;
 * 
 */ 

#define PTPGP_URI_PARSER_BUFFER_SIZE 1024

typedef struct ptpgp_uri_parser_t_ ptpgp_uri_parser_t;

typedef enum {
  PTPGP_URI_PARSER_TOKEN_INIT,

  PTPGP_URI_PARSER_TOKEN_SCHEME,
  PTPGP_URI_PARSER_TOKEN_AUTH,
  PTPGP_URI_PARSER_TOKEN_HOST,
  PTPGP_URI_PARSER_TOKEN_PORT,
  PTPGP_URI_PARSER_TOKEN_PATH,
  PTPGP_URI_PARSER_TOKEN_QUERY,
  PTPGP_URI_PARSER_TOKEN_FRAGMENT,

  /* sentinel */
  PTPGP_URI_PARSER_TOKEN_LAST
} ptpgp_uri_parser_token_t;

typedef enum {
  PTPGP_URI_PARSER_STATE_INIT,

  PTPGP_URI_PARSER_STATE_AFTER_SCHEME,
  PTPGP_URI_PARSER_STATE_AFTER_AUTH,
  PTPGP_URI_PARSER_STATE_PATH,
  PTPGP_URI_PARSER_STATE_QUERY,
  PTPGP_URI_PARSER_STATE_FRAGMENT,

  /* sentinel */
  PTPGP_URI_PARSER_STATE_LAST
} ptpgp_uri_parser_state_t;

typedef ptpgp_err_t (*ptpgp_uri_parser_cb_t)(ptpgp_uri_parser_t *,
                                             ptpgp_uri_parser_token_t,
                                             u8 *, size_t);

struct ptpgp_uri_parser_t_ {
  ptpgp_err_t last_err;
  bool is_done;

  ptpgp_uri_parser_state_t state;

  u8 buf[PTPGP_URI_PARSER_BUFFER_SIZE];
  size_t buf_len;

  ptpgp_uri_parser_cb_t cb;
  void *user_data;
};

ptpgp_err_t
ptpgp_uri_parser_init(ptpgp_uri_parser_t *,
                      ptpgp_uri_parser_cb_t,
                      void *);

ptpgp_err_t
ptpgp_uri_parser_push(ptpgp_uri_parser_t *,
                      u8 *, size_t);

ptpgp_err_t
ptpgp_uri_parser_done(ptpgp_uri_parser_t *);
