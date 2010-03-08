#define PTPGP_STREAM_PARSER_STATE_STACK_DEPTH        1024
#define PTPGP_STREAM_PARSER_BUFFER_SIZE              4096

typedef enum {
  PTPGP_STREAM_PARSER_TOKEN_START,
  PTPGP_STREAM_PARSER_TOKEN_BODY,
  PTPGP_STREAM_PARSER_TOKEN_END,
  PTPGP_STREAM_PARSER_TOKEN_LAST
} ptpgp_stream_parser_token_t;

typedef struct ptpgp_stream_parser_t_ ptpgp_stream_parser_t;

typedef ptpgp_err_t (*ptpgp_stream_parser_cb_t)(ptpgp_stream_parser_t *,
                                                ptpgp_stream_parser_token_t,
                                                ptpgp_packet_header_t *,
                                                u8 *, size_t);
typedef enum {
  PTPGP_STREAM_PARSER_STATE_NONE,
  PTPGP_STREAM_PARSER_STATE_NEW_HEADER_AFTER_TAG,
  PTPGP_STREAM_PARSER_STATE_OLD_HEADER_AFTER_TAG,
  PTPGP_STREAM_PARSER_STATE_BODY,
  PTPGP_STREAM_PARSER_STATE_PARTIAL_BODY_LENGTH,
  PTPGP_STREAM_PARSER_STATE_LAST
} ptpgp_stream_parser_state_t;

struct ptpgp_stream_parser_t_ {
  ptpgp_stream_parser_state_t state[PTPGP_STREAM_PARSER_STATE_STACK_DEPTH];
  size_t state_len;

  /* last parser error */
  ptpgp_err_t last_err;

  /* parser finished flag */
  char is_done;

  u8 buf[PTPGP_STREAM_PARSER_BUFFER_SIZE];
  size_t buf_len;

  /* remaining octets for header length */
  size_t remaining_length_octets;

  /* cache of last packet header */
  ptpgp_packet_header_t header;

  uint32_t partial_body_length;

  /* number of bytes read from the current packet */
  uint32_t bytes_read;

  /* callback members */
  ptpgp_stream_parser_cb_t cb;
  void *cb_data;
};

ptpgp_err_t
ptpgp_stream_parser_init(ptpgp_stream_parser_t *p,
                         ptpgp_stream_parser_cb_t cb,
                         void *cb_data);
ptpgp_err_t
ptpgp_stream_parser_push(ptpgp_stream_parser_t *p,
                         u8 *src,
                         size_t src_len);
ptpgp_err_t
ptpgp_stream_parser_done(ptpgp_stream_parser_t *p);
