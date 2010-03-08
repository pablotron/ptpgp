#define PTPGP_PACKET_PARSER_BUFFER_SIZE 1024

typedef enum {
  PTPGP_PACKET_PARSER_TOKEN_PACKET_START,
  PTPGP_PACKET_PARSER_TOKEN_PACKET_END,

  PTPGP_PACKET_PARSER_TOKEN_MPI_START,
  PTPGP_PACKET_PARSER_TOKEN_MPI_BODY,
  PTPGP_PACKET_PARSER_TOKEN_MPI_END,

  /* sentinel */
  PTPGP_PACKET_PARSER_TOKEN_LAST
} ptpgp_packet_parser_token_t;

typedef struct ptpgp_packet_parser_t_ ptpgp_packet_parser_t;

typedef ptpgp_err_t (*ptpgp_packet_parser_cb_t)(ptpgp_packet_parser_t *,
                                                ptpgp_packet_parser_token_t,
                                                ptpgp_packet_t *p,
                                                u8 *,
                                                size_t);

typedef enum {
  PTPGP_PACKET_PARSER_STATE_INIT,
  PTPGP_PACKET_PARSER_STATE_MPI_LIST,
  PTPGP_PACKET_PARSER_STATE_MPI_BODY,

  /* sentinel */
  PTPGP_PACKET_PARSER_STATE_LAST
} ptpgp_packet_parser_state_t;

struct ptpgp_packet_parser_t_ {
  uint32_t flags;
   
  ptpgp_err_t last_err;

  ptpgp_packet_parser_state_t state;

  ptpgp_packet_t packet;

  u8 buf[PTPGP_PACKET_PARSER_BUFFER_SIZE];
  size_t buf_len;

  size_t remaining_bytes;

  ptpgp_packet_parser_cb_t cb;
  void *user_data;
};
