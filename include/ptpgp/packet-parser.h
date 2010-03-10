#define PTPGP_PACKET_PARSER_BUFFER_SIZE 1024

typedef enum {
  PTPGP_PACKET_PARSER_TOKEN_PACKET_START,
  PTPGP_PACKET_PARSER_TOKEN_PACKET_END,

  PTPGP_PACKET_PARSER_TOKEN_MPI_START,
  PTPGP_PACKET_PARSER_TOKEN_MPI_BODY,
  PTPGP_PACKET_PARSER_TOKEN_MPI_END,

  PTPGP_PACKET_PARSER_TOKEN_SIGNATURE_SUBPACKET_HASHED_LIST_START,
  PTPGP_PACKET_PARSER_TOKEN_SIGNATURE_SUBPACKET_HASHED_LIST_END,

  PTPGP_PACKET_PARSER_TOKEN_SIGNATURE_SUBPACKET_UNHASHED_LIST_START,
  PTPGP_PACKET_PARSER_TOKEN_SIGNATURE_SUBPACKET_UNHASHED_LIST_END,

  PTPGP_PACKET_PARSER_TOKEN_SIGNATURE_SUBPACKET_START,
  PTPGP_PACKET_PARSER_TOKEN_SIGNATURE_SUBPACKET_BODY,
  PTPGP_PACKET_PARSER_TOKEN_SIGNATURE_SUBPACKET_END,

  PTPGP_PACKET_PARSER_TOKEN_SIGNATURE_LEFT16,

  PTPGP_PACKET_PARSER_TOKEN_SYMMETRIC_KEY_ENCRYPTED_SESSION_KEY,

  PTPGP_PACKET_PARSER_TOKEN_COMPRESSED_DATA,
  PTPGP_PACKET_PARSER_TOKEN_LITERAL_DATA,

  PTPGP_PACKET_PARSER_TOKEN_KEY_DATA,
  PTPGP_PACKET_PARSER_TOKEN_PACKET_DATA,

  PTPGP_PACKET_PARSER_TOKEN_ONE_PASS_SIGNATURE,

  PTPGP_PACKET_PARSER_TOKEN_SYM_ENCRYPTED_INTEGRITY_PROTECTED_DATA,

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

  PTPGP_PACKET_PARSER_STATE_SIGNATURE_SUBPACKET_HASHED_LIST,
  PTPGP_PACKET_PARSER_STATE_SIGNATURE_SUBPACKET_HASHED,

  PTPGP_PACKET_PARSER_STATE_SIGNATURE_SUBPACKET_UNHASHED_LIST_SIZE,
  PTPGP_PACKET_PARSER_STATE_SIGNATURE_SUBPACKET_UNHASHED_LIST,
  PTPGP_PACKET_PARSER_STATE_SIGNATURE_SUBPACKET_UNHASHED,

  PTPGP_PACKET_PARSER_STATE_SIGNATURE_LEFT16,

  PTPGP_PACKET_PARSER_STATE_KEY_DATA,
  PTPGP_PACKET_PARSER_STATE_PACKET_DATA,

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

  ptpgp_signature_subpacket_header_t subpacket_header;

  ptpgp_packet_parser_cb_t cb;
  void *user_data;
};

ptpgp_err_t
ptpgp_packet_parser_init(ptpgp_packet_parser_t *p,
                         ptpgp_tag_t tag,
                         ptpgp_packet_parser_cb_t cb,
                         void *user_data);
ptpgp_err_t
ptpgp_packet_parser_push(ptpgp_packet_parser_t *p, 
                         u8 *src,
                         size_t src_len);
ptpgp_err_t
ptpgp_packet_parser_done(ptpgp_packet_parser_t *p);
