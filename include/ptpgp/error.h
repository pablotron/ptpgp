typedef enum {
  PTPGP_OK, /* ok (no error) */

  /* error string errors */
  PTPGP_ERR_ERROR_CODE_UNKNOWN, /* unknown error code */
  PTPGP_ERR_ERROR_BUFFER_TOO_SMALL, /* output error buffer too small */

  /* stream parser errors */
  PTPGP_ERR_STREAM_PARSER_INCOMPLETE_PACKET, /* packet stream ended before end of packets */
  PTPGP_ERR_STREAM_PARSER_CALLBACK, /* callback returned an error */
  PTPGP_ERR_STREAM_PARSER_STATE_STACK_OVERFLOW, /* parser state exceeded stack size */
  PTPGP_ERR_STREAM_PARSER_STATE_STACK_UNDERFLOW, /* parser state below zero */
  PTPGP_ERR_STREAM_PARSER_BAD_PACKET_TAG, /* invalid packet header tag */
  PTPGP_ERR_STREAM_PARSER_INPUT_BUFFER_OVERFLOW, /* input buffer overflow (bug!) */
  PTPGP_ERR_STREAM_PARSER_BAD_OLD_PACKET_LENGTH_TYPE, /* bad packet length type (bug!) */
  PTPGP_ERR_STREAM_PARSER_UNKNOWN_PARSER_STATE, /* unknown parser state (bug!) */
  PTPGP_ERR_STREAM_PARSER_INVALID_PACKET_LENGTH, /* invalid packet length (bug!) */
  PTPGP_ERR_STREAM_PARSER_INVALID_CONTENT_TAG, /* invalid packet content tag */
  PTPGP_ERR_STREAM_PARSER_INVALID_PARTIAL_BODY_LENGTH, /* invalid partial body length */
  PTPGP_ERR_STREAM_PARSER_ALREADY_DONE, /* stream parser already done */

  /* armor parser errors */
  PTPGP_ERR_ARMOR_PARSER_ALREADY_DONE, /* armor parser already done */
  PTPGP_ERR_ARMOR_PARSER_INCOMPLETE_MESSAGE, /* armor parser already done */
  PTPGP_ERR_ARMOR_PARSER_BIG_HEADER_LINE, /* header line too large */
  PTPGP_ERR_ARMOR_PARSER_BAD_HEADER_LINE, /* invalid header line */
  PTPGP_ERR_ARMOR_PARSER_BAD_STATE, /* bad parser state */

  /* base64 errors */
  PTPGP_ERR_BASE64_ALREADY_DONE, /* base64 context already done */

  /* tag errors */
  PTPGP_ERR_TAG_INVALID, /* invalid tag ID */
  PTPGP_ERR_TAG_BUFFER_TOO_SMALL, /* tag output buffer too small */

  /* packet parser errors */
  PTPGP_ERR_PACKET_PARSER_INVALID_STATE, /* invalid parser state (bug?) */
  PTPGP_ERR_PACKET_PARSER_ALREADY_DONE, /* packet parser already done */
  PTPGP_ERR_PACKET_PARSER_INPUT_BUFFER_OVERFLOW, /* input buffer overflow (bug?) */
  PTPGP_ERR_PACKET_PARSER_BAD_PACKET_VERSION, /* bad packet version */

  /* sentinel */
  PTPGP_ERR_LAST
} ptpgp_err_t;

ptpgp_err_t
ptpgp_strerror(ptpgp_err_t err,
               char *buf,
               size_t buf_len,
               size_t *out_len);