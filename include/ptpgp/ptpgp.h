#ifndef PTPGP_H
#define PTPGP_H

#include <stdint.h> /* for uint32_t */

#define PTPGP_STREAM_PARSER_STATE_STACK_DEPTH        1024
#define PTPGP_STREAM_PARSER_BUFFER_SIZE              4096

typedef struct ptpgp_stream_parser_t_ ptpgp_stream_parser_t;

typedef enum {
  PTPGP_OK,

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

  /* sentinel */
  PTPGP_ERR_LAST
} ptpgp_err_t;

#define PTPGP_PACKET_FLAG_NEW_PACKET     (1 << 0)
#define PTPGP_PACKET_FLAG_INDETERMINITE  (1 << 1)
#define PTPGP_PACKET_FLAG_PARTIAL        (1 << 2)

typedef struct {
  uint32_t flags;
  uint32_t content_tag;
  uint64_t length;
} ptpgp_packet_header_t;

typedef enum {
  PTPGP_STREAM_PARSER_TOKEN_START,
  PTPGP_STREAM_PARSER_TOKEN_BODY,
  PTPGP_STREAM_PARSER_TOKEN_END,
  PTPGP_STREAM_PARSER_TOKEN_LAST
} ptpgp_stream_parser_token_t;

typedef ptpgp_err_t (*ptpgp_stream_parser_cb_t)(ptpgp_stream_parser_t *, 
                                                ptpgp_stream_parser_token_t, 
                                                ptpgp_packet_header_t *, 
                                                char *, size_t);
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

  unsigned char buf[PTPGP_STREAM_PARSER_BUFFER_SIZE];
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
                         char *src, 
                         size_t src_len);
ptpgp_err_t
ptpgp_stream_parser_done(ptpgp_stream_parser_t *p);



#define PTPGP_ARMOR_PARSER_BUFFER_SIZE          1024
#define PTPGP_ARMOR_PARSER_OUTPUT_BUFFER_SIZE   1024

typedef struct ptpgp_armor_parser_t_ ptpgp_armor_parser_t;

typedef enum {
  PTPGP_ARMOR_PARSER_TOKEN_START_ARMOR,
  PTPGP_ARMOR_PARSER_TOKEN_HEADER_NAME,
  PTPGP_ARMOR_PARSER_TOKEN_HEADER_VALUE,
  PTPGP_ARMOR_PARSER_TOKEN_BODY,
  PTPGP_ARMOR_PARSER_TOKEN_END_ARMOR,
  PTPGP_ARMOR_PARSER_TOKEN_DONE,
  PTPGP_ARMOR_PARSER_TOKEN_LAST
} ptpgp_armor_parser_token_t;

typedef ptpgp_err_t (*ptpgp_armor_parser_cb_t)(ptpgp_armor_parser_t *, 
                                      ptpgp_armor_parser_token_t, 
                                      char *, size_t);

typedef enum {
  PTPGP_ARMOR_PARSER_STATE_NONE,
  PTPGP_ARMOR_PARSER_STATE_LINE_START,
  PTPGP_ARMOR_PARSER_STATE_MAYBE_ENVELOPE,
  PTPGP_ARMOR_PARSER_STATE_HEADERS,
  PTPGP_ARMOR_PARSER_STATE_BODY,
  PTPGP_ARMOR_PARSER_STATE_DONE,
  PTPGP_ARMOR_PARSER_STATE_LAST
} ptpgp_arpmor_parser_state_t;

struct ptpgp_armor_parser_t_ {
  ptpgp_err_t last_err;

  ptpgp_arpmor_parser_state_t state;

  ptpgp_armor_parser_cb_t cb;
  void *user_data;

  char buf[PTPGP_ARMOR_PARSER_BUFFER_SIZE];
  size_t buf_len;

  char out_buf[PTPGP_ARMOR_PARSER_OUTPUT_BUFFER_SIZE];
  size_t out_buf_len;
};

ptpgp_err_t
ptpgp_armor_parser_init(ptpgp_armor_parser_t *p, ptpgp_armor_parser_cb_t cb, void *user_data);

ptpgp_err_t
ptpgp_armor_parser_push(ptpgp_armor_parser_t *p, char *src, size_t src_len);

ptpgp_err_t
ptpgp_armor_parser_done(ptpgp_armor_parser_t *p);



#define PTPGP_BASE64_BUFFER_SIZE     1024

typedef struct ptpgp_base64_t_ ptpgp_base64_t;

typedef ptpgp_err_t (*ptpgp_base64_cb_t)(ptpgp_base64_t *, char *, size_t);

struct ptpgp_base64_t_ {
  ptpgp_err_t last_err;

  uint32_t flags;

  char src_buf[4];
  size_t src_buf_len;

  char out_buf[PTPGP_BASE64_BUFFER_SIZE];
  size_t out_buf_len;

  ptpgp_base64_cb_t cb;
  void *user_data;
};


ptpgp_err_t
ptpgp_base64_init(ptpgp_base64_t *p, 
                  char encode, 
                  ptpgp_base64_cb_t cb, 
                  void *user_data);

ptpgp_err_t
ptpgp_base64_push(ptpgp_base64_t *p, 
                  char *src,
                  size_t src_len);

ptpgp_err_t
ptpgp_base64_done(ptpgp_base64_t *p);

#endif /* PTPGP_H */
