#ifndef PTPGP_H
#define PTPGP_H

#include <stdint.h> /* for uint32_t */

#define PTPGP_VERSION "0.1.0"

#ifndef u8
#define u8 unsigned char
#endif /* u8 */

/* TODO: */
typedef void* ptpgp_signature_subpacket_t;
typedef void* ptpgp_mpi_t;


/**********************/
/* ERROR DECLARATIONS */
/**********************/

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

  /* sentinel */
  PTPGP_ERR_LAST
} ptpgp_err_t;

ptpgp_err_t
ptpgp_strerror(ptpgp_err_t err,
               char *buf,
               size_t buf_len,
               size_t *out_len);


/********************/
/* TAG DECLARATIONS */
/********************/

typedef enum {
  PTPGP_TAG_RESERVED                                    =  0,
  PTPGP_TAG_PUBLIC_KEY_ENCRYPTED_SESSION_KEY            =  1,
  PTPGP_TAG_SIGNATURE_PACKET                            =  2,
  PTPGP_TAG_SYMMETRIC_KEY_ENCRYPTED_SESSION_KEY         =  3,
  PTPGP_TAG_ONE_PASS_SIGNATURE_PACKET                   =  4,
  PTPGP_TAG_SECRET_KEY                                  =  5,
  PTPGP_TAG_PUBLIC_KEY                                  =  6,
  PTPGP_TAG_SECRET_SUBKEY                               =  7,
  PTPGP_TAG_COMPRESSED_DATA                             =  8,
  PTPGP_TAG_SYMMETRICALLY_ENCRYPTED_DATA                =  9,
  PTPGP_TAG_MARKER                                      = 10,
  PTPGP_TAG_LITERAL_DATA                                = 11,
  PTPGP_TAG_TRUST                                       = 12,
  PTPGP_TAG_USER_ID                                     = 13,
  PTPGP_TAG_PUBLIC_SUBKEY                               = 14,

  PTPGP_TAG_USER_ATTRIBUTE_PACKET                       = 17,
  PTPGP_TAG_SYM_ENCRYPTED_AND_INTEGRITY_PROTECTED_DATA  = 18,
  PTPGP_TAG_MODIFICATION_DETECTION_CODE                 = 19,

  PTPGP_TAG_PRIVATE_OR_EXPERIMENTAL_60                  = 60,
  PTPGP_TAG_PRIVATE_OR_EXPERIMENTAL_61                  = 61,
  PTPGP_TAG_PRIVATE_OR_EXPERIMENTAL_62                  = 62,
  PTPGP_TAG_PRIVATE_OR_EXPERIMENTAL_63                  = 63,

  PTPGP_TAG_LAST                                        = 64
} ptpgp_tag_t;

ptpgp_err_t
ptpgp_tag_to_s(ptpgp_tag_t tag,
               char *buf,
               size_t buf_len,
               size_t *out_len);


/******************************/
/* PACKET HEADER DECLARATIONS */
/******************************/

#define PTPGP_PACKET_FLAG_NEW_PACKET     (1 << 0)
#define PTPGP_PACKET_FLAG_INDETERMINITE  (1 << 1)
#define PTPGP_PACKET_FLAG_PARTIAL        (1 << 2)

typedef struct {
  uint32_t flags;
  ptpgp_tag_t content_tag;
  uint64_t length;
} ptpgp_packet_header_t;


/******************************/
/* STREAM PARSER DECLARATIONS */
/******************************/

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


/*****************************/
/* ARMOR PARSER DECLARATIONS */
/*****************************/

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
} ptpgp_armor_parser_state_t;

struct ptpgp_armor_parser_t_ {
  ptpgp_err_t last_err;

  ptpgp_armor_parser_state_t state;

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


/***************************************/
/* BASE64 ENCODER/DECODER DECLARATIONS */
/***************************************/

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


/******************************/
/* PACKET PARSER DECLARATIONS */
/******************************/

typedef struct ptpgp_packet_parser_t_ ptpgp_packet_parser_t;
typedef ptpgp_err_t (*ptpgp_packet_parser_cb_t)(ptpgp_packet_parser_t *,
                                                char *,
                                                size_t);

struct ptpgp_packet_parser_t_ {
  ptpgp_packet_parser_cb_t cb;
  void *user_data;
};

/*********************************/
/* PACKET STRUCTURE DECLARATIONS */
/*********************************/

/* public key encrypted session key packet (tag 1, rfc4880 5.1) */
typedef struct {
  uint32_t version,
           algorithm;

  u8 key_id[8],
     *session_key;

  size_t session_key_len;
} ptpgp_packet_public_key_encrypted_session_key_t;

/* signature packet (tag 2, rfc4880 5.2.2) */
typedef struct {
  u8 version;

  union {
    /* v3 signature packet (rfc4880 5.2.2) */
    struct {
      uint32_t creation_time;

      u8 signature_type,
         signer_key_id[8],
         public_key_algorithm,
         hash_algorithm,
         left16[2];

      ptpgp_mpi_t **mpis;
      size_t num_mpis;
    } v3;

    /* v4 signature packet (rfc480 5.2.3) */
    struct {
      u8 signature_type,
         public_key_algorithm,
         hash_algorithm,
         left16[2];

      /* length of subpacket data (in bytes) */
      ptpgp_signature_subpacket_t  *hashed_subpackets;
      size_t num_hashed_subpackets;

      ptpgp_signature_subpacket_t  *unhashed_subpackets;
      size_t num_unhashed_subpackets;

      ptpgp_mpi_t **mpis;
      size_t num_mpis;
    } v4;
  } versions;
} ptpgp_packet_signature_t;

typedef struct {
  ptpgp_tag_t tag;
  u8 *data;
  size_t data_len;
} ptpgp_packet_raw_t;

typedef struct {
  ptpgp_tag_t tag;

  union {
    ptpgp_packet_raw_t raw;
    ptpgp_packet_public_key_encrypted_session_key_t t1;
    ptpgp_packet_signature_t                        t2;
  } types;
} ptpgp_packet_t;


#endif /* PTPGP_H */
