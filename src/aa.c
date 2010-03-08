#include <string.h> /* for memset()/memcmp() */
#include <stdint.h> /* for uint32_t */

#define OP_AA_BUFFER_SIZE       1024
#define OP_AA_OUT_BUFFER_SIZE   1024

typedef struct op_aa_parser_t_ op_aa_parser_t;

typedef enum {
  OP_AA_TOKEN_START_ARMOR,
  OP_AA_TOKEN_HEADER_NAME,
  OP_AA_TOKEN_HEADER_VALUE,
  OP_AA_TOKEN_ARMOR_BODY,
  OP_AA_TOKEN_END_ARMOR,
  OP_AA_TOKEN_DONE,
  OP_AA_TOKEN_LAST
} op_aa_token_t;

typedef op_err_t (*op_aa_parser_cb_t)(op_aa_parser_t *, 
                                      op_aa_token_t, 
                                      char *, size_t);

typedef enum {
  OP_AA_PARSER_STATE_NONE,
  OP_AA_PARSER_STATE_LINE_START,
  OP_AA_PARSER_STATE_MAYBE_ENVELOPE,
  OP_AA_PARSER_STATE_HEADERS,
  OP_AA_PARSER_STATE_BODY,
  OP_AA_PARSER_STATE_DONE,
  OP_AA_PARSER_STATE_LAST
} op_aa_parser_state_t;

struct {
  op_aa_parser_state_t state;

  op_aa_parser_cb_t cb;
  void *user_data;

  char buf[OP_AA_BUFFER_SIZE];
  size_t buf_len;

  char out_buf[OP_AA_OUT_BUFFER_SIZE];
  size_t out_buf_len;
} op_aa_parser_t;

#define DIE(p, err) do {                                    \
  return (p)->last_err = OP_ERR_AA_##err;                   \
} while (0)

#define SEND(p, t, b, l) do {                               \
  op_err_t err = (p)->cb((p), (OP_AA_TOKEN_##t), (b), (l)); \
  if (err != OP_OK)                                         \
    DIE((p), err);                                          \
} while (0)


op_err_t
op_aa_parser_init(op_aa_parser_t *p, op_aa_parser_cb_t cb, void *user_data) {
  memset(p, 0, sizeof(op_aa_parser_t));

  p->state = OP_AA_PARSER_STATE_NONE;

  p->cb = cb;
  p->user_data = user_data;

  return OP_OK;
}

op_err_t
op_aa_parser_push(op_aa_parser_t *p, char *src, size_t src_len) {
  if (p->last_err)
    return p->last_err;

  if (p->state == OP_AA_PARSER_STATE_DONE)
    DIE(p, ALREADY_DONE);

  if (!src || !src_len) {
    /* if the parser isn in the middle of a message, then raise error */
    if (p->state != OP_AA_PARSER_STATE_NONE)
      DIE(p, INCOMPLETE_MESSAGE);

    /* mark parser as finished */
    p->state = OP_AA_PARSER_STATE_DONE;
    SEND(p, DONE, 0, 0);

    /* return success */
    return OP_OK;
  }

retry:
  if (src_len > 0) {
    switch (p->state) {
    case OP_AA_PARSER_STATE_NONE:
      for (i = 0; i < src_len; i++) {
        if (src[i] == '\n') {
          p->buf_len = 0;
          p->state = OP_AA_PARSER_STATE_LINE_START;

          SHIFT(i);
          goto retry;
        }
      }

      break;
    case OP_AA_PARSER_STATE_LINE_START:
      for (i = 0; i < src_len; i++) {
        p->buf[p->buf_len++] = src[i];

        if (p->buf_len == 5) {
          if (!memcmp(p->buf, "-----", 5)) {
            p->buf_len = 0;
            p->state = OP_AA_PARSER_STATE_MAYBE_ENVELOPE;

            SHIFT(i);
            goto retry;
          } else {
            p->buf_len = 0;
            p->state = OP_AA_PARSER_STATE_NONE;

            SHIFT(i);
            goto retry;
          }
        }
      }

      break;
    case OP_AA_PARSER_STATE_MAYBE_ENVELOPE:
      for (i = 0; i < src_len; i++) {
        p->buf[p->buf_len++] = src[i];

        /* ignore lines greater than 80 characters (not an AA header) */
        if (p->buf_len > 80) {
          p->buf_len = 0;
          p->state = OP_AA_PARSER_STATE_NONE;

          SHIFT(i);
          goto retry;
        }

        /* if the buffer length is greater than 6 characters and ends in
         * a newline, then this might be the beginning of an AA chunk */
        if (p->buf_len > 6 && p->buf[p->buf_len - 1] == '\n') {

          /* strip newline */
          p->buf_len--;

          /* strip cr */
          if (p->buf[p->buf_len - 1] == '\r')
            p->buf_len--;

          if (!memcmp(p->buf + p->buf_len - 5, "-----", 5)) {
            /* AA header line, pass to callback */
            SEND(p, START_ARMOR, p->buf, p->buf_len - 5);

            p->buf_len = 0;
            p->state = OP_AA_PARSER_STATE_HEADERS;

            SHIFT(i);
            goto retry;
          } else {
            /* not an AA header line */

            p->buf_len = 0;
            p->state = OP_AA_PARSER_STATE_NONE;
            
            SHIFT(i);
            goto retry;
          }
        }
      }

      break;
    case OP_AA_PARSER_STATE_HEADERS:
      for (i = 0; i < src_len; i++) {
        p->buf[p->buf_len++] = src[i];

        /* check for buffer overflow */
        if (p->buf_len == OP_AA_BUFFER_SIZE - 1)
          DIE(p, BIG_HEADER_LINE);

        if (p->buf[p->buf_len - 1] == '\n') {
          /* strip newline */
          p->buf_len--;

          /* strip cr */
          if (p->buf_len > 0 && p->buf[p->buf_len - 1] == '\r')
            p->buf_len--;

          if (p->buf_len == 0) {
            /* end of headers */
            p->buf_len = 0;
            p->state = OP_AA_PARSER_STATE_BODY;

            SHIFT(i);
            goto retry;
          } else if (p->buf_len < 4) {
            DIE(p, BAD_HEADER_LINE);
          } else {
            for (j = 0; j < p->buf_len - 1; j++) {
              if (p->buf[j] == ':' && p->buf[j + 1] == ' ') {
                /* send header */
                SEND(p, HEADER_NAME, p->buf, j);
                SEND(p, HEADER_VALUE, p->buf + j + 2, p->buf_len - j - 2);

                /* clear buffer */
                p->buf_len = 0;
                break;
              }
            }
          }
        }
      }

      break;
    case OP_AA_PARSER_STATE_BODY:
      for (i = 0; i < src_len; i++) {
        p->buf[p->buf_len++] = src[i];

        if (src[i] == '\n') {
          /* strip newline */
          p->buf_len--;

          /* strip cr */
          if (p->buf_len > 0 && p->buf[p->buf_len - 1] == '\r')
            p->buf_len--;

          if (p->buf_len > 1 && p->buf[0] == '-' && p->buf[1] == ' ') {
            /* handle dash escape */
            p->buf[1] = '-';

            /* flush buffer */
            DECODE_AND_SEND(p, BODY, p->buf + 1, p->buf_len - 1);
            p->buf_len = 0;
          } else if (p->buf_len > 11 && 
                     !memcmp(p->buf, "-----", 5) &&
                     !memcmp(p->buf + p->buf_len - 5, "-----", 5)) {
            /* handle end envelope */
            SEND(p, END_ARMOR, p->buf + 5, p->buf_len - 10);

            p->buf_len = 0;
            p->state = OP_AA_PARSER_STATE_NONE;

            SHIFT(i);
            goto retry;
          } else {
            /* flush buffer */
            SEND(p, BODY, p->buf, p->buf_len);
            p->buf_len = 0;
          }
        }

        /* check for buffer overflow */
        if (p->buf_len == OP_AA_BUFFER_SIZE - 1) {
          /* flush buffer */
          /* (XXX: this means long lines aren't properly dash-escaped */
          DECODE_AND_SEND(p, BODY, p->buf, p->buf_len);
          p->buf_len = 0;
        }
      }

      break;
    default:
      /* never reached */
      DIE(p, BAD_STATE);
    }
  }

  /* return success */
  return OP_OK;
}

op_err_t
op_aa_parser_done(op_aa_parser_t *p) {
  return op_aa_parser_push(p, 0, 0);
}
