#include "internal.h"

#define STATE(s) PTPGP_ARMOR_PARSER_STATE_##s

#define DIE(p, err) do {                                    \
  return (p)->last_err = PTPGP_ERR_ARMOR_PARSER_##err;      \
} while (0)

#define SEND(p, t, b, l) do {                               \
  ptpgp_err_t err = (p)->cb(                                \
    (p), (PTPGP_ARMOR_PARSER_TOKEN_##t),                    \
    (b), (l)                                                \
  );                                                        \
                                                            \
  if (err != PTPGP_OK)                                      \
    return (p)->last_err = err;                             \
} while (0)

#define DECODE_AND_SEND(p, b, l) do {                       \
  /* FIXME: need to decode buffer first */                  \
  SEND(p, BODY, b, l);                                      \
} while (0)

#define SHIFT(i) do { \
  src += i;           \
  src_len -= i;       \
} while (0)

ptpgp_err_t
ptpgp_armor_parser_init(ptpgp_armor_parser_t *p, ptpgp_armor_parser_cb_t cb, void *user_data) {
  memset(p, 0, sizeof(ptpgp_armor_parser_t));

  p->state = STATE(NONE);

  p->cb = cb;
  p->user_data = user_data;

  return PTPGP_OK;
}

ptpgp_err_t
ptpgp_armor_parser_push(ptpgp_armor_parser_t *p, char *src, size_t src_len) {
  size_t i, j;

  if (p->last_err)
    return p->last_err;

  if (p->state == STATE(DONE))
    DIE(p, ALREADY_DONE);

  if (!src || !src_len) {
    /* if the parser isn in the middle of a message, then raise error */
    if (p->state != STATE(NONE))
      DIE(p, INCOMPLETE_MESSAGE);

    /* mark parser as finished */
    p->state = STATE(DONE);
    SEND(p, DONE, 0, 0);

    /* return success */
    return PTPGP_OK;
  }

retry:
  if (src_len > 0) {
    switch (p->state) {
    case STATE(NONE):
      for (i = 0; i < src_len; i++) {
        if (src[i] == '\n') {
          p->buf_len = 0;
          p->state = STATE(LINE_START);

          SHIFT(i);
          goto retry;
        }
      }

      break;
    case STATE(LINE_START):
      for (i = 0; i < src_len; i++) {
        p->buf[p->buf_len++] = src[i];

        if (p->buf_len == 5) {
          if (!memcmp(p->buf, "-----", 5)) {
            p->buf_len = 0;
            p->state = STATE(MAYBE_ENVELOPE);

            SHIFT(i);
            goto retry;
          } else {
            p->buf_len = 0;
            p->state = STATE(NONE);

            SHIFT(i);
            goto retry;
          }
        }
      }

      break;
    case STATE(MAYBE_ENVELOPE):
      for (i = 0; i < src_len; i++) {
        p->buf[p->buf_len++] = src[i];

        /* ignore lines greater than 80 characters (not an AA header) */
        if (p->buf_len > 80) {
          p->buf_len = 0;
          p->state = STATE(NONE);

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
            p->state = STATE(HEADERS);

            SHIFT(i);
            goto retry;
          } else {
            /* not an AA header line */

            p->buf_len = 0;
            p->state = STATE(NONE);
            
            SHIFT(i);
            goto retry;
          }
        }
      }

      break;
    case STATE(HEADERS):
      for (i = 0; i < src_len; i++) {
        p->buf[p->buf_len++] = src[i];

        /* check for buffer overflow */
        if (p->buf_len == PTPGP_ARMOR_PARSER_BUFFER_SIZE - 1)
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
            p->state = STATE(BODY);

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
    case STATE(BODY):
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
            DECODE_AND_SEND(p, p->buf + 1, p->buf_len - 1);
            p->buf_len = 0;
          } else if (p->buf_len == 5 && p->buf[0] == '=') {
          } else if (p->buf_len > 11 && 
                     !memcmp(p->buf, "-----", 5) &&
                     !memcmp(p->buf + p->buf_len - 5, "-----", 5)) {
            /* handle end envelope */
            SEND(p, END_ARMOR, p->buf + 5, p->buf_len - 10);

            p->buf_len = 0;
            p->state = STATE(NONE);

            SHIFT(i);
            goto retry;
          } else {
            /* flush buffer */
            SEND(p, BODY, p->buf, p->buf_len);
            p->buf_len = 0;
          }
        }

        /* check for buffer overflow */
        if (p->buf_len == PTPGP_ARMOR_PARSER_BUFFER_SIZE - 1) {
          /* flush buffer */
          /* (XXX: this means long lines aren't properly dash-escaped */
          DECODE_AND_SEND(p, p->buf, p->buf_len);
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
  return PTPGP_OK;
}

ptpgp_err_t
ptpgp_armor_parser_done(ptpgp_armor_parser_t *p) {
  return ptpgp_armor_parser_push(p, 0, 0);
}
