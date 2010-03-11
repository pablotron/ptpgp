#include "internal.h"

#define STATE(s) PTPGP_ARMOR_PARSER_STATE_##s

#define DIE(p, err) do {                                    \
  return (p)->last_err = PTPGP_ERR_ARMOR_PARSER_##err;      \
} while (0)

#define SEND(p, t, b, l) do {                               \
  D("sending %s (%d bytes)", #t, (int) (l));                \
                                                            \
  ptpgp_err_t err = (p)->cb(                                \
    (p), (PTPGP_ARMOR_PARSER_TOKEN_##t),                    \
    (b), (l)                                                \
  );                                                        \
                                                            \
  if (err != PTPGP_OK)                                      \
    return (p)->last_err = err;                             \
} while (0)

#define SHIFT(i) do { \
  src += (i);         \
  src_len -= (i);     \
} while (0)

ptpgp_err_t
ptpgp_armor_parser_init(ptpgp_armor_parser_t *p, ptpgp_armor_parser_cb_t cb, void *user_data) {
  memset(p, 0, sizeof(ptpgp_armor_parser_t));

  p->state = STATE(INIT);
  p->cb = cb;
  p->user_data = user_data;

    /* return success */
  return PTPGP_OK;
}

ptpgp_err_t
ptpgp_armor_parser_push(ptpgp_armor_parser_t *p, u8 *src, size_t src_len) {
  size_t i, j;

  D("src_len = %d", (int) src_len);

  if (p->last_err)
    return p->last_err;

  if (p->state == STATE(DONE))
    DIE(p, ALREADY_DONE);

  if (!src || !src_len) {
    /* if the parser isn't in the middle of a message, then raise error */
    if (p->state != STATE(INIT))
      DIE(p, INCOMPLETE_MESSAGE);

    /* send DONE to clients */
    SEND(p, DONE, 0, 0);

    /* mark parser as finished */
    p->state = STATE(DONE);

    /* return success */
    return PTPGP_OK;
  }

  D("past done check");
retry:
  if (src_len > 0) {
    switch (p->state) {
    case STATE(INIT):
      for (i = 0; i < src_len; i++) {
        p->buf[p->buf_len++] = src[i];

        p->buf[p->buf_len] = 0;
        D("INIT: p->buf = \"%s\"", p->buf);

        if (p->buf_len == 5) {
          if (!memcmp(p->buf, "-----", 5)) {
            D("found envelope (maybe)");
            
            p->buf_len = 0;
            SHIFT(i + 1);

            p->state = STATE(MAYBE_ENVELOPE);
            goto retry;
          } else {
            p->buf[p->buf_len] = 0;
            D("not envelope line, line = %s", p->buf);

            p->buf_len = 0;
            SHIFT(i + 1);

            p->state = STATE(SKIP_LINE);
            goto retry;
          }
        }
      }

      break;
    case STATE(SKIP_LINE):
      for (i = 0; i < src_len; i++) {
        if (src[i] == '\n') {
          /* D("got newline"); */

          p->buf_len = 0;
          SHIFT(i + 1);

          p->state = STATE(INIT);
          goto retry;
        }
      }

      break;
    case STATE(MAYBE_ENVELOPE):
      for (i = 0; i < src_len; i++) {
        p->buf[p->buf_len++] = src[i];

        p->buf[p->buf_len] = 0;
        D("MAYBE_ENVELOPE: p->buf = \"%s\"", p->buf);

        /* ignore lines greater than 80 characters (not an AA header) */
        if (p->buf_len > 80) {
          D("not envelope (len > 80)");

          p->buf_len = 0;
          SHIFT(i + 1);

          p->state = STATE(SKIP_LINE);
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

          if (p->buf_len > 5 && !memcmp(p->buf + p->buf_len - 5, "-----", 5)) {
            D("found armor envelope, sending name");

            /* got AA header line, pass to callback */
            SEND(p, START_ARMOR, p->buf, p->buf_len - 5);

            p->buf_len = 0;
            SHIFT(i + 1);

            p->state = STATE(HEADERS);
            goto retry;
          } else {
            D("not armor envelope");

            p->buf_len = 0;
            SHIFT(i + 1);

            p->state = STATE(SKIP_LINE);
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
            SHIFT(i + 1);

            p->state = STATE(BODY);
            goto retry;
          } else if (p->buf_len < 4) {
            DIE(p, BAD_HEADER_LINE);
          } else {
            for (j = 1; j < p->buf_len - 1; j++) {
              if (p->buf[j] == ':' && p->buf[j + 1] == ' ') {
                /* send header */
                SEND(p, HEADER_NAME, p->buf, j);
                SEND(p, HEADER_VALUE, p->buf + j + 2, p->buf_len - j - 2);

                /* clear buffer */
                p->buf_len = 0;
                SHIFT(i + 1);

                goto retry;
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
            if (p->buf_len - 1 > 0)
              SEND(p, BODY, p->buf + 1, p->buf_len - 1);

            p->buf_len = 0;
            SHIFT(i + 1);
          } else if (p->buf_len == 5 && p->buf[0] == '=') {
            /* send crc24 (still encoded) */
            SEND(p, CRC24, p->buf + 1, 4);

            /* clear buffer */
            p->buf_len = 0;
            SHIFT(i + 1);

            /* FIXME: should switch state here */

            goto retry;
          } else if (p->buf_len > 11 &&
                     !memcmp(p->buf, "-----", 5) &&
                     !memcmp(p->buf + p->buf_len - 5, "-----", 5)) {
            /* handle end envelope */
            SEND(p, END_ARMOR, p->buf + 5, p->buf_len - 10);

            p->buf_len = 0;
            SHIFT(i + 1);

            p->state = STATE(INIT);
            goto retry;
          } else {
            /* flush buffer */
            if (p->buf_len > 0)
              SEND(p, BODY, p->buf, p->buf_len);

            p->buf_len = 0;
            SHIFT(i + 1);
          }
        }

        /* check for buffer overflow */
        if (p->buf_len == PTPGP_ARMOR_PARSER_BUFFER_SIZE - 1) {
          /* flush buffer */
          /* (FIXME: this means long lines aren't properly dash-escaped */
          if (p->buf_len > 0)
            SEND(p, BODY, p->buf, p->buf_len);

          p->buf_len = 0;
          SHIFT(i + 1);
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
  D("entered");
  return ptpgp_armor_parser_push(p, 0, 0);
}
