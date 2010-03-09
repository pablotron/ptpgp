#include "internal.h"

#define DIE(p, err) do {                                              \
  D("returning error %s", #err);                                      \
  return (p)->last_err = PTPGP_ERR_STREAM_PARSER_##err;               \
} while (0)

#define PUSH(p, s) do {                                               \
  D("pushing state %s", #s);                                          \
                                                                      \
  /* check for state stack overflow */                                \
  if ((p)->state_len >= PTPGP_STREAM_PARSER_STATE_STACK_DEPTH - 1)    \
    DIE((p), STATE_STACK_OVERFLOW);                                   \
                                                                      \
  /* save state, increment depth */                                   \
  (p)->state[(p)->state_len] = (PTPGP_STREAM_PARSER_STATE_##s);       \
  (p)->state_len++;                                                   \
} while (0)

#define POP(p) do {                                                   \
  D("popping state");                                                 \
                                                                      \
  /* check for state stack underflow */                               \
  if ((p)->state_len == 0)                                            \
    DIE((p), STATE_STACK_UNDERFLOW);                                  \
                                                                      \
  /* decriment stack depth */                                         \
  (p)->state_len--;                                                   \
} while (0)

#define PEEK(p) (((p)->state_len > 0) ? (p)->state[(p)->state_len - 1] : PTPGP_STREAM_PARSER_STATE_NONE)

#define SWAP(p, s) do {                                               \
  POP(p);                                                             \
  PUSH(p, s);                                                         \
} while (0)

#define SHIFT(n) do {                                                 \
  D("shifting %d byte%s", (int) (n), ((n) > 1) ? "s" : "");           \
                                                                      \
  /* check for input buffer overflow */                               \
  if ((n) > src_len)                                                  \
    DIE((p), INPUT_BUFFER_OVERFLOW);                                  \
                                                                      \
  /* shift input buffer ptr and length */                             \
  src += (n);                                                         \
  src_len -= (n);                                                     \
} while (0)

#define ASSERT_VALID_CONTENT_TAG(p) do {                              \
  if (!IS_VALID_CONTENT_TAG((p)->header.content_tag))                 \
    DIE((p), INVALID_CONTENT_TAG);                                    \
} while (0)

#define SEND(p, t, b, l) do {                                         \
  D("sending %s data to callback (%d bytes)", #t, (int) (l));         \
                                                                      \
  ptpgp_err_t err = (p)->cb(                                          \
    (p), (PTPGP_STREAM_PARSER_TOKEN_##t),                             \
    &((p)->header), (b), (l)                                          \
  );                                                                  \
                                                                      \
  if (err != PTPGP_OK)                                                \
    return (p)->last_err = err;                                       \
} while (0)

ptpgp_err_t
ptpgp_stream_parser_init(ptpgp_stream_parser_t *p, 
                         ptpgp_stream_parser_cb_t cb, 
                         void *cb_data) {
  /* clear parser */
  memset(p, 0, sizeof(ptpgp_stream_parser_t));

  /* save callback */
  p->cb = cb;
  p->cb_data = cb_data;

  /* return success */
  return PTPGP_OK;
}

ptpgp_err_t
ptpgp_stream_parser_push(ptpgp_stream_parser_t *p, 
                         unsigned char *src, 
                         size_t src_len) {
  int c;

  /* return last error */
  if (p->last_err)
    return p->last_err;

  if (p->is_done)
    DIE(p, ALREADY_DONE);

  if (!src || !src_len) {
    if (p->state_len > 0) {
      if (PEEK(p) == PTPGP_STREAM_PARSER_STATE_BODY &&
          p->header.flags & PTPGP_PACKET_FLAG_INDETERMINITE) {
        /* reached end of indeterminite packet */
        SEND(p, END, 0, 0);
        POP(p);
      } else {
        DIE(p, INCOMPLETE_PACKET);
      }
    }

    /* flag parser as finished */
    p->is_done = 1;

    /* return success */
    return PTPGP_OK;
  }

retry:
  if (src_len > 0) {
    /* grab first byte */
    c = src[0];

    /* dump current byte */
    D("c = %d", c);

    if (!p->state_len) {
      /* clear buffer and packet header */
      p->buf_len = 0;
      memset(&(p->header), 0, sizeof(ptpgp_packet_header_t));

      /* check packet header tag (RFC2440 S4.2: bit 7 is always 1) */
      if (!(c & 0x80))
        DIE(p, BAD_PACKET_TAG);

      if (c & (1 << 6)) {
        D("new-style packet header");

        p->header.flags |= PTPGP_PACKET_FLAG_NEW_PACKET;

        /* dump content tag */
        D("content_tag = %d", (c & 0x3f));

        /* save content tag */
        p->header.content_tag = (c & 0x3f);
        ASSERT_VALID_CONTENT_TAG(p);

        /* push state */
        PUSH(p, NEW_HEADER_AFTER_TAG);

        /* shift header tag */
        SHIFT(1);
        goto retry;
      } else {
        D("old-style packet header");

        /* dump content tag */
        D("content_tag = %d", (c & 0x3f) >> 2);

        /* save content tag */
        p->header.content_tag = (c & 0x3f) >> 2;
        ASSERT_VALID_CONTENT_TAG(p);

        /* handle length type */
        switch (c & 0x3) {
        case 0:
          D("remaining length octets = 1");

          p->remaining_length_octets = 1;

          /* push state */
          PUSH(p, OLD_HEADER_AFTER_TAG);

          break;
        case 1:
          D("remaining length octets = 2");

          p->remaining_length_octets = 2;

          /* push state */
          PUSH(p, OLD_HEADER_AFTER_TAG);

          break;
        case 2:
          D("remaining length octets = 4");

          p->remaining_length_octets = 4;

          /* push state */
          PUSH(p, OLD_HEADER_AFTER_TAG);

          break;
        case 3:
          D("remaining length octets = indeterminite");

          p->header.flags |= PTPGP_PACKET_FLAG_INDETERMINITE;
          p->remaining_length_octets = 0;

          /* push state */
          PUSH(p, BODY);

          break;
        default:
          /* never reached */
          DIE(p, BAD_OLD_PACKET_LENGTH_TYPE);
        }

        /* shift header byte */
        SHIFT(1);
        goto retry;
      }
    } else {
      D("state = %d", PEEK(p));

      switch (PEEK(p)) {
      case PTPGP_STREAM_PARSER_STATE_OLD_HEADER_AFTER_TAG:
        /* append length octet to buffer */
        p->buf[p->buf_len++] = c;
        SHIFT(1);

        if (p->buf_len < p->remaining_length_octets)
          goto retry;

        /* clear packet byte count */
        p->bytes_read = 0;

        /* decode packet length */
        if (p->buf_len == 1) {
          p->header.length = p->buf[0];
        } else if (p->buf_len == 2) {
          p->header.length = (p->buf[0] << 8) | 
                             (p->buf[1]);
        } else if (p->buf_len == 4) {
          p->header.length = (p->buf[0] << 24) | 
                             (p->buf[1] << 16) |
                             (p->buf[2] <<  8) |
                             (p->buf[3]);
        } else {
          /* never reached */
          DIE(p, INVALID_PACKET_LENGTH);
        }

        D("packet length = %d bytes", (int) p->header.length);
        p->buf_len = 0;

        SEND(p, START, 0, 0);

        SWAP(p, BODY);
        goto retry;

        /* never reached */
        break;
      case PTPGP_STREAM_PARSER_STATE_NEW_HEADER_AFTER_TAG:
        /* append length octet to buffer */
        p->buf[p->buf_len++] = c;
        SHIFT(1);
        
        /* clear packet byte count */
        p->bytes_read = 0;

        if (p->buf[0] < 192) {
          D("new-style one-octet packet length (rfc4880 4.2.2.1)");
          p->header.length = p->buf[0];

          /* emit packet header */
          SEND(p, START, 0, 0);

          SWAP(p, BODY);
          goto retry;
        } else if (p->buf_len == 2 && p->buf[0] >= 192 && p->buf[0] <= 223) {
          D("new-style two-octet packet length (rfc4880 4.2.2.2)");

          p->header.length = ((p->buf[0] - 192) << 8) |
                              (p->buf[1] + 192);

          /* emit packet header */
          SEND(p, START, 0, 0);

          SWAP(p, BODY);
          goto retry;
        } else if (p->buf_len == 5 && p->buf[0] == 255) {
          D("new-style five-octet packet length (rfc4880 4.2.2.3)");

          p->header.length = (p->buf[1] << 24) | 
                             (p->buf[2] << 16) |
                             (p->buf[3] <<  8) |
                             (p->buf[4]);

          /* emit packet header */
          SEND(p, START, 0, 0);

          SWAP(p, BODY);
          goto retry;
        } else if (p->buf_len == 1 && p->buf[0] >= 224 && p->buf[0] < 255) {
          D("new-style partial body packet length (rfc4880 4.2.2.4)");

          /* mark packet as partial and save partial body length */
          p->header.flags |= PTPGP_PACKET_FLAG_PARTIAL;
          p->header.length = 0;
          p->partial_body_length = 1 << (p->buf[0] & 0x1f);

          D("partial_body_length = %d", p->partial_body_length);

          /* emit packet header */
          SEND(p, START, 0, 0);

          SWAP(p, BODY);
          goto retry;
        }

        goto retry;

        /* never reached */
        break;
      case PTPGP_STREAM_PARSER_STATE_BODY:
        if (p->header.flags & PTPGP_PACKET_FLAG_PARTIAL) { 
          if (src_len < p->partial_body_length) {
            if (src_len > 0) {
              SEND(p, BODY, src, src_len);
              p->partial_body_length -= src_len;
            }

            return PTPGP_OK;
          } else {
            if (p->partial_body_length > 0) {
              SEND(p, BODY, src, p->partial_body_length);

              SHIFT(p->partial_body_length);
            }

            p->buf_len = 0;
            p->partial_body_length = 0;

            D("end of partial body");

            PUSH(p, PARTIAL_BODY_LENGTH);
            goto retry;
          }
        } else {
          if (p->bytes_read + src_len < p->header.length) {
            if (src_len > 0) {
              SEND(p, BODY, src, src_len);
              p->bytes_read += src_len;
            }

            return PTPGP_OK;
          } else {
            if (p->header.length - p->bytes_read > 0) {
              SEND(p, BODY, src, p->header.length - p->bytes_read);
              SHIFT(p->header.length - p->bytes_read);
            }

            SEND(p, END, 0, 0);

            POP(p);
            goto retry;
          }
        }

        /* never reached */
        break;
      case PTPGP_STREAM_PARSER_STATE_PARTIAL_BODY_LENGTH:
        /* append length octet to buffer */
        p->buf[p->buf_len++] = c;
        SHIFT(1);
        
        if (p->buf[0] < 192) {
          D("one-octet partial packet body length (rfc4880 4.2.2.1)");

          /* clear partial header flag */
          p->header.flags ^= PTPGP_PACKET_FLAG_PARTIAL;

          /* save header length */
          p->header.length = p->buf[0];

          /* dump header length */
          D("header.length = %d", (int) p->header.length);

          POP(p);
          goto retry;
        } else if (p->buf_len == 2 && p->buf[0] >= 192 && p->buf[0] <= 223) {
          D("two-octet partial packet body length (rfc4880 4.2.2.2)");

          /* clear partial header flag */
          p->header.flags ^= PTPGP_PACKET_FLAG_PARTIAL;

          /* save header length */
          p->header.length = ((p->buf[0] - 192) << 8) |
                              (p->buf[1] + 192);

          /* dump header length */
          D("header.length = %d", (int) p->header.length);

          POP(p);
          goto retry;
        } else if (p->buf_len == 5 && p->buf[0] == 255) {
          D("four-octet partial packet body length (rfc4880 4.2.2.3)");

          /* clear partial header flag */
          p->header.flags ^= PTPGP_PACKET_FLAG_PARTIAL;

          /* save header length */
          p->header.length = (p->buf[1] << 24) | 
                             (p->buf[2] << 16) |
                             (p->buf[3] <<  8) |
                             (p->buf[4]);

          /* dump header length */
          D("header.length = %d", (int) p->header.length);

          POP(p);
          goto retry;
        } else if (p->buf_len == 1 && p->buf[0] >= 224 && p->buf[0] < 255) {
          D("new-style partial body packet length (rfc4880 4.2.2.4)");

          /* save partial body length */
          p->partial_body_length = 1 << (p->buf[0] & 0x1f);

          D("partial_body_length = %d", p->partial_body_length);

          POP(p);
          goto retry;
        }

        goto retry;

        /* never reached */
        break;
      default:
        /* never reached */
        DIE(p, UNKNOWN_PARSER_STATE);
      }
    }
  }

  /* return success */
  return PTPGP_OK;
}

ptpgp_err_t
ptpgp_stream_parser_done(ptpgp_stream_parser_t *p) {
  return ptpgp_stream_parser_push(p, 0, 0);
}
