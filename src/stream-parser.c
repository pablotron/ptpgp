#include "internal.h"

#define DIE(p, err) do {                                              \
  return (p)->last_err = PTPGP_ERR_STREAM_PARSER_##err;               \
} while (0)

#define PUSH(p, s) do {                                               \
  /* check for state stack overflow */                                \
  if ((p)->state_len >= PTPGP_STREAM_PARSER_STATE_STACK_DEPTH - 1)    \
    DIE((p), STATE_STACK_OVERFLOW);                                   \
                                                                      \
  /* save state, increment depth */                                   \
  (p)->state[(p)->state_len] = (PTPGP_STREAM_PARSER_STATE_##s);       \
  (p)->state_len++;                                                   \
} while (0)

#define POP(p) do {                                                   \
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
  /* check for input buffer overflow */                               \
  if ((n) > src_len)                                                  \
    DIE((p), INPUT_BUFFER_OVERFLOW);                                  \
                                                                      \
  /* shift input buffer ptr and length */                             \
  src += n;                                                           \
  src_len -= n;                                                       \
} while (0)

#define ASSERT_VALID_CONTENT_TAG(p) do {                              \
  /* rfc2440 4.3 (valid packet tags) */                               \
  if ((p)->header.content_tag == 0    ||                              \
      ((p)->header.content_tag > 14   &&                              \
       (p)->header.content_tag < 60)  ||                              \
      (p)->header.content_tag > 63)                                   \
    DIE((p), INVALID_CONTENT_TAG);                                    \
} while (0)

#define SEND(p, t, b, l) do {                                         \
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
                         char *src, 
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

    /* clear buffer and packet flags */
    p->buf_len = 0;

    memset(&(p->header), 0, sizeof(ptpgp_packet_header_t));

    if (!p->state_len) {
      /* check packet header tag (RFC2440 S4.2: bit 7 is always 1) */
      if (!(c & 0x80))
        DIE(p, BAD_PACKET_TAG);

      if (c & (1 << 6)) {
        /* new-style packet header */
        p->header.flags |= PTPGP_PACKET_FLAG_NEW_PACKET;

        /* save content tag */
        p->header.content_tag = (c & 0x3f);
        ASSERT_VALID_CONTENT_TAG(p);

        /* push state */
        PUSH(p, NEW_HEADER_AFTER_TAG);

        /* shift header tag */
        SHIFT(1);
        goto retry;
      } else {
        /* old-style packet header */

        /* save content tag */
        p->header.content_tag = (c & 0x3f) >> 2;
        ASSERT_VALID_CONTENT_TAG(p);

        /* handle length type */
        switch (c & 0x3) {
        case 0:
          p->remaining_length_octets = 1;

          /* push state */
          PUSH(p, OLD_HEADER_AFTER_TAG);

          break;
        case 1:
          p->remaining_length_octets = 2;

          /* push state */
          PUSH(p, OLD_HEADER_AFTER_TAG);

          break;
        case 2:
          p->remaining_length_octets = 4;

          /* push state */
          PUSH(p, OLD_HEADER_AFTER_TAG);

          break;
        case 3:
          p->header.flags |= PTPGP_PACKET_FLAG_INDETERMINITE;
          p->remaining_length_octets = 0;

          /* push state */
          PUSH(p, BODY);

          break;
        default:
          /* never reached */
          DIE(p, BAD_OLD_PACKET_LENGTH_TYPE);
        }

        /* shift header tag */
        SHIFT(1);
        goto retry;
      }
    } else {
      switch (PEEK(p)) {
      case PTPGP_STREAM_PARSER_STATE_OLD_HEADER_AFTER_TAG:
        /* append length octet to buffer */
        p->buf[p->buf_len++] = c;

        if (p->buf_len < p->remaining_length_octets) {
          SHIFT(1);
          goto retry;
        }

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

        SEND(p, START, 0, 0);

        SHIFT(1);
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
          /* new-style one-octet packet length */
          /* (rfc2440 4.2.2.1) */
          p->header.length = p->buf[0];

          /* emit packet header */
          SEND(p, START, 0, 0);

          SWAP(p, BODY);
          goto retry;
        } else if (p->buf_len == 2 && p->buf[0] >= 192 && p->buf[0] <= 223) {
          /* new-style two-octet packet length */
          /* (rfc2440 4.2.2.2) */
          p->header.length = ((p->buf[0] - 192) << 8) |
                              (p->buf[1] + 192);

          /* emit packet header */
          SEND(p, START, 0, 0);

          SWAP(p, BODY);
          goto retry;
        } else if (p->buf_len == 5 && p->buf[0] == 255) {
          /* new-style five-octet packet length */
          /* (rfc2440 4.2.2.3) */
          p->header.length = (p->buf[1] << 24) | 
                             (p->buf[2] << 16) |
                             (p->buf[3] <<  8) |
                             (p->buf[4]);

          /* emit packet header */
          SEND(p, START, 0, 0);

          SWAP(p, BODY);
          goto retry;
        } else if (p->buf_len == 1 && p->buf[0] >= 224 && p->buf[0] < 255) {
          /* new-style partial body packet length */
          /* (rfc2440 4.2.2.4) */

          /* mark packet as partial and save partial body length */
          p->header.flags |= PTPGP_PACKET_FLAG_PARTIAL;
          p->partial_body_length = 1 << (p->buf[0] & 0x1f);

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
            p->partial_body_length -= src_len;
            SEND(p, BODY, src, src_len);
            return PTPGP_OK;
          } else {
            SEND(p, BODY, src, p->partial_body_length);

            SHIFT(p->partial_body_length);

            p->buf_len = 0;
            p->partial_body_length = 0;

            PUSH(p, PARTIAL_BODY_LENGTH);
            goto retry;
          }
        } else {
          if (p->bytes_read + src_len < p->header.length) {
            SEND(p, BODY, src, src_len);
            p->bytes_read += src_len;
            return PTPGP_OK;
          } else {
            SEND(p, BODY, src, p->header.length - p->bytes_read);
            SEND(p, END, 0, 0);

            SHIFT(p->header.length - p->bytes_read);
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
          /* one-octet partial packet body length */
          /* (rfc2440 4.2.2.1) */
          p->partial_body_length = p->buf[0];

          /* clear partial header flag */
          p->header.flags ^= PTPGP_PACKET_FLAG_PARTIAL;

          POP(p);
          goto retry;
        } else if (p->buf_len == 2 && p->buf[0] >= 192 && p->buf[0] <= 223) {
          /* two-octet partial packet body length */
          /* (rfc2440 4.2.2.2) */
          p->partial_body_length = ((p->buf[0] - 192) << 8) |
                                    (p->buf[1] + 192);

          /* clear partial header flag */
          p->header.flags ^= PTPGP_PACKET_FLAG_PARTIAL;

          POP(p);
          goto retry;
        } else if (p->buf_len == 5 && p->buf[0] == 255) {
          /* unsupported 5-byte partial body length */
          /* new-style five-octet packet length */
          /* (rfc2440 4.2.2.4) */
          DIE(p, INVALID_PARTIAL_BODY_LENGTH);
        } else if (p->buf_len == 1 && p->buf[0] >= 224 && p->buf[0] < 255) {
          /* new-style partial body packet length */
          /* (rfc2440 4.2.2.4) */

          /* save partial body length */
          p->partial_body_length = 1 << (p->buf[0] & 0x1f);

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
