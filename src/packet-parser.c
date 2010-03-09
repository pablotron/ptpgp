#include "internal.h"

#define FLAG_DONE (1 << 0)

#define FLAG_IS_SET(p, f) ((p)->flags & FLAG_##f)
#define FLAG_SET(p, f) do { (p)->flags |= FLAG_##f; } while (0)

#define DIE(p, err) do {                                              \
  D("returning error %s", #err);                                      \
  return (p)->last_err = PTPGP_ERR_PACKET_PARSER_##err;               \
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

#define SEND(p, t, b, l) do {                                         \
  D("sending %s data to callback (%d bytes)", #t, (int) (l));         \
                                                                      \
  ptpgp_err_t err = (p)->cb(                                          \
    (p), (PTPGP_PACKET_PARSER_TOKEN_##t),                             \
    &((p)->packet), (b), (l)                                          \
  );                                                                  \
                                                                      \
  if (err != PTPGP_OK)                                                \
    return (p)->last_err = err;                                       \
} while (0)

ptpgp_err_t
ptpgp_packet_parser_init(ptpgp_packet_parser_t *p,
                         ptpgp_tag_t tag,
                         ptpgp_packet_parser_cb_t cb,
                         void *user_data) {
  memset(p, 0, sizeof(ptpgp_packet_parser_t));

  /* save tag, callback, and user data */
  p->packet.tag = tag;
  p->cb = cb;
  p->user_data = user_data;

  /* return success */
  return PTPGP_OK;
}

ptpgp_err_t
ptpgp_packet_parser_push(ptpgp_packet_parser_t *p, 
                         u8 *src,
                         size_t src_len) {
  size_t i;

  if (p->last_err)
    return p->last_err;

  if (!src || !src_len) {
    if (FLAG_IS_SET(p, DONE))
      DIE(p, ALREADY_DONE);

    /* mark parser as done */
    FLAG_SET(p, DONE);

    SEND(p, PACKET_END, 0, 0);

    /* return success */
    return PTPGP_OK;
  }

retry:
  if (src_len > 0) {
    switch (p->packet.tag) {
    /* signature packet (t1, rfc4880 5.1) */
    case PTPGP_TAG_PUBLIC_KEY_ENCRYPTED_SESSION_KEY:
      switch (p->state) {
      case PTPGP_PACKET_PARSER_STATE_INIT:
        for (i = 0; i < src_len; i++) {
          p->buf[p->buf_len++] = src[i];

          if (p->buf_len == 10) {
            /* verify version number of packet */
            if (p->buf[0] != 3)
              DIE(p, BAD_PACKET_VERSION);

            /* populate packet */
            p->packet.packet.t1.version = p->buf[0];
            memcpy(p->packet.packet.t1.key_id, p->buf + 1, 8);
            p->packet.packet.t1.algorithm = p->buf[9];

            /* send packet header */
            SEND(p, PACKET_START, 0, 0);

            /* clear buffer */
            p->buf_len = 0;

            /* switch state */
            p->state = PTPGP_PACKET_PARSER_STATE_MPI_LIST;
            SHIFT(i);
            goto retry;
          }
        }

        break;
      case PTPGP_PACKET_PARSER_STATE_MPI_LIST:
        for (i = 0; i < src_len; i++) {
          p->buf[p->buf_len++] = src[i];

          if (p->buf_len == 2) {
            size_t num_bits = (p->buf[0] << 8) | p->buf[1];

            p->remaining_bytes = (num_bits + 7) / 8;

            /* send packet */
            SEND(p, MPI_START, (u8*) &(num_bits), sizeof(size_t));

            /* clear buffer */
            p->buf_len = 0;

            /* switch state */
            p->state = PTPGP_PACKET_PARSER_STATE_MPI_BODY;
            SHIFT(i);
            goto retry;
          }
        }

        break;
      case PTPGP_PACKET_PARSER_STATE_MPI_BODY:
        if (src_len < p->remaining_bytes) {
          /* send mpi body fragment */
          SEND(p, MPI_BODY, src, src_len);
          p->remaining_bytes -= src_len;

          /* return success */
          return PTPGP_OK;
        } else {
          /* send final mpi body fragment and end notice */
          SEND(p, MPI_BODY, src, p->remaining_bytes);
          SEND(p, MPI_END, 0, 0);

          /* switch state */
          p->state = PTPGP_PACKET_PARSER_STATE_MPI_LIST;
          SHIFT(p->remaining_bytes);
          goto retry;
        }

        break;
      default:
        /* never reached */
        DIE(p, INVALID_STATE);
      }

      break;

    /* signature packet (t2, rfc4880 5.2) */
    case PTPGP_TAG_SIGNATURE:
      switch (p->state) {
      case PTPGP_PACKET_PARSER_STATE_INIT:
        for (i = 0; i < src_len; i++) {
          p->buf[p->buf_len++] = src[i];

          /* verify version number of packet */
          if (p->buf[0] != 3 && p->buf[0] != 4)
            DIE(p, BAD_PACKET_VERSION);

          if (p->buf[0] == 3 && p->buf_len == 19) {
            /* v3 signature packet (rfc4880 5.2.2) */
            ptpgp_packet_signature_t *pp = &(p->packet.packet.t2);

            /* populate packet version */
            pp->version = p->buf[0];

            /* verify hashed material length */
            if (p->buf[1] != 5)
              DIE(p, BAD_HASHED_MATERIAL_LENGTH);

            pp->versions.v3.signature_type = p->buf[2];
            pp->versions.v3.creation_time = 
              (p->buf[3] << 24) |
              (p->buf[4] << 16) |
              (p->buf[5] <<  8) |
              (p->buf[6]);

            memcpy(pp->versions.v3.signer_key_id, p->buf + 7, 8);
            pp->versions.v3.public_key_algorithm = p->buf[15];
            pp->versions.v3.hash_algorithm = p->buf[16];
            memcpy(pp->versions.v3.left16, p->buf + 17, 2); 

            /* send packet header */
            SEND(p, PACKET_START, 0, 0);

            /* clear buffer */
            p->buf_len = 0;

            /* switch state */
            p->state = PTPGP_PACKET_PARSER_STATE_MPI_LIST;
            SHIFT(i);
            goto retry;
          } else if (p->buf[0] == 4 && p->buf_len == 6) {
            /* v4 signature packet (rfc4880 5.2.3) */

          } else {
          }
        }

        break;
      default:
        /* never reached */
        DIE(p, INVALID_STATE);
      }
    default:
      W("unimplemented tag: %d", p->packet.tag);
    }
  }

  /* return success */
  return PTPGP_OK;
};

ptpgp_err_t
ptpgp_packet_parser_done(ptpgp_packet_parser_t *p) {
  return ptpgp_packet_parser_push(p, 0, 0);
}
