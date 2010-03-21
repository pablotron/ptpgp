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

#define STATE(s) PTPGP_PACKET_PARSER_STATE_##s

#define SEND_SUBPACKET_HEADER(p, s, t) do {                           \
  /* clear subpacket header */                                        \
  memset(                                                             \
    &((p)->subpacket_header), 0,                                      \
    sizeof(ptpgp_signature_subpacket_header_t)                        \
  );                                                                  \
                                                                      \
  /* save subpacket size and type */                                  \
  (p)->subpacket_header.size = (s);                                   \
  (p)->subpacket_header.type = (t);                                   \
                                                                      \
  /* flag critical subheaders */                                      \
  if ((p)->subpacket_header.type & (1 << 7)) {                        \
    (p)->subpacket_header.critical = 1;                               \
    (p)->subpacket_header.type ^= (1 << 7);                           \
  }                                                                   \
                                                                      \
  /* decriment remaining_bytes (blech) */                             \
  (p)->remaining_bytes -= (p)->buf_len + (p)->subpacket_header.size;  \
  (p)->buf_len = 0;                                                   \
                                                                      \
  /* send subpacket header */                                         \
  SEND(                                                               \
    (p), SIGNATURE_SUBPACKET_START,                                   \
    (u8*) &((p)->subpacket_header),                                   \
    sizeof(ptpgp_signature_subpacket_header_t)                        \
  );                                                                  \
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
  uint32_t sp_size, sp_type;

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
      case STATE(INIT):
        for (i = 0; i < src_len; i++) {
          p->buf[p->buf_len++] = src[i];

          if (p->buf_len == 10) {
            /* verify version number of packet */
            if (p->buf[0] != 3) {
              D("packet version = %d", p->buf[0]);
              DIE(p, BAD_PACKET_VERSION);
            }

            /* populate packet */
            p->packet.packet.t1.version = p->buf[0];
            memcpy(p->packet.packet.t1.key_id, p->buf + 1, 8);
            p->packet.packet.t1.algorithm = p->buf[9];

            /* send packet header */
            SEND(p, PACKET_START, 0, 0);

            /* clear buffer */
            p->buf_len = 0;
            SHIFT(i + 1);

            /* switch state */
            p->state = STATE(MPI_LIST);
            goto retry;
          }
        }

        break;
      case STATE(MPI_LIST):
        for (i = 0; i < src_len; i++) {
          p->buf[p->buf_len++] = src[i];

          if (p->buf_len == 2) {
            size_t num_bits = (p->buf[0] << 8) | p->buf[1];

            p->remaining_bytes = (num_bits + 7) / 8;

            /* send packet */
            SEND(p, MPI_START, (u8*) &(num_bits), sizeof(size_t));

            /* clear buffer */
            p->buf_len = 0;
            SHIFT(i + 1);

            /* switch state */
            p->state = STATE(MPI_BODY);
            goto retry;
          }
        }

        break;
      case STATE(MPI_BODY):
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
          p->state = STATE(MPI_LIST);
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
      case STATE(INIT):
        for (i = 0; i < src_len; i++) {
          p->buf[p->buf_len++] = src[i];

          /* verify version number of packet */
          if (p->buf[0] < 2 || p->buf[0] > 4) {
            D("bad signature packet version = %d", p->buf[0]);
            DIE(p, BAD_PACKET_VERSION);
          }

          if (p->buf[0] < 4 && p->buf_len == 19) {
            /* v2/v3 signature packet (rfc4880 5.2.2) */
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
            SHIFT(i + 1);

            /* switch state */
            p->state = STATE(MPI_LIST);
            goto retry;
          } else if (p->buf[0] == 4 && p->buf_len == 6) {
            /* v4 signature packet (rfc4880 5.2.3) */

            ptpgp_packet_signature_t *pp = &(p->packet.packet.t2);

            /* populate packet version */
            pp->version = p->buf[0];

            /* populate signature type, pk algo, and hash algo */
            pp->versions.v3.signature_type = p->buf[1];
            pp->versions.v3.public_key_algorithm = p->buf[2];
            pp->versions.v3.hash_algorithm = p->buf[3];

            /* send packet header */
            SEND(p, PACKET_START, 0, 0);

            p->remaining_bytes = (p->buf[4] << 8) | p->buf[5];

            /* send hashed list start */
            SEND(p, SIGNATURE_SUBPACKET_HASHED_LIST_START, 0, 0);

            p->buf_len = 0;
            SHIFT(i + 1);

            p->state = STATE(SIGNATURE_SUBPACKET_HASHED_LIST);
            goto retry;
          }
        }

        break;
      case STATE(MPI_LIST):
        for (i = 0; i < src_len; i++) {
          p->buf[p->buf_len++] = src[i];

          if (p->buf_len == 2) {
            size_t num_bits = (p->buf[0] << 8) | p->buf[1];

            p->remaining_bytes = (num_bits + 7) / 8;

            /* send packet */
            SEND(p, MPI_START, (u8*) &(num_bits), sizeof(size_t));

            /* clear buffer */
            p->buf_len = 0;
            SHIFT(i + 1);

            /* switch state */
            p->state = STATE(MPI_BODY);
            goto retry;
          }
        }

        break;
      case STATE(MPI_BODY):
        if (src_len < p->remaining_bytes) {
          /* send mpi body fragment */
          if (src_len > 0) {
            SEND(p, MPI_BODY, src, src_len);
            p->remaining_bytes -= src_len;
          }

          /* return success */
          return PTPGP_OK;
        } else {
          /* send final mpi body fragment and end notice */
          if (p->remaining_bytes > 0) {
            SEND(p, MPI_BODY, src, p->remaining_bytes);
            SHIFT(p->remaining_bytes);
          }

          /* send end notice */
          SEND(p, MPI_END, 0, 0);

          /* switch state */
          p->state = STATE(MPI_LIST);
          goto retry;
        }

        break;
      case STATE(SIGNATURE_SUBPACKET_HASHED_LIST):
        if (!p->remaining_bytes) {
          /* send hashed list end */
          SEND(p, SIGNATURE_SUBPACKET_HASHED_LIST_END, 0, 0);

          p->state = STATE(SIGNATURE_SUBPACKET_UNHASHED_LIST_SIZE);
          goto retry;
        }

        for (i = 0; i < src_len; i++) {
          p->buf[p->buf_len++] = src[i];

          if (p->buf_len == 2 && p->buf[0] < 192) {
            sp_size = p->buf[0];
            sp_type = p->buf[1];

            SEND_SUBPACKET_HEADER(p, sp_size, sp_type);

            SHIFT(i + 1);

            p->state = STATE(SIGNATURE_SUBPACKET_HASHED);
            goto retry;
          } else if (p->buf_len == 3 && p->buf[0] >= 192 && p->buf[0] < 255) {
            sp_size = ((p->buf[0] - 192) << 8) + p->buf[1] + 192;
            sp_type = p->buf[2];

            SEND_SUBPACKET_HEADER(p, sp_size, sp_type);

            SHIFT(i + 1);

            p->state = STATE(SIGNATURE_SUBPACKET_HASHED);
            goto retry;
          } else if (p->buf_len == 6 && p->buf[0] == 255) {
            sp_size = (p->buf[1] << 24) |
                      (p->buf[2] << 16) |
                      (p->buf[3] <<  8) |
                      (p->buf[4]);
            sp_type = p->buf[5];

            SEND_SUBPACKET_HEADER(p, sp_size, sp_type);

            SHIFT(i + 1);

            p->state = STATE(SIGNATURE_SUBPACKET_HASHED);
            goto retry;
          } else if (p->buf_len > 6) {
            DIE(p, INVALID_SUBPACKET_HEADER);
          }
        }

        break;
      case STATE(SIGNATURE_SUBPACKET_HASHED):
        /* actual subpacket parsing */
        if (src_len < p->subpacket_header.size) {
          /* send hashed subpacket fragment */
          if (src_len > 0) {
            SEND(p, SIGNATURE_SUBPACKET_BODY, src, src_len);
            p->subpacket_header.size -= src_len;
          }

          /* return success */
          return PTPGP_OK;
        } else {
          if (p->subpacket_header.size > 0)
            SEND(p, SIGNATURE_SUBPACKET_BODY, src, p->subpacket_header.size);

          SEND(p, SIGNATURE_SUBPACKET_END, 0, 0);

          p->state = STATE(SIGNATURE_SUBPACKET_HASHED_LIST);
          SHIFT(p->subpacket_header.size);
          goto retry;
        }

        break;
      case STATE(SIGNATURE_SUBPACKET_UNHASHED_LIST_SIZE):
        for (i = 0; i < src_len; i++) {
          p->buf[p->buf_len++] = src[i];

          if (p->buf_len == 2) {
            p->remaining_bytes = (p->buf[0] << 8) | p->buf[1];

            /* send unhashed list start */
            SEND(p, SIGNATURE_SUBPACKET_UNHASHED_LIST_START, 0, 0);

            p->buf_len = 0;
            SHIFT(i + 1);

            p->state = STATE(SIGNATURE_SUBPACKET_UNHASHED_LIST);
            goto retry;
          }
        }

        break;
      case STATE(SIGNATURE_SUBPACKET_UNHASHED_LIST):
        if (!p->remaining_bytes) {
          /* send unhashed list end */
          SEND(p, SIGNATURE_SUBPACKET_UNHASHED_LIST_END, 0, 0);

          p->state = STATE(SIGNATURE_LEFT16);
          goto retry;
        }

        for (i = 0; i < src_len; i++) {
          p->buf[p->buf_len++] = src[i];

          if (p->buf_len == 2 && p->buf[0] < 192) {
            sp_size = p->buf[0];
            sp_type = p->buf[1];

            SEND_SUBPACKET_HEADER(p, sp_size, sp_type);

            SHIFT(i + 1);

            p->state = STATE(SIGNATURE_SUBPACKET_UNHASHED);
            goto retry;
          } else if (p->buf_len == 3 && p->buf[0] >= 192 && p->buf[0] < 255) {
            sp_size = ((p->buf[0] - 192) << 8) + p->buf[1] + 192;
            sp_type = p->buf[2];

            SEND_SUBPACKET_HEADER(p, sp_size, sp_type);

            SHIFT(i + 1);

            p->state = STATE(SIGNATURE_SUBPACKET_UNHASHED);
            goto retry;
          } else if (p->buf_len == 6 && p->buf[0] == 255) {
            sp_size = (p->buf[1] << 24) |
                      (p->buf[2] << 16) |
                      (p->buf[3] <<  8) |
                      (p->buf[4]);
            sp_type = p->buf[5];

            SEND_SUBPACKET_HEADER(p, sp_size, sp_type);

            p->buf_len = 0;
            SHIFT(i + 1);

            p->state = STATE(SIGNATURE_SUBPACKET_UNHASHED);
            goto retry;
          } else if (p->buf_len > 6) {
            DIE(p, INVALID_SUBPACKET_HEADER);
          }
        }

        break;
      case STATE(SIGNATURE_SUBPACKET_UNHASHED):
        /* actual subpacket parsing */
        if (src_len < p->subpacket_header.size) {
          /* send subpacket fragment */
          SEND(p, SIGNATURE_SUBPACKET_BODY, src, src_len);
          p->subpacket_header.size -= src_len;

          /* return success */
          return PTPGP_OK;
        } else {
          SEND(p, SIGNATURE_SUBPACKET_BODY, src, p->subpacket_header.size);
          SEND(p, SIGNATURE_SUBPACKET_END, 0, 0);

          p->state = STATE(SIGNATURE_SUBPACKET_UNHASHED_LIST);
          SHIFT(p->subpacket_header.size);
          goto retry;
        }

        break;
      case STATE(SIGNATURE_LEFT16):
        for (i = 0; i < src_len; i++) {
          p->buf[p->buf_len++] = src[i];

          if (p->buf_len == 2) {
            SEND(p, SIGNATURE_LEFT16, p->buf, 2);

            p->buf_len = 0;
            SHIFT(i + 1);

            p->state = STATE(MPI_LIST);
            goto retry;
          }
        }

        break;
      default:
        /* never reached */
        DIE(p, INVALID_STATE);
      }

      break;

    /* symmetric-key encrypted session key packet (t3, rfc4880 5.3) */
    case PTPGP_TAG_SYMMETRIC_ENCRYPTED_SESSION_KEY:
      switch (p->state) {
      case STATE(INIT):
        for (i = 0; i < src_len; i++) {
          p->buf[p->buf_len++] = src[i];

          /* verify version number of packet */
          if (p->buf[0] != 4) {
            D("bad symmetric-key encrypted sesion key packet version = %d", p->buf[0]);
            DIE(p, BAD_PACKET_VERSION);
          }

          if (p->buf_len == 2) {
            /* populate algorithm and version */
            p->packet.packet.t3.version   = p->buf[0];
            p->packet.packet.t3.algorithm = p->buf[1];
          } else if (
            (p->buf_len == 4 &&
             p->buf[2] == PTPGP_S2K_TYPE_SIMPLE) ||
            (p->buf_len == 12 &&
             p->buf[2] == PTPGP_S2K_TYPE_SALTED) ||
            (p->buf_len == 13 &&
             p->buf[2] == PTPGP_S2K_TYPE_ITERATED_AND_SALTED)
          ) {
            ptpgp_err_t err;

            switch (p->buf[2]) {
            case PTPGP_S2K_TYPE_SIMPLE:
              err = ptpgp_s2k_init(
                &(p->packet.packet.t3.s2k),
                p->buf[2], p->buf[3], 0, 0
              );

              break;
            case PTPGP_S2K_TYPE_SALTED:
              err = ptpgp_s2k_init(
                &(p->packet.packet.t3.s2k),
                p->buf[2], p->buf[3], p->buf + 4, 0
              );

              break;
            case PTPGP_S2K_TYPE_ITERATED_AND_SALTED:
              err = ptpgp_s2k_init(
                &(p->packet.packet.t3.s2k),
                p->buf[2], p->buf[3], p->buf + 4,
                PTPGP_S2K_COUNT_DECODE(p->buf[12])
              );

              break;
            default:
              /* never reached */
              DIE(p, BAD_S2K_TYPE);
            }

            if (err != PTPGP_OK) {
              D("s2k init failed: %d", err);
              return p->last_err = err;
            }

            SEND(p, SYMMETRIC_ENCRYPTED_SESSION_KEY, 0, 0);

            p->buf_len = 0;
            SHIFT(i + 1);

            p->state = STATE(KEY_DATA);
            goto retry;
          } else if (p->buf_len > 13) {
            D("bad s2k type: %d", p->buf[2]);
            DIE(p, BAD_S2K_TYPE);
          }
        }

        break;
      case STATE(KEY_DATA):
        SEND(p, KEY_DATA, src, src_len);
        return PTPGP_OK;

        break;
      default:
        /* never reached */
        DIE(p, INVALID_STATE);
      }

      break;

    /* one-pass signature packet (t4, rfc4880 5.4) */
    case PTPGP_TAG_ONE_PASS_SIGNATURE:
      for (i = 0; i < src_len; i++) {
        p->buf[p->buf_len++] = src[i];

        /* verify version number of packet */
        if (p->buf[0] != 3) {
          D("bad one pass signature packet version = %d", p->buf[0]);
          DIE(p, BAD_PACKET_VERSION);
        }

        if (p->buf_len == 13) {
          p->packet.packet.t4.version               = p->buf[0];
          p->packet.packet.t4.signature_type        = p->buf[1];
          p->packet.packet.t4.hash_algorithm        = p->buf[2];
          p->packet.packet.t4.public_key_algorithm  = p->buf[3];
          memcpy(p->packet.packet.t4.key_id, p->buf + 4, 8);
          p->packet.packet.t4.nested                = p->buf[12];

          SEND(p, ONE_PASS_SIGNATURE, 0, 0);
          SHIFT(i + 1);

          return PTPGP_OK;
        }
      }

      break;

    /* compressed data packet (t8, rfc4880 5.6) */
    case PTPGP_TAG_COMPRESSED_DATA:
      switch (p->state) {
      case STATE(INIT):
        for (i = 0; i < src_len; i++) {
          p->buf[p->buf_len++] = src[i];

          if (p->buf_len == 1) {
            p->packet.packet.t8.compression_algorithm = p->buf[0];

            /* send compressed data header */
            SEND(p, COMPRESSED_DATA, 0, 0);

            p->buf_len = 0;
            SHIFT(i + 1);

            p->state = STATE(PACKET_DATA);
            goto retry;
          }
        }

        break;
      case STATE(PACKET_DATA):
        SEND(p, PACKET_DATA, src, src_len);
        return PTPGP_OK;

        break;
      default:
        /* never reached */
        DIE(p, INVALID_STATE);
      }

      break;

    /* symmetrically encrypted data packet (t9, rfc4880 5.7) */
    case PTPGP_TAG_SYMMETRICALLY_ENCRYPTED_DATA:
      SEND(p, PACKET_DATA, src, src_len);
      return PTPGP_OK;

      break;

    /* marker packet (t10, rfc4880 5.8) */
    case PTPGP_TAG_MARKER:
      /* always ignore marker tags */
      return PTPGP_OK;

      break;

    /* literal data packet (t11, rfc4880 5.9) */
    case PTPGP_TAG_LITERAL_DATA:
      switch (p->state) {
      case STATE(INIT):
        for (i = 0; i < src_len; i++) {
          p->buf[p->buf_len++] = src[i];

          /* XXX: fixme */
          if (p->buf_len == 2) {
            p->packet.packet.t11.format = p->buf[0];
            p->packet.packet.t11.file_name_len = p->buf[1];

            goto retry;
          } else if (p->buf_len > 2) {
            if (p->buf_len == (size_t) 2 + p->buf[1] + 4) {
              /* decode date */
              p->packet.packet.t11.date = (p->buf[2 + p->buf[1] + 0] << 24) |
                                          (p->buf[2 + p->buf[1] + 1] << 16) |
                                          (p->buf[2 + p->buf[1] + 2] <<  8) |
                                          (p->buf[2 + p->buf[1] + 3]);
              /* save file name */
              p->packet.packet.t11.file_name = (p->buf[1]) ? p->buf + 1 : NULL;
                
              /* send literal data header */
              SEND(p, LITERAL_DATA, 0, 0);

              /* explicitly clear file name and length */
              p->packet.packet.t11.file_name     = NULL;
              p->packet.packet.t11.file_name_len = 0;

              p->buf_len = 0;
              SHIFT(i + 1);

              p->state = STATE(PACKET_DATA);
              goto retry;
            }
          }
        }

        break;
      case STATE(PACKET_DATA):
        SEND(p, PACKET_DATA, src, src_len);
        return PTPGP_OK;

        break;
      default:
        /* never reached */
        DIE(p, INVALID_STATE);
      }

      break;

    /* trust packet (t12, rfc4880 5.10) */
    case PTPGP_TAG_TRUST:
      SEND(p, PACKET_DATA, src, src_len);
      return PTPGP_OK;

      break;

    /* user id packet (t13, rfc4880 5.11) */
    case PTPGP_TAG_USER_ID:
      SEND(p, PACKET_DATA, src, src_len);
      return PTPGP_OK;

      break;

    /* sym encrypted integrity protected data packet (t18, rfc4880 5.13) */
    case PTPGP_TAG_SYM_ENCRYPTED_INTEGRITY_PROTECTED_DATA:
      switch (p->state) {
      case STATE(INIT):
        p->packet.packet.t18.version = src[0];

        SEND(p, SYM_ENCRYPTED_INTEGRITY_PROTECTED_DATA, 0, 0);

        SHIFT(1);

        p->state = STATE(PACKET_DATA);
        goto retry;
        
        break;
      case STATE(PACKET_DATA):
        SEND(p, PACKET_DATA, src, src_len);
        return PTPGP_OK;
      default:
        /* never reached */
        DIE(p, INVALID_STATE);
      }

      break;

    /* modification detection code packet (t19, rfc4880 5.14) */
    case PTPGP_TAG_MODIFICATION_DETECTION_CODE:
      switch (p->state) {
      case STATE(INIT):
        p->buf_len = 0;
        p->state = STATE(PACKET_DATA);

        /* fall-through */
      case STATE(PACKET_DATA):
        if (p->buf_len + src_len <= 20) {
          memcpy(p->buf + p->buf_len, src, src_len);
          p->buf_len += src_len;

          if (p->buf_len + src_len == 20)
            SEND(p, PACKET_DATA, p->buf, p->buf_len);

          /* return success */
          return PTPGP_OK;
        } else {
          DIE(p, BAD_MDC_SIZE);
        }

        break;
      default:
        /* never reached */
        DIE(p, INVALID_STATE);
      }

      break;
    /* public-key packets     (t6, rfc4880 5.5.1.1 and 5.5.2)
     * public-subkey packets  (t14, rfc4880 5.5.1.2 and 5.5.2)
     * secret-key packets     (t5, rfc4880 5.5.1.3 and 5.5.3)
     * secret-subkey packets  (t7, rfc4880 5.5.1.4 and 5.5.3) 
     */
    case PTPGP_TAG_PUBLIC_KEY:
    case PTPGP_TAG_PUBLIC_SUBKEY:
    case PTPGP_TAG_SECRET_KEY:
    case PTPGP_TAG_SECRET_SUBKEY:
      switch (p->state) {
      case STATE(INIT):
        for (i = 0; i < src_len; i++) {
          p->buf[p->buf_len++] = src[i];

          if (p->buf_len > 4) {
            ptpgp_err_t err;
            ptpgp_type_info_t *info;

            if (p->buf_len == 5) {
              /* populate shared fields */
              p->packet.packet.t6.all.version = p->buf[0];
              p->packet.packet.t6.all.creation_time = (p->buf[1] << 24) |
                                                      (p->buf[2] << 16) |
                                                      (p->buf[3] <<  8) |
                                                      (p->buf[4]);
            } else if ((p->buf_len == 8 && p->buf[0] == 3) ||
                       (p->buf_len == 6 && p->buf[0] == 4)) {
              if (p->buf[0] == 3) {
                p->packet.packet.t6.v3.valid_days = (p->buf[5] << 8) |
                                                    (p->buf[6]);
                p->packet.packet.t6.all.public_key_algorithm = p->buf[7];
              } else {
                p->packet.packet.t6.all.public_key_algorithm = p->buf[5];
              }

              /* get public key algorithm info */
              err = ptpgp_type_info(
                PTPGP_TYPE_PUBLIC_KEY,
                p->packet.packet.t6.all.public_key_algorithm,
                &info
              );

              /* check for error */
              if (err != PTPGP_OK)
                return p->last_err = err;

              /* get num remaining mpis */
              p->packet.packet.t6.all.num_mpis = info->num_public_key_mpis;
              p->packet.packet.t5.num_mpis     = info->num_private_key_mpis;
              p->num_mpis = info->num_public_key_mpis;

              /* send packet info */
              SEND(p, KEY_PACKET_HEADER, 0, 0);

              p->buf_len = 0;
              SHIFT(i + i);

              p->state = STATE(MPI_LIST);
              goto retry;
            } else if (p->buf_len > 8) {
              DIE(p, BAD_PUBLIC_KEY_PACKET);
            }
          }
        }

        break;
      case STATE(MPI_LIST):
        for (i = 0; i < src_len; i++) {
          p->buf[p->buf_len++] = src[i];

          if (p->buf_len == 2) {
            size_t num_bits = (p->buf[0] << 8) | p->buf[1];

            p->remaining_bytes = (num_bits + 7) / 8;

            /* send packet */
            SEND(p, MPI_START, (u8*) &(num_bits), sizeof(size_t));

            /* clear buffer */
            p->buf_len = 0;
            SHIFT(i + 1);

            /* switch state */
            p->state = STATE(MPI_BODY);
            goto retry;
          }
        }

        break;
      case STATE(MPI_BODY):
        if (src_len < p->remaining_bytes) {
          /* send mpi body fragment */
          if (src_len > 0) {
            SEND(p, MPI_BODY, src, src_len);
            p->remaining_bytes -= src_len;
          }

          /* return success */
          return PTPGP_OK;
        } else {
          /* send final mpi body fragment and end notice */
          if (p->remaining_bytes > 0) {
            SEND(p, MPI_BODY, src, p->remaining_bytes);
            SHIFT(p->remaining_bytes);
          }

          /* send end notice */
          SEND(p, MPI_END, 0, 0);

          /* decriment mpi count */
          p->num_mpis--;

          /* switch state */
          if (p->num_mpis > 0)
            p->state = STATE(MPI_LIST);
          else {
            switch (p->packet.tag) {
            case PTPGP_TAG_PUBLIC_KEY:
            case PTPGP_TAG_PUBLIC_SUBKEY:
              /* any additional data is an error */
              p->state = STATE(LAST);
              break;
            case PTPGP_TAG_SECRET_KEY:
            case PTPGP_TAG_SECRET_SUBKEY:
              if (p->packet.packet.t5.key_usage || 
                  p->packet.packet.t5.plaintext_secret_key) {
                /* have private key fields; now read the checksum */
                p->state = STATE(SECRET_KEY_CHECKSUM);
              } else {
                /* now fetch private key fields */
                p->state = STATE(SECRET_KEY_FIELDS);
              }

              break;
            default:
              /* if we reach here, it's an error */
              D("invalid packet tag");
              DIE(p, INVALID_STATE);
            }
          }

          goto retry;
        }

        break;
      case STATE(SECRET_KEY_FIELDS):
        p->packet.packet.t5.key_usage = src[0];
        p->num_mpis = p->packet.packet.t5.num_mpis;

        if (src[0] == 254 || src[0] == 255) {
          /* encrypted key with s2k specifier */
          p->state = STATE(SECRET_KEY_SYMMETRIC_ALGORITHM);
        } else if (src[0] > 0) {
          /* octet is symmetric algorithm */
          ptpgp_type_info_t *info;
          ptpgp_err_t err;

          /* get symmetric algorithm info */
          err = ptpgp_type_info(
            PTPGP_TYPE_SYMMETRIC,
            src[0], &info
          );

          /* check for error */
          if (err != PTPGP_OK)
            return p->last_err = err;

          /* save algorithm in packet and blcok size in context */
          p->packet.packet.t5.symmetric_algorithm = src[0];
          p->symmetric_block_size = info->symmetric_block_size;

          /* get IV */
          p->state = STATE(SECRET_KEY_IV);
        } else {
          /* key is not encrypted, so save the number of mpis
           * and switch state */
          p->packet.packet.t5.plaintext_secret_key = 1;
          SEND(p, SECRET_KEY_PACKET_HEADER, 0, 0);
          p->state = STATE(MPI_LIST);
        }

        p->buf_len = 0;
        SHIFT(1);

        goto retry;

        break;
      case STATE(SECRET_KEY_SYMMETRIC_ALGORITHM):
        do {
          ptpgp_type_info_t *info;
          ptpgp_err_t err;

          /* get symmetric algorithm info */
          err = ptpgp_type_info(
            PTPGP_TYPE_SYMMETRIC,
            src[0], &info
          );

          /* check for error */
          if (err != PTPGP_OK)
            return p->last_err = err;

          /* save algorithm in packet and blcok size in context */
          p->packet.packet.t5.symmetric_algorithm = src[0];
          p->symmetric_block_size = info->symmetric_block_size;

          /* clear buffer, shift input */
          p->buf_len = 0;
          SHIFT(1);

          /* get s2k */
          p->state = STATE(SECRET_KEY_S2K);
          goto retry;
        } while (0);

        break;
      case STATE(SECRET_KEY_S2K):
        for (i = 0; i < src_len; i++) {
          p->buf[p->buf_len++] = src[i];

          if (
            (p->buf_len ==  2 &&
             p->buf[0] == PTPGP_S2K_TYPE_SIMPLE) ||
            (p->buf_len == 10 &&
             p->buf[0] == PTPGP_S2K_TYPE_SALTED) ||
            (p->buf_len == 11 &&
             p->buf[0] == PTPGP_S2K_TYPE_ITERATED_AND_SALTED)
          ) {
            ptpgp_err_t err;
            u8 *salt = 0;
            size_t count = 0;

            switch (p->buf[0]) {
            case PTPGP_S2K_TYPE_ITERATED_AND_SALTED:
              count = PTPGP_S2K_COUNT_DECODE(p->buf[10]);
              /* fall-through */
            case PTPGP_S2K_TYPE_SALTED:
              salt = p->buf + 2;
              break;
            case PTPGP_S2K_TYPE_SIMPLE:
              /* do nothing */
              break;
            default:
              /* never reached */
              D("invalid s2k type =  %d", (int) p->buf[0]);
              DIE(p, BAD_S2K_TYPE);
            }

            /* init s2k */
            err = ptpgp_s2k_init(
              &(p->packet.packet.t5.s2k),
              p->buf[2], p->buf[3], salt, count
            );

            /* check for error */
            if (err != PTPGP_OK) {
              D("s2k init failed: %d", err);
              return p->last_err = err;
            }

            /* clear buffer, shift input */
            p->buf_len = 0;
            SHIFT(i + 1);

            /* read IV */
            p->state = STATE(SECRET_KEY_IV);
            goto retry;
          } else if (p->buf_len > 11) {
            /* corrupt packet */
            D("s2k parse failed");
            DIE(p, BAD_S2K_TYPE);
          }
        }
        
        break;
      case STATE(SECRET_KEY_IV):
        for (i = 0; i < src_len; i++) {
          p->buf[p->buf_len++] = src[i];

          if (p->buf_len == p->symmetric_block_size) {
            memcpy(p->packet.packet.t5.iv, p->buf, p->symmetric_block_size);

            SEND(p, SECRET_KEY_PACKET_HEADER, 0, 0);

            p->buf_len = 0;
            SHIFT(1);

            p->state = STATE(MPI_LIST);
            goto retry;
          } else if (p->buf_len > p->symmetric_block_size) {
            /* FIXME: corruption! */
          }
        }

        break;
      case STATE(SECRET_KEY_CHECKSUM):
        for (i = 0; i < src_len; i++) {
          p->buf[p->buf_len++] = src[i];

          if ((p->buf_len == 2  && p->packet.packet.t5.key_usage != 254) ||
              (p->buf_len == 20 && p->packet.packet.t5.key_usage == 254)) {
            SEND(p, SECRET_KEY_PACKET_CHECKSUM, p->buf, p->buf_len);

            /* clear buffer, shift input */
            p->buf_len = 0;
            SHIFT(1);

            /* any packet data after this is an error */
            p->state = STATE(LAST);
            goto retry;
          } else if (p->buf_len > 20) {
            DIE(p, BAD_SECRET_KEY_CHECKSUM);
          }
        }

        break;
      default:
        /* if we reach here, it's an error */
        DIE(p, INVALID_STATE);
      }

      break;
    default:
      /* pass the raw packet data for unsupported packets */
      switch (p->state) {
      case STATE(INIT):
        /* warn about unsupported packet type */
        W("unimplemented tag: %d", p->packet.tag);
        p->state = STATE(PACKET_DATA);

        /* fall-through */
      case STATE(PACKET_DATA):
        /* send raw packet data */
        SEND(p, PACKET_DATA, src, src_len);
        return PTPGP_OK;

        break;
      default:
        /* never reached */
        DIE(p, INVALID_STATE);
      }
    }
  }

  /* return success */
  return PTPGP_OK;
};

ptpgp_err_t
ptpgp_packet_parser_done(ptpgp_packet_parser_t *p) {
  return ptpgp_packet_parser_push(p, 0, 0);
}
