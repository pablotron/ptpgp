#include "internal.h"

#define STATE(s) PTPGP_SIGNATURE_SUBPACKET_PARSER_STATE_##s

#define DIE(p, err) do {                                              \
  D("returning error %s", #err);                                      \
  return (p)->last_err = PTPGP_ERR_SIGNATURE_SUBPACKET_PARSER_##err;  \
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
    (p), (PTPGP_SIGNATURE_SUBPACKET_PARSER_TOKEN_##t),                \
    (b), (l)                                                          \
  );                                                                  \
                                                                      \
  if (err != PTPGP_OK)                                                \
    return (p)->last_err = err;                                       \
} while (0)

#define SEND_TIME_SUBPACKET(k) do {                                   \
  for (i = 0; i < src_len; i++) {                                     \
    p->buf[p->buf_len++] = src[i];                                    \
                                                                      \
    if (p->buf_len == 4) {                                            \
      uint32_t t = (p->buf[0] << 24) |                                \
                   (p->buf[1] << 16) |                                \
                   (p->buf[2] <<  8) |                                \
                   (p->buf[3]);                                       \
                                                                      \
      SEND(p, k, (u8*) &t, sizeof(uint32_t));                         \
                                                                      \
      p->buf_len = 0;                                                 \
      return PTPGP_OK;                                                \
    }                                                                 \
  }                                                                   \
                                                                      \
} while (0)

#define SEND_OCTET_ARRAY(k) do {                                      \
  for (i = 0; i < src_len; i++)                                       \
    SEND(p, k, src + i, 1);                                           \
  return PTPGP_OK;                                                    \
} while (0)


ptpgp_err_t
ptpgp_signature_subpacket_parser_init(ptpgp_signature_subpacket_parser_t *p,
                                      ptpgp_signature_subpacket_type_t t,
                                      ptpgp_signature_subpacket_parser_cb_t cb,
                                      void *user_data) {
  memset(p, 0, sizeof(ptpgp_signature_subpacket_parser_t));

  p->type = t;
  p->cb = cb;
  p->user_data = user_data;

  /* return success */
  return PTPGP_OK;
}

ptpgp_err_t
ptpgp_signature_subpacket_parser_push(ptpgp_signature_subpacket_parser_t *p,
                                      u8 *src, size_t src_len) {
  size_t i;

  if (p->last_err)
    return p->last_err;

  if (!src || !src_len) {
    if (p->state == STATE(DONE))
      DIE(p, ALREADY_DONE);
    p->state = STATE(DONE);

    /* return success */
    return PTPGP_OK;
  }

retry:
  if (src_len > 0) {
    switch (p->state) {
    case STATE(INIT):
      switch (p->type) {
      case PTPGP_SIGNATURE_SUBPACKET_TYPE_SIGNATURE_CREATION_TIME:
        /* rfc4880 5.2.3.4 */

        SEND_TIME_SUBPACKET(SIGNATURE_CREATION_TIME);

        break;
      case PTPGP_SIGNATURE_SUBPACKET_TYPE_ISSUER:
        /* rfc4880 5.2.3.5 */

        for (i = 0; i < src_len; i++) {
          p->buf[p->buf_len++] = src[i];

          if (p->buf_len == 8) {
            SEND(p, ISSUER, p->buf, p->buf_len);
            p->buf_len = 0;

            return PTPGP_OK;
          }
        }

        break;
      case PTPGP_SIGNATURE_SUBPACKET_TYPE_KEY_EXPIRATION_TIME:
        /* rfc4880 5.2.3.6 */

        SEND_TIME_SUBPACKET(KEY_EXPIRATION_TIME);

        break;
      case PTPGP_SIGNATURE_SUBPACKET_TYPE_PREFERRED_SYMMETRIC_ALGORITHMS:
        /* rfc4880 5.2.3.7 */

        SEND_OCTET_ARRAY(PREFERRED_SYMMETRIC_ALGORITHM);

        break;
      case PTPGP_SIGNATURE_SUBPACKET_TYPE_PREFERRED_HASH_ALGORITHMS:
        /* rfc4880 5.2.3.8 */

        SEND_OCTET_ARRAY(PREFERRED_HASH_ALGORITHM);

        break;
      case PTPGP_SIGNATURE_SUBPACKET_TYPE_PREFERRED_COMPRESSION_ALGORITHMS:
        /* rfc4880 5.2.3.9 */

        SEND_OCTET_ARRAY(PREFERRED_COMPRESSION_ALGORITHM);

        break;
      case PTPGP_SIGNATURE_SUBPACKET_TYPE_SIGNATURE_EXPIRATION_TIME:
        /* rfc4880 5.2.3.10 */

        SEND_TIME_SUBPACKET(SIGNATURE_EXPIRATION_TIME);

        break;
      case PTPGP_SIGNATURE_SUBPACKET_TYPE_EXPORTABLE_CERTIFICATION:
        /* rfc4880 5.2.3.11 */

        SEND(p, EXPORTABLE_CERTIFICATION, src, 1);
        return PTPGP_OK;

        break;
      case PTPGP_SIGNATURE_SUBPACKET_TYPE_REVOCABLE:
        /* rfc4880 5.2.3.12 */

        SEND(p, REVOCABLE, src, 1);
        return PTPGP_OK;

        break;
      case PTPGP_SIGNATURE_SUBPACKET_TYPE_TRUST_SIGNATURE:
        /* rfc4880 5.2.3.13 */

        for (i = 0; i < src_len; i++) {
          p->buf[p->buf_len++] = src[i];

          if (p->buf_len == 2) {
            SEND(p, TRUST_LEVEL, p->buf, 1);
            SEND(p, TRUST_AMOUNT, p->buf + 1, 1);

            p->buf_len = 0;
            return PTPGP_OK;
          }
        }

        break;
      case PTPGP_SIGNATURE_SUBPACKET_TYPE_REGULAR_EXPRESSION:
        /* rfc4880 5.2.3.14 */

        SEND(p, REGULAR_EXPRESSION_FRAGMENT, src, src_len);
        return PTPGP_OK;

        break;
      case PTPGP_SIGNATURE_SUBPACKET_TYPE_REVOCATION_KEY:
        /* rfc4880 5.2.3.15 */

        for (i = 0; i < src_len; i++) {
          p->buf[p->buf_len++] = src[i];

          if (p->buf_len == 22) {

            SEND(p, REVOCATION_KEY_CLASS, p->buf, 1);
            SEND(p, REVOCATION_PUBLIC_KEY_ALGORITHM, p->buf + 1, 1);
            SEND(p, REVOCATION_FINGERPRINT, p->buf + 2, 20);

            p->buf_len = 0;
            return PTPGP_OK;
          }
        }

        break;
      case PTPGP_SIGNATURE_SUBPACKET_TYPE_NOTATION_DATA:
        /* rfc4880 5.2.3.16 */

        for (i = 0; i < src_len; i++) {
          p->buf[p->buf_len++] = src[i];

          if (p->buf_len == 8) {
            uint32_t flags = (p->buf[0] << 24) | 
                             (p->buf[1] << 16) | 
                             (p->buf[2] <<  8) | 
                             (p->buf[3]);

            SEND(p, NOTATION_DATA_FLAGS, (u8*) &flags, 4);
            p->remaining_name_bytes  = (p->buf[4] << 8) | p->buf[5];
            p->remaining_value_bytes = (p->buf[6] << 8) | p->buf[7];

            p->buf_len = 0;
            SHIFT(8);
            p->state = STATE(NOTATION_DATA_NAME);
            goto retry;
          }
        }

        break;
      case PTPGP_SIGNATURE_SUBPACKET_TYPE_KEY_SERVER_PREFERENCES:
        /* rfc4880 5.2.3.17 */

        SEND_OCTET_ARRAY(KEY_SERVER_PREFERENCE);

        break;
      case PTPGP_SIGNATURE_SUBPACKET_TYPE_PREFERRED_KEY_SERVER:
        /* rfc4880 5.2.3.18 */

        SEND(p, PREFERRED_KEY_SERVER, src, src_len);
        return PTPGP_OK;

        break;
      case PTPGP_SIGNATURE_SUBPACKET_TYPE_PRIMARY_USER_ID:
        /* rfc4880 5.2.3.19 */

        SEND(p, PRIMARY_USER_ID, src, 1);
        return PTPGP_OK;

        break;
      case PTPGP_SIGNATURE_SUBPACKET_TYPE_POLICY_URI:
        /* rfc4880 5.2.3.20 */

        SEND(p, POLICY_URI, src, src_len);
        return PTPGP_OK;

        break;
      case PTPGP_SIGNATURE_SUBPACKET_TYPE_KEY_FLAGS:
        /* rfc4880 5.2.3.21 */

        SEND_OCTET_ARRAY(KEY_FLAG);

        break;
      case PTPGP_SIGNATURE_SUBPACKET_TYPE_SIGNERS_USER_ID:
        /* rfc4880 5.2.3.22 */

        SEND(p, SIGNERS_USER_ID, src, src_len);
        return PTPGP_OK;

        break;
      case PTPGP_SIGNATURE_SUBPACKET_TYPE_REASON_FOR_REVOCATION:
        /* rfc4880 5.2.3.23 */

        SEND(p, REVOCATION_CODE, src, 1);

        SHIFT(1);
        p->state = STATE(REVOCATION_REASON);
        goto retry;

        break;
      case PTPGP_SIGNATURE_SUBPACKET_TYPE_FEATURES:
        /* rfc4880 5.2.3.24 */

        SEND_OCTET_ARRAY(FEATURE);

        break;
      case PTPGP_SIGNATURE_SUBPACKET_TYPE_SIGNATURE_TARGET:
        /* rfc4880 5.2.3.25 */

        for (i = 0; i < src_len; i++) {
          p->buf[p->buf_len++] = src[i];

          if (p->buf_len == 2) {
            SEND(p, SIGNATURE_TARGET_PUBLIC_KEY_ALGORITHM, p->buf, 1);
            SEND(p, SIGNATURE_TARGET_HASH_ALGORITHM, p->buf + 1, 1);

            p->buf_len = 0;
            SHIFT(2);
            p->state = STATE(SIGNATURE_TARGET_HASH);
            goto retry;
          }
        }

        break;
      case PTPGP_SIGNATURE_SUBPACKET_TYPE_EMBEDDED_SIGNATURE:
        /* rfc4880 5.2.3.26 */
        
        SEND(p, EMBEDDED_SIGNATURE, src, src_len);
        return PTPGP_OK;

        break;
      default:
        /* ignore unknown subpacket types */
        return PTPGP_OK;
      }

      break;
    case STATE(NOTATION_DATA_NAME):
      if (src_len < p->remaining_name_bytes) {
        SEND(p, NOTATION_DATA_NAME, src, src_len);
        p->remaining_name_bytes -= src_len;
        return PTPGP_OK;
      } else {
        SEND(p, NOTATION_DATA_NAME, src, p->remaining_name_bytes);
        SHIFT(p->remaining_name_bytes);
        p->state = STATE(NOTATION_DATA_VALUE);
        goto retry;
      }

      break;
    case STATE(NOTATION_DATA_VALUE):
      if (src_len < p->remaining_value_bytes) {
        SEND(p, NOTATION_DATA_VALUE, src, src_len);
        p->remaining_value_bytes -= src_len;
        return PTPGP_OK;
      } else {
        SEND(p, NOTATION_DATA_VALUE, src, p->remaining_value_bytes);
        SHIFT(p->remaining_value_bytes);
        p->state = STATE(INIT);
        goto retry;
      }

      break;
    case STATE(REVOCATION_REASON):
      SEND(p, REVOCATION_REASON, src, src_len);
      return PTPGP_OK;

      break;
    case STATE(SIGNATURE_TARGET_HASH):
      SEND(p, SIGNATURE_TARGET_HASH_DATA, src, src_len);
      return PTPGP_OK;

      break;
    default:
      DIE(p, INVALID_STATE);
    }
  }

  /* return success */
  return PTPGP_OK;
}

ptpgp_err_t
ptpgp_signature_subpacket_parser_done(ptpgp_signature_subpacket_parser_t *p) {
  return ptpgp_signature_subpacket_parser_push(p, 0, 0);
}
