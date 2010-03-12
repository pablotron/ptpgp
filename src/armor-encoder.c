#include "internal.h"

#define DIE(p, e) do {                                                \
  return (p)->last_err = PTPGP_ERR_ARMOR_ENCODER_##e;                 \
} while (0)

#define FLUSH(p) do {                                                 \
  TRY((p)->cb((p), (p)->buf, (p)->buf_len));                          \
  (p)->buf_len = 0;                                                   \
} while (0)

#define PUSH(p, b, l) TRY(push((p), (u8*) (b), (l)))

static ptpgp_err_t
push(ptpgp_armor_encoder_t *p, u8 *src, size_t src_len) {
  size_t num_bytes;

  while (src_len > 0) {
    /* how many bytes can we copy? */
    num_bytes = PTPGP_ARMOR_ENCODER_OUT_BUF_SIZE - p->buf_len;

    /* clamp to input value */
    if (num_bytes > src_len)
      num_bytes = src_len;

    /* copy input chunk to output buffer */
    memcpy(p->buf + p->buf_len, src, num_bytes);
    p->buf_len += num_bytes;

    /* shift input data */
    src += num_bytes;
    src_len -= num_bytes;

    /* maybe flush */
    if (p->buf_len == PTPGP_ARMOR_ENCODER_OUT_BUF_SIZE)
      FLUSH(p);
  }

  /* return success */
  return PTPGP_OK;
}

static ptpgp_err_t
base64_cb(ptpgp_base64_t *b, u8 *src, size_t src_len) {
  ptpgp_armor_encoder_t *p = (ptpgp_armor_encoder_t*) b->user_data;
  PUSH(p, src, src_len);
  return PTPGP_OK;
}

ptpgp_err_t
ptpgp_armor_encoder_init(ptpgp_armor_encoder_t *p,
                         char *envelope_name,
                         char **headers,
                         ptpgp_armor_encoder_cb_t cb,
                         void *user_data) {
  u8 buf[128];
  size_t l;
  bool k = 1;

  /* check name length */
  l = strlen(envelope_name) + 1;
  if (l >= PTPGP_ARMOR_ENCODER_ENVELOPE_NAME_SIZE)
    DIE(p, ENVELOPE_NAME_TOO_LONG);

  /* clear encoder */
  memset(p, 0, sizeof(ptpgp_armor_encoder_t));

  /* populate encoder */
  memcpy(p->envelope_name, envelope_name, l);
  p->cb = cb;
  p->user_data = user_data;

  /* begin armor envelope */
  l = snprintf(
    (char*) buf, sizeof(buf),
    "-----%s-----\r\n",
    p->envelope_name
  );

  PUSH(p, buf, l);

  while (*headers) {
    /* get header name/value length */
    l = strlen(*headers);

    /* don't allow header values with lengtsh > 80 */
    if (l > PTPGP_ARMOR_ENCODER_HEADER_VALUE_SIZE) {
      if (k)
        DIE(p, HEADER_NAME_TOO_LONG);
      else
        DIE(p, HEADER_VALUE_TOO_LONG);
    }

    /* add header name/value */
    l = snprintf(
      (char*) buf, sizeof(buf), "%s%s",
      *headers, k ? ": " : "\r\n"
    );

    PUSH(p, buf, l);

    /* increment header pointer */
    headers++;
    k = !k;
  }

  /* make sure we didn't have an odd number of header values */
  if (!k)
    DIE(p, MISSING_HEADER_VALUE);

  /* push header terminater */
  PUSH(p, "\r\n", 2);

  /* init crc24 encoder */
  TRY(ptpgp_crc24_init(&(p->crc24)));

  /* init base64 encoder */
  TRY(ptpgp_base64_init(&(p->base64), 1, base64_cb, p));

  /* return success */
  return PTPGP_OK;
}

ptpgp_err_t
ptpgp_armor_encoder_push(ptpgp_armor_encoder_t *p,
                         u8 *src,
                         size_t src_len) {
  if (p->last_err)
    return p->last_err;

  if (p->is_done)
    DIE(p, ALREADY_DONE);

  if (!src || !src_len) {
    u8 crc[3], buf[128];
    size_t l;

    /* mark encoder as finished */
    p->is_done = 1;

    /* finalize base64 and crc24 contexts */
    TRY(ptpgp_base64_done(&(p->base64)));
    TRY(ptpgp_crc24_done(&(p->crc24)));

    /* pack crc */
    crc[0] = (p->crc24.crc >> 16) & 0xff;
    crc[1] = (p->crc24.crc >>  8) & 0xff;
    crc[2] = (p->crc24.crc)       & 0xff;

    /* append crc to output buffer */
    buf[0] = '=';
    TRY(ptpgp_base64_encode(crc, 3, buf + 1, 6, 0));

    /* add armor envelope footer to buffer */
    l = snprintf(
      (char*) buf + 5, sizeof(buf) - 5,
      "\r\n-----%s-----\r\n",
      p->envelope_name
    ) + 5;

    /* send buffer */
    PUSH(p, buf, l);

    /* flush buffer */
    FLUSH(p);

    /* return success */
    return PTPGP_OK;
  }

  /* push data to crc and base64 contexts */
  TRY(ptpgp_crc24_push(&(p->crc24), src, src_len));
  TRY(ptpgp_base64_push(&(p->base64), src, src_len));

  /* return success */
  return PTPGP_OK;
}

ptpgp_err_t
ptpgp_armor_encoder_done(ptpgp_armor_encoder_t *p) {
  return ptpgp_armor_encoder_push(p, 0, 0);
}
