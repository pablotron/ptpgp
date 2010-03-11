#include "internal.h"

#define FLAG_ENCODE   (1 << 0)
#define FLAG_DONE     (1 << 1)

#define FLAG_IS_SET(p, f) ((p)->flags & FLAG_##f)
#define FLAG_SET(p, f) do { (p)->flags |= FLAG_##f; } while (0)

#define DIE(p, e) do {                                                \
  return (p)->last_err = PTPGP_ERR_BASE64_##e;                        \
} while (0)

#define FLUSH(p) do {                                                 \
  if ((p)->out_buf_len > 0) {                                         \
    D("sending %d bytes", (int) (p)->out_buf_len);                    \
    ptpgp_err_t err = (p)->cb((p), (p)->out_buf, (p)->out_buf_len);   \
    if (err)                                                          \
      return (p)->last_err = err;                                     \
                                                                      \
    (p)->out_buf_len = 0;                                             \
  }                                                                   \
} while (0)

#define PUSH(p, c) do {                                               \
  /* D("pushing character"); */                                       \
  (p)->out_buf[(p)->out_buf_len++] = (c);                             \
  if ((p)->out_buf_len == PTPGP_BASE64_OUT_BUF_SIZE - 2)              \
    FLUSH(p);                                                         \
} while (0)

#define VALID_BASE64_CHAR(c) (                                        \
  ((c) >= 'A' && (c) <= 'Z') ||                                       \
  ((c) >= 'a' && (c) <= 'z') ||                                       \
  ((c) >= '0' && (c) <= '9') ||                                       \
  (c) == '+' || (c) == '/' || (c) == '='                              \
)

static char *lut = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
                   "abcdefghijklmnopqrstuvwxyz"
                   "0123456789+/";

static ptpgp_err_t
convert(ptpgp_base64_t *p) {
  u8    *s = p->src_buf;
  bool   e = FLAG_IS_SET(p, ENCODE);
  size_t l = p->src_buf_len;

  if (!l)
    return PTPGP_OK;

  if (e) {
    if (l == 3) {
      PUSH(p, lut[s[0] >> 2]);
      PUSH(p, lut[(s[0] & 3) << 4 | s[1] >> 4]);
      PUSH(p, lut[(s[1] & 15) << 2 | s[2] >> 5]);
      PUSH(p, lut[s[2] & 63]);
    } else if (l == 2) {
      PUSH(p, lut[s[0] >> 2]);
      PUSH(p, lut[(s[0] & 3) << 4 | s[1] >> 4]);
      PUSH(p, lut[(s[1] & 15) << 2]);
      PUSH(p, '=');
    } else if (l == 1) {
      PUSH(p, lut[s[0] >> 2]);
      PUSH(p, lut[(s[0] & 3) << 4]);
      PUSH(p, '=');
      PUSH(p, '=');
    }
  } else {
    int a, b, c, d;

    /* valid base64 input should always be a multiple of 4 */
    if (l != 4)
      return PTPGP_ERR_BASE64_CORRUPT_INPUT;

    if (s[2] != '=' && s[3] != '=') {
      a = strchr(lut, s[0]) - lut;
      b = strchr(lut, s[1]) - lut;
      c = strchr(lut, s[2]) - lut;
      d = strchr(lut, s[3]) - lut;

      PUSH(p, a << 2 | b >> 4);
      PUSH(p, (b & 15) << 4 | c >> 2);
      PUSH(p, (c & 3) << 6 | d);
    } else if (s[2] != '=' && s[3] == '=') {
      a = strchr(lut, s[0]) - lut;
      b = strchr(lut, s[1]) - lut;
      c = strchr(lut, s[2]) - lut;

      PUSH(p, a << 2 | b >> 4);
      PUSH(p, (b & 15) << 4 | c >> 2);
      PUSH(p, (c & 3) << 6);
    } else if (s[2] == '=' && s[3] == '=') {
      a = strchr(lut, s[0]) - lut;
      b = strchr(lut, s[1]) - lut;

      PUSH(p, a << 2 | b >> 4);
      PUSH(p, (b & 15) << 4);
    }
  }

  /* clear source buffer */
  memset(p->src_buf, 0, 4);
  p->src_buf_len = 0;

  /* return success */
  return PTPGP_OK;
}

ptpgp_err_t
ptpgp_base64_init(ptpgp_base64_t *p,
               bool encode,
               ptpgp_base64_cb_t cb,
               void *user_data) {
  memset(p, 0, sizeof(ptpgp_base64_t));

  if (encode)
    FLAG_SET(p, ENCODE);

  p->cb = cb;
  p->user_data = user_data;

  /* return success */
  return PTPGP_OK;
}

ptpgp_err_t
ptpgp_base64_push(ptpgp_base64_t *p, u8 *src, size_t src_len) {
  size_t i;
  int e = FLAG_IS_SET(p, ENCODE);

  if (p->last_err)
    return p->last_err;

  if (FLAG_IS_SET(p, DONE))
    DIE(p, ALREADY_DONE);

  if (!src || !src_len) {
    /* encode/decode remaining chunk (if necessary) */
    TRY(convert(p));

    /* flush remaining output */
    FLUSH(p);

    /* mark context as done */
    FLAG_SET(p, DONE);

    /* return success */
    return PTPGP_OK;
  }

  if (p->src_buf_len > 0) {
    /* calculate the number of bytes we need */
    size_t num_bytes = (e ? 3 : 4) - p->src_buf_len;

    if (num_bytes > src_len)
      num_bytes = src_len;

    memcpy(p->src_buf + p->src_buf_len, src, src_len);
    p->src_buf_len += src_len;

    /* shift input */
    src += num_bytes;
    src_len -= num_bytes;

    if (p->src_buf_len == (e ? 3 : 4))
      TRY(convert(p));

    if (src_len == 0)
      return PTPGP_OK;
  }

  for (i = 0; i < src_len; i++) {
    if (e || VALID_BASE64_CHAR(src[i])) {
      p->src_buf[p->src_buf_len++] = src[i];

      if (p->src_buf_len == (e ? 3 : 4))
        TRY(convert(p));
    }
  }

  /* return success */
  return PTPGP_OK;
}

ptpgp_err_t
ptpgp_base64_done(ptpgp_base64_t *p) {
  return ptpgp_base64_push(p, 0, 0);
}

size_t 
ptpgp_base64_space_needed(bool encode, 
                          size_t num_bytes) {
  size_t r = 0;

  if (encode) { 
    /* pad to a multiple of 3 */
    if (num_bytes % 3)
      num_bytes += 3 - (num_bytes % 3);

    r = num_bytes * 4 / 3;
  } else {
    /* pad to a multiple of 4 */
    if (num_bytes % 4)
      num_bytes += 4 - (num_bytes % 4);

    r = num_bytes * 3 / 4;
  }

  D("encode = %s, num_bytes = %d, r = %d", 
    encode ? "y" : "n", (int) num_bytes, (int) r);

  return r;
}

typedef struct {
  u8 *dst;
  size_t ofs, dst_len;
} once_data_t;

static ptpgp_err_t
once_cb(ptpgp_base64_t *b, u8 *src, size_t src_len) {
  once_data_t *d = b->user_data;

  /* sanity check (should never happen) */
  if (d->ofs + src_len > d->dst_len) {
    D("d->ofs = %d, src_len = %d, d->dst_len = %d", 
      (int) d->ofs, (int) src_len, (int) d->dst_len);
    return PTPGP_ERR_BASE64_DEST_BUFFER_TOO_SMALL;
  }

  /* copy data, increment offset */
  memcpy(d->dst + d->ofs, src, src_len);
  d->ofs += src_len;

  /* return success */
  return PTPGP_OK;
}

ptpgp_err_t
ptpgp_base64_once(bool    encode,
                  u8     *src,
                  size_t  src_len,
                  u8     *dst,
                  size_t  dst_len,
                  size_t *out_len) {
  once_data_t d;
  ptpgp_base64_t b;

  /* populate data handler */
  d.ofs = 0;
  d.dst = dst;
  d.dst_len = dst_len;

  /* make sure output buffer is large enough */
  if (dst_len < ptpgp_base64_space_needed(encode, src_len)) {
    D("src_len = %d, dst_len = %d", (int) src_len, (int) dst_len);
    return PTPGP_ERR_BASE64_DEST_BUFFER_TOO_SMALL;
  }

  TRY(ptpgp_base64_init(&b, encode, once_cb, &d));
  TRY(ptpgp_base64_push(&b, src, src_len));
  TRY(ptpgp_base64_done(&b));

  /* save length (if requested) */
  if (out_len)
    *out_len = d.ofs;

  /* return success */
  return PTPGP_OK;
}
