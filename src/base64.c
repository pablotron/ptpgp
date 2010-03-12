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
    /* null-terminate output buffer (for debugging) */                \
    /* (p)->out_buf[(p)->out_buf_len] = 0; */                         \
                                                                      \
    /* D("sending %d bytes\nout_buf = %s",                            \
      (int) (p)->out_buf_len, (p)->out_buf); */                       \
                                                                      \
    /* pass buffer to callback */                                     \
    ptpgp_err_t err = (p)->cb((p), (p)->out_buf, (p)->out_buf_len);   \
    if (err)                                                          \
      return (p)->last_err = err;                                     \
                                                                      \
    /* clear output buffer */                                         \
    (p)->out_buf_len = 0;                                             \
  }                                                                   \
} while (0)

#define PUSH(p, c) do {                                               \
  /* D("pushing character"); */                                       \
  (p)->out_buf[(p)->out_buf_len++] = (c);                             \
  if ((p)->out_buf_len >= PTPGP_BASE64_OUT_BUF_SIZE - 2)              \
    FLUSH(p);                                                         \
                                                                      \
  /* wrap encoded output lines at 60 characters */                    \
  if (FLAG_IS_SET(p, ENCODE) && (p)->line_len++ > 59) {               \
    (p)->out_buf[(p)->out_buf_len++] = '\n';                          \
    (p)->line_len = 0;                                                \
  }                                                                   \
} while (0)

#define VALID_BASE64_CHAR(c) (                                        \
  ((c) >= 'A' && (c) <= 'Z') ||                                       \
  ((c) >= 'a' && (c) <= 'z') ||                                       \
  ((c) >= '0' && (c) <= '9') ||                                       \
  (c) == '+' || (c) == '/' || (c) == '='                              \
)

static char *e_lut = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
                     "abcdefghijklmnopqrstuvwxyz"
                     "0123456789+/";

static int d_lut[] = {
  -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
  -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
  -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 62, -1, -1, -1, 63,
  52, 53, 54, 55, 56, 57, 58, 59, 60, 61, -1, -1, -1, -1, -1, -1,
  -1,  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14,
  15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, -1, -1, -1, -1, -1,
  -1, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40,
  41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, -1, -1, -1, -1, -1
};

#if 0
static u8
decode(u8 c) {
  if (c >= 'A' && c <= 'Z')
    return c - 'A';
  if (c >= 'a' && c <= 'z')
    return c - 'a' + 26;
  if (c >= '0' && c <= '9')
    return c - '0' + 52;
  if (c == '+')
    return 62;
  if (c == '/')
    return 63;

  /* never reached */
  return 0xFF;
}
#endif /* 0 */

#define BITS(n) ((1 << n) - 1)

static ptpgp_err_t
convert(ptpgp_base64_t *p) {
  u8    *s = p->src_buf;
  bool   e = FLAG_IS_SET(p, ENCODE);
  size_t l = p->src_buf_len;

  if (!l)
    return PTPGP_OK;

  if (e) {
    if (l == 3) {
      PUSH(p, e_lut[s[0] >> 2]);
      PUSH(p, e_lut[((s[0] & 3) << 4)  | (s[1] >> 4)]);
      PUSH(p, e_lut[((s[1] & 15) << 2) | (s[2] >> 6)]);
      PUSH(p, e_lut[s[2] & 63]);
    } else if (l == 2) {
      PUSH(p, e_lut[s[0] >> 2]);
      PUSH(p, e_lut[((s[0] & 3) << 4) | (s[1] >> 4)]);
      PUSH(p, e_lut[(s[1] & 15) << 2]);
      PUSH(p, '=');
    } else if (l == 1) {
      PUSH(p, e_lut[s[0] >> 2]);
      PUSH(p, e_lut[(s[0] & 3) << 4]);
      PUSH(p, '=');
      PUSH(p, '=');
    }
  } else {
    int a, b, c, d;

    /* valid base64 input should always be a multiple of 4 */
    if (l != 4)
      return PTPGP_ERR_BASE64_CORRUPT_INPUT;

    /* strip trailing markers */
    while (s[l - 1] == '=')
      l--;

    /* check length and make sure there are no embedded '='s */
    if (l < 2 || s[0] == '=' || s[1] == '=')
      return PTPGP_ERR_BASE64_CORRUPT_INPUT;

    if (l == 4) {
      a = d_lut[s[0]];
      b = d_lut[s[1]];
      c = d_lut[s[2]];
      d = d_lut[s[3]];

      PUSH(p, (a << 2) | (b >> 4));
      PUSH(p, ((b & BITS(4)) << 4) | (c >> 2));
      PUSH(p, ((c & BITS(2)) << 6) | (d));
    } else if (l == 3) {
      a = d_lut[s[0]];
      b = d_lut[s[1]];
      c = d_lut[s[2]];

      PUSH(p, (a << 2) | (b >> 4));
      PUSH(p, ((b & BITS(4)) << 4) | (c >> 2));
    } else if (l == 2) { 
      a = d_lut[s[0]];
      b = d_lut[s[1]];

      PUSH(p, (a << 2) | (b >> 4));
    } else {
      /* never reached */
      return PTPGP_ERR_BASE64_CORRUPT_INPUT;
    }
  }

  /* clear source buffer */
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

    if (e && p->line_len > 0)
      PUSH(p, '\n');

    /* flush remaining output */
    FLUSH(p);

    /* mark context as done */
    FLAG_SET(p, DONE);

    /* return success */
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
