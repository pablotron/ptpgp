#include <string.h> /* for memset()/memcmp() */
#include <ptpgp/ptpgp.h>

static char *lut = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
                   "abcdefghijklmnopqrstuvwxyz"
                   "0123456789+/";

#define FLAG_ENCODE   (1 << 0)
#define FLAG_DONE     (1 << 1)

#define FLAG_IS_SET(p, f) ((p)->flags & FLAG_##f)
#define FLAG_SET(p, f) do { (p)->flags |= FLAG_##f; } while (0)

#define DIE(p, e) do {                                                \
  return (p)->last_err = PTPGP_ERR_BASE64_##e;                        \
} while (0)

#define FLUSH(p) do {                                                 \
  if ((p)->out_buf_len > 0) {                                         \
    ptpgp_err_t err = (p)->cb((p), (p)->out_buf, (p)->out_buf_len);   \
    if (err)                                                          \
      return (p)->last_err = err;                                     \
                                                                      \
    (p)->out_buf_len = 0;                                             \
  }                                                                   \
} while (0)

#define PUSH(p, c) do {                                               \
  (p)->out_buf[(p)->out_buf_len++] = (c);                             \
} while (0)

#define CONVERT(p) do {                                               \
  char *s = (p)->src_buf;                                             \
  int l = (p)->src_buf_len;                                           \
                                                                      \
  if (FLAG_IS_SET((p), ENCODE)) {                                     \
    if (l == 3) {                                                     \
      PUSH(p, lut[s[0] >> 2]);                                        \
      PUSH(p, lut[(s[0] & 3) << 4 | s[1] >> 4]);                      \
      PUSH(p, lut[(s[1] & 15) << 2 | s[2] >> 5]);                     \
      PUSH(p, lut[s[2] & 63]);                                        \
    } else if (l == 2) {                                              \
      PUSH(p, lut[s[0] >> 2]);                                        \
      PUSH(p, lut[(s[0] & 3) << 4 | s[1] >> 4]);                      \
      PUSH(p, lut[(s[1] & 15) << 2]);                                 \
      PUSH(p, '=');                                                   \
    } else if (l == 1) {                                              \
      PUSH(p, lut[s[0] >> 2]);                                        \
      PUSH(p, lut[(s[0] & 3) << 4]);                                  \
      PUSH(p, '=');                                                   \
      PUSH(p, '=');                                                   \
    }                                                                 \
  } else {                                                            \
    int a, b, c, d;                                                   \
                                                                      \
    if (s[2] != '=' && s[3] != '=') {                                 \
      a = strchr(lut, s[0]) - lut;                                    \
      b = strchr(lut, s[1]) - lut;                                    \
      c = strchr(lut, s[2]) - lut;                                    \
      d = strchr(lut, s[3]) - lut;                                    \
                                                                      \
      PUSH(p, a << 2 | b >> 4);                                       \
      PUSH(p, (b & 15) << 4 | c >> 2);                                \
      PUSH(p, (c & 3) << 6 | d);                                      \
    } else if (s[2] != '=' && s[3] == '=') {                          \
      a = strchr(lut, s[0]) - lut;                                    \
      b = strchr(lut, s[1]) - lut;                                    \
      c = strchr(lut, s[2]) - lut;                                    \
                                                                      \
      PUSH(p, a << 2 | b >> 4);                                       \
      PUSH(p, (b & 15) << 4 | c >> 2);                                \
      PUSH(p, (c & 3) << 6);                                          \
    } else if (s[2] == '=' && s[3] == '=') {                          \
      a = strchr(lut, s[0]) - lut;                                    \
      b = strchr(lut, s[1]) - lut;                                    \
                                                                      \
      PUSH(p, a << 2 | b >> 4);                                       \
      PUSH(p, (b & 15) << 4);                                         \
    }                                                                 \
  }                                                                   \
                                                                      \
  memset(s, 0, 4);                                                    \
} while (0)

#define VALID_BASE64_CHAR(c) (                                        \
  ((c) >= 'A' && (c) <= 'Z') ||                                       \
  ((c) >= 'a' && (c) <= 'z') ||                                       \
  ((c) >= '0' && (c) <= '9') ||                                       \
  (c) == '+' || (c) == '/' || (c) == '='                              \
)

ptpgp_err_t
ptpgp_base64_init(ptpgp_base64_t *p, 
               char encode, 
               ptpgp_base64_cb_t cb, 
               void *user_data) {
  memset(p, 0, sizeof(ptpgp_base64_t));

  if (encode)
    FLAG_SET(p, ENCODE);

  p->cb = cb;
  p->user_data = user_data;

  return PTPGP_OK;
}

ptpgp_err_t
ptpgp_base64_push(ptpgp_base64_t *p, char *src, size_t src_len) {
  size_t i;
  int e = FLAG_IS_SET(p, ENCODE);

  if (p->last_err)
    return p->last_err;

  if (!src || !src_len) {
    if (FLAG_IS_SET(p, DONE))
      DIE(p, ALREADY_DONE);
    
    /* encode/decode remaining chunk (if necessary) */
    if (p->src_buf_len > 0) {
      /* flush output buffer (if necessary) */
      if (p->out_buf_len + 3 >= PTPGP_BASE64_BUFFER_SIZE)
        FLUSH(p);

      /* convert remaining piece */
      CONVERT(p);
    }

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

      if ((e && p->src_buf_len == 3) || (!e && p->src_buf_len == 4)) {
        if (p->out_buf_len + 3 >= PTPGP_BASE64_BUFFER_SIZE)
          FLUSH(p);
        CONVERT(p);
      }
    }
  }

  /* return success */
  return PTPGP_OK;
}

ptpgp_err_t
ptpgp_base64_done(ptpgp_base64_t *p) {
  return ptpgp_base64_push(p, 0, 0);
}
