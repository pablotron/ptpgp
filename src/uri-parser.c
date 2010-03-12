#include "internal.h"

#ifdef TRY
#undef TRY
#endif /* TRY */

#define TRY(v) do {           \
  ptpgp_err_t err = (v);      \
  if (err != PTPGP_OK)        \
    return p->last_err = err; \
} while (0)

#define STATE(s) PTPGP_URI_PARSER_STATE_##s

#define DIE(p, e) return (p)->last_err = PTPGP_ERR_URI_PARSER_##e

#define SHIFT(n) do { \
  src     += (n);     \
  src_len -= (n);     \
} while (0)

#define SEND(p, t, b, l) \
  TRY((p)->cb(p, PTPGP_URI_PARSER_TOKEN_##t, b, l))

static ptpgp_err_t
parse_hostspec(ptpgp_uri_parser_t *p, 
               u8 *src,
               size_t src_len) {
  size_t i;

  for (i = 0; i < src_len; i++)
    if (src[i] == ':') 
      break;

  if (i < src_len) {
    /* send hostspec and port */
    SEND(p, HOST, src, i);
    SEND(p, PORT, src + i + 1, src_len - i - 1);
  } else {
    /* no port, just send hostspec */
    SEND(p, HOST, src, src_len);
  }

  /* return success */
  return PTPGP_OK;
}

ptpgp_err_t
ptpgp_uri_parser_init(ptpgp_uri_parser_t *p,
                      ptpgp_uri_parser_cb_t cb,
                      void *user_data) {
  memset(p, 0, sizeof(ptpgp_uri_parser_t));

  p->cb = cb;
  p->user_data = user_data;

  /* return success */
  return PTPGP_OK;
}

ptpgp_err_t
ptpgp_uri_parser_push(ptpgp_uri_parser_t *p,
                      u8 *src,
                      size_t src_len) {
  size_t i;
  u8 c;

  if (p->last_err)
    return p->last_err;

  if (p->is_done)
    DIE(p, ALREADY_DONE);

  if (!src || !src_len) {
    p->is_done = 1;

    if (p->buf_len > 0) {
      switch (p->state) {
      case STATE(INIT):
        /* send scheme */
        SEND(p, SCHEME, p->buf, p->buf_len);

        break;
      case STATE(AFTER_SCHEME):
      case STATE(AFTER_AUTH):
        TRY(parse_hostspec(p, p->buf, p->buf_len));

        break;
      case STATE(PATH):
        /* send path */
        SEND(p, PATH, p->buf, p->buf_len);

        break;
      case STATE(QUERY):
        /* send query */
        SEND(p, QUERY, p->buf, p->buf_len);

        break;
      case STATE(FRAGMENT):
        /* send query */
        SEND(p, FRAGMENT, p->buf, p->buf_len);

        break;
      default:
        /* never reached */
        DIE(p, UNKNOWN_STATE);
      }
    }

    /* return success */
    return PTPGP_OK;
  }

retry:
  switch (p->state) {
  case STATE(INIT):
    for (i = 0; i < src_len; i++) {
      p->buf[p->buf_len++] = src[i];

      if (p->buf_len > 3) {
        if (p->buf[p->buf_len - 3] == ':' && 
            p->buf[p->buf_len - 2] == '/' && 
            p->buf[p->buf_len - 1] == '/') {
          /* strip suffix from scheme */
          p->buf_len -= 3;

          /* send scheme */
          SEND(p, SCHEME, p->buf, p->buf_len);

          p->buf_len = 0;
          SHIFT(i + 1);

          p->state = STATE(AFTER_SCHEME);
          goto retry;
        } else if (p->buf_len == PTPGP_URI_PARSER_BUFFER_SIZE) {
          DIE(p, MISSING_SCHEME);
        }
      }
    }

    break;
  case STATE(AFTER_SCHEME):
  case STATE(AFTER_AUTH):
    for (i = 0; i < src_len; i++) {
      p->buf[p->buf_len++] = c = src[i];

      if (c == '/') {
        if (p->buf_len > 1) {
          /* strip trailing slash */
          p->buf_len -= 1;

          TRY(parse_hostspec(p, p->buf, p->buf_len));
        }

        p->buf[0] = '/';
        p->buf_len = 1;
        SHIFT(i + 1);

        p->state = STATE(PATH);
        goto retry;
      } else if (c == '@') {
        if (p->state == STATE(AFTER_AUTH)) 
          DIE(p, DUPLICATE_AUTH);

        /* strip '@' */
        p->buf_len--;

        /* send auth */
        SEND(p, AUTH, p->buf, p->buf_len);

        p->buf_len = 0;
        SHIFT(i + 1);

        p->state = STATE(AFTER_AUTH);
        goto retry;
      } else if (p->buf_len == PTPGP_URI_PARSER_BUFFER_SIZE) {
        DIE(p, HOST_TOO_LONG);
      }
    }

    break;
  case STATE(PATH):
    for (i = 0; i < src_len; i++) {
      p->buf[p->buf_len++] = c = src[i];

      if (c == '?') {
        /* strip suffix */
        p->buf_len--;

        SEND(p, PATH, p->buf, p->buf_len);

        p->buf_len = 0;
        SHIFT(i + 1);

        p->state = STATE(QUERY);
        goto retry;
      } else if (p->buf_len == PTPGP_URI_PARSER_BUFFER_SIZE) {
        DIE(p, PATH_TOO_LONG);
      }
    }

    break;
  case STATE(QUERY):
    for (i = 0; i < src_len; i++) {
      p->buf[p->buf_len++] = c = src[i];

      if (c == '#') {
        /* strip suffix */
        p->buf_len--;

        SEND(p, QUERY, p->buf, p->buf_len);

        p->buf_len = 0;
        SHIFT(i + 1);

        p->state = STATE(FRAGMENT);
        goto retry;
      } else if (p->buf_len == PTPGP_URI_PARSER_BUFFER_SIZE) {
        DIE(p, QUERY_TOO_LONG);
      }
    }

    break;
  case STATE(FRAGMENT):
    for (i = 0; i < src_len; i++) {
      p->buf[p->buf_len++] = c = src[i];

      if (c == '#') {
        /* strip suffix */
        p->buf_len--;

        SEND(p, QUERY, p->buf, p->buf_len);

        p->buf_len = 0;
        SHIFT(i + 1);

        p->state = STATE(FRAGMENT);
        goto retry;
      } else if (p->buf_len == PTPGP_URI_PARSER_BUFFER_SIZE) {
        DIE(p, FRAGMENT_TOO_LONG);
      }
    }

    break;
  default:
    /* never reached */
    DIE(p, UNKNOWN_STATE);
  }

  return PTPGP_OK;
}

ptpgp_err_t
ptpgp_uri_parser_done(ptpgp_uri_parser_t *p) {
  return ptpgp_uri_parser_push(p, 0, 0);
}
