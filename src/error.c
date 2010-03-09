#include "internal.h"

static char *errors[] = {
  "ok (no error)",

  /* error string errors */
  "unknown error code",
  "output error buffer too small",

  /* utility errors */
  "destination buffer is too small",

  /* stream parser errors */
  "packet stream ended before end of packets",
  "callback returned an error",
  "parser state exceeded stack size",
  "parser state below zero",
  "invalid packet header tag",
  "input buffer overflow (bug!)",
  "bad packet length type (bug!)",
  "unknown parser state (bug!)",
  "invalid packet length (bug!)",
  "invalid packet content tag",
  "invalid partial body length",
  "stream parser already done",

  /* armor parser errors */
  "armor parser already done",
  "armor parser already done",
  "header line too large",
  "invalid header line",
  "bad parser state",

  /* base64 errors */
  "base64 context already done",

  /* tag errors */
  "invalid tag ID",
  "tag output buffer too small",

  /* packet parser errors */
  "invalid parser state (bug?)",
  "packet parser already done",
  "input buffer overflow (bug?)",
  "bad packet version",
  "bad hashed material length",
  "invalid subpacket header",

  /* signature type errors */
  "unknown signature type",
  "output buffer too small",

  /* signature subpacket type errors */
  "destination buffer too small for subpacket description",

  /* sentinel */
  NULL
};

ptpgp_err_t
ptpgp_strerror(ptpgp_err_t err, char *buf, size_t buf_len, size_t *out_len) {
  char *s;
  size_t len;

  /* check error code */
  if (err >= PTPGP_ERR_LAST)
    return PTPGP_ERR_ERROR_CODE_UNKNOWN;

  /* get error string and length */
  s = errors[err];
  len = strlen(s) + 1;

  /* check buffer size */
  if (buf_len < len)
    return PTPGP_ERR_ERROR_BUFFER_TOO_SMALL;

  /* copy string to buffer */
  memcpy(buf, s, len);

  /* save string length */
  if (out_len)
    *out_len = len;

  /* return success */
  return PTPGP_OK;
}
