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
  "base64 output buffer too small",
  "base64 input is corrupt",

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
  "invalid S2K type",
  "invalid MDC size (corrupt integrity)",
  "bad public key packet",
  "bad secret key checksum",

  /* signature type errors */
  "unknown signature type",
  "output buffer too small",

  /* signature subpacket type errors */
  "destination buffer too small for subpacket description",

  /* signature subpacket parser errors */
  "invalid subpacket parser state (bug?)",
  "signature subpacket parser already done",
  "input buffer overflow (bug?)",

  /* algorithm type errors */
  "unknown algorithm",
  "output buffer too small",

  /* s2k errors */
  "S2K salt is NULL",
  "output buffer too small",

  /* key flag errors */
  "unknown key flag",
  "output buffer too small",

  /* crc24 errors */
  "crc24 context already done",

  /* armor encoder errors */
  "armor envelope name too long",
  "header name too long",
  "header value too long",
  "missing header value",
  "armor encoder context already done",

  /* uri parser errors */
  "URI parser already done",
  "unknown state (memory corruption?)",
  "unspecified URI scheme",
  "duplicate authspecs in URI",
  "host portion of URI too long",
  "path portion of URI too long",
  "query portion of URI too long",
  "fragment portion of URI too long",

  /* public key algorithm errors */
  "unknown or unsupported public key algorithm",

  /* engine errors */
  "couldn't initialize crypto engine",

  /* engine-hash errors */
  "hash context init failed",
  "couldn't push data to hash context",
  "couldn't finalize hash context",
  "hash context already done",
  "hash context not done",
  "hash output buffer too small",

  /* engine-encrypt errors */
  "symmetric encryption context init failed",
  "unsupported symmetric cipher or mode",
  "couldn't set symmetric key",
  "couldn't set initialization vector",
  "push failed",
  "couldn't finalize symmetric encryption context",

  /* engine-random errors */
  "random numbers unsupported by this engine",
  "couldn't generate random number",


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
