#include "internal.h"
#include <stdarg.h>
#include <stdlib.h>
#include <errno.h>

static char *lut = "0123456789abcdef";

ptpgp_err_t ptpgp_to_hex(u8 *src, size_t src_len, u8 *dst, size_t dst_len) {
  size_t i;

  /* check output buffer */
  if (src_len * 2 > dst_len)
    return PTPGP_ERR_HEX_DEST_BUF_TOO_SMALL;

  /* convert buffer */
  for (i = 0; i < src_len; i++) {
    dst[i * 2] = lut[src[i] >> 4];
    dst[i * 2 + 1] = lut[src[i] & 15];
  }

  /* return success */
  return PTPGP_OK;
}

static void
sys_carp(char *prefix, int saved_errno, char *msg) {
  char *err_str = strerror(saved_errno);

  /* make sure error string is defined */
  if (!err_str)
    err_str = "unknown error";

  /* print error */
  fprintf(stderr, "[%s] %s: %s\n", prefix, msg, err_str);
}

void
ptpgp_sys_die(char *fmt, ...) {
  va_list ap;
  char buf[1024];
  int saved_errno = errno;

  /* build error message */
  va_start(ap, fmt);
  vsnprintf(buf, sizeof(buf), fmt, ap);
  va_end(ap);

  sys_carp("FATAL", saved_errno, buf);
  exit(EXIT_FAILURE);
}

void
ptpgp_sys_warn(char *fmt, ...) {
  va_list ap;
  char buf[1024];
  int saved_errno = errno;

  /* build error message */
  va_start(ap, fmt);
  vsnprintf(buf, sizeof(buf), fmt, ap);
  va_end(ap);

  sys_carp("WARNING", saved_errno, buf);
}

static void
carp(const char *fn, char *prefix, ptpgp_err_t err, char *msg) {
  char buf[512];
  ptpgp_err_t e;

  if ((e = ptpgp_strerror(err, buf, sizeof(buf), NULL)) != PTPGP_OK)
    ptpgp_die(e, "%s(): unknown error code %d", fn, err);

  fprintf(stderr, "[%s] %s: %s\n", prefix, msg, buf);
}

void
ptpgp_warn(ptpgp_err_t err, char *fmt, ...) {
  va_list ap;
  char buf[1024];

  va_start(ap, fmt);
  vsnprintf(buf, sizeof(buf), fmt, ap);
  va_end(ap);

  carp(__func__, "W", err, buf);
}

void
ptpgp_die(ptpgp_err_t err, char *fmt, ...) {
  va_list ap;
  char buf[1024];

  va_start(ap, fmt);
  vsnprintf(buf, sizeof(buf), fmt, ap);
  va_end(ap);

  carp(__func__, "E", err, buf);
  exit(EXIT_FAILURE);
}
