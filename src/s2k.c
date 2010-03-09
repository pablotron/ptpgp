#include "internal.h"

ptpgp_err_t
ptpgp_s2k_init(ptpgp_s2k_t *r,
               ptpgp_s2k_algorithm_type_t t,
               ptpgp_hash_algorithm_type_t h,
               u8 *salt,
               uint32_t count) {
  /* clear result */
  memset(r, 0, sizeof(ptpgp_s2k_t));


  /* populate result */
  r->type = t;
  r->algorithm = h;
  r->count = count;

  if (t == PTPGP_S2K_ALGORITHM_TYPE_SALTED ||
      t == PTPGP_S2K_ALGORITHM_TYPE_ITERATED_AND_SALTED) {
    /* make sure salt is defined */
    if (!salt)
      return PTPGP_ERR_S2K_MISSING_SALT;

    /* copy salt */
    memcpy(r->salt, salt, 8);
  }

  /* return success */
  return PTPGP_OK;
}

ptpgp_err_t
ptpgp_s2k_to_s(ptpgp_s2k_t *r,
               char *dst,
               size_t dst_len,
               size_t *out_len) {
  char buf[256], tmp[128];
  ptpgp_err_t err;
  size_t l;

  memset(buf, 0, sizeof(buf));
  l = 0;

  /* get s2k type */
  err = ptpgp_algorithm_to_s(
    PTPGP_ALGORITHM_TYPE_S2K,
    r->type,
    (u8*) tmp, sizeof(tmp),
    NULL
  );

  /* check for error */
  if (err != PTPGP_OK)
    return err;

  /* append type to output */
  l += snprintf(
    buf + l, sizeof(buf) - l,
    "{\"type\":{\"id\":%d,\"name\":\"%s\"}",
    r->type, tmp
  );

  /* get hash type */
  err = ptpgp_algorithm_to_s(
    PTPGP_ALGORITHM_TYPE_HASH,
    r->algorithm,
    (u8*) tmp, sizeof(tmp),
    NULL
  );

  /* check for error */
  if (err != PTPGP_OK)
    return err;

  /* append hash to output */
  l += snprintf(
    buf + l, sizeof(buf) - l,
    ",\"hash\":{\"id\":%d,\"name\":\"%s\"}",
    r->algorithm, tmp
  );

  if (r->type == PTPGP_S2K_ALGORITHM_TYPE_SALTED ||
      r->type == PTPGP_S2K_ALGORITHM_TYPE_ITERATED_AND_SALTED) {
    /* convert salt to hex */
    err = ptpgp_to_hex(r->salt, 8, (u8*) tmp, sizeof(tmp));

    /* check for error */
    if (err != PTPGP_OK)
      return err;

    /* append salt to output */
    tmp[16] = '\0';
    l += snprintf(buf + l, sizeof(buf) - l, ",\"salt\":\"%s\"", tmp);

    /* append count to output */
    if (r->type == PTPGP_S2K_ALGORITHM_TYPE_ITERATED_AND_SALTED)
      l += snprintf(buf + l, sizeof(buf) - l, ",count:%d", r->count);
  }

  /* make sure buffer is null terminated */
  buf[l++] = '}';
  buf[l++] = '\0';

  /* check length of output buffer */
  if (l > dst_len)
    return PTPGP_ERR_S2K_DEST_BUFFER_TOO_SMALL;

  /* copy data to output buffer */
  memcpy(dst, buf, l);

  /* return length (maybe) */
  if (out_len)
    *out_len = l;

  /* return success */
  return PTPGP_OK;
}
