#include "internal.h"

#define H(a) PTPGP_KEY_FLAG_##a
static ptpgp_key_flag_info_t flags[] = {{
  H(CERTIFY), "Certify", 
  "This key may be used to certify other keys."
}, {
  H(SIGN_DATA), "Sign Data", 
  "This key may be used to sign data."
}, {
  H(ENCRYPT_COMMUNICATION), "Encrypt Communication",
  "This key may be used to encrypt communications."
}, {
  H(ENCRYPT_STORAGE), "Encrypt Storage",
  "This key may be used to encrypt storage."
}, {
  H(SPLIT_PRIVATE_KEY), "Split Private Key",
  "The private component of this key may have been split by a secret-sharing mechanism."
}, {
  H(AUTHENTICATION), "Authentication",
  "This key may be used for authentication."
}, {
  H(SHARED_PRIVATE_KEY), "Shared Private Key",
  "The private component of this key may be in the possession of more than one person."
}, {
  /* sentinel */
  0, 0, 0
}};
#undef H

ptpgp_err_t
ptpgp_key_flag_info(ptpgp_key_flag_t flag,
                    ptpgp_key_flag_info_t **r) {
  size_t i;

  for (i = 0; flags[i].name; i++) {
    if (flags[i].flag == flag) {
      if (r)
        *r = flags + i;

      /* return success */
      return PTPGP_OK;
    }
  }

  /* return error */
  return PTPGP_ERR_KEY_FLAG_NOT_FOUND;
}

ptpgp_err_t
ptpgp_key_flag_to_s(ptpgp_key_flag_t t,
                    char *dst,
                    size_t dst_len, 
                    size_t *out_len) {
  ptpgp_key_flag_info_t *r;
  ptpgp_err_t err;
  size_t l;

  /* get flag info */
  if ((err = ptpgp_key_flag_info(t, &r)) != PTPGP_OK)
    return err;

  /* get string length */
  l = strlen(r->name) + 1;

  /* check output buffer length */
  if (l > dst_len)
    return PTPGP_ERR_KEY_FLAG_DEST_BUFFER_TOO_SMALL;

  /* copy string */
  memcpy(dst, r->name, l);

  /* return length (if requested) */
  if (out_len)
    *out_len = l;

  /* return success */
  return PTPGP_OK;
}
