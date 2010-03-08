#include "internal.h"

static char *tags[] = {
  "Reserved",
  "Public-Key Encrypted Session Key Packet",
  "Signature Packet",
  "Symmetric-Key Encrypted Session Key Packet",
  "One-Pass Signature Packet",
  "Secret Key Packet",
  "Public Key Packet",
  "Secret Subkey Packet",
  "Compressed Data Packet",
  "Symmetrically Encrypted Data Packet",
  "Marker Packet",
  "Literal Data Packet",
  "Trust Packet",
  "User ID Packet",
  "Public-Subkey Packet",
  NULL,
  NULL,
  "User Atatribute Packet",
  "Sym. Encrypted and Integrity Protected Data Packet",
  "Modification Detection Code Packet",
  NULL
};

static char *private_tag = "Private or Experimental Value";

ptpgp_err_t
ptpgp_tag_to_s(uint32_t tag, char *buf, size_t buf_len, size_t *out_len) {
  char *s;
  size_t len;

  if (!IS_VALID_CONTENT_TAG(tag))
    return PTPGP_ERR_TAG_INVALID;

  /* get string and length of string */
  s = (tag >= 60 && tag <= 63) ? private_tag : tags[tag];
  len = strlen(s) + 1; 

  /* check output buffer length */
  if (buf_len < len)
    return PTPGP_ERR_TAG_BUFFER_TOO_SMALL;

  /* copy string to buffer */
  memcpy(buf, s, len);

  /* return length */
  if (out_len)
    *out_len = len;

  /* return success */
  return PTPGP_OK;
}
