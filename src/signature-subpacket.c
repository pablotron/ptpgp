#include "internal.h"

static char *types[] = {
  "Reserved",
  "Reserved",
  "Signature Creation Time",
  "Signature Expiration Time",
  "Exportable Certification",
  "Trust Signature",
  "Regular Expression",
  "Revocable",
  "Reserved",
  "Key Expiration Time",
  "Placeholder for Backward Compatibility",
  "Preferred Symmetric Algorithms",
  "Revocation Key",
  "Reserved",
  "Reserved",
  "Reserved",
  "Issuer",
  "Reserved",
  "Reserved",
  "Reserved",
  "Notation Data",
  "Preferred Hash Algorithms",
  "Preferred Compression Algorithms",
  "Key Server Preferences",
  "Preferred Key Server",
  "Primary User ID",
  "Policy URI",
  "Key Flags",
  "Signer's User ID",
  "Reason for Revocation",
  "Features",
  "Signature Target",
  "Embedded Signature",

  /* sentinel */
  NULL
};

static char *private = "Private or Experimental",
            *unknown = "Unknown Subpacket";

ptpgp_err_t
ptpgp_signature_subpacket_type_to_s(ptpgp_signature_subpacket_type_t t, 
                                    char *dst, 
                                    size_t dst_len,
                                    size_t *out_len) {
  char *s;
  size_t l;

  /* get string for subpacket type */
  if (t <= 32) {
    s = types[t];
  } else if (t >= 100 && t <= 110) {
    s = private;
  } else { 
    s = unknown;
  }

  /* get length */
  l = strlen(s) + 1;

  /* check output buffer length */
  if (l > dst_len)
    return PTPGP_ERR_SIGNATURE_SUBPACKET_TYPE_DEST_BUFFER_TO_SMALL;

  /* copy string */
  memcpy(dst, s, l);

  /* save length */
  if (out_len)
    *out_len = l;

  /* return success */
  return PTPGP_OK;
}
