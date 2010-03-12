#include "internal.h"

#define A(a) PTPGP_PUBLIC_KEY_ALGORITHM_TYPE_##a
static ptpgp_public_key_algorithm_info_t
algos[] = {{
  A(RSA),                     2, 4
}, {
  A(RSA_ENCRYPT_ONLY),        2, 4
}, {
  A(RSA_SIGN_ONLY),           2, 4
}, {
  A(ELGAMEL_ENCRYPT_ONLY),    3, 1
}, {
  A(DSA),                     4, 1
}, {
  A(ELGAMAL_ENCRYPT_OR_SIGN), 3, 1
}, {
  0,                          0, 0
}};

ptpgp_err_t
ptpgp_public_key_algorithm_info(ptpgp_public_key_algorithm_type_t t,
                                ptpgp_public_key_algorithm_info_t **r) {
  size_t i;

  for (i = 0; algos[i].algorithm; i++) {
    if (algos[i].algorithm == t) {
      /* save algorithm information (if requested) */
      if (r)
        (*r) = algos + i;

      /* return success */
      return PTPGP_OK;
    }
  }

  /* return failure */
  return PTPGP_ERR_PUBLIC_KEY_ALGORITHM_NOT_FOUND;
}
