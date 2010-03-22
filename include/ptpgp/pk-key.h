typedef union {
  ptpgp_public_key_type_t algorithm;

  struct {
    ptpgp_public_key_type_t algorithm;

    ptpgp_mpi_t n,    /* public modulus */
                e,    /* public exponent */
                d,    /* private exponent */
                p,    /* secret prime factor */
                q,    /* secret prime factor */
                dmp1, /* d mod (p - 1) */
                dmq1, /* d mod (q - 1) */
                iqmp; /* q^-1 mod p */
  } rsa;

  struct {
    ptpgp_public_key_type_t algorithm;
    /* TODO */
  } elgamal;

  struct {
    ptpgp_public_key_type_t algorithm;
    /* TODO */
  } dsa;

  struct {
    ptpgp_public_key_type_t algorithm;
    /* TODO */
  } dh;
} ptpgp_pk_key_t;
