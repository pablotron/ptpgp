#ifdef PTPGP_USE_OPENSSL

#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/rsa.h>
#include <openssl/bn.h>

ptpgp_err_t ptpgp_openssl_engine_init(ptpgp_engine_t *);

#endif /* PTPGP_USE_OPENSSL */
