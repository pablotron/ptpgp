#include "test-common.h"

#define USAGE \
  "%s - Generate public keypair with specified algorithm.\n" \
  "\n" \
  "Usage:\n" \
  "  gcrypt-genkey <algorithm> [num_bits]\n" \
  "\n" \
  "Options:\n" \
  "  algorithm - public key algorithm (e.g. \"rsa\")\n" \
  "  num_bits  - number of bits (e.g. \"1024\".  defaults to 1024\n" \
  "              if unspecified)\n"

static ptpgp_public_key_type_t
find_algorithm(char *key) {
  uint32_t r;

  PTPGP_ASSERT(
    ptpgp_type_find(PTPGP_TYPE_PUBLIC_KEY, key, &r),
    "find public key algorithm \"%s\"", key
  );

  return (ptpgp_public_key_type_t) r;
}

static void
generate_key(ptpgp_engine_t *e,
             ptpgp_public_key_type_t algo, 
             size_t num_bits) {
  ptpgp_pk_genkey_context_t c;
  ptpgp_pk_genkey_options_t o;

  /* populate genkey options */
  o.engine    = e;
  o.algorithm = algo;
  o.num_bits  = num_bits;
  /* FIXME */
  o.params.rsa.e = 65537;

  PTPGP_ASSERT(
    ptpgp_engine_pk_generate_key(&c, &o),
    "generate public key"
  );
}

int main(int argc, char *argv[]) {
  ptpgp_engine_t engine;
  ptpgp_public_key_type_t algo;
  size_t i, num_bits = 1024;

  /* check command-line argument count */
  if (argc < 2)
    print_usage_and_exit(argv[0], USAGE);

  /* check for help */
  for (i = 1; (int) i < argc; i++)
    if (IS_HELP(argv[i]))
      print_usage_and_exit(argv[0], USAGE);

  /* init engine */
  init_gcrypt(&engine);

  /* find public key algorithm */
  algo = find_algorithm(argv[1]);

  /* get the number of bits */
  if (argc > 2)
    num_bits = atoi(argv[2]);

  /* generate key with given algorithm */
  generate_key(&engine, algo, num_bits);

  /* return success */
  return EXIT_SUCCESS;
}
