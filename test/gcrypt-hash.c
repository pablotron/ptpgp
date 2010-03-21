#include "test-common.h"

#define USAGE \
  "%s - Hash input files with given digest algorithm.\n"

static void
read_cb(u8 *data, size_t data_len, void *user_data) {
  ptpgp_hash_context_t *h = (ptpgp_hash_context_t*) user_data;

  /* write file data to parser */
  PTPGP_ASSERT(
    ptpgp_engine_hash_push(h, data, data_len),
    "write data to hash context"
  );
}

static void
hash(ptpgp_engine_t *engine, 
     ptpgp_hash_type_t algorithm, 
     char *path) {
  ptpgp_hash_context_t h;
  u8 src_buf[128], dst_buf[512];
  size_t len;

  /* init ptpgp stream parser */
  PTPGP_ASSERT(
    ptpgp_engine_hash_init(&h, engine, algorithm),
    "initialize hash context for \"%s\"", path
  );

  /* read input file */
  file_read(path, read_cb, &h);

  /* finish hash context */
  PTPGP_ASSERT(
    ptpgp_engine_hash_done(&h),
    "finalize hash context"
  );

  /* read hash value into source buffer */
  PTPGP_ASSERT(
    ptpgp_engine_hash_read(&h, src_buf, sizeof(src_buf), &len),
    "read hash value"
  );

  /* convert hash value to hex */
  PTPGP_ASSERT(
    ptpgp_to_hex(src_buf, len, dst_buf, sizeof(dst_buf)),
    "convert hash value to hex"
  );

  /* null-terminate output buffer */
  dst_buf[len * 2] = 0;

  /* print digest result */
  printf("%s %s\n", dst_buf, path);
}

static void 
init(ptpgp_engine_t *engine) {
  /* check gcrypt version */
  if (!gcry_check_version(GCRYPT_VERSION))
    ptpgp_sys_die("libgcrypt version mismatch");

  /* disable secure memory */
  gcry_control(GCRYCTL_DISABLE_SECMEM, 0);

  /* finish intializing gcrypt */
  gcry_control(GCRYCTL_INITIALIZATION_FINISHED, 0);

  /* init ptpgp gcrypt engine */
  PTPGP_ASSERT(
    ptpgp_gcrypt_engine_init(engine),
    "init gcrypt engine"
  );
}

static ptpgp_hash_type_t
find_hash_algorithm(char *key) {
  uint32_t r;

  PTPGP_ASSERT(
    ptpgp_type_find(PTPGP_TYPE_HASH, key, &r),
    "find hash algorithm \"%s\"", key
  );

  return (ptpgp_hash_type_t) r;
}

int main(int argc, char *argv[]) {
  ptpgp_engine_t engine;
  ptpgp_hash_type_t hash_algo;

  /* check command-line arguments */
  if (argc < 2) 
    print_usage_and_exit(argv[0], USAGE);

  /* init engine */
  init(&engine);

  /* find hash algorithm */
  hash_algo = find_hash_algorithm(argv[1]);

  if (argc > 2) {
    int i;

    /* check for help option */
    for (i = 2; i < argc; i++)
      if (IS_HELP(argv[i]))
        print_usage_and_exit(argv[0], USAGE);

    /* hash each input file */
    for (i = 1; i < argc; i++)
      hash(&engine, hash_algo, argv[i]);
  } else {
    /* read from standard input */
    hash(&engine, hash_algo, "-");
  }

  /* return success */
  return EXIT_SUCCESS;
}
