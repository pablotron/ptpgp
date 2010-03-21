#include "test-common.h"

#define USAGE \
  "%s - Encrypt or decrypt files with given symmetric cipher/mode.\n" \
  "Usage:\n" \
  "\n" \
  "  gcrypt-encrypt <-e|-d> <algo> <mode> <password> [files...]\n"


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
run(ptpgp_encrypt_options_t *o,
     char *path) {
  ptpgp_encrypt_context_t c;
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

static ptpgp_symmetric_type_t
find_algorithm(char *key) {
  uint32_t r;

  PTPGP_ASSERT(
    ptpgp_type_find(PTPGP_TYPE_SYMMETRIC, key, &r),
    "find symmetric algorithm \"%s\"", key
  );

  return (ptpgp_symmetric_type_t) r;
}

static ptpgp_symmetric_mode_type_t
find_mode(char *key) {
  uint32_t r;

  PTPGP_ASSERT(
    ptpgp_type_find(PTPGP_TYPE_SYMMETRIC_MODE, key, &r),
    "find mode \"%s\"", key
  );

  return (ptpgp_symmetric_mode_type_t) r;
}

static size_t
hash_password(ptpgp_engine_t *engine, char *src, char *dst, size_t dst_len) {
  size_t r;

  /* hash password */
  PTPGP_ASSERT(
    ptpgp_engine_hash_once(engine, PTPGP_HASH_TYPE_SHA1,
                           src, strlen(src),
                           dst, dst_len, &r),
    "hash password"
  );

  return r;
}

/* evil globals */
static char key[128];
static size_t key_len = 0;

static unsigned char iv[64];

static void
init_options(ptpgp_symmetric_options_t *o, ptpgp_engine_t *e, char **argv) {
  /* get encrypt/decrypt mode */
  o->encrypt = (!strncmp("-e", argv[1], 3) ||
                !strncmp("--encrypt", argv[1], 10));

  /* find symmetric algorithm */
  o->algorithm = find_algorithm(argv[2]);

  /* find symmetric mode */
  o->mode = find_mode(argv[3]);

  /* hash password */
  hash_password(&engine, argv[4], key, sizeof(key), &key_len);

  o->key = key;
  o->key_len = key_len;

  memset(iv, 0, sizeof(iv));
  o->iv = iv;
  o->iv_len = sizeof(iv);
}

int main(int argc, char *argv[]) {
  ptpgp_engine_t engine;
  ptpgp_encrypt_options_t o;

  /* check command-line arguments */
  if (argc < 5)
    print_usage_and_exit(argv[0], USAGE);

  /* init engine */
  init(&engine);

  /* init options */
  init_options(&o, &e, argv);

  if (argc > 5) {
    int i;

    /* check for help option */
    for (i = 1; i < argc; i++)
      if (IS_HELP(argv[i]))
        print_usage_and_exit(argv[0], USAGE);

    /* encrypt each input file */
    for (i = 5; i < argc; i++)
      run(&o, argv[i]);
  } else {
    /* read from standard input */
    run(&o, "-");
  }

  /* return success */
  return EXIT_SUCCESS;
}
