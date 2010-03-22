#include "test-common.h"

/* 
 * Example:
 *
 *   $ echo 'hello this is a test' | \
 *       ./openssl-encrypt -e aes-128 cfb foobarbaz | \
 *       ./openssl-encrypt -d aes-128 cfb foobarbaz
 *
 * You should also be able to mix and match between gcrypt and openssl,
 * like so:
 *
 *   $ echo 'hello this is a test' | \
 *       ./gcrypt-encrypt -e aes-128 cfb foobarbaz | \
 *       ./openssl-encrypt -d aes-128 cfb foobarbaz
 *
 */

#define USAGE \
  "%s - Encrypt or decrypt files with given symmetric cipher/mode.\n" \
  "Usage:\n" \
  "\n" \
  "  openssl-encrypt <-e|-d> <algo> <mode> <password> [files...]\n"

static ptpgp_err_t
data_cb(ptpgp_encrypt_context_t *c, u8 *data, size_t data_len) {
  FILE *fh = (FILE*) c->options.user_data;

  /* write to output */
  if (data_len > 0)
    if (!fwrite(data, data_len, 1, fh))
      ptpgp_sys_die("fwrite() failed:");

  /* return success */
  return PTPGP_OK;
}

static void
read_cb(u8 *data, size_t data_len, void *user_data) {
  ptpgp_encrypt_context_t *c = (ptpgp_encrypt_context_t*) user_data;

  /* write file data to parser */
  PTPGP_ASSERT(
    ptpgp_engine_encrypt_push(c, data, data_len),
    "write data to encryption context"
  );
}

static void
run(ptpgp_encrypt_options_t *o, char *path) {
  ptpgp_encrypt_context_t c;

  /* init ptpgp stream parser */
  PTPGP_ASSERT(
    ptpgp_engine_encrypt_init(&c, o),
    "initialize encrypt context for \"%s\"", path
  );

  /* read input file */
  file_read(path, read_cb, &c);

  /* finish encrypt context */
  PTPGP_ASSERT(
    ptpgp_engine_encrypt_done(&c),
    "finalize encrypt context"
  );
}

static void
init(ptpgp_engine_t *engine) {
  /* init ptpgp openssl engine */
  PTPGP_ASSERT(
    ptpgp_openssl_engine_init(engine),
    "init openssl engine"
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
hash_password(ptpgp_engine_t *engine, u8 *src, u8 *dst, size_t dst_len) {
  size_t r;

  /* hash password */
  PTPGP_ASSERT(
    ptpgp_engine_hash_once(engine, PTPGP_HASH_TYPE_SHA512,
                           src, strlen((char*) src),
                           dst, dst_len, &r),
    "hash password"
  );

  return r;
}

/* evil globals */
/* note: the key and iv buffers must be larger than the largest key size
 * and largest block size, respectively, for all symmetric algorithms */
static u8 key[512], iv[512];
static size_t key_len = 0;

static void
init_options(ptpgp_encrypt_options_t *o,
             ptpgp_engine_t *e,
             char *argv[]) {
  ptpgp_type_info_t *info;

  /* set engine */
  o->engine = e;

  /* set encrypt/decrypt mode */
  o->encrypt = (!strncmp("-e", argv[1], 3) ||
                !strncmp("--encrypt", argv[1], 10));

  /* set algorithm */
  o->algorithm = find_algorithm(argv[2]);

  /* get algorithm info */
  PTPGP_ASSERT(
    ptpgp_type_info(PTPGP_TYPE_SYMMETRIC, o->algorithm, &info),
    "get symmetric algorithm info"
  );

  /* set mode */
  o->mode = find_mode(argv[3]);

  /* hash password */
  key_len = hash_password(e, (u8*) argv[4], key, sizeof(key));

  /* set key */
  o->key = key;
  o->key_len = PTPGP_INFO_SYMMETRIC_KEY_SIZE(info) / 8;

  /* set iv */
  memset(iv, 0, sizeof(iv));
  o->iv = iv;
  o->iv_len = PTPGP_INFO_SYMMETRIC_BLOCK_SIZE(info) / 8;

  D("o->key_len = %d, o->iv_len = %d", (int) o->key_len, (int) o->iv_len);

  /* set callback */
  o->cb = data_cb;
  o->user_data = stdout;
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
  init_options(&o, &engine, argv);

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
