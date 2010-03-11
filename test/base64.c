#include "test-common.h"

#define IS_ENCODE(s) (          \
  !strncmp((s), "-e", 3) ||     \
  !strncmp((s), "--encode", 9)  \
)

#define USAGE \
  "%s - Test PTPGP Base-64 encoder/decoder.\n"

static ptpgp_err_t
base64_cb(ptpgp_base64_t *b, u8 *data, size_t data_len) {
  /* write output */
  if (!fwrite(data, data_len, 1, (FILE*) b->user_data))
    ptpgp_sys_die("Couldn't write decoded data to standard output:");

  /* return success */
  return PTPGP_OK;
}

static void
read_cb(u8 *data, size_t data_len, void *user_data) {
  ptpgp_base64_t *b = (ptpgp_base64_t*) user_data;

  PTPGP_ASSERT(
    ptpgp_base64_push(b, data, data_len),
    "push data to base64 context"
  );
}

static void
dump(char *path, bool encode) {
  ptpgp_base64_t b;

  PTPGP_ASSERT(
    ptpgp_base64_init(&b, encode, base64_cb, stdout),
    "init base64 context"
  );

  /* read input file and pass it to decoder */
  file_read(path, read_cb, &b);

  PTPGP_ASSERT(
    ptpgp_base64_done(&b),
    "finalize base64 context"
  );
}


int main(int argc, char *argv[]) {
  size_t i;
  bool encode = 0;

  /* check command-line arguments */
  if (argc < 2) 
    print_usage_and_exit(argv[0], USAGE);
    
  /* check for help argument */
  for (i = 0; (int) i < argc; i++)
    if (IS_HELP(argv[i]))
      print_usage_and_exit(argv[0], USAGE);

  /* get encode flag */
  encode = IS_ENCODE(argv[1]);

  /* dump file(s) */
  if (argc > 2) {
    for (i = 2; (int) i < argc; i++);
      dump(argv[i], encode);
  } else {
    dump("-", encode);
  }

  /* return success */
  return EXIT_SUCCESS;
}
