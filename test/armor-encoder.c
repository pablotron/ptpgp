#include "test-common.h"

#define USAGE \
  "%s - Test PTPGP ASCII-armor encoder.\n"

static char *headers[] = {
  "Version", "PTPGP/" PTPGP_VERSION,
  NULL
};

static ptpgp_err_t
encoder_cb(ptpgp_armor_encoder_t *e, u8 *data, size_t data_len) {
  FILE *fh = (FILE*) e->user_data;

  if (!fwrite(data, 1, data_len, fh))
    ptpgp_sys_die("Couldn't write to output stream:");

  return PTPGP_OK;
}

static void
read_cb(u8 *data, size_t data_len, void *user_data) {
  ptpgp_armor_encoder_t *e = (ptpgp_armor_encoder_t*) user_data;

  PTPGP_ASSERT(
    ptpgp_armor_encoder_push(e, data, data_len),
    "push data to armor encoder"
  );
}

int main(int argc, char *argv[]) {
  int i;
  ptpgp_armor_encoder_t e;

  /* check for help option */
  if (argc > 1) {
    for (i = 1; i < argc; i++)
      if (IS_HELP(argv[i]))
        print_usage_and_exit(argv[0], USAGE);
  }

  /* initialize armor encoder */
  PTPGP_ASSERT(
    ptpgp_armor_encoder_init(
      &e, "ARMORED STUFF", 
      headers, encoder_cb, stdout
    ),

    "initialize armor encoder context"
  );

  if (argc > 1) {
    /* dump each input file */
    for (i = 1; i < argc; i++)
      file_read(argv[i], read_cb, &e);
  } else {
    /* read from standard input */
    file_read("-", read_cb, &e);
  }

  /* finish armor encoder */
  PTPGP_ASSERT(
    ptpgp_armor_encoder_done(&e),
    "finalize armor encoder context"
  );

  /* return success */
  return EXIT_SUCCESS;
}
