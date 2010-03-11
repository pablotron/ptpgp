#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include "test-common.h"

void
print_usage_and_exit(char *app, char *fmt) {
  printf(fmt, app);
  exit(EXIT_SUCCESS);
}

static FILE *
file_open(char *path) {
  FILE *r;

  if (!strncmp(path, "-", 2)) {
    r = stdin;
  } else {
    /* open input file */
    if ((r = fopen(path, "rb")) == NULL)
      ptpgp_sys_die("Couldn't open input file \"%s\":", path);
  }

  /* return result */
  return r;
}

static void
file_close(FILE *fh) {
  if (fh != stdin && fclose(fh))
    ptpgp_sys_warn("Couldn't close file:");
}

void file_read(char *path, 
               void (*cb)(u8 *, size_t, void *), 
               void *user_data) {
  FILE *fh;
  size_t len;
  u8 buf[1024];

  /* open input file */
  fh = file_open(path);

  /* read input file */
  while (!feof(fh) && (len = fread(buf, 1, sizeof(buf), fh)) > 0)
    cb(buf, len, user_data);

  file_close(fh);
}
