#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <ptpgp/ptpgp.h>

int main(int argc, char *argv[]) {
  ptpgp_err_t i;

  for (i = 0; i < PTPGP_ERR_LAST; i++)
    ptpgp_warn(i, "some warning with \"%s\" %d", "formatting", i);

  ptpgp_die(0, "fatal error with \"%s\" %d", "formatting", 20);

  /* return success */
  return EXIT_SUCCESS;
}
