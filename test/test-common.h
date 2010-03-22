#include <string.h>
#include <stdlib.h>
#include <ptpgp/ptpgp.h>

#define IS_HELP(s) (          \
  !strncmp((s), "-h", 3) ||   \
  !strncmp((s), "-?", 3) ||   \
  !strncmp((s), "--help", 3)  \
)

#define UNUSED(a) ((void) (a))

#ifdef PTPGP_DEBUG
#include <stdio.h>
#define D(fmt, ...) fprintf(stderr, "[D] %s:%d:%s() " fmt "\n", __FILE__, __LINE__, __func__, ## __VA_ARGS__)
#define W(fmt, ...) fprintf(stderr, "[W] %s:%d:%s() " fmt "\n", __FILE__, __LINE__, __func__, ## __VA_ARGS__)
#else
#define D(...)
#define W(...)
#endif /* PTPGP_DEBUG */

void print_usage_and_exit(char *app, char *fmt);
void file_read(char *path, void (*)(u8 *, size_t, void *), void *);

void init_gcrypt(ptpgp_engine_t *engine);
void init_openssl(ptpgp_engine_t *engine);
