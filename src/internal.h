#include <string.h> /* for memset()/memcmp() */
#include <ptpgp/ptpgp.h>

#ifdef PTPGP_DEBUG
#include <stdio.h>
#define D(fmt, ...) fprintf(stderr, "[DEBUG] %s:%d:%s() " fmt "\n", __FILE__, __LINE__, __func__, ## __VA_ARGS__)
#else
#define D(...)
#endif /* PTPGP_DEBUG */
