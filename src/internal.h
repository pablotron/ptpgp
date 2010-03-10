#include <string.h> /* for memset()/memcmp() */
#include <ptpgp/ptpgp.h>

#ifdef PTPGP_DEBUG
#include <stdio.h>
#define D(fmt, ...) fprintf(stderr, "[D] %s:%d:%s() " fmt "\n", __FILE__, __LINE__, __func__, ## __VA_ARGS__)
#define W(fmt, ...) fprintf(stderr, "[W] %s:%d:%s() " fmt "\n", __FILE__, __LINE__, __func__, ## __VA_ARGS__)
#else
#define D(...)
#define W(...)
#endif /* PTPGP_DEBUG */

#define IS_VALID_CONTENT_TAG(t) ( \
  ((t) >   0 && (t) <= 14) ||     \
  ((t) >= 17 && (t) <= 19) ||     \
  ((t) >= 60 && (t) <= 63)        \
)

#define TRY(f) do {               \
  ptpgp_err_t try_err = (f);      \
  if (try_err != PTPGP_OK)        \
    return try_err;               \
} while (0)
