#define _BSD_SOURCE     /* for madvise() */
#define _POSIX_SOURCE   /* for fileno() */

#include <sys/types.h>  /* for fstat() */
#include <sys/stat.h>   /* for fstat() */
#include <sys/mman.h>   /* for mmap() */

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

static size_t
file_size(FILE *fh) {
  struct stat st;

  if (fstat(fileno(fh), &st))
      ptpgp_sys_die("Couldn't stat() input file:");

  return st.st_size;
}

static void
file_close(FILE *fh) {
  if (fh != stdin && fclose(fh))
    ptpgp_sys_warn("Couldn't close file:");
}

typedef struct {
  void *addr;
  size_t size;
} file_map_t;

static bool
file_map(FILE *fh, file_map_t *r) {
  /* check for stdin */
  if (fh == stdin) {
    W("can't mmap() stdin");
    return 0;
  }

  /* get file size */
  r->size = file_size(fh);

  /* map file */
  r->addr = mmap(NULL, r->size, PROT_READ, MAP_SHARED, fileno(fh), 0);

  if (r->addr == NULL) {
    ptpgp_sys_warn("mmap() failed:");
    return 0;
  }

  if (madvise(r->addr, r->size, MADV_SEQUENTIAL | MADV_WILLNEED))
    ptpgp_sys_warn("madvise() failed:");

  /* return success */
  return 1;
}

static void
file_unmap(file_map_t *r) {
  if (munmap(r->addr, r->size))
    ptpgp_sys_warn("munmap() failed:");
}

void file_read(char *path,
               void (*cb)(u8 *, size_t, void *),
               void *user_data) {
  FILE *fh;
  size_t len = 0;
  file_map_t m;
  u8 buf[1024];

  /* open input file */
  fh = file_open(path);

  /* try to mmap() the file first */
  if (file_map(fh, &m)) {
    /* read input file */
    cb(m.addr, m.size, user_data);
    file_unmap(&m);
  } else {
    /* if mmap() failed, then read input file sequentially */
    while (!feof(fh) && (len = fread(buf, 1, sizeof(buf), fh)) > 0)
      cb(buf, len, user_data);
  }

  /* close input file */
  file_close(fh);
}

void 
init_openssl(ptpgp_engine_t *engine) {
#ifdef PTPGP_USE_OPENSSL
  /* init ptpgp openssl engine */
  PTPGP_ASSERT(
    ptpgp_openssl_engine_init(engine),
    "init openssl engine"
  );
#else /* !PTPGP_USE_OPENSSL */
  UNUSED(engine);
  ptpgp_sys_die("no openssl support");
#endif /* PTPGP_USE_OPENSSL */
}

void 
init_gcrypt(ptpgp_engine_t *engine) {
#ifdef PTPGP_USE_GCRYPT
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
#else /* !PTPGP_USE_GCRYPT */
  UNUSED(engine);
  ptpgp_sys_die("no gcrypt support");
#endif /* PTPGP_USE_GCRYPT */
}
