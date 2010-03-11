#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <ptpgp/ptpgp.h>

#define IS_HELP(s) (          \
  !strncmp((s), "-h", 3) ||   \
  !strncmp((s), "-?", 3) ||   \
  !strncmp((s), "--help", 3)  \
)

#define UNUSED(a) ((void) (a))

typedef struct {
  ptpgp_base64_t base64;
  ptpgp_crc24_t crc24;

  u8 armor_crc[3];

  char header[1024],
       value[1024];

  size_t header_len,
         value_len;
} dump_context_t;

static void
print_usage_and_exit(char *app) {
  printf("%s - Test PTPGP ASCII-armor decoder.\n", app);
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

static void
verify_crc(dump_context_t *c) {
  long body_crc = c->crc24.crc,
       armor_crc = (c->armor_crc[0] << 16) |
                   (c->armor_crc[1] <<  8) |
                   (c->armor_crc[2]);

  /* compare checksums */
  if (body_crc != armor_crc)
    ptpgp_sys_die("CRC mismatch (body: %d, armor: %d)", body_crc, armor_crc);
}

static void
dump_header(dump_context_t *c) {
  /* null-terminate header and value */
  c->header[c->header_len] = 0;
  c->value[c->value_len] = 0;

  /* dump armor header and value */
  fprintf(stderr, "armor header: %s: %s\n", c->header, c->value);

  /* clear header and value */
  c->header_len = 0;
  c->value_len = 0;
}


static ptpgp_err_t
base64_cb(ptpgp_base64_t *b,
          u8 *data,
          size_t data_len) {
  dump_context_t *c = (dump_context_t*) b->user_data;

  PTPGP_ASSERT(
    ptpgp_crc24_push(&(c->crc24), data, data_len),
    "write data to crc context"
  );

  if (!fwrite(data, data_len, 1, stdout))
    ptpgp_sys_die("Couldn't write decoded data to standard output:");

  /* return success */
  return PTPGP_OK;
}

static ptpgp_err_t
dump_cb(ptpgp_armor_parser_t *a, 
        ptpgp_armor_parser_token_t t,
        u8 *data,
        size_t data_len) {
  dump_context_t *c = (dump_context_t*) a->user_data;

  switch (t) {
  case PTPGP_ARMOR_PARSER_TOKEN_START_ARMOR:
    /* init crc24 context */
    PTPGP_ASSERT(
      ptpgp_crc24_init(&(c->crc24)),
      "init crc24 context"
    );

    /* initialize base64 decoder */
    PTPGP_ASSERT(
      ptpgp_base64_init(&(c->base64), 0, base64_cb, c),
      "init base64 decoder"
    );

    /* clear header and value */
    c->header_len = 0;
    c->value_len = 0;

    break;
  case PTPGP_ARMOR_PARSER_TOKEN_HEADER_NAME:
    /* if there was a previous header, then flush it */
    if (c->header_len > 0 && c->value_len > 0)
      dump_header(c);

    /* check buffer length */
    if (c->header_len + data_len > 1024)
      ptpgp_sys_die("armor header name too long");

    /* append header name data */
    memcpy(c->header + c->header_len, data, data_len);
    c->header_len += data_len;

    break;
  case PTPGP_ARMOR_PARSER_TOKEN_HEADER_VALUE:
    if (c->value_len + data_len > 1024)
      ptpgp_sys_die("armor header value too long");

    /* append header value data */
    memcpy(c->value + c->value_len, data, data_len);
    c->value_len += data_len;

    break;
  case PTPGP_ARMOR_PARSER_TOKEN_BODY:
    /* if there was a previous header, then flush it */
    if (c->header_len > 0 && c->value_len > 0)
      dump_header(c);

    PTPGP_ASSERT(
      ptpgp_base64_push(&(c->base64), data, data_len),
      "push data to base64 decoder"
    );

    break;
  case PTPGP_ARMOR_PARSER_TOKEN_CRC24:
    if (data_len != 4)
      ptpgp_sys_die("invalid crc length: %d", data_len);

    PTPGP_ASSERT(
      ptpgp_base64_decode(data, data_len, c->armor_crc, 3, 0),
      "decode armor crc"
    );

    break;
  case PTPGP_ARMOR_PARSER_TOKEN_END_ARMOR:
    /* finalize base64 */
    PTPGP_ASSERT(
      ptpgp_base64_done(&(c->base64)),
      "finalize base64 decoder"
    );

    /* finalize crc24 */
    PTPGP_ASSERT(
      ptpgp_crc24_done(&(c->crc24)),
      "finalize crc24 context"
    );

    /* verify checksum */
    verify_crc(c);

    break;
  default:
    /* skip unknown tokens */
    ptpgp_sys_warn("unknown token: %d", t);
  }

  /* return success */
  return PTPGP_OK;
}

static void 
dump(char *path) {
  FILE *fh;
  u8 buf[4096];
  size_t len;
  ptpgp_armor_parser_t a;
  dump_context_t c;

  /* init armor parser */
  PTPGP_ASSERT(
    ptpgp_armor_parser_init(&a, dump_cb, &c),
    "init armor parser"
  );

  /* open input file */
  fh = file_open(path);

  /* read input file */
  while (!feof(fh) && (len = fread(buf, 1, sizeof(buf), fh)) > 0) {
    PTPGP_ASSERT(
      ptpgp_armor_parser_push(&a, buf, len),
      "push data to armor parser"
    );
  }

  /* close input file */
  file_close(fh);

  /* finish armor parser */
  PTPGP_ASSERT(
    ptpgp_armor_parser_done(&a),
    "finish armor parser"
  );
}

int main(int argc, char *argv[]) {
  int i;

  if (argc > 1) {
    /* check for help option */
    for (i = 1; i < argc; i++)
      if (IS_HELP(argv[i]))
        print_usage_and_exit(argv[0]);

    /* dump each input file */
    for (i = 1; i < argc; i++)
      dump(argv[i]);
  } else {
    /* read from standard input */
    dump("-");
  }

  /* return success */
  return EXIT_SUCCESS;
}
