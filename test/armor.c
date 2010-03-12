#include "test-common.h"

#define USAGE \
  "%s - Test PTPGP ASCII-armor decoder.\n"

typedef struct {
  ptpgp_base64_t base64;
  ptpgp_crc24_t crc24;

  bool got_armor_crc;
  u8 armor_crc[3];

  char header[1024],
       value[1024];

  size_t header_len,
         value_len;
} dump_context_t;

static void
verify_crc(dump_context_t *c) {
  long body_crc = c->crc24.crc,
       armor_crc = (c->armor_crc[0] << 16) |
                   (c->armor_crc[1] <<  8) |
                   (c->armor_crc[2]);

  /* compare checksums */
  if (c->got_armor_crc && body_crc != armor_crc)
    ptpgp_sys_die("CRC mismatch (body: %6x, armor: %6x)", body_crc, armor_crc);

  D("armor crc ok");
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

  D("writing data to crc context");
  PTPGP_ASSERT(
    ptpgp_crc24_push(&(c->crc24), data, data_len),
    "write data to crc context"
  );

  D("writing data to stdout (len = %d)", (int) data_len);
  if (!fwrite(data, data_len, 1, stdout))
    ptpgp_sys_die("Couldn't write decoded data to standard output:");

  /* return success */
  return PTPGP_OK;
}

static ptpgp_err_t
armor_cb(ptpgp_armor_parser_t *a, 
         ptpgp_armor_parser_token_t t,
         u8 *data,
         size_t data_len) {
  dump_context_t *c = (dump_context_t*) a->user_data;
  u8 buf[512];

  D("token = %d", (int) t);

  switch (t) {
  case PTPGP_ARMOR_PARSER_TOKEN_START_ARMOR:
    /* clear dump context */
    memset(c, 0, sizeof(dump_context_t));

    memcpy(buf, data, data_len);
    buf[data_len] = 0;

    D("start armor \"%s\"", buf);

    D("init crc24 context");
    PTPGP_ASSERT(
      ptpgp_crc24_init(&(c->crc24)),
      "init crc24 context"
    );

    D("init base64 decoder");
    PTPGP_ASSERT(
      ptpgp_base64_init(&(c->base64), 0, base64_cb, c),
      "init base64 decoder"
    );

    /* clear header and value */
    c->header_len = 0;
    c->value_len = 0;

    break;
  case PTPGP_ARMOR_PARSER_TOKEN_HEADER_NAME:
    D("got header name");

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
    D("got header value");

    if (c->value_len + data_len > 1024)
      ptpgp_sys_die("armor header value too long");

    /* append header value data */
    memcpy(c->value + c->value_len, data, data_len);
    c->value_len += data_len;

    break;
  case PTPGP_ARMOR_PARSER_TOKEN_BODY:
    D("got armor body fragment");
    
    /* if there was a previous header, then flush it */
    if (c->header_len > 0 && c->value_len > 0)
      dump_header(c);

#ifdef PTPGP_DEBUG
    memcpy(buf, data, data_len);
    buf[data_len] = 0;
    D("got body: \"%s\" (%d bytes)", buf, (int) data_len);
#endif /* PTPGP_DEBUG */

    PTPGP_ASSERT(
      ptpgp_base64_push(&(c->base64), data, data_len),
      "push data to base64 decoder"
    );

    break;
  case PTPGP_ARMOR_PARSER_TOKEN_CRC24:
    if (data_len != 4)
      ptpgp_sys_die("invalid crc length: %d", data_len);

#ifdef PTPGP_DEBUG
    memcpy(buf, data, data_len);
    buf[data_len] = 0;
    D("got crc24: \"%s\" (%d bytes)", buf, (int) data_len);
#endif /* PTPGP_DEBUG */

    c->got_armor_crc = 1;

    PTPGP_ASSERT(
      ptpgp_base64_decode(data, data_len, c->armor_crc, 3, 0),
      "decode armor crc (len = %d)", data_len
    );

    break;
  case PTPGP_ARMOR_PARSER_TOKEN_END_ARMOR:
    D("finalize base64 decoder");
    PTPGP_ASSERT(
      ptpgp_base64_done(&(c->base64)),
      "finalize base64 decoder"
    );

    D("finalize crc24 context");
    PTPGP_ASSERT(
      ptpgp_crc24_done(&(c->crc24)),
      "finalize crc24 context"
    );

    D("verifying checksums");
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
read_cb(u8 *data, size_t data_len, void *user_data) {
  ptpgp_armor_parser_t *a = (ptpgp_armor_parser_t*) user_data;

  PTPGP_ASSERT(
    ptpgp_armor_parser_push(a, data, data_len),
    "push data to armor parser"
  );
}

static void 
dump(char *path) {
  ptpgp_armor_parser_t a;
  dump_context_t c;

  D("init armor parser");
  PTPGP_ASSERT(
    ptpgp_armor_parser_init(&a, armor_cb, &c),
    "init armor parser"
  );

  /* read input file */
  file_read(path, read_cb, &a);

  D("finalize armor parser");
  PTPGP_ASSERT(
    ptpgp_armor_parser_done(&a),
    "finalize armor parser"
  );
}

int main(int argc, char *argv[]) {
  int i;

  if (argc > 1) {
    /* check for help option */
    for (i = 1; i < argc; i++)
      if (IS_HELP(argv[i]))
        print_usage_and_exit(argv[0], USAGE);

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
