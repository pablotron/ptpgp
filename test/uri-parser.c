#include "test-common.h"

#define USAGE \
  "%s - Test PTPGP URI parser.\n"

static ptpgp_err_t
parser_cb(ptpgp_uri_parser_t *p,
          ptpgp_uri_parser_token_t t,
          u8 *data, size_t data_len) {
  FILE *fh = (FILE*) p->user_data;
  char *key;

  switch (t) {
  case PTPGP_URI_PARSER_TOKEN_SCHEME:
    key = "scheme";
    break;
  case PTPGP_URI_PARSER_TOKEN_AUTH:
    key = "auth";
    break;
  case PTPGP_URI_PARSER_TOKEN_HOST:
    key = "host";
    break;
  case PTPGP_URI_PARSER_TOKEN_PORT:
    key = "port";
    break;
  case PTPGP_URI_PARSER_TOKEN_PATH:
    key = "path";
    break;
  case PTPGP_URI_PARSER_TOKEN_QUERY:
    key = "query";
    break;
  case PTPGP_URI_PARSER_TOKEN_FRAGMENT:
    key = "fragment";
    break;
  default:
    key = NULL;
  }
    
  if (key) {
    /* write key */
    fprintf(fh, "%s: ", key);

    /* write data */
    if (!fwrite(data, data_len, 1, fh))
      ptpgp_sys_die("Couldn't write %s to output", key);

    /* end line */
    fprintf(fh, "\n");
  }

  /* return success */
  return PTPGP_OK;
}

static void 
dump(char *uri) {
  ptpgp_uri_parser_t p;
  size_t len = strlen(uri);

  PTPGP_ASSERT(
    ptpgp_uri_parser_init(&p, parser_cb, stdout),
    "init uri parser context"
  );

  PTPGP_ASSERT(
    ptpgp_uri_parser_push(&p, (u8*) uri, len),
    "push command-line argument"
  );
  
  PTPGP_ASSERT(
    ptpgp_uri_parser_done(&p),
    "finish uri parser context"
  );
}

int main(int argc, char *argv[]) {
  if (argc > 1) {
    int i;

    /* check for help option */
    for (i = 1; i < argc; i++)
      if (IS_HELP(argv[i]))
        print_usage_and_exit(argv[0], USAGE);

    /* decode each uri */
    for (i = 1; i < argc; i++)
      dump(argv[i]);
  }
  
  /* return success */
  return EXIT_SUCCESS;
}
