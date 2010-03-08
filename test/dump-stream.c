#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <ptpgp/ptpgp.h>

#define IS_HELP(s) (              \
  !strncasecmp((s), "-h", 3) ||   \
  !strncasecmp((s), "-?", 3) ||   \
  !strncasecmp((s), "--help", 3)  \
)

#define UNUSED(a) ((void) (a))

static void
print_usage_and_exit(char *app) {
  printf("%s - Decode and print PGP packet headers.\n", app);
  exit(EXIT_SUCCESS);
}

static FILE *
file_open(char *path) {
  FILE *r;
  char buf[1024];

  if (!strncmp(path, "-", 2)) {
    r = stdin;
  } else {
    /* open input file */
    if ((r = fopen(path, "rb")) == NULL) {
      /* build error message */
      snprintf(buf, sizeof(buf), "FATAL: Couldn't open file \"%s\"", path);

      /* print error message */
      perror(buf);

      /* exit with error */
      exit(EXIT_FAILURE);
    }
  }

  /* return result */
  return r;
}

static void
file_close(FILE *fh) {
  if (fh != stdin && fclose(fh))
    perror("WARNING: Couldn't close file");
}

static ptpgp_err_t 
dump_cb(ptpgp_stream_parser_t *p, 
        ptpgp_stream_parser_token_t t, 
        ptpgp_packet_header_t *header, 
        char *data, size_t data_len) {
  char buf[1024];
  ptpgp_err_t err;

  UNUSED(p);
  UNUSED(data);
  UNUSED(data_len);

  /* skip non-start tokens */
  if (t != PTPGP_STREAM_PARSER_TOKEN_START) 
    return PTPGP_OK;

  /* get name of content tag */
  err = ptpgp_tag_to_s(header->content_tag, buf, sizeof(buf), NULL);

  /* check for error */
  if (err != PTPGP_OK) {
    /* print error */
    fprintf(
      stderr, 
      "FATAL: Couldn't get tag name %d: %s\n",
      header->content_tag, "dunno"
    );

    /* exit with error */
    exit(EXIT_FAILURE);
  }

  /* print packet type and length to standard output */
  printf("%s,%d,%d\n", buf, header->content_tag, (int) header->length);

  /* return success */
  return PTPGP_OK;
}

static void
dump(char *path) {
  FILE *fh;
  int len;
  char buf[1024];
  ptpgp_err_t err;
  ptpgp_stream_parser_t p;
  
  /* init ptpgp stream parser */
  err = ptpgp_stream_parser_init(&p, dump_cb, path);
  if (err != PTPGP_OK) {
    /* print error message */
    fprintf(
      stderr,
      "FATAL: Couldn't initialize stream parser for \"%s\": %s\n", 
      path, "dunno"
    );

    /* exit with error */
    exit(EXIT_FAILURE);
  }

  /* open input file */
  fh = file_open(path);

  /* dump packets from file */
  while (!feof(fh) && (len = fread(buf, 1, sizeof(buf), fh)) > 0) {
    /* write file data to parser */
    err = ptpgp_stream_parser_push(&p, buf, len);

    /* handle error */
    if (err != PTPGP_OK) {
      /* print error message */
      fprintf(
        stderr,
        "FATAL: Couldn't write data to parser: %s\n", 
        "dunno"
      );

      /* exit with error */
      exit(EXIT_FAILURE);
    }
  }

  /* close input file */
  file_close(fh);

  /* finish parser */
  err = ptpgp_stream_parser_done(&p);

  /* handle error */
  if (err != PTPGP_OK) {
    fprintf(
      stderr,
      "FATAL: Couldn't close stream parser: %s\n", 
      "dunno"
    );

    /* exit with error */
    exit(EXIT_FAILURE);
  }
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
