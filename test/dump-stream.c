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
      snprintf(buf, sizeof(buf), "[FATAL] Couldn't open file \"%s\"", path);

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
    perror("[WARNING] Couldn't close file");
}

static ptpgp_packet_parser_t pp;

static ptpgp_err_t
dump_packet_cb(ptpgp_packet_parser_t *p,
               ptpgp_packet_parser_token_t t,
               ptpgp_packet_t *packet,
               u8 *data, size_t data_len) {
  u8 key_id[20];
  char errbuf[1024];
  ptpgp_err_t err;

  UNUSED(p);
  UNUSED(data);
  UNUSED(data_len);

  /* ignore unknown tags */
  if (packet->tag != PTPGP_TAG_PUBLIC_KEY_ENCRYPTED_SESSION_KEY)
    return PTPGP_OK;

  switch (t) {
  case PTPGP_PACKET_PARSER_TOKEN_PACKET_START:
    /* convert key id to hex */
    memset(key_id, 0, sizeof(key_id));
    err = ptpgp_to_hex(packet->packet.t1.key_id, 8, key_id, sizeof(key_id));

    /* check for error */
    if (err != PTPGP_OK) {
      /* get ptpgp error */
      ptpgp_strerror(err, errbuf, sizeof(errbuf), NULL);

      /* print error */
      fprintf(
        stderr,
        "[FATAL] Couldn't convert key id to hex: %s (#%d)\n",
        errbuf, err
      );

      /* exit with error */
      exit(EXIT_FAILURE);
    }

    /* dump packet contents */
    printf(
      "  version = %d, algorithm = %d, key_id = 0x%s\n",
      packet->packet.t1.version,
      packet->packet.t1.algorithm,
      key_id
    );

    break;
  case PTPGP_PACKET_PARSER_TOKEN_MPI_START:
    printf("  mpi: num_bits = %d\n", (int) *((size_t*) data));

    break;
  default: 
    /* ignore unknown tokens */
    return PTPGP_OK;
  }

  /* return success */
  return PTPGP_OK;
}

static ptpgp_err_t
dump_stream_cb(ptpgp_stream_parser_t *p,
               ptpgp_stream_parser_token_t t,
               ptpgp_packet_header_t *header,
               u8 *data, size_t data_len) {
  char buf[1024], errbuf[1024];
  ptpgp_err_t err;

  UNUSED(p);
  UNUSED(data);
  UNUSED(data_len);

  switch (t) {
  case PTPGP_STREAM_PARSER_TOKEN_START:
    /* skip non-start tokens */
    if (t != PTPGP_STREAM_PARSER_TOKEN_START)
      return PTPGP_OK;

    /* get name of content tag */
    err = ptpgp_tag_to_s(header->content_tag, buf, sizeof(buf), NULL);

    /* check for error */
    if (err != PTPGP_OK) {
      /* get ptpgp error */
      ptpgp_strerror(err, errbuf, sizeof(errbuf), NULL);

      /* print error */
      fprintf(
        stderr,
        "[FATAL] Couldn't get tag name %d: %s (#%d)\n",
        header->content_tag, errbuf, err
      );

      /* exit with error */
      exit(EXIT_FAILURE);
    }

    /* print packet type and length to standard output */
    printf("%s,%d,%d\n", buf, header->content_tag, (int) header->length);

    /* initialize packet parser */
    err = ptpgp_packet_parser_init(&pp, header->content_tag, dump_packet_cb, NULL);

    /* check for error */
    if (err != PTPGP_OK) {
      /* get ptpgp error */
      ptpgp_strerror(err, errbuf, sizeof(errbuf), NULL);

      /* print error */
      fprintf(
        stderr,
        "[FATAL] Couldn't initialize packet parser for tag %d: %s (#%d)\n",
        header->content_tag, errbuf, err
      );

      /* exit with error */
      exit(EXIT_FAILURE);
    }

    break;
  case PTPGP_STREAM_PARSER_TOKEN_BODY:
    err = ptpgp_packet_parser_push(&pp, data, data_len);

    /* check for error */
    if (err != PTPGP_OK) {
      /* get ptpgp error */
      ptpgp_strerror(err, errbuf, sizeof(errbuf), NULL);

      /* print error */
      fprintf(
        stderr,
        "[FATAL] Couldn't push data to packet parser: %s (#%d)\n",
        errbuf, err
      );

      /* exit with error */
      exit(EXIT_FAILURE);
    }

    break;
  case PTPGP_STREAM_PARSER_TOKEN_END:
    err = ptpgp_packet_parser_done(&pp);

    /* check for error */
    if (err != PTPGP_OK) {
      /* get ptpgp error */
      ptpgp_strerror(err, errbuf, sizeof(errbuf), NULL);

      /* print error */
      fprintf(
        stderr,
        "[FATAL] Couldn't finalize packet parser: %s (#%d)\n",
        errbuf, err
      );

      /* exit with error */
      exit(EXIT_FAILURE);
    }

    break;
  default:
    /* ignore unknown tags */
    return PTPGP_OK;
  }
    
  /* return success */
  return PTPGP_OK;
}

static void
dump(char *path) {
  FILE *fh;
  int len;
  unsigned char buf[1024];
  char errbuf[1024];
  ptpgp_err_t err;
  ptpgp_stream_parser_t p;

  /* init ptpgp stream parser */
  err = ptpgp_stream_parser_init(&p, dump_stream_cb, path);
  if (err != PTPGP_OK) {
    /* get ptpgp error */
    ptpgp_strerror(err, errbuf, sizeof(errbuf), NULL);

    /* print error message */
    fprintf(
      stderr,
      "[FATAL] Couldn't initialize stream parser for \"%s\": %s (#%d)\n",
      path, errbuf, err
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
      /* get ptpgp error */
      ptpgp_strerror(err, errbuf, sizeof(errbuf), NULL);

      /* print error message */
      fprintf(
        stderr,
        "[FATAL] Couldn't write data to parser: %s (#%d)\n",
        errbuf, err
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
    /* get ptpgp error */
    ptpgp_strerror(err, errbuf, sizeof(errbuf), NULL);

    fprintf(
      stderr,
      "[FATAL] Couldn't close stream parser: %s (#%d)\n",
      errbuf, err
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
