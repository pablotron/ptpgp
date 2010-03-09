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
static ptpgp_signature_subpacket_parser_t sspp;

static char *algo_to_s(ptpgp_algorithm_type_t t,
                       uint32_t a,
                       char *buf,
                       size_t buf_len) {
  ptpgp_err_t err = ptpgp_algorithm_to_s(t, a, (u8*) buf, buf_len, NULL);

  /* check for error */
  if (err != PTPGP_OK) {
    char errbuf[1024];

    /* get ptpgp error */
    ptpgp_strerror(err, errbuf, sizeof(errbuf), NULL);

    /* print error */
    fprintf(
      stderr,
      "[FATAL] Couldn't get algorithm name for [%d, %d]: %s (#%d)\n",
      t, a, errbuf, err
    );

    /* exit with error */
    exit(EXIT_FAILURE);
  }

  return buf;
}


#define P "    signature_subpacket: "
static ptpgp_err_t
dump_signature_subpacket_cb(ptpgp_signature_subpacket_parser_t *p,
                            ptpgp_signature_subpacket_parser_token_t t,
                            u8 *data, size_t data_len) {
  char buf[1024], errbuf[1024];
  ptpgp_err_t err;

  UNUSED(p);

  switch (t) {
  case PTPGP_SIGNATURE_SUBPACKET_PARSER_TOKEN_SIGNATURE_CREATION_TIME:
    printf(P "signature_creation_time: %d\n", *((uint32_t*) data));
    break;
  case PTPGP_SIGNATURE_SUBPACKET_PARSER_TOKEN_ISSUER:
    /* convert key id to hex */
    memset(buf, 0, sizeof(buf));
    err = ptpgp_to_hex(data, data_len, (u8*) buf, sizeof(buf));

    /* check for error */
    if (err != PTPGP_OK) {
      /* get ptpgp error */
      ptpgp_strerror(err, errbuf, sizeof(errbuf), NULL);

      /* print error */
      fprintf(
        stderr,
        "[FATAL] Couldn't convert issuer key id to hex: %s (#%d)\n",
        errbuf, err
      );

      /* exit with error */
      exit(EXIT_FAILURE);
    }

    printf(P "issuer: 0x%s\n", buf);
    break;
  case PTPGP_SIGNATURE_SUBPACKET_PARSER_TOKEN_KEY_EXPIRATION_TIME:
    printf(P "key_expiration_time: %d\n", *((uint32_t*) data));
    break;
  case PTPGP_SIGNATURE_SUBPACKET_PARSER_TOKEN_PREFERRED_SYMMETRIC_ALGORITHM:
    printf(
      P "preferred_symmetric_algorithm: %s (%d)\n",
      algo_to_s(PTPGP_ALGORITHM_TYPE_SYMMETRIC_KEY, *data, buf, sizeof(buf)),
      *data
    );
    break;
  case PTPGP_SIGNATURE_SUBPACKET_PARSER_TOKEN_PREFERRED_HASH_ALGORITHM:
    printf(
      P "preferred_hash_algorithm: %s (%d)\n",
      algo_to_s(PTPGP_ALGORITHM_TYPE_HASH, *data, buf, sizeof(buf)),
      *data
    );
    break;
  case PTPGP_SIGNATURE_SUBPACKET_PARSER_TOKEN_PREFERRED_COMPRESSION_ALGORITHM:
    printf(
      P "preferred_compression_algorithm: %s (%d)\n",
      algo_to_s(PTPGP_ALGORITHM_TYPE_COMPRESSION, *data, buf, sizeof(buf)),
      *data
    );
    break;
  case PTPGP_SIGNATURE_SUBPACKET_PARSER_TOKEN_SIGNATURE_EXPIRATION_TIME:
    printf(P "signature_expiration_time: %d\n", *((uint32_t*) data));
    break;
  case PTPGP_SIGNATURE_SUBPACKET_PARSER_TOKEN_EXPORTABLE_CERTIFICATION:
    printf(P "exportable_certification: %s\n", *data ? "yes" : "no");
    break;
  case PTPGP_SIGNATURE_SUBPACKET_PARSER_TOKEN_REVOCABLE:
    printf(P "revocable: %s\n", *data ? "yes" : "no");
    break;
  case PTPGP_SIGNATURE_SUBPACKET_PARSER_TOKEN_TRUST_LEVEL:
    printf(P "trust_level: %d\n", *data);
    break;
  case PTPGP_SIGNATURE_SUBPACKET_PARSER_TOKEN_TRUST_AMOUNT:
    printf(P "trust_amount: %d\n", *data);
    break;
  case PTPGP_SIGNATURE_SUBPACKET_PARSER_TOKEN_REGULAR_EXPRESSION_FRAGMENT:
    memset(buf, 0, sizeof(buf));
    memcpy(buf, data, data_len);
    printf(P "regex_fragment: %s\n", buf);
    break;
  case PTPGP_SIGNATURE_SUBPACKET_PARSER_TOKEN_REVOCATION_KEY_CLASS:
    printf(P "revocation_key_class: %d\n", *data);
    break;
  case PTPGP_SIGNATURE_SUBPACKET_PARSER_TOKEN_REVOCATION_PUBLIC_KEY_ALGORITHM:
    printf(
      P "revocation_public_key_algorithm: %s (%d)\n",
      algo_to_s(PTPGP_ALGORITHM_TYPE_PUBLIC_KEY, *data, buf, sizeof(buf)),
      *data
    );
    break;
  case PTPGP_SIGNATURE_SUBPACKET_PARSER_TOKEN_REVOCATION_FINGERPRINT:
    memset(buf, 0, sizeof(buf));
    memcpy(buf, data, data_len);
    printf(P "revocation_fingerprint_fragment: %s\n", buf);
    break;
  case PTPGP_SIGNATURE_SUBPACKET_PARSER_TOKEN_NOTATION_DATA_FLAGS:
    printf(P "notation_data_flags: %d\n", *((uint32_t*) data));
    break;
  case PTPGP_SIGNATURE_SUBPACKET_PARSER_TOKEN_KEY_SERVER_PREFERENCE:
    memset(buf, 0, sizeof(buf));
    memcpy(buf, data, data_len);
    printf(P "key_server_preference_fragment: %s\n", buf);
    break;
  case PTPGP_SIGNATURE_SUBPACKET_PARSER_TOKEN_PREFERRED_KEY_SERVER:
    memset(buf, 0, sizeof(buf));
    memcpy(buf, data, data_len);
    printf(P "preferred_key_server_fragment: %s\n", buf);
    break;
  case PTPGP_SIGNATURE_SUBPACKET_PARSER_TOKEN_PRIMARY_USER_ID:
    printf(P "primary_user_id: %s\n", *data ? "yes" : "no");
    break;
  case PTPGP_SIGNATURE_SUBPACKET_PARSER_TOKEN_POLICY_URI:
    memset(buf, 0, sizeof(buf));
    memcpy(buf, data, data_len);
    printf(P "policy_uri_fragment: %s\n", buf);
    break;
  case PTPGP_SIGNATURE_SUBPACKET_PARSER_TOKEN_KEY_FLAG:
    printf(P "key_flag: %d\n", *data);
    break;
  case PTPGP_SIGNATURE_SUBPACKET_PARSER_TOKEN_SIGNERS_USER_ID:
    memset(buf, 0, sizeof(buf));
    memcpy(buf, data, data_len);
    printf(P "signers_user_id_fragment: %s\n", buf);
    break;
  case PTPGP_SIGNATURE_SUBPACKET_PARSER_TOKEN_REVOCATION_CODE:
    printf(P "revocation_code: %d\n", *data);
    break;
  case PTPGP_SIGNATURE_SUBPACKET_PARSER_TOKEN_FEATURE:
    printf(P "feature: %d\n", *data);
    break;
  case PTPGP_SIGNATURE_SUBPACKET_PARSER_TOKEN_SIGNATURE_TARGET_PUBLIC_KEY_ALGORITHM:
    printf(
      P "signature_target_public_key_algorithm: %s (%d)\n",
      algo_to_s(PTPGP_ALGORITHM_TYPE_PUBLIC_KEY, *data, buf, sizeof(buf)),
      *data
    );
    break;
  case PTPGP_SIGNATURE_SUBPACKET_PARSER_TOKEN_SIGNATURE_TARGET_HASH_ALGORITHM:
    printf(
      P "signature_target_hash_algorithm: %s (%d)\n",
      algo_to_s(PTPGP_ALGORITHM_TYPE_HASH, *data, buf, sizeof(buf)),
      *data
    );
    break;
  case PTPGP_SIGNATURE_SUBPACKET_PARSER_TOKEN_EMBEDDED_SIGNATURE:
    printf(P "embedded_signature_fragment: %d bytes\n", (int) data_len);
    break;
  case PTPGP_SIGNATURE_SUBPACKET_PARSER_TOKEN_NOTATION_DATA_NAME:
    memset(buf, 0, sizeof(buf));
    memcpy(buf, data, data_len);
    printf(P "notation_data_name_fragment: %s\n", buf);
    break;
  case PTPGP_SIGNATURE_SUBPACKET_PARSER_TOKEN_NOTATION_DATA_VALUE:
    memset(buf, 0, sizeof(buf));
    memcpy(buf, data, data_len);
    printf(P "notation_data_value_fragment: %s\n", buf);
    break;
  case PTPGP_SIGNATURE_SUBPACKET_PARSER_TOKEN_REVOCATION_REASON:
    memset(buf, 0, sizeof(buf));
    memcpy(buf, data, data_len);
    printf(P "revocation_reason_fragment: %s\n", buf);
    break;
  case PTPGP_SIGNATURE_SUBPACKET_PARSER_TOKEN_SIGNATURE_TARGET_HASH_DATA:
    /* convert hash data fragment to hex */
    memset(buf, 0, sizeof(buf));
    err = ptpgp_to_hex(data, data_len, (u8*) buf, sizeof(buf));

    /* check for error */
    if (err != PTPGP_OK) {
      /* get ptpgp error */
      ptpgp_strerror(err, errbuf, sizeof(errbuf), NULL);

      /* print error */
      fprintf(
        stderr,
        "[FATAL] Couldn't convert hash data fragment to hex: %s (#%d)\n",
        errbuf, err
      );

      /* exit with error */
      exit(EXIT_FAILURE);
    }

    printf(P "hash_data_fragment: %s\n", buf);
    break;
  default:
    /* ignore unknown token types */
    return PTPGP_OK;
  }

  /* return success */
  return PTPGP_OK;
}
#undef P

static ptpgp_err_t
dump_packet_cb(ptpgp_packet_parser_t *p,
               ptpgp_packet_parser_token_t t,
               ptpgp_packet_t *packet,
               u8 *data, size_t data_len) {
  u8 key_id[20];
  char buf[1024], errbuf[1024];
  ptpgp_err_t err;
  ptpgp_signature_subpacket_header_t *subpacket_header;

  UNUSED(p);

  switch (packet->tag) {
  case PTPGP_TAG_PUBLIC_KEY_ENCRYPTED_SESSION_KEY:
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
        "  version = %d, algorithm = \"%s\" (%d), key_id = 0x%s\n",
        packet->packet.t1.version,

        algo_to_s(
          PTPGP_ALGORITHM_TYPE_PUBLIC_KEY,
          packet->packet.t1.algorithm,
          buf, sizeof(buf)
        ),

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

    break;
  case PTPGP_TAG_SIGNATURE:
    switch (t) {
    case PTPGP_PACKET_PARSER_TOKEN_PACKET_START:
      switch (packet->packet.t2.version) {
      case 3:
        /* convert key id to hex */
        memset(key_id, 0, sizeof(key_id));
        err = ptpgp_to_hex(
          packet->packet.t2.versions.v3.signer_key_id,
          8, key_id, sizeof(key_id)
        );

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

        do {
          char hash_buf[256];

          /* dump packet contents */
          printf(
            "  version = %d, "
            "signature_type = %d, "
            "public_key_algorithm = \"%s\" (%d), "
            "hash_algorithm = \"%s\" (%d), "
            "key_id = 0x%s\n",

            packet->packet.t2.version,
            packet->packet.t2.versions.v3.signature_type,

            algo_to_s(
              PTPGP_ALGORITHM_TYPE_PUBLIC_KEY,
              packet->packet.t2.versions.v3.public_key_algorithm,
              buf, sizeof(buf)
            ),
            packet->packet.t2.versions.v3.public_key_algorithm,

            algo_to_s(
              PTPGP_ALGORITHM_TYPE_HASH,
              packet->packet.t2.versions.v3.hash_algorithm,
              hash_buf, sizeof(hash_buf)
            ),
            packet->packet.t2.versions.v3.hash_algorithm,

            key_id
          );
        } while (0);

        break;
      case 4:
        break;
      default:
        /* ignore unknown versions */
        return PTPGP_OK;
      }

      break;
    case PTPGP_PACKET_PARSER_TOKEN_MPI_START:
      printf("  mpi: num_bits = %d\n", (int) *((size_t*) data));

      break;
    case PTPGP_PACKET_PARSER_TOKEN_SIGNATURE_SUBPACKET_START:
      /* get subpacket header */
      subpacket_header = (ptpgp_signature_subpacket_header_t*) data;

      /* get signature subpacket type */
      err = ptpgp_signature_subpacket_type_to_s(
        subpacket_header->type,
        buf, sizeof(buf), NULL
      );

      /* check for error */
      if (err != PTPGP_OK) {
        /* get ptpgp error */
        ptpgp_strerror(err, errbuf, sizeof(errbuf), NULL);

        /* print error */
        fprintf(
          stderr,
          "[FATAL] Couldn't get signature subpacket type name: %s (#%d)\n",
          errbuf, err
        );

        /* exit with error */
        exit(EXIT_FAILURE);
      }

      /* dump subpacket information */
      printf(
        "  subpacket%s: type = %s (#%d), size = %d\n",
        (subpacket_header->critical) ? " (CRITICAL)" : "",
        buf,
        subpacket_header->type,
        (int) subpacket_header->size
      );

      /* init signature subpacket parser */
      err = ptpgp_signature_subpacket_parser_init(
        &sspp,
        subpacket_header->type,
        dump_signature_subpacket_cb,
        NULL
      );

      /* check for error */
      if (err != PTPGP_OK) {
        /* get ptpgp error */
        ptpgp_strerror(err, errbuf, sizeof(errbuf), NULL);

        /* print error */
        fprintf(
          stderr,
          "[FATAL] Couldn't init signature subpacket parser: %s (#%d)\n",
          errbuf, err
        );

        /* exit with error */
        exit(EXIT_FAILURE);
      }

      break;
    case PTPGP_PACKET_PARSER_TOKEN_SIGNATURE_SUBPACKET_BODY:
      err = ptpgp_signature_subpacket_parser_push(&sspp, data, data_len);

      /* check for error */
      if (err != PTPGP_OK) {
        /* get ptpgp error */
        ptpgp_strerror(err, errbuf, sizeof(errbuf), NULL);

        /* print error */
        fprintf(
          stderr,
          "[FATAL] Couldn't push data to signature subpacket parser: %s (#%d)\n",
          errbuf, err
        );

        /* exit with error */
        exit(EXIT_FAILURE);
      }

      break;
    case PTPGP_PACKET_PARSER_TOKEN_SIGNATURE_SUBPACKET_END:
      err = ptpgp_signature_subpacket_parser_done(&sspp);

      /* check for error */
      if (err != PTPGP_OK) {
        /* get ptpgp error */
        ptpgp_strerror(err, errbuf, sizeof(errbuf), NULL);

        /* print error */
        fprintf(
          stderr,
          "[FATAL] Couldn't finish signature subpacket parser: %s (#%d)\n",
          errbuf, err
        );

        /* exit with error */
        exit(EXIT_FAILURE);
      }

      break;
    default:
      /* ignore unknown tokens */
      return PTPGP_OK;
    }

    break;
  default:
    /* ignore unknown tags */
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
