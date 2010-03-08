typedef struct ptpgp_packet_parser_t_ ptpgp_packet_parser_t;

typedef ptpgp_err_t (*ptpgp_packet_parser_cb_t)(ptpgp_packet_parser_t *,
                                                char *,
                                                size_t);

struct ptpgp_packet_parser_t_ {
  ptpgp_packet_parser_cb_t cb;
  void *user_data;
};
