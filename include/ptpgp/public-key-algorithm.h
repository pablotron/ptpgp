typedef struct {
  ptpgp_public_key_algorithm_type_t algorithm;
  size_t                            num_public_key_packet_mpis,
  size_t                            num_private_key_packet_mpis;
} ptpgp_public_key_algorithm_info_t;

ptpgp_err_t
ptpgp_public_key_algorithm_info(ptpgp_public_key_algorithm_type_t,
                                ptpgp_public_key_algorithm_info_t **);
