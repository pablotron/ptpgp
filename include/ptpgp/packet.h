/* TODO: */
typedef void* ptpgp_signature_subpacket_t;
typedef void* ptpgp_mpi_t;

/* public key encrypted session key packet (tag 1, rfc4880 5.1) */
typedef struct {
  u8 version,
     algorithm,
     key_id[8],
     *session_keys;

  size_t num_session_keys;
} ptpgp_packet_public_key_encrypted_session_key_t;

/* signature packet (tag 2, rfc4880 5.2.2) */
typedef struct {
  u8 version;

  union {
    /* v3 signature packet (rfc4880 5.2.2) */
    struct {
      uint32_t creation_time;

      u8 signature_type,
         signer_key_id[8],
         public_key_algorithm,
         hash_algorithm,
         left16[2];

      ptpgp_mpi_t **mpis;
      size_t num_mpis;
    } v3;

    /* v4 signature packet (rfc480 5.2.3) */
    struct {
      u8 signature_type,
         public_key_algorithm,
         hash_algorithm,
         left16[2];

      /* length of subpacket data (in bytes) */
      ptpgp_signature_subpacket_t  *hashed_subpackets;
      size_t num_hashed_subpackets;

      ptpgp_signature_subpacket_t  *unhashed_subpackets;
      size_t num_unhashed_subpackets;

      ptpgp_mpi_t **mpis;
      size_t num_mpis;
    } v4;
  } versions;
} ptpgp_packet_signature_t;

/* signature packet (tag 3, rfc4880 5.3) */
typedef struct {
  u8                                    version;
  ptpgp_symmetric_key_algorithm_type_t  algorithm;
  ptpgp_s2k_t                           s2k;
  u8                                    *key;
  size_t                                key_len;
} ptpgp_packet_symmetric_key_encrypted_session_key_t;

/* signature packet (tag 4, rfc4880 5.4) */
typedef struct {
  u8                                    version;
  ptpgp_signature_type_t                signature_type;
  ptpgp_hash_algorithm_type_t           hash_algorithm;
  ptpgp_public_key_algorithm_type_t     public_key_algorithm;
  u8                                    key_id[8],
                                        nested;
} ptpgp_packet_one_pass_signature_t;

/* compressed data packet (tag 8, rfc4880 5.6) */
typedef struct {
  ptpgp_compression_algorithm_type_t    compression_algorithm;
  u8                                   *data;
  size_t                                data_len;
} ptpgp_packet_compressed_data_t;

/* symmetrically encrypted data packet (tag 9, rfc4880 5.7) */
typedef struct {
  u8                                   *data;
  size_t                                data_len;
} ptpgp_packet_symmetrically_encrypted_data_t;

/* literal data packet (tag 11, rfc4880 5.9) */
typedef struct {
  u8                                    format;

  u8                                   *file_name;
  size_t                                file_name_len;

  uint32_t                              date;

  u8                                   *data;
  size_t                                data_len;
} ptpgp_packet_literal_data_t;

/* sym encrypted integrity protected data packet (tag 18, rfc4880 5.13) */
typedef struct {
  u8                                    version,
                                       *data;
  size_t                                data_len;
} ptpgp_packet_sym_encrypted_integrity_protected_data_t;

typedef struct {
  ptpgp_tag_t tag;
  u8 *data;
  size_t data_len;
} ptpgp_packet_raw_t;

typedef struct {
  ptpgp_tag_t tag;

  union {
    ptpgp_packet_raw_t                                    raw;
    ptpgp_packet_public_key_encrypted_session_key_t       t1;
    ptpgp_packet_signature_t                              t2;
    ptpgp_packet_symmetric_key_encrypted_session_key_t    t3;
    ptpgp_packet_one_pass_signature_t                     t4;

    /* TODO: pk public/private packets/subpackets */

    ptpgp_packet_compressed_data_t                        t8;
    ptpgp_packet_symmetrically_encrypted_data_t           t9;
    ptpgp_packet_literal_data_t                           t11;
    ptpgp_packet_sym_encrypted_integrity_protected_data_t t18;
  } packet;
} ptpgp_packet_t;
