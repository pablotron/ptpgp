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

typedef struct {
  ptpgp_tag_t tag;
  u8 *data;
  size_t data_len;
} ptpgp_packet_raw_t;

typedef struct {
  ptpgp_tag_t tag;

  union {
    ptpgp_packet_raw_t raw;
    ptpgp_packet_public_key_encrypted_session_key_t t1;
    ptpgp_packet_signature_t                        t2;
  } packet;
} ptpgp_packet_t;
