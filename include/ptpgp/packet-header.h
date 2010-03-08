#define PTPGP_PACKET_FLAG_NEW_PACKET     (1 << 0)
#define PTPGP_PACKET_FLAG_INDETERMINITE  (1 << 1)
#define PTPGP_PACKET_FLAG_PARTIAL        (1 << 2)

typedef struct {
  uint32_t flags;
  ptpgp_tag_t content_tag;
  uint64_t length;
} ptpgp_packet_header_t;
