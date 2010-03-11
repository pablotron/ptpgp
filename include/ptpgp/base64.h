#define PTPGP_BASE64_SRC_BUF_SIZE     4
#define PTPGP_BASE64_OUT_BUF_SIZE     1024

typedef struct ptpgp_base64_t_ ptpgp_base64_t;

typedef ptpgp_err_t (*ptpgp_base64_cb_t)(ptpgp_base64_t *, u8 *, size_t);

struct ptpgp_base64_t_ {
  ptpgp_err_t last_err;

  uint32_t flags, 
           line_len;

  u8 src_buf[PTPGP_BASE64_SRC_BUF_SIZE];
  size_t src_buf_len;

  u8 out_buf[PTPGP_BASE64_OUT_BUF_SIZE];
  size_t out_buf_len;

  ptpgp_base64_cb_t cb;
  void *user_data;
};

ptpgp_err_t
ptpgp_base64_init(ptpgp_base64_t *p,
                  bool encode,
                  ptpgp_base64_cb_t cb,
                  void *user_data);

ptpgp_err_t
ptpgp_base64_push(ptpgp_base64_t *p,
                  u8 *src,
                  size_t src_len);

ptpgp_err_t
ptpgp_base64_done(ptpgp_base64_t *p);

size_t 
ptpgp_base64_space_needed(bool encode, 
                          size_t num_bytes);
ptpgp_err_t
ptpgp_base64_once(bool encode,
                  u8 *src,
                  size_t src_len,
                  u8 *dst,
                  size_t dst_len,
                  size_t *out_len);

#define ptpgp_base64_encode(s, sl, d, dl, o) \
  ptpgp_base64_once(1, (s), (sl), (d), (dl), (o))

#define ptpgp_base64_decode(s, sl, d, dl, o) \
  ptpgp_base64_once(0, (s), (sl), (d), (dl), (o))
