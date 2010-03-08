#define PTPGP_BASE64_BUFFER_SIZE     1024

typedef struct ptpgp_base64_t_ ptpgp_base64_t;

typedef ptpgp_err_t (*ptpgp_base64_cb_t)(ptpgp_base64_t *, char *, size_t);

struct ptpgp_base64_t_ {
  ptpgp_err_t last_err;

  uint32_t flags;

  char src_buf[4];
  size_t src_buf_len;

  char out_buf[PTPGP_BASE64_BUFFER_SIZE];
  size_t out_buf_len;

  ptpgp_base64_cb_t cb;
  void *user_data;
};


ptpgp_err_t
ptpgp_base64_init(ptpgp_base64_t *p,
                  char encode,
                  ptpgp_base64_cb_t cb,
                  void *user_data);

ptpgp_err_t
ptpgp_base64_push(ptpgp_base64_t *p,
                  char *src,
                  size_t src_len);

ptpgp_err_t
ptpgp_base64_done(ptpgp_base64_t *p);
