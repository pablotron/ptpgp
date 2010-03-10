ptpgp_err_t
ptpgp_to_hex(u8 *src, size_t src_len, u8 *dst, size_t dst_len);

void
ptpgp_warn(ptpgp_err_t, char *, ...);

void
ptpgp_die(ptpgp_err_t, char *, ...);
