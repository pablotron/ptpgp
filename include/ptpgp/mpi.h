#define PTPGP_MPI_BUF_SIZE 8192

typedef struct {
  size_t num_bits;
  u8 data[PTPGP_MPI_BUF_SIZE];
} ptpgp_mpi_t;
