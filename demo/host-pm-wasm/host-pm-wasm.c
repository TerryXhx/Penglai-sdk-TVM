#include "penglai-enclave.h"
#include <stdlib.h>
#include <pthread.h>
#include <time.h>

#define PENGLAI_WASM_VM_MR_SEC_ADDR 0xfffffff000000000UL
#define PENGLAI_WASM_VM_MR_SEC_SIZE 0x1000UL
#define PENGLAI_WASM_SEC_ADDR       0xfffffff000001000UL
#define PENGLAI_WASM_SEC_SIZE       0x5000UL

struct args
{
  void* in;
  int i;
};

typedef struct _penglai_wasm_t {
    unsigned long size;
    unsigned char wasm_blob[];
} penglai_wasm_t;

void printHex(unsigned int *c, int n)
{
	int i;
	for (i = 0; i < n; i++)
    printf("0x%x\n", c[i]);
}

void printHash(unsigned char *hash)
{
  int i;
  for (i = 0; i < HASH_SIZE; i++)
    printf("%02x", hash[i]);
  printf("\n");
}

unsigned long wasm_vm_mr[4096] = {
  PENGLAI_WASM_SEC_ADDR,
  0x0000000000a51023,
  0x0000000000000000,
  0xfc12191ec405a817,
  0xffff29ef731c24e6,
  0x000000197fd657a8,
  0x000001cc33339f9f,
  0xf84f2e2c076c7306,
  0xfbd07b75be232ecd,
  0x0003e9fb1a7540d6,
  0x00013a858d6b5191,
  0x0000000000000000,
  0x0000000000000000,
  0x0000000000000000,
  0x0000000000000000,
  0x0000000000000000,
  0x0000000000000000,
  0x0000000000000000,
  0x0000000000000000
};

unsigned char wasm_file_buf[PENGLAI_WASM_SEC_SIZE] = {
  0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00, 0x01, 0x08, 0x02, 0x60,
  0x00, 0x01, 0x7f, 0x60, 0x00, 0x00, 0x02, 0x2a, 0x01, 0x16, 0x77, 0x61,
  0x73, 0x69, 0x5f, 0x73, 0x6e, 0x61, 0x70, 0x73, 0x68, 0x6f, 0x74, 0x5f,
  0x70, 0x72, 0x65, 0x76, 0x69, 0x65, 0x77, 0x31, 0x0f, 0x67, 0x65, 0x74,
  0x5f, 0x6d, 0x65, 0x61, 0x73, 0x75, 0x72, 0x65, 0x6d, 0x65, 0x6e, 0x74,
  0x00, 0x00, 0x03, 0x02, 0x01, 0x01, 0x05, 0x03, 0x01, 0x00, 0x01, 0x07,
  0x13, 0x02, 0x06, 0x6d, 0x65, 0x6d, 0x6f, 0x72, 0x79, 0x02, 0x00, 0x06,
  0x5f, 0x73, 0x74, 0x61, 0x72, 0x74, 0x00, 0x01, 0x0a, 0x07, 0x01, 0x05,
  0x00, 0x10, 0x00, 0x0f, 0x0b
};
unsigned int wasm_file_buf_len = 101;

void* create_mapping_enclave(void* in)
{
  int ret = 0, result = 0;

  struct PLenclave* enclave = malloc(sizeof(struct PLenclave));
  struct enclave_args* params = malloc(sizeof(struct enclave_args));
  PLenclave_init(enclave);
  enclave_args_init(params);

  struct elf_args *enclaveFile = (struct elf_args *)in;

  params->wasm_vm_mr_ptr = (unsigned long) wasm_vm_mr;
  params->wasm_vm_mr_size = PENGLAI_WASM_VM_MR_SEC_SIZE;

  penglai_wasm_t *wasm_blob_buf = (penglai_wasm_t *)malloc(PENGLAI_WASM_SEC_SIZE);
  wasm_blob_buf->size = wasm_file_buf_len;
  memcpy(wasm_blob_buf->wasm_blob, wasm_file_buf, wasm_file_buf_len);
  params->wasm_ptr = (unsigned long)wasm_blob_buf;
  params->wasm_size = PENGLAI_WASM_SEC_SIZE;

  char str_num[15];
  sprintf(str_num, "mappingEnclave");
  strcpy(params->name, str_num);

  if(PLenclave_create(enclave, enclaveFile, params) < 0)
  {
    printf("host:mapping enclave: failed to create enclave\n");
  }
  else
  {
    printf("%s's measurement:\n", str_num);
    PLenclave_attest(enclave, 0);
    printHash(enclave->attest_param.report.enclave.hash);

    while (result = PLenclave_run(enclave))
    {
      switch (result)
      {
        case RETURN_USER_RELAY_PAGE:
          PLenclave_set_rerun_arg(enclave, RETURN_USER_RELAY_PAGE);
          break;
        default:
        {
          printf("[ERROR] host: result %d val is wrong!\n", result);
          goto free_enclave;
        }
      }
    }
  }
  PLenclave_destruct(enclave);
  printf("host: PLenclave run is finish \n");

free_enclave:
  free(enclave);
  free(params);
}

void* create_vm_enclave(void* in)
{
  int ret = 0, result = 0;

  struct PLenclave* enclave = malloc(sizeof(struct PLenclave));
  struct enclave_args* params = malloc(sizeof(struct enclave_args));
  PLenclave_init(enclave);
  enclave_args_init(params);

  struct elf_args *enclaveFile = (struct elf_args *)in;

  penglai_wasm_t *wasm_blob_buf = (penglai_wasm_t*)malloc(PENGLAI_WASM_SEC_SIZE);
  wasm_blob_buf->size = wasm_file_buf_len;
  memcpy(wasm_blob_buf->wasm_blob, wasm_file_buf, wasm_file_buf_len);
  params->wasm_ptr = (unsigned long)wasm_blob_buf;
  params->wasm_size = PENGLAI_WASM_SEC_SIZE;

  char str_num[15];
  sprintf(str_num, "vmEnclave");
  strcpy(params->name, str_num);

  if(PLenclave_create(enclave, enclaveFile, params) < 0)
  {
    printf("host:vm enclave: failed to create enclave\n");
  }
  else
  {
    printf("%s's measurement:\n", str_num);
    PLenclave_attest(enclave, 0);
    printHash(enclave->attest_param.report.enclave.hash);

    while (result = PLenclave_run(enclave))
    {
      switch (result)
      {
        case RETURN_USER_RELAY_PAGE:
          PLenclave_set_rerun_arg(enclave, RETURN_USER_RELAY_PAGE);
          break;
        default:
        {
          printf("[ERROR] host: result %d val is wrong!\n", result);
          goto free_enclave;
        }
      }
    }
  }
  PLenclave_destruct(enclave);
  printf("host: PLenclave run is finish \n");

free_enclave:
  free(enclave);
  free(params);
}

int main(int argc, char** argv)
{
  struct elf_args* mappingEnclaveFile = malloc(sizeof(struct elf_args));
  struct elf_args* vmEnclaveFile = malloc(sizeof(struct elf_args));
  char* eappMappingFile = "pm-mapping";
  char* eappVmFile = "wamr";
  elf_args_init(mappingEnclaveFile, eappMappingFile);
  elf_args_init(vmEnclaveFile, eappVmFile);

  if(!elf_valid(mappingEnclaveFile) || !elf_valid(vmEnclaveFile))
  {
    printf("error when initializing enclaveFile\n");
    goto out;
  }

  create_vm_enclave((void*)vmEnclaveFile);
  create_mapping_enclave((void*)mappingEnclaveFile);
out:
  elf_args_destroy(mappingEnclaveFile);
  elf_args_destroy(vmEnclaveFile);
  free(mappingEnclaveFile);
  free(vmEnclaveFile);


  return 0;
}
