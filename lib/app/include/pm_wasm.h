#ifndef _PM_WASM_H
#define _PM_WASM_H
#include "sm3.h"

#define PENGLAI_WASM_VM_MR_SEC_ADDR 0xfffffff000000000UL
#define PENGLAI_WASM_VM_MR_SEC_SIZE 0x1000UL
#define PENGLAI_WASM_SEC_ADDR       0xfffffff000001000UL
#define PENGLAI_WASM_SEC_SIZE       0x5000UL

#define PENGLAI_SM3_SIZE (sizeof(penglai_wasm_vm_mr_t) - sizeof(unsigned long))

#define DATA_BLOCK_SIZE 64
#define SIZE_NAMED_VALUE 8
#define SE_PAGE_SIZE 0x1000

typedef struct _penglai_wasm_t {
    unsigned long size;
    unsigned char wasm_blob[];
} penglai_wasm_t;

typedef struct _penglai_wasm_vm_mr_t {
    unsigned long offset;       /*!< offset of penglai_wasm section */
    unsigned long total[2];     /*!< number of bytes processed      */
    unsigned long state[8];     /*!< intermediate digest state      */
    unsigned char buffer[64];   /*!< data block being processed     */
} penglai_wasm_vm_mr_t;

unsigned char* penglai_get_wasm_sec_buf_addr();

unsigned char* penglai_get_wasm_vm_mr_sec_buf_addr();

// set wasm_blob as a parameter instead of get it from memory
void penglai_wasm_derive_measurement(unsigned char *hash, unsigned long nonce);

void penglai_wasm_get_hash(unsigned char *wasm_blob, unsigned long wasm_blob_size, unsigned char *hash);

#define MAX_FUNC_NAME_LEN 32
#define MAX_FUNC_ARGC 8
#define MAX_FUNC_ARG_LEN 16

typedef struct _penglai_vm_params_t {
    char func_name[MAX_FUNC_NAME_LEN];
    unsigned long stack_size;
    unsigned long heap_size;
    int log_verbose_level;
    bool is_repl_mode;
    bool alloc_with_pool;
    int max_thread_num;
    unsigned long argc;
    // uint64_t args[MAX_FUNC_ARGC];
    char args[MAX_FUNC_ARGC][MAX_FUNC_ARG_LEN];
} penglai_vm_params_t;

#endif /* _MAGE_H */