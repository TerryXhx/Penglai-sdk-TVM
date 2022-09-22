#include "attest.h"
#include "pm_wasm.h"
#include "sm3.h"
#include <string.h>
#include "wolfcrypt/sha256.h"

void printHashCtx(unsigned long *hash)
{
  int i;
  eapp_print("intermediate hash ctx:\n");
  for (i = 0; i < 18; i++) {
    eapp_print("0x%016lx,\n", (*hash));
    ++hash;
  }
}

void measure_sim(struct sm3_context *hash_ctx, void* hash, unsigned long nonce)
{
    unsigned long curr_va = PENGLAI_WASM_SEC_ADDR;
    unsigned char pte = 0;
    int offset;

    sm3_update(hash_ctx, (unsigned char*)&curr_va, sizeof(unsigned long));
    sm3_update(hash_ctx, &pte, 1);
    sm3_update(hash_ctx, (void*)curr_va, 0x1000);
    curr_va += 0x1000;

    for (offset = 0x1000; offset < PENGLAI_WASM_SEC_SIZE; offset += 0x1000, curr_va += 0x1000)
        sm3_update(hash_ctx, (void*)curr_va, 0x1000);

    sm3_update(hash_ctx, (unsigned char*)(&nonce), sizeof(unsigned long));
    sm3_final(hash_ctx, hash);
}

unsigned char* penglai_get_wasm_sec_buf_addr()
{
    return (unsigned char*)PENGLAI_WASM_SEC_ADDR;
}

unsigned char* penglai_get_wasm_vm_mr_sec_buf_addr()
{
    return (unsigned char*)PENGLAI_WASM_VM_MR_SEC_ADDR;
}

void penglai_wasm_derive_measurement(unsigned char *hash, unsigned long nonce)
{
    penglai_wasm_vm_mr_t* wasm_vm_mr = (penglai_wasm_vm_mr_t*)penglai_get_wasm_vm_mr_sec_buf_addr();
    struct sm3_context hash_ctx;

    memcpy(&hash_ctx, (void*)(wasm_vm_mr->total), PENGLAI_SM3_SIZE);

    measure_sim(&hash_ctx, hash, 0);

    sm3_init(&hash_ctx);

    sm3_update(&hash_ctx, (unsigned char*)(hash), HASH_SIZE);

    sm3_update(&hash_ctx, (unsigned char*)(&nonce), sizeof(unsigned long));

    sm3_final(&hash_ctx, hash);
}

// TODO: Implement using sha256 algorithm
void penglai_wasm_get_hash(unsigned char *wasm_blob, unsigned long wasm_blob_size, unsigned char *hash)
{

}