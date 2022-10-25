#include "eapp.h"
#include "print.h"
#include <stdlib.h>
#include "pm_wasm.h"
#include "sm3.h"

void printHash(unsigned char *hash)
{
	char hex[17] = "0123456789abcdef";
	char tmp[65] = {0};
	int i;
	for (i = 0; i < HASH_SIZE; i++) {
    tmp[i + i] = hex[hash[i] / 16];
	  tmp[i + i + 1] = hex[hash[i] % 16];
	}
  eapp_print("%s\n", tmp);
}

int hello(unsigned long * args)
{
  eapp_print("mapping enclave begin to run...\n");
	unsigned char hash[32] = {0};
  
  eapp_print("mapping enclave derived vm measurement:\n");
  penglai_wasm_derive_measurement(hash, 0);
  printHash(hash);

  EAPP_RETURN(0);
}

int EAPP_ENTRY main(){
  unsigned long * args;
  EAPP_RESERVE_REG;
  hello(args);
}
