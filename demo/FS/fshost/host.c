#include "penglai-enclave.h"
#include <stdlib.h>
#include <string.h>
int main(int argc, char**argv){
  if(argc != 3){
    printf("Usage:\n ./fshost client filesystem\n");
      exit(0);
  }
  if(argc == 3){
    struct elf_args *server_enclaveFile = NULL;
    struct PLenclave *server_enclave = NULL;
    struct enclave_args *server_params = NULL;
    struct elf_args *caller_enclaveFile = NULL;
    struct PLenclave *caller_enclave = NULL;
    struct enclave_args *caller_params = NULL;
    if(argc < 3){
        printf("Usage: ./fshost client server");
        exit(0);
    }
server:
    server_enclaveFile = malloc(sizeof(struct elf_args));
    char* server_eappfile = argv[2];
    elf_args_init(server_enclaveFile,server_eappfile);
    if(!elf_valid(server_enclaveFile)){
        printf("host: error when initializing server_enclaveFile");
        goto out1;
    }
    server_enclave = malloc(sizeof(struct PLenclave));
    PLenclave_init(server_enclave);
    server_params = malloc(sizeof(struct enclave_args));
    enclave_args_init(server_params);
    strcpy(server_params->name,"filesystem");
    server_params->type = SERVER_ENCLAVE;

    if(PLenclave_create(server_enclave,server_enclaveFile,server_params) < 0){
        printf("host: failed to create server_enclave\n");
        goto out1;
    }

    caller_enclaveFile = malloc(sizeof(struct elf_args));
    char *caller_eappfile = argv[1];
    elf_args_init(caller_enclaveFile, caller_eappfile);
  
    if(!elf_valid(caller_enclaveFile))
    {
      printf("host:error when initializing caller_enclaveFile\n");
      goto out1;
    }

    caller_enclave = malloc(sizeof(struct PLenclave));
    PLenclave_init(caller_enclave);
    caller_params = malloc(sizeof(struct enclave_args));
    enclave_args_init(caller_params);

    if(PLenclave_create(caller_enclave, caller_enclaveFile, caller_params) < 0 )
    {
      printf("host: failed to create caller_enclave\n");
      goto out1;
    }
    PLenclave_run(caller_enclave);

out1:
  if(server_enclaveFile)
    {
      elf_args_destroy(server_enclaveFile);
      free(server_enclaveFile);
    }
    if(server_enclave)
    {
      PLenclave_destroy(server_enclave);
      free(server_enclave);
    }
    if(server_params)
    {
      free(server_params);
    }
    if(caller_enclaveFile)
    {
      elf_args_destroy(caller_enclaveFile);
      free(caller_enclaveFile);
    }
    if(caller_enclave)
    {
      free(caller_enclave);
    }
    if(caller_params)
    {
      free(caller_params);
    }
    return 0;
  }
}