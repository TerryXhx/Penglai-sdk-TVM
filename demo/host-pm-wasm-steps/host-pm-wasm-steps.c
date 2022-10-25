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

#define MAX_FUNC_NAME_LEN 32
#define MAX_FUNC_ARGC 8
#define MAX_FUNC_ARG_LEN 16

typedef enum EcallCmd {
    CMD_INIT_RUNTIME = 0,     /* wasm_runtime_init/full_init() */
    CMD_LOAD_MODULE,          /* wasm_runtime_load() */
    CMD_INSTANTIATE_MODULE,   /* wasm_runtime_instantiate() */
    CMD_LOOKUP_FUNCTION,      /* wasm_runtime_lookup_function() */
    CMD_CREATE_EXEC_ENV,      /* wasm_runtime_create_exec_env() */
    CMD_CALL_WASM,            /* wasm_runtime_call_wasm */
    CMD_EXEC_APP_FUNC,        /* wasm_application_execute_func() */
    CMD_EXEC_APP_MAIN,        /* wasm_application_execute_main() */
    CMD_GET_EXCEPTION,        /* wasm_runtime_get_exception() */
    CMD_DEINSTANTIATE_MODULE, /* wasm_runtime_deinstantiate() */
    CMD_UNLOAD_MODULE,        /* wasm_runtime_unload() */
    CMD_DESTROY_RUNTIME,      /* wasm_runtime_destroy() */
    CMD_SET_WASI_ARGS,        /* wasm_runtime_set_wasi_args() */
    CMD_SET_LOG_LEVEL,        /* bh_log_set_verbose_level() */
    CMD_GET_VERSION,          /* wasm_runtime_get_version() */
    CMD_EXIT,
} EcallCmd;

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
    unsigned ecall_cmd;
    uint8_t *wasm_file_buf;
    uint32_t wasm_file_size;
    void* wasm_module;
    void* wasm_module_inst;
} penglai_vm_params_t;

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

static int
print_help()
{
  printf("Usage: iwasm [-options] [args...]\n");
  printf("options:\n");
  printf("  -f|--function name     Specify a function name of the module to run rather\n"
          "                         than main\n");
  printf("  -v=n                   Set log verbose level (0 to 5, default is 2) larger\n"
          "                         level with more log\n");
  printf("  --stack-size=n         Set maximum stack size in bytes, default is 16 KB\n");
  printf("  --heap-size=n          Set maximum heap size in bytes, default is 16 KB\n");
  // printf("  --repl                 Start a very simple REPL (read-eval-print-loop) mode\n"
  //        "                         that runs commands in the form of `FUNC ARG...`\n");
  // printf("  --env=<env>            Pass wasi environment variables with \"key=value\"\n");
  // printf("                         to the program, for example:\n");
  // printf("                           --env=\"key1=value1\" --env=\"key2=value2\"\n");
  // printf("  --dir=<dir>            Grant wasi access to the given host directories\n");
  // printf("                         to the program, for example:\n");
  // printf("                           --dir=<dir1> --dir=<dir2>\n");
  // printf("  --addr-pool=           Grant wasi access to the given network addresses in\n");
  // printf("                         CIRD notation to the program, seperated with ',',\n");
  // printf("                         for example:\n");
  // printf("                           --addr-pool=1.2.3.4/15,2.3.4.5/16\n");
  printf("  --max-threads=n        Set maximum thread number per cluster, default is 4\n");
  return 1;
}

unsigned long wasm_vm_mr[4096] = {
  PENGLAI_WASM_SEC_ADDR,
  0x0000000000a53023,
  0x0000000000000000,
  0xfa69f8bb35c8e7f8,
  0xffff367f0268a040,
  0x000001d57c41ccfc,
  0x000001e9381b9fa1,
  0xffe567f120cfb967,
  0xff7aeb3fe2f11551,
  0x0006bdfb2eb2cc67,
  0x0000d27e401b5d39,
  0x0000000000000000,
  0x0000000000000000,
  0x0000000000000000,
  0x0000000000000000,
  0x0000000000000000,
  0x0000000000000000,
  0x0000000000000000,
  0x0000000000000000
};

// unsigned char wasm_file_buf[PENGLAI_WASM_SEC_SIZE] = {
//   0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00, 0x01, 0x08, 0x02, 0x60,
//   0x00, 0x01, 0x7f, 0x60, 0x00, 0x00, 0x02, 0x2a, 0x01, 0x16, 0x77, 0x61,
//   0x73, 0x69, 0x5f, 0x73, 0x6e, 0x61, 0x70, 0x73, 0x68, 0x6f, 0x74, 0x5f,
//   0x70, 0x72, 0x65, 0x76, 0x69, 0x65, 0x77, 0x31, 0x0f, 0x67, 0x65, 0x74,
//   0x5f, 0x6d, 0x65, 0x61, 0x73, 0x75, 0x72, 0x65, 0x6d, 0x65, 0x6e, 0x74,
//   0x00, 0x00, 0x03, 0x02, 0x01, 0x01, 0x05, 0x03, 0x01, 0x00, 0x01, 0x07,
//   0x13, 0x02, 0x06, 0x6d, 0x65, 0x6d, 0x6f, 0x72, 0x79, 0x02, 0x00, 0x06,
//   0x5f, 0x73, 0x74, 0x61, 0x72, 0x74, 0x00, 0x01, 0x0a, 0x07, 0x01, 0x05,
//   0x00, 0x10, 0x00, 0x0f, 0x0b
// };
// unsigned int wasm_file_buf_len = 101;

unsigned char wasm_file_buf[PENGLAI_WASM_SEC_SIZE] = {
  0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00, 0x01, 0x10, 0x03, 0x60,
  0x02, 0x7f, 0x7f, 0x01, 0x7f, 0x60, 0x01, 0x7f, 0x01, 0x7f, 0x60, 0x00,
  0x01, 0x7f, 0x02, 0x0e, 0x01, 0x03, 0x65, 0x6e, 0x76, 0x06, 0x70, 0x72,
  0x69, 0x6e, 0x74, 0x66, 0x00, 0x00, 0x03, 0x04, 0x03, 0x01, 0x02, 0x00,
  0x04, 0x05, 0x01, 0x70, 0x01, 0x01, 0x01, 0x05, 0x03, 0x01, 0x00, 0x01,
  0x06, 0x07, 0x01, 0x7f, 0x01, 0x41, 0xe0, 0x28, 0x0b, 0x07, 0x18, 0x03,
  0x06, 0x6d, 0x65, 0x6d, 0x6f, 0x72, 0x79, 0x02, 0x00, 0x04, 0x6d, 0x75,
  0x6c, 0x37, 0x00, 0x01, 0x04, 0x6d, 0x61, 0x69, 0x6e, 0x00, 0x03, 0x0a,
  0xa8, 0x02, 0x03, 0xb9, 0x01, 0x01, 0x10, 0x7f, 0x23, 0x80, 0x80, 0x80,
  0x80, 0x00, 0x21, 0x01, 0x41, 0x20, 0x21, 0x02, 0x20, 0x01, 0x20, 0x02,
  0x6b, 0x21, 0x03, 0x20, 0x03, 0x24, 0x80, 0x80, 0x80, 0x80, 0x00, 0x20,
  0x03, 0x20, 0x00, 0x36, 0x02, 0x1c, 0x41, 0x80, 0x88, 0x80, 0x80, 0x00,
  0x21, 0x04, 0x20, 0x03, 0x20, 0x04, 0x36, 0x02, 0x00, 0x41, 0x85, 0x88,
  0x80, 0x80, 0x00, 0x21, 0x05, 0x20, 0x05, 0x20, 0x03, 0x10, 0x80, 0x80,
  0x80, 0x80, 0x00, 0x1a, 0x20, 0x03, 0x28, 0x02, 0x1c, 0x21, 0x06, 0x41,
  0x07, 0x21, 0x07, 0x20, 0x06, 0x20, 0x07, 0x6c, 0x21, 0x08, 0x20, 0x03,
  0x20, 0x08, 0x36, 0x02, 0x1c, 0x20, 0x03, 0x28, 0x02, 0x1c, 0x21, 0x09,
  0x20, 0x03, 0x20, 0x09, 0x36, 0x02, 0x14, 0x41, 0x80, 0x88, 0x80, 0x80,
  0x00, 0x21, 0x0a, 0x20, 0x03, 0x20, 0x0a, 0x36, 0x02, 0x10, 0x41, 0xc3,
  0x88, 0x80, 0x80, 0x00, 0x21, 0x0b, 0x41, 0x10, 0x21, 0x0c, 0x20, 0x03,
  0x20, 0x0c, 0x6a, 0x21, 0x0d, 0x20, 0x0b, 0x20, 0x0d, 0x10, 0x80, 0x80,
  0x80, 0x80, 0x00, 0x1a, 0x20, 0x03, 0x28, 0x02, 0x1c, 0x21, 0x0e, 0x41,
  0x20, 0x21, 0x0f, 0x20, 0x03, 0x20, 0x0f, 0x6a, 0x21, 0x10, 0x20, 0x10,
  0x24, 0x80, 0x80, 0x80, 0x80, 0x00, 0x20, 0x0e, 0x0f, 0x0b, 0x5b, 0x01,
  0x09, 0x7f, 0x23, 0x80, 0x80, 0x80, 0x80, 0x00, 0x21, 0x00, 0x41, 0x10,
  0x21, 0x01, 0x20, 0x00, 0x20, 0x01, 0x6b, 0x21, 0x02, 0x20, 0x02, 0x24,
  0x80, 0x80, 0x80, 0x80, 0x00, 0x41, 0x00, 0x21, 0x03, 0x20, 0x02, 0x20,
  0x03, 0x36, 0x02, 0x0c, 0x41, 0xa5, 0x88, 0x80, 0x80, 0x00, 0x21, 0x04,
  0x41, 0x00, 0x21, 0x05, 0x20, 0x04, 0x20, 0x05, 0x10, 0x80, 0x80, 0x80,
  0x80, 0x00, 0x1a, 0x41, 0x00, 0x21, 0x06, 0x41, 0x10, 0x21, 0x07, 0x20,
  0x02, 0x20, 0x07, 0x6a, 0x21, 0x08, 0x20, 0x08, 0x24, 0x80, 0x80, 0x80,
  0x80, 0x00, 0x20, 0x06, 0x0f, 0x0b, 0x0f, 0x01, 0x01, 0x7f, 0x10, 0x82,
  0x80, 0x80, 0x80, 0x00, 0x21, 0x02, 0x20, 0x02, 0x0f, 0x0b, 0x0b, 0x5d,
  0x01, 0x00, 0x41, 0x80, 0x08, 0x0b, 0x56, 0x6d, 0x75, 0x6c, 0x37, 0x00,
  0x63, 0x61, 0x6c, 0x6c, 0x69, 0x6e, 0x67, 0x20, 0x69, 0x6e, 0x74, 0x6f,
  0x20, 0x57, 0x41, 0x53, 0x4d, 0x20, 0x66, 0x75, 0x6e, 0x63, 0x74, 0x69,
  0x6f, 0x6e, 0x3a, 0x20, 0x25, 0x73, 0x2c, 0x00, 0x48, 0x65, 0x6c, 0x6c,
  0x6f, 0x20, 0x77, 0x6f, 0x72, 0x6c, 0x64, 0x2c, 0x20, 0x49, 0x27, 0x6d,
  0x20, 0x61, 0x20, 0x57, 0x41, 0x53, 0x4d, 0x20, 0x61, 0x70, 0x70, 0x21,
  0x0a, 0x00, 0x20, 0x20, 0x20, 0x20, 0x25, 0x73, 0x20, 0x72, 0x65, 0x74,
  0x75, 0x72, 0x6e, 0x20, 0x25, 0x64, 0x20, 0x0a, 0x00
};
unsigned int wasm_file_buf_len = 489;
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

void 
run_enclave(struct PLenclave* enclave, unsigned long mm_arg_size, int mm_arg_id, void* mm_arg, int argc, char** argv){
    
    /* Process options Begin. */
    char func_name[MAX_FUNC_NAME_LEN] = "\0";
    unsigned long stack_size = 16 * 1024;
    unsigned long heap_size = 16 * 1024;
    int log_verbose_level = 2;
    bool is_repl_mode = false;
    bool alloc_with_pool = true;
    int max_thread_num = 4;
  
    for (argc--, argv++; argc > 0 && argv[0][0] == '-'; argc--, argv++) {
        if (!strcmp(argv[0], "-f") || !strcmp(argv[0], "--function")) {
            argc--, argv++;
            if (argc < 2) {
                print_help();
                return 0;
            }
            strcpy(func_name, argv[0]);
        }
        else if (!strncmp(argv[0], "-v=", 3)) {
            log_verbose_level = atoi(argv[0] + 3);
            if (log_verbose_level < 0 || log_verbose_level > 5)
                return print_help();
        }
        // else if (!strcmp(argv[0], "--repl")) { 
        //   is_repl_mode = true;
        // }
        else if (!strncmp(argv[0], "--stack-size=", 13)) {
            if (argv[0][13] == '\0')
                return print_help();
            stack_size = atoi(argv[0] + 13);
        }
        else if (!strncmp(argv[0], "--heap-size=", 12)) {
            if (argv[0][12] == '\0')
                return print_help();
            heap_size = atoi(argv[0] + 12);
        }
        // else if (!strncmp(argv[0], "--dir=", 6)) {
        //   if (argv[0][6] == '\0')
        //     return print_help();
        //   if (dir_list_size >= sizeof(dir_list) / sizeof(char *)) {
        //     printf("Only allow max dir number %d\n",
        //           (int)(sizeof(dir_list) / sizeof(char *)));
        //     return -1;
        //   }
        //   dir_list[dir_list_size++] = argv[0] + 6;
        // }
        // else if (!strncmp(argv[0], "--env=", 6)) {
        //   char *tmp_env;

        //   if (argv[0][6] == '\0')
        //     return print_help();
        //   if (env_list_size >= sizeof(env_list) / sizeof(char *)) {
        //     printf("Only allow max env number %d\n",
        //       (int)(sizeof(env_list) / sizeof(char *)));
        //     return -1;
        //   }
        //   tmp_env = argv[0] + 6;
        //   if (validate_env_str(tmp_env))
        //     env_list[env_list_size++] = tmp_env;
        //   else {
        //     printf("Wasm parse env string failed: expect \"key=value\", "
        //            "got \"%s\"\n",
        //            tmp_env);
        //     return print_help();
        //   }
        // }
        /* TODO: parse the configuration file via --addr-pool-file */
        // else if (!strncmp(argv[0], "--addr-pool=", strlen("--addr-pool="))) {
        //   /* like: --addr-pool=100.200.244.255/30 */
        //   char *token = NULL;

        //   if ('\0' == argv[0][12])
        //     return print_help();

        //   token = strtok(argv[0] + strlen("--addr-pool="), ",");
        //   while (token) {
        //     if (addr_pool_size >= sizeof(addr_pool) / sizeof(char *)) {
        //       printf("Only allow max address number %d\n",
        //               (int)(sizeof(addr_pool) / sizeof(char *)));
        //       return -1;
        //     }

        //     addr_pool[addr_pool_size++] = token;
        //     token = strtok(NULL, ";");
        //   }
        // }
        else if (!strncmp(argv[0], "--max-threads=", 14)) {
            if (argv[0][14] == '\0')
                return print_help();
            max_thread_num = atoi(argv[0] + 14);
        }
        else
            return print_help();
    }


    penglai_vm_params_t vm_params;
    strcpy(vm_params.func_name, func_name);
    vm_params.stack_size = stack_size;
    vm_params.heap_size = heap_size;
    vm_params.log_verbose_level = log_verbose_level;
    vm_params.is_repl_mode = is_repl_mode;
    vm_params.argc = argc;

    for (int i = 0; i < argc; ++i)
        strcpy(vm_params.args[i], argv[i]);
    /* Process options End. */

    int result = PLenclave_run(enclave);
    if(result != RETURN_USER_RELAY_PAGE){
        printf("[ERROR] host: result %d val is wrong!\n", result);
        return;
    }

    ///**********init**************
    vm_params.ecall_cmd = CMD_INIT_RUNTIME;
    vm_params.alloc_with_pool = alloc_with_pool;
    vm_params.max_thread_num = max_thread_num;
    memcpy(mm_arg, &vm_params, sizeof(vm_params));
    if(mm_arg_id > 0 && mm_arg)
        PLenclave_set_mem_arg(enclave, mm_arg_id, 0, mm_arg_size);
    PLenclave_set_rerun_arg(enclave, RETURN_USER_RELAY_PAGE);

    result = PLenclave_run(enclave);
    if(result != RETURN_USER_RELAY_PAGE) return;

    ///*************load module***************
    vm_params.ecall_cmd = CMD_LOAD_MODULE;
    memcpy(mm_arg, &vm_params, sizeof(vm_params));
    if(mm_arg_id > 0 && mm_arg)
        PLenclave_set_mem_arg(enclave, mm_arg_id, 0, mm_arg_size);
    PLenclave_set_rerun_arg(enclave, RETURN_USER_RELAY_PAGE);
    
    result = PLenclave_run(enclave);
    if(result != RETURN_USER_RELAY_PAGE) return;

    
    ///*************instantiate module**********
    vm_params.ecall_cmd = CMD_INSTANTIATE_MODULE;
    memcpy(mm_arg, &vm_params, sizeof(vm_params));
    if(mm_arg_id > 0 && mm_arg)
        PLenclave_set_mem_arg(enclave, mm_arg_id, 0, mm_arg_size);
    PLenclave_set_rerun_arg(enclave, RETURN_USER_RELAY_PAGE);
    
    result = PLenclave_run(enclave);
    if(result != RETURN_USER_RELAY_PAGE) return;

    //***************execution*****************
    int func_name_len = strlen(vm_params.func_name);
    if(func_name_len > 0)
        vm_params.ecall_cmd = CMD_EXEC_APP_FUNC;
    else
        vm_params.ecall_cmd = CMD_EXEC_APP_MAIN;
    memcpy(mm_arg, &vm_params, sizeof(vm_params));
    if(mm_arg_id > 0 && mm_arg)
        PLenclave_set_mem_arg(enclave, mm_arg_id, 0, mm_arg_size);
    PLenclave_set_rerun_arg(enclave, RETURN_USER_RELAY_PAGE);
    
    result = PLenclave_run(enclave);
    if(result != RETURN_USER_RELAY_PAGE) return;

    //*********deinstantiate module************
    vm_params.ecall_cmd = CMD_DEINSTANTIATE_MODULE;
    memcpy(mm_arg, &vm_params, sizeof(vm_params));
    if(mm_arg_id > 0 && mm_arg)
        PLenclave_set_mem_arg(enclave, mm_arg_id, 0, mm_arg_size);
    PLenclave_set_rerun_arg(enclave, RETURN_USER_RELAY_PAGE);
    
    result = PLenclave_run(enclave);
    if(result != RETURN_USER_RELAY_PAGE) return;

    //************unload module****************
    vm_params.ecall_cmd = CMD_UNLOAD_MODULE;
    memcpy(mm_arg, &vm_params, sizeof(vm_params));
    if(mm_arg_id > 0 && mm_arg)
        PLenclave_set_mem_arg(enclave, mm_arg_id, 0, mm_arg_size);
    PLenclave_set_rerun_arg(enclave, RETURN_USER_RELAY_PAGE);
    
    result = PLenclave_run(enclave);
    if(result != RETURN_USER_RELAY_PAGE) return;

    //*********destroy runtime environment**********
    vm_params.ecall_cmd = CMD_DESTROY_RUNTIME;
    memcpy(mm_arg, &vm_params, sizeof(vm_params));
    if(mm_arg_id > 0 && mm_arg)
        PLenclave_set_mem_arg(enclave, mm_arg_id, 0, mm_arg_size);
    PLenclave_set_rerun_arg(enclave, RETURN_USER_RELAY_PAGE);

    result = PLenclave_run(enclave);
    if(result != RETURN_USER_RELAY_PAGE) return;

    //*****************exit*******************
    vm_params.ecall_cmd = CMD_EXIT;
    memcpy(mm_arg, &vm_params, sizeof(vm_params));
    if(mm_arg_id > 0 && mm_arg)
        PLenclave_set_mem_arg(enclave, mm_arg_id, 0, mm_arg_size);
    PLenclave_set_rerun_arg(enclave, RETURN_USER_RELAY_PAGE);
    
    result = PLenclave_run(enclave);
    if(result != RETURN_USER_RELAY_PAGE) return;
}

void* create_vm_enclave(void* in, int argc, char** argv)
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

  // Assign the relay/schrodinger page for enclave
  unsigned long mm_arg_size = 0x1000 * 4;
  int mm_arg_id = PLenclave_schrodinger_get(mm_arg_size);
  void* mm_arg = PLenclave_schrodinger_at(mm_arg_id, 0);

  if(PLenclave_create(enclave, enclaveFile, params) < 0)
  {
    printf("host:vm enclave: failed to create enclave\n");
  }
  else
  {
    printf("%s's measurement:\n", str_num);
    PLenclave_attest(enclave, 0);
    printHash(enclave->attest_param.report.enclave.hash);
    if(mm_arg_id > 0 && mm_arg)
      PLenclave_set_mem_arg(enclave, mm_arg_id, 0, mm_arg_size);
    run_enclave(enclave, mm_arg_size, mm_arg_id, mm_arg, argc, argv);
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

  create_vm_enclave((void*)vmEnclaveFile, argc, argv);
  create_mapping_enclave((void*)mappingEnclaveFile);
out:
  elf_args_destroy(mappingEnclaveFile);
  elf_args_destroy(vmEnclaveFile);
  free(mappingEnclaveFile);
  free(vmEnclaveFile);

  return 0;
}
