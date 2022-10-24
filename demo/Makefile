all:
	CC=$(CC) LINK=$(LINK) AR=$(AR) make -C host
	CC=$(CC) LINK=$(LINK) AR=$(AR) make -C fork-host
	CC=$(CC) LINK=$(LINK) AR=$(AR) make -C host-pm-wasm
	CC=$(CC) LINK=$(LINK) AR=$(AR) make -C host-pm-wasm-evaluation
	CC=$(CC) LINK=$(LINK) AR=$(AR) make -C host-pm-wasm-steps
	make -C pm-mapping
	make -C hello-world
	make -C relay-page
	make -C mem
	make -C IPC
	make -C FS
	make -C test-stop
	make -C psa
	make -C seperated_filesystem_simple

	#CC=$(CC) LINK=$(LINK) AR=$(AR) make -C  mphost_normal

clean:
	CC=$(CC) LINK=$(LINK) AR=$(AR) make -C host clean
	CC=$(CC) LINK=$(LINK) AR=$(AR) make -C fork-host clean
	CC=$(CC) LINK=$(LINK) AR=$(AR) make -C host-pm-wasm clean
	CC=$(CC) LINK=$(LINK) AR=$(AR) make -C host-pm-wasm-evaluation clean
	CC=$(CC) LINK=$(LINK) AR=$(AR) make -C host-pm-wasm-steps clean
	make -C pm-mapping clean
	make -C hello-world clean
	make -C relay-page clean
	make -C mem clean
	make -C IPC clean
	make -C FS clean
	make -C test-stop clean
	make -C psa clean
	make -C seperated_filesystem_simple clean

