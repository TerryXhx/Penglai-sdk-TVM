# This version of config.mak was generated by:
# ./configure --disable-shared --target=riscv64 CROSS_COMPILE=riscv64-unknown-linux-gnu-
# Any changes made here will be lost if configure is re-run
AR = riscv64-unknown-linux-gnu-ar
RANLIB =riscv64-unknown-linux-gnu-ranlib
ARCH = riscv64
SUBARCH = 
ASMSUBARCH = 
srcdir = .
prefix = /usr/local/musl
exec_prefix = $(prefix)
bindir = $(exec_prefix)/bin
libdir = $(prefix)/lib
includedir = $(prefix)/include
syslibdir = /lib
CC = riscv64-unknown-linux-gnu-gcc
CFLAGS = 
CFLAGS_AUTO = -mabi=lp64  -march=rv64imac -Os -pipe -fomit-frame-pointer -fno-unwind-tables -fno-asynchronous-unwind-tables -ffunction-sections -fdata-sections -Werror=implicit-function-declaration -Werror=implicit-int -Werror=pointer-sign -Werror=pointer-arith
CFLAGS_C99FSE = -std=c99 -nostdinc -ffreestanding -fexcess-precision=standard -frounding-math -Wa,--noexecstack
CFLAGS_MEMOPS = -fno-tree-loop-distribute-patterns
CFLAGS_NOSSP = -fno-stack-protector
CPPFLAGS = 
LDFLAGS = 
LDFLAGS_AUTO = -Wl,--sort-section,alignment -Wl,--sort-common -Wl,--gc-sections -Wl,--hash-style=both -Wl,--no-undefined -Wl,--exclude-libs=ALL -Wl,--dynamic-list=./dynamic.list
CROSS_COMPILE =$(MULTILIB_TOOLCHAIN)/riscv64-unknown-linux-gnu-
LIBCC = -lgcc -lgcc_eh
OPTIMIZE_GLOBS = internal/*.c malloc/*.c string/*.c
ALL_TOOLS =  obj/musl-gcc
TOOL_LIBS =  lib/musl-gcc.specs
ADD_CFI = no
SHARED_LIBS =
WRAPCC_GCC = $(CC)
