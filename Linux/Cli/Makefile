# TrueCrypt Linux Makefile

TC_COMMON := ../../Common
TC_CRYPTO := ../../Crypto

CC := gcc

ifneq ($(MAKECMDGOALS),clean)
-include ../Common/.platform
endif

ifdef NO_WARNINGS
CFLAGS := -w
else
CFLAGS := -W
endif
CFLAGS += -I../../Crypto -I../../Common -I../Kernel
CFLAGS += -D_cdecl="" -DBOOL=int -DTRUE=1 -DFALSE=0 -DMAX_PATH=260
CFLAGS += $(TYPES)

ifndef DEBUG
CFLAGS += -O2 -fno-strict-aliasing
else
CFLAGS += -ggdb
endif

KERNEL_OBJS_F := ../.kernel-objs
USER_OBJS_F := ../.user-objs

OBJS := $(TC_CRYPTO)/Aescrypt.o
OBJS += $(TC_CRYPTO)/Aeskey.o
OBJS += $(TC_CRYPTO)/Aestab.o
OBJS += $(TC_CRYPTO)/Bf_ecb.o
OBJS += $(TC_CRYPTO)/Bf_enc.o
OBJS += $(TC_CRYPTO)/Bf_skey.o
OBJS += $(TC_CRYPTO)/C_ecb.o
OBJS += $(TC_CRYPTO)/C_enc.o
OBJS += $(TC_CRYPTO)/C_skey.o
OBJS += $(TC_CRYPTO)/Des.o
OBJS += $(TC_CRYPTO)/Des_enc.o
OBJS += $(TC_CRYPTO)/Ecb3_enc.o
OBJS += $(TC_CRYPTO)/Rmd160.o
OBJS += $(TC_CRYPTO)/Serpent.o
OBJS += $(TC_CRYPTO)/Set_key.o
OBJS += $(TC_CRYPTO)/Sha1.o
OBJS += $(TC_CRYPTO)/Twofish.o
OBJS += $(TC_CRYPTO)/Whirlpool.o
OBJS += $(TC_COMMON)/Crc.o
OBJS += $(TC_COMMON)/Crypto.o
OBJS += $(TC_COMMON)/Endian.o
OBJS += $(TC_COMMON)/Keyfiles.o
OBJS += $(TC_COMMON)/Pkcs5.o
OBJS += $(TC_COMMON)/Volumes.o
OBJS += $(TC_COMMON)/Tests.o
OBJS += Cli.o 

%.o: %.c
	@echo Compiling $(<F)
	@$(CC) $(CFLAGS) $(EXTRA_CFLAGS) -o $@ -c $<

%.dep: %.c
	@$(CC) $(CFLAGS) $(EXTRA_CFLAGS) -M -MT $*.o $< >$@

all: objclean truecrypt
	@echo Done.

../Common/.platform: ../Common/Platform.c
	@$(CC) -o ../Common/platform $<
	@../Common/platform >../Common/.platform

ifneq ($(MAKECMDGOALS),clean)
-include $(OBJS:.o=.dep)
endif

truecrypt: $(OBJS)
	@echo Linking truecrypt
	@$(CC) -o truecrypt $(OBJS)
ifndef DEBUG
	@strip truecrypt
endif

man: truecrypt.1

truecrypt.1: objclean truecrypt
	help2man -N -i Man/help2man.inc ./truecrypt >Man/truecrypt.1
	
objclean:
	@if [ -f $(KERNEL_OBJS_F) ]; then rm -f ${OBJS} $(KERNEL_OBJS_F); fi
	@>$(USER_OBJS_F)

clean:
	-rm -f truecrypt ${OBJS} *.dep $(TC_COMMON)/*.dep $(TC_CRYPTO)/*.dep ../Common/platform ../Common/.platform
