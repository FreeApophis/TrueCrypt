#
# Copyright (c) TrueCrypt Foundation. All rights reserved.
#
# Covered by the TrueCrypt License 2.2 the full text of which is contained
# in the file License.txt included in TrueCrypt binary and source code
# distribution packages.
#

TC_COMMON := ../../Common
TC_CRYPTO := ../../Crypto

CC ?= gcc

ifneq ($(MAKECMDGOALS),clean)
-include ../Common/.platform
endif

ifdef NO_WARNINGS
CFLAGS := -w
else
CFLAGS := -W
endif
CFLAGS += -I../../Crypto -I../../Common -I../Kernel -I../..
CFLAGS += -DBOOL=int -DTRUE=1 -DFALSE=0 -DMAX_PATH=260
CFLAGS += $(TYPES)

ifndef DEBUG
# Do not enable strict aliasing
CFLAGS += -O2 -fno-strict-aliasing
else
CFLAGS += -ggdb
NO_STRIP := 1
endif

KERNEL_OBJS_PRESENT := ../.kernel-objs
KERNEL_OBJS_CLEAN := ../.user-objs

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
OBJS += $(TC_COMMON)/GfMul.o
OBJS += $(TC_COMMON)/Fat.o
OBJS += $(TC_COMMON)/Format.o
OBJS += $(TC_COMMON)/Keyfiles.o
OBJS += $(TC_COMMON)/Pkcs5.o
OBJS += $(TC_COMMON)/Random.o
OBJS += $(TC_COMMON)/Volumes.o
OBJS += $(TC_COMMON)/Tests.o
OBJS += Cli.o 

%.o: %.c
	@echo Compiling $(<F)
	@$(CC) $(CFLAGS) $(EXTRA_CFLAGS) -MMD -o $@ -c $<

.PHONY: all clean man

all: $(KERNEL_OBJS_CLEAN) truecrypt
	@echo Done.

$(KERNEL_OBJS_CLEAN):
	@rm -f ${OBJS} $(KERNEL_OBJS_PRESENT)
	@>$(KERNEL_OBJS_CLEAN)
	
../Common/.platform: ../Common/Platform.c
	@echo Compiling Platform.c
	@$(CC) $(CFLAGS) $(EXTRA_CFLAGS) -o ../Common/platform $<
	@echo Detecting platform options
	@../Common/platform >../Common/.platform

-include $(OBJS:.o=.d)

truecrypt: $(OBJS)
	@echo Linking $@
	@$(CC) $(EXTRA_LFLAGS) -o $@ $(OBJS)
ifndef NO_STRIP
	@strip $@
endif
	
man: truecrypt.1

truecrypt.1: $(KERNEL_OBJS_CLEAN) truecrypt
	help2man -N -i Man/help2man.inc ./truecrypt >Man/truecrypt.1

clean:
	-rm -f truecrypt ${OBJS} *.d $(TC_COMMON)/*.d $(TC_CRYPTO)/*.d ../Common/platform ../Common/.platform
