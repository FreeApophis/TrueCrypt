#
# Copyright (c) TrueCrypt Foundation. All rights reserved.
#
# Covered by the TrueCrypt License 2.3 the full text of which is contained
# in the file License.txt included in TrueCrypt binary and source code
# distribution packages.
#

KERNEL_SRC ?= /usr/src/linux
KERNEL_BUILD ?= $(KERNEL_SRC)

TC_COMMON := ../../Common
TC_CRYPTO := ../../Crypto

ifneq ($(MAKECMDGOALS),clean)
ifdef TC_BASE
-include $(TC_BASE)/Linux/Common/.platform
endif
endif

ifdef NO_WARNINGS
EXTRA_CFLAGS += -w
else
EXTRA_CFLAGS += -Wno-strict-prototypes
endif
# Do not enable strict aliasing
EXTRA_CFLAGS += -fno-strict-aliasing
EXTRA_CFLAGS += $(TYPES)
EXTRA_CFLAGS += -DBOOL=int -DTRUE=1 -DFALSE=0
EXTRA_CFLAGS += -DLINUX_DRIVER
EXTRA_CFLAGS += -I$(KERNEL_SRC)/drivers/md
EXTRA_CFLAGS += -I$(TC_BASE)/Crypto
EXTRA_CFLAGS += -I$(TC_BASE)/Common
EXTRA_CFLAGS += -I$(TC_BASE)

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
OBJS += $(TC_CRYPTO)/Serpent.o
OBJS += $(TC_CRYPTO)/Set_key.o
OBJS += $(TC_CRYPTO)/Twofish.o
OBJS += $(TC_COMMON)/Crc.o
OBJS += $(TC_COMMON)/Crypto.o
OBJS += $(TC_COMMON)/Endian.o
OBJS += $(TC_COMMON)/GfMul.o
OBJS += $(TC_COMMON)/Tests.o
OBJS += Dm-target.o

truecrypt-objs := $(OBJS)
obj-m := truecrypt.o

USER_OBJS_PRESENT := ../.user-objs
USER_OBJS_CLEAN := ../.kernel-objs

.PHONY:	clean install truecrypt

truecrypt: $(USER_OBJS_CLEAN) platform
	@$(MAKE) TC_BASE=$(PWD)/../.. -C $(KERNEL_BUILD) SUBDIRS=$(PWD) M=$(PWD) modules 

CMN := ../../Linux/Common

platform: $(CMN)/.platform

$(CMN)/.platform: $(CMN)/Platform.c
	@$(CC) -o $(CMN)/platform $<
	@$(CMN)/platform >$(CMN)/.platform

$(USER_OBJS_CLEAN):
	@rm -f $(OBJS) $(USER_OBJS_PRESENT)
	@>$(USER_OBJS_CLEAN)

clean:
	-rm -f $(OBJS) ../Common/.platform ../Common/platform
	$(MAKE) -C $(KERNEL_BUILD) SUBDIRS=$(PWD) M=$(PWD) clean

install: truecrypt
	$(MAKE) -C $(KERNEL_BUILD) SUBDIRS=$(PWD) M=$(PWD) modules_install
	depmod -a
