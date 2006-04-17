# TrueCrypt Linux Kernel Module Makefile

ifndef KERNEL_SRC
KERNEL_SRC := /usr/src/linux
endif

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
EXTRA_CFLAGS += $(TYPES)
EXTRA_CFLAGS += -D_cdecl="" -DBOOL=int -DTRUE=1 -DFALSE=0
EXTRA_CFLAGS += -DLINUX_DRIVER
EXTRA_CFLAGS += -I$(KERNEL_SRC)/drivers/md
EXTRA_CFLAGS += -I$(TC_BASE)/Crypto
EXTRA_CFLAGS += -I$(TC_BASE)/Common

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

USER_OBJS_F := ../.user-objs
KERNEL_OBJS_F := ../.kernel-objs

truecrypt: objclean platform
	@$(MAKE) TC_BASE=$(PWD)/../.. -C $(KERNEL_SRC) SUBDIRS=$(PWD) M=$(PWD) modules 

CMN := ../../Linux/Common

platform: $(CMN)/.platform

$(CMN)/.platform: $(CMN)/Platform.c
	@$(CC) -o $(CMN)/platform $<
	@$(CMN)/platform >$(CMN)/.platform

objclean:
	@if [ -f $(USER_OBJS_F) ]; then rm -f $(OBJS) $(USER_OBJS_F); fi
	@>$(KERNEL_OBJS_F)

clean:
	-rm -f $(OBJS) ../Common/.platform ../Common/platform
	$(MAKE) -C $(KERNEL_SRC) SUBDIRS=$(PWD) M=$(PWD) clean

install: truecrypt
	$(MAKE) -C $(KERNEL_SRC) SUBDIRS=$(PWD) M=$(PWD) modules_install
	depmod -a
