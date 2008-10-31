#
# Copyright (c) 2008 TrueCrypt Foundation. All rights reserved.
#
# Governed by the TrueCrypt License 2.6 the full text of which is contained
# in the file License.txt included in TrueCrypt binary and source code
# distribution packages.
#

NAME := Driver

OBJS :=
OBJS += FuseService.o

CXXFLAGS += $(shell pkg-config fuse --cflags)

include $(BUILD_INC)/Makefile.inc
