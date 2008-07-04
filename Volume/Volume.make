#
# Copyright (c) 2008 TrueCrypt Foundation. All rights reserved.
#
# Governed by the TrueCrypt License 2.5 the full text of which is contained
# in the file License.txt included in TrueCrypt binary and source code
# distribution packages.
#

OBJS :=
OBJS += Cipher.o
OBJS += EncryptionAlgorithm.o
OBJS += EncryptionMode.o
OBJS += EncryptionModeCBC.o
OBJS += EncryptionModeLRW.o
OBJS += EncryptionModeXTS.o
OBJS += EncryptionTest.o
OBJS += EncryptionThreadPool.o
OBJS += Hash.o
OBJS += Keyfile.o
OBJS += Pkcs5Kdf.o
OBJS += Volume.o
OBJS += VolumeException.o
OBJS += VolumeHeader.o
OBJS += VolumeInfo.o
OBJS += VolumeLayout.o
OBJS += VolumePassword.o
OBJS += VolumePasswordCache.o

OBJS += ../Crypto/Aescrypt.o
OBJS += ../Crypto/Aeskey.o
OBJS += ../Crypto/Aestab.o
OBJS += ../Crypto/Bf_ecb.o
OBJS += ../Crypto/Bf_enc.o
OBJS += ../Crypto/Bf_skey.o
OBJS += ../Crypto/C_ecb.o
OBJS += ../Crypto/C_enc.o
OBJS += ../Crypto/C_skey.o
OBJS += ../Crypto/Des.o
OBJS += ../Crypto/Des_enc.o
OBJS += ../Crypto/Ecb3_enc.o
OBJS += ../Crypto/Rmd160.o
OBJS += ../Crypto/Serpent.o
OBJS += ../Crypto/Set_key.o
OBJS += ../Crypto/Sha1.o
OBJS += ../Crypto/Sha2.o
OBJS += ../Crypto/Twofish.o
OBJS += ../Crypto/Whirlpool.o

OBJS += ../Common/Crc.o
OBJS += ../Common/Endian.o
OBJS += ../Common/GfMul.o
OBJS += ../Common/Pkcs5.o

VolumeLibrary: Volume.a

include $(BUILD_INC)/Makefile.inc
