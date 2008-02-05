/*
 Legal Notice: Some portions of the source code contained in this file were
 derived from the source code of Encryption for the Masses 2.02a, which is
 Copyright (c) 1998-2000 Paul Le Roux and which is governed by the 'License
 Agreement for Encryption for the Masses'. Modifications and additions to
 the original source code (contained in this file) and all other portions of
 this file are Copyright (c) 2003-2008 TrueCrypt Foundation and are governed
 by the TrueCrypt License 2.4 the full text of which is contained in the
 file License.txt included in TrueCrypt binary and source code distribution
 packages. */

#include "Password.h"


#ifdef __cplusplus
extern "C" {
#endif

#define TC_HEADER_OFFSET_MAGIC					64
#define TC_HEADER_OFFSET_VERSION				68
#define TC_HEADER_OFFSET_REQUIRED_VERSION		70
#define TC_HEADER_OFFSET_KEY_AREA_CRC			72
#define TC_HEADER_OFFSET_VOLUME_CREATION_TIME	76
#define TC_HEADER_OFFSET_MODIFICATION_TIME		84
#define TC_HEADER_OFFSET_HIDDEN_VOLUME_SIZE		92
#define TC_HEADER_OFFSET_VOLUME_SIZE			100
#define TC_HEADER_OFFSET_ENCRYPTED_AREA_START	108
#define TC_HEADER_OFFSET_ENCRYPTED_AREA_LENGTH	116

uint16 GetHeaderField16 (byte *header, size_t offset);
uint32 GetHeaderField32 (byte *header, size_t offset);
UINT64_STRUCT GetHeaderField64 (byte *header, size_t offset);
int VolumeReadHeader (BOOL bBoot, char *encryptedHeader, Password *password, PCRYPTO_INFO *retInfo, CRYPTO_INFO *retHeaderCryptoInfo);
#ifndef TC_WINDOWS_BOOT
int VolumeWriteHeader (BOOL bBoot, char *encryptedHeader, int ea, int mode, Password *password, int pkcs5_prf, char *masterKeydata, unsigned __int64 volumeCreationTime, PCRYPTO_INFO *retInfo, unsigned __int64 volumeSize, unsigned __int64 hiddenVolumeSize, unsigned __int64 encryptedAreaStart, unsigned __int64 encryptedAreaLength, BOOL bWipeMode);
#endif

#ifdef __cplusplus
}
#endif

