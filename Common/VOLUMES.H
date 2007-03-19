/*
 Legal Notice: The source code contained in this file has been derived from
 the source code of Encryption for the Masses 2.02a, which is Copyright (c)
 Paul Le Roux and which is covered by the 'License Agreement for Encryption
 for the Masses'. Modifications and additions to that source code contained
 in this file are Copyright (c) TrueCrypt Foundation and are covered by the
 TrueCrypt License 2.2 the full text of which is contained in the file
 License.txt included in TrueCrypt binary and source code distribution
 packages. */

#include "Password.h"

int VolumeReadHeader (char *encryptedHeader, Password *password, PCRYPTO_INFO *retInfo);
int VolumeWriteHeader (char *encryptedHeader, int ea, int mode, Password *password , int pkcs5 , char *masterKey, unsigned __int64 volumeCreationTime, PCRYPTO_INFO *retInfo, unsigned __int64 hiddenVolumeSize, BOOL bWipeMode);
