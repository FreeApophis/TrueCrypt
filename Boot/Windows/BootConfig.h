/*
 Copyright (c) 2008 TrueCrypt Foundation. All rights reserved.

 Governed by the TrueCrypt License 2.4 the full text of which is contained
 in the file License.txt included in TrueCrypt binary and source code
 distribution packages.
*/

#ifndef TC_HEADER_Boot_BootConfig
#define TC_HEADER_Boot_BootConfig

#include "Crypto.h"
#include "Platform.h"
#include "BootDiskIo.h"

extern byte BootSectorFlags;

extern byte BootLoaderDrive;
extern byte BootDrive;
extern bool BootDriveGeometryValid;
extern DriveGeometry BootDriveGeometry;

extern CRYPTO_INFO *BootCryptoInfo;
extern Partition EncryptedVirtualPartition;

#endif // TC_HEADER_Boot_BootConfig
