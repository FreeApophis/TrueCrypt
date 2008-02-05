/*
 Copyright (c) 2008 TrueCrypt Foundation. All rights reserved.

 Governed by the TrueCrypt License 2.4 the full text of which is contained
 in the file License.txt included in TrueCrypt binary and source code
 distribution packages.
*/

#include "Crypto.h"
#include "Platform.h"
#include "Bios.h"
#include "BootConfig.h"
#include "BootDebug.h"
#include "BootDiskIo.h"
#include "BootEncryptedIo.h"


BiosResult ReadEncryptedSectors (uint16 destSegment, uint16 destOffset, byte drive, uint64 sector, uint16 sectorCount)
{
	BiosResult result;
	byte sectorBuf[TC_LB_SIZE];

	while (sectorCount-- > 0)
	{
		result = ReadSectors (sectorBuf, drive, sector, 1);

		if (result != BiosResultSuccess)
			return result;

		if (drive == EncryptedVirtualPartition.Drive && sector >= EncryptedVirtualPartition.StartSector && sector <= EncryptedVirtualPartition.EndSector)
		{
			DecryptDataUnits (sectorBuf, &sector, 1, BootCryptoInfo);
		}

		CopyMemory (sectorBuf, destSegment, destOffset, sizeof (sectorBuf));

		++sector;
		destOffset += sizeof (sectorBuf);
	}

	return result;
}


BiosResult WriteEncryptedSectors (uint16 sourceSegment, uint16 sourceOffset, byte drive, uint64 sector, uint16 sectorCount)
{
	BiosResult result;
	byte sectorBuf[TC_LB_SIZE];

	while (sectorCount-- > 0)
	{
		CopyMemory (sourceSegment, sourceOffset, sectorBuf, sizeof (sectorBuf));

		if (drive == EncryptedVirtualPartition.Drive && sector >= EncryptedVirtualPartition.StartSector && sector <= EncryptedVirtualPartition.EndSector)
		{
			EncryptDataUnits (sectorBuf, &sector, 1, BootCryptoInfo);
		}

		result = WriteSectors (sectorBuf, drive, sector, 1);

		if (result != BiosResultSuccess)
			return result;

		++sector;
		sourceOffset += sizeof (sectorBuf);
	}

	return result;
}
