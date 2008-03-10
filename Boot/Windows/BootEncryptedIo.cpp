/*
 Copyright (c) 2008 TrueCrypt Foundation. All rights reserved.

 Governed by the TrueCrypt License 2.4 the full text of which is contained
 in the file License.txt included in TrueCrypt binary and source code
 distribution packages.
*/

#include "Crypto.h"
#include "Platform.h"
#include "BootConfig.h"
#include "BootDebug.h"
#include "BootDefs.h"
#include "BootDiskIo.h"
#include "BootEncryptedIo.h"


BiosResult ReadEncryptedSectors (uint16 destSegment, uint16 destOffset, byte drive, uint64 sector, uint16 sectorCount)
{
	BiosResult result;

	result = ReadSectors (destSegment, destOffset, drive, sector, sectorCount);

	if (result != BiosResultSuccess)
		return result;

	if (drive == EncryptedVirtualPartition.Drive)
	{
		while (sectorCount-- > 0)
		{
			if (sector >= EncryptedVirtualPartition.StartSector && sector <= EncryptedVirtualPartition.EndSector)
			{
				AcquireSectorBuffer();
				CopyMemory (destSegment, destOffset, SectorBuffer, TC_LB_SIZE);

				DecryptDataUnits (SectorBuffer, &sector, 1, BootCryptoInfo);

				CopyMemory (SectorBuffer, destSegment, destOffset, TC_LB_SIZE);
				ReleaseSectorBuffer();
			}

			++sector;
			destOffset += TC_LB_SIZE;
		}
	}

	return result;
}


BiosResult WriteEncryptedSectors (uint16 sourceSegment, uint16 sourceOffset, byte drive, uint64 sector, uint16 sectorCount)
{
	BiosResult result;
	AcquireSectorBuffer();

	while (sectorCount-- > 0)
	{
		CopyMemory (sourceSegment, sourceOffset, SectorBuffer, TC_LB_SIZE);

		if (drive == EncryptedVirtualPartition.Drive && sector >= EncryptedVirtualPartition.StartSector && sector <= EncryptedVirtualPartition.EndSector)
		{
			EncryptDataUnits (SectorBuffer, &sector, 1, BootCryptoInfo);
		}

		result = WriteSectors (SectorBuffer, drive, sector, 1);

		if (result != BiosResultSuccess)
			break;

		++sector;
		sourceOffset += TC_LB_SIZE;
	}

	ReleaseSectorBuffer();
	return result;
}
