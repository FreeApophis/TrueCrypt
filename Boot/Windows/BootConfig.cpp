/*
 Copyright (c) 2008-2009 TrueCrypt Foundation. All rights reserved.

 Governed by the TrueCrypt License 2.7 the full text of which is contained
 in the file License.txt included in TrueCrypt binary and source code
 distribution packages.
*/

#include "BootConfig.h"

byte BootSectorFlags;

byte BootLoaderDrive;
byte BootDrive;
bool BootDriveGeometryValid = false;
bool PreventNormalSystemBoot = false;
bool PreventBootMenu = false;
char CustomUserMessage[TC_BOOT_SECTOR_USER_MESSAGE_MAX_LENGTH + 1];
uint32 OuterVolumeBackupHeaderCrc;

bool BootStarted = false;

DriveGeometry BootDriveGeometry;

CRYPTO_INFO *BootCryptoInfo;
Partition EncryptedVirtualPartition;

Partition ActivePartition;
Partition PartitionFollowingActive;
uint64 HiddenVolumeStartUnitNo;
uint64 HiddenVolumeStartSector;


#ifndef TC_WINDOWS_BOOT_RESCUE_DISK_MODE

void ReadBootSectorUserConfiguration ()
{
	byte userConfig;

	AcquireSectorBuffer();

	if (ReadWriteMBR (false, BootLoaderDrive, true) != BiosResultSuccess)
		goto ret;

	userConfig = SectorBuffer[TC_BOOT_SECTOR_USER_CONFIG_OFFSET];
	PreventBootMenu = (userConfig & TC_BOOT_USER_CFG_FLAG_DISABLE_ESC);

	memcpy (CustomUserMessage, SectorBuffer + TC_BOOT_SECTOR_USER_MESSAGE_OFFSET, TC_BOOT_SECTOR_USER_MESSAGE_MAX_LENGTH);
	CustomUserMessage[TC_BOOT_SECTOR_USER_MESSAGE_MAX_LENGTH] = 0;

	if (userConfig & TC_BOOT_USER_CFG_FLAG_SILENT_MODE)
	{
		if (CustomUserMessage[0])
			Print (CustomUserMessage);
		
		DisableScreenOutput();
	}
	
	OuterVolumeBackupHeaderCrc = *(uint32 *) (SectorBuffer + TC_BOOT_SECTOR_OUTER_VOLUME_BAK_HEADER_CRC_OFFSET);

ret:
	ReleaseSectorBuffer();
}


BiosResult UpdateBootSectorConfiguration (byte drive)
{
	AcquireSectorBuffer();

	BiosResult result = ReadWriteMBR (false, drive);
	if (result != BiosResultSuccess)
		goto ret;

	SectorBuffer[TC_BOOT_SECTOR_CONFIG_OFFSET] = BootSectorFlags;
	result = ReadWriteMBR (true, drive);

ret:
	ReleaseSectorBuffer();
	return result;
}

#endif // !TC_WINDOWS_BOOT_RESCUE_DISK_MODE
