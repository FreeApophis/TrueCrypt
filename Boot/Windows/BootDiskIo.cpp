/*
 Copyright (c) 2008 TrueCrypt Foundation. All rights reserved.

 Governed by the TrueCrypt License 2.4 the full text of which is contained
 in the file License.txt included in TrueCrypt binary and source code
 distribution packages.
*/

#include "Bios.h"
#include "BootConsoleIo.h"
#include "BootDebug.h"
#include "BootDiskIo.h"


bool IsLbaSupported (byte drive)
{
	uint16 result = 0;
	__asm
	{
		mov bx, 0x55aa
		mov dl, drive
		mov ah, 0x41
		int 0x13
		jc err
		mov result, bx
	err:
	}

	return result == 0xaa55;
}


void PrintDiskError (BiosResult error, bool write, byte drive, const uint64 *sector, const ChsAddress *chs)
{
	PrintEndl();
	Print (write ? "Write" : "Read"); Print (" error:");
	PrintHex (error);
	Print (" Drive:");
	Print (drive < TC_FIRST_BIOS_DRIVE ? drive : drive - TC_FIRST_BIOS_DRIVE);

	if (sector)
	{
		Print (" Sector:");
		Print (*sector);
	}

	if (chs)
	{
		Print (" CHS:");
		Print (*chs);
	}

	PrintEndl();
	Beep();
}


void Print (const ChsAddress &chs)
{
	Print (chs.Cylinder);
	PrintChar ('/');
	Print (chs.Head);
	PrintChar ('/');
	Print (chs.Sector);
}


BiosResult ReadWriteSectors (bool write, byte *buffer, byte drive, const ChsAddress &chs, byte sectorCount, bool silent)
{
	byte cylinderLow = (byte) chs.Cylinder;
	byte sector = chs.Sector;
	sector |= byte (chs.Cylinder >> 2) & 0xc0;
	byte function = write ? 0x03 : 0x02;
	
	BiosResult result;
	__asm
	{
		push es
		mov ax, ds
		mov	es, ax
		mov	bx, ss:buffer
		mov dl, ss:drive
		mov ch, ss:cylinderLow
		mov si, chs
		mov dh, ss:[si].Head
		mov cl, ss:sector
		mov	al, ss:sectorCount
		mov	ah, function
		int	0x13
		mov	result, ah
		pop es
	}

	if (result == BiosResultEccCorrected)
		result = BiosResultSuccess;

	if (!silent && result != BiosResultSuccess)
		PrintDiskError (result, write, drive, nullptr, &chs);

	return result;
}


BiosResult ReadSectors (byte *buffer, byte drive, const ChsAddress &chs, byte sectorCount, bool silent)
{
	return ReadWriteSectors (false, buffer, drive, chs, sectorCount, silent);
}


BiosResult WriteSectors (byte *buffer, byte drive, const ChsAddress &chs, byte sectorCount, bool silent)
{
	return ReadWriteSectors (true, buffer, drive, chs, sectorCount, silent);
}


static BiosResult ReadWriteSectors (bool write, BiosLbaPacket &dapPacket, byte drive, const uint64 &sector, uint16 sectorCount, bool silent)
{
	dapPacket.Size = sizeof (dapPacket);
	dapPacket.Reserved = 0;
	dapPacket.SectorCount = sectorCount;
	dapPacket.Sector = sector;

	byte function = write ? 0x43 : 0x42;
	
	BiosResult result;
	__asm
	{
		mov	bx, 0x55aa
		mov	dl, drive
		mov si, [dapPacket]
		mov	ah, function
		xor al, al
		int	0x13
		mov	result, ah
	}

	if (result == BiosResultEccCorrected)
		result = BiosResultSuccess;

	if (!silent && result != BiosResultSuccess)
		PrintDiskError (result, write, drive, &sector);

	return result;
}


static BiosResult ReadWriteSectors (bool write, byte *buffer, byte drive, const uint64 &sector, uint16 sectorCount, bool silent)
{
	BiosLbaPacket dapPacket;
	dapPacket.Buffer = (uint32) buffer;
	return ReadWriteSectors (write, dapPacket, drive, sector, sectorCount, silent);
}


BiosResult ReadWriteSectors (bool write, uint16 bufferSegment, uint16 bufferOffset, byte drive, const uint64 &sector, uint16 sectorCount, bool silent)
{
	BiosLbaPacket dapPacket;
	dapPacket.Buffer = ((uint32) bufferSegment << 16) | bufferOffset;
	return ReadWriteSectors (write, dapPacket, drive, sector, sectorCount, silent);
}


BiosResult ReadSectors (byte *buffer, byte drive, const uint64 &sector, uint16 sectorCount, bool silent)
{
	if (IsLbaSupported (drive))
		return ReadWriteSectors (false, buffer, drive, sector, sectorCount, silent);

	DriveGeometry geometry;

	BiosResult result = GetDriveGeometry (drive, geometry, silent);
	if (result != BiosResultSuccess)
		return result;

	ChsAddress chs;
	LbaToChs (geometry, sector, chs);
	return ReadWriteSectors (false, buffer, drive, chs, sectorCount, silent);
}


BiosResult WriteSectors (byte *buffer, byte drive, const uint64 &sector, uint16 sectorCount, bool silent)
{
	return ReadWriteSectors (true, buffer, drive, sector, sectorCount, silent);
}


BiosResult GetDriveGeometry (byte drive, DriveGeometry &geometry, bool silent)
{
	byte maxCylinderLow, maxHead, maxSector;
	BiosResult result;
	__asm
	{
		push es
		mov dl, drive
		mov ah, 0x08
		int	0x13

		mov	result, ah
		jc err
		mov maxCylinderLow, ch
		mov maxSector, cl
		mov maxHead, dh
err:
		pop es
	}

	if (result == BiosResultSuccess)
	{
		geometry.Cylinders = (maxCylinderLow | (uint16 (maxSector & 0xc0) << 2)) + 1;
		geometry.Heads = maxHead + 1;
		geometry.Sectors = maxSector & ~0xc0;
	}
	else if (!silent)
	{
		PrintError ("Cannot get geometry of drive ", true, false);
		Print (drive);
		PrintEndl();
	}

	return result;
}


void ChsToLba (const DriveGeometry &geometry, const ChsAddress &chs, uint64 &lba)
{
	lba.HighPart = 0;
	lba.LowPart = (uint32 (chs.Cylinder) * geometry.Heads + chs.Head) * geometry.Sectors + chs.Sector - 1;
}


void LbaToChs (const DriveGeometry &geometry, const uint64 &lba, ChsAddress &chs)
{
	chs.Sector = (lba.LowPart % geometry.Sectors) + 1;
	uint32 ch = lba.LowPart / geometry.Sectors;
	chs.Head = ch % geometry.Heads;
	chs.Cylinder = ch / geometry.Heads;
}


BiosResult ReadMBR (byte drive, MBR &mbr, bool silent)
{
	ChsAddress chs;
	chs.Cylinder = 0;
	chs.Head = 0;
	chs.Sector = 1;

	return ReadSectors ((byte *) &mbr, drive, chs, 1, silent);
}


void PartitionEntryMBRToPartition (const PartitionEntryMBR &partEntry, Partition &partition)
{
	partition.Active = partEntry.BootIndicator == 0x80;
	partition.EndSector.HighPart = 0;
	partition.EndSector.LowPart = partEntry.StartLBA + partEntry.SectorCountLBA - 1;
	partition.SectorCount.HighPart = 0;
	partition.SectorCount.LowPart = partEntry.SectorCountLBA;
	partition.StartSector.HighPart = 0;
	partition.StartSector.LowPart = partEntry.StartLBA;

	partition.StartChsAddress.Cylinder = partEntry.StartCylinder | (uint16 (partEntry.StartCylSector & 0xc0) << 2);
	partition.StartChsAddress.Head = partEntry.StartHead;
	partition.StartChsAddress.Sector = partEntry.StartCylSector & ~0xc0;

	partition.Type = partEntry.Type;
}


BiosResult GetDrivePartitions (byte drive, Partition *partitionArray, size_t partitionArrayCapacity, size_t &partitionCount, bool activeOnly, bool silent)
{
	MBR mbr;
	BiosResult result = ReadMBR (drive, mbr, silent);
	partitionCount = 0;
	
	if (result != BiosResultSuccess || mbr.Signature != 0xaa55)
		return result;

	size_t partitionArrayPos = 0, partitionNumber;
	
	for (partitionNumber = 0;
		partitionNumber < array_capacity (mbr.Partitions) && partitionArrayPos < partitionArrayCapacity;
		++partitionNumber)
	{
		const PartitionEntryMBR &partEntry = mbr.Partitions[partitionNumber];
		
		if (partEntry.SectorCountLBA > 0)
		{
			Partition &partition = partitionArray[partitionArrayPos];
			PartitionEntryMBRToPartition (partEntry, partition);

			if (activeOnly && !partition.Active)
				continue;

			partition.Drive = drive;
			partition.Number = partitionNumber;

			if (partEntry.Type == 0x5 || partEntry.Type == 0xf) // Extended partition
			{
				if (IsLbaSupported (drive))
				{
					// Find all extended partitions
					uint64 firstExtStartLBA = partition.StartSector;
					uint64 extStartLBA = partition.StartSector;
					MBR extMbr;

					while (partitionArrayPos < partitionArrayCapacity &&
						(result = ReadSectors ((byte *) &extMbr, drive, extStartLBA, 1, silent)) == BiosResultSuccess
						&& extMbr.Signature == 0xaa55)
					{
						if (extMbr.Partitions[0].SectorCountLBA > 0)
						{
							Partition &logPart = partitionArray[partitionArrayPos++];
							PartitionEntryMBRToPartition (extMbr.Partitions[0], logPart);
							logPart.Drive = drive;

							logPart.Number = partitionNumber++;
							logPart.Primary = false;

							logPart.StartSector.LowPart += extStartLBA.LowPart;
							logPart.EndSector.LowPart += extStartLBA.LowPart;
						}

						// Secondary extended
						if (extMbr.Partitions[1].Type != 0x5 && extMbr.Partitions[1].Type == 0xf
							|| extMbr.Partitions[1].SectorCountLBA == 0)
							break;

						extStartLBA.LowPart = extMbr.Partitions[1].StartLBA + firstExtStartLBA.LowPart;
					}
				}
			}
			else
			{
				++partitionArrayPos;
				partition.Primary = true;
			}
		}
	}

	partitionCount = partitionArrayPos;
	return result;
}


BiosResult GetActivePartition (byte drive, Partition &partition, size_t &partitionCount, bool silent)
{
	return GetDrivePartitions (drive, &partition, 1, partitionCount, true, silent);
}
