/*
 Copyright (c) 2008 TrueCrypt Foundation. All rights reserved.

 Governed by the TrueCrypt License 2.4 the full text of which is contained
 in the file License.txt included in TrueCrypt binary and source code
 distribution packages.
*/

#include "Bios.h"
#include "BootConsoleIo.h"
#include "BootDebug.h"
#include "BootDefs.h"
#include "BootDiskIo.h"


byte SectorBuffer[TC_LB_SIZE];

#ifdef TC_BOOT_DEBUG_ENABLED
static bool SectorBufferInUse = false;

void AcquireSectorBuffer ()
{
	if (SectorBufferInUse)
		TC_THROW_FATAL_EXCEPTION;

	SectorBufferInUse = true;
}


void ReleaseSectorBuffer ()
{
	SectorBufferInUse = false;
}

#endif


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


BiosResult ReadWriteSectors (bool write, uint16 bufferSegment, uint16 bufferOffset, byte drive, const ChsAddress &chs, byte sectorCount, bool silent)
{
	CheckStack();

	byte cylinderLow = (byte) chs.Cylinder;
	byte sector = chs.Sector;
	sector |= byte (chs.Cylinder >> 2) & 0xc0;
	byte function = write ? 0x03 : 0x02;

	BiosResult result;
	__asm
	{
		push es
		mov ax, bufferSegment
		mov	es, ax
		mov	bx, bufferOffset
		mov dl, drive
		mov ch, cylinderLow
		mov si, chs
		mov dh, [si].Head
		mov cl, sector
		mov	al, sectorCount
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


BiosResult ReadWriteSectors (bool write, byte *buffer, byte drive, const ChsAddress &chs, byte sectorCount, bool silent)
{
	uint16 codeSeg;
	__asm mov codeSeg, cs
	return ReadWriteSectors (false, codeSeg, (uint16) buffer, drive, chs, sectorCount, silent);
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
	CheckStack();

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


BiosResult ReadSectors (uint16 bufferSegment, uint16 bufferOffset, byte drive, const uint64 &sector, uint16 sectorCount, bool silent)
{
	if (IsLbaSupported (drive))
		return ReadWriteSectors (false, bufferSegment, bufferOffset, drive, sector, sectorCount, silent);

	DriveGeometry geometry;

	BiosResult result = GetDriveGeometry (drive, geometry, silent);
	if (result != BiosResultSuccess)
		return result;

	ChsAddress chs;
	LbaToChs (geometry, sector, chs);
	return ReadWriteSectors (false, bufferSegment, bufferOffset, drive, chs, sectorCount, silent);
}


BiosResult ReadSectors (byte *buffer, byte drive, const uint64 &sector, uint16 sectorCount, bool silent)
{
	uint16 codeSeg;
	__asm mov codeSeg, cs
	return ReadSectors (codeSeg, (uint16) buffer, drive, sector, sectorCount, silent);
}


BiosResult WriteSectors (byte *buffer, byte drive, const uint64 &sector, uint16 sectorCount, bool silent)
{
	return ReadWriteSectors (true, buffer, drive, sector, sectorCount, silent);
}


BiosResult GetDriveGeometry (byte drive, DriveGeometry &geometry, bool silent)
{
	CheckStack();

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


void PartitionEntryMBRToPartition (const PartitionEntryMBR &partEntry, Partition &partition)
{
	partition.Active = partEntry.BootIndicator == 0x80;
	partition.EndSector.HighPart = 0;
	partition.EndSector.LowPart = partEntry.StartLBA + partEntry.SectorCountLBA - 1;
	partition.SectorCount.HighPart = 0;
	partition.SectorCount.LowPart = partEntry.SectorCountLBA;
	partition.StartSector.HighPart = 0;
	partition.StartSector.LowPart = partEntry.StartLBA;
	partition.Type = partEntry.Type;
}


BiosResult GetDrivePartitions (byte drive, Partition *partitionArray, size_t partitionArrayCapacity, size_t &partitionCount, bool activeOnly, bool silent)
{
	ChsAddress chs;
	chs.Cylinder = 0;
	chs.Head = 0;
	chs.Sector = 1;

	AcquireSectorBuffer();
	BiosResult result = ReadSectors (SectorBuffer, drive, chs, 1, silent);
	
	ReleaseSectorBuffer();
	partitionCount = 0;

	MBR *mbr = (MBR *) SectorBuffer;
	if (result != BiosResultSuccess || mbr->Signature != 0xaa55)
		return result;

	PartitionEntryMBR mbrPartitions[4];
	memcpy (mbrPartitions, mbr->Partitions, sizeof (mbrPartitions));
	size_t partitionArrayPos = 0, partitionNumber;
	
	for (partitionNumber = 0;
		partitionNumber < array_capacity (mbrPartitions) && partitionArrayPos < partitionArrayCapacity;
		++partitionNumber)
	{
		const PartitionEntryMBR &partEntry = mbrPartitions[partitionNumber];
		
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
					MBR *extMbr = (MBR *) SectorBuffer;

					while (partitionArrayPos < partitionArrayCapacity &&
						(result = ReadSectors ((byte *) extMbr, drive, extStartLBA, 1, silent)) == BiosResultSuccess
						&& extMbr->Signature == 0xaa55)
					{
						if (extMbr->Partitions[0].SectorCountLBA > 0)
						{
							Partition &logPart = partitionArray[partitionArrayPos++];
							PartitionEntryMBRToPartition (extMbr->Partitions[0], logPart);
							logPart.Drive = drive;

							logPart.Number = partitionNumber++;
							logPart.Primary = false;

							logPart.StartSector.LowPart += extStartLBA.LowPart;
							logPart.EndSector.LowPart += extStartLBA.LowPart;
						}

						// Secondary extended
						if (extMbr->Partitions[1].Type != 0x5 && extMbr->Partitions[1].Type == 0xf
							|| extMbr->Partitions[1].SectorCountLBA == 0)
							break;

						extStartLBA.LowPart = extMbr->Partitions[1].StartLBA + firstExtStartLBA.LowPart;
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
