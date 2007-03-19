/*
 Legal Notice: The source code contained in this file has been derived from
 the source code of Encryption for the Masses 2.02a, which is Copyright (c)
 Paul Le Roux and which is covered by the 'License Agreement for Encryption
 for the Masses'. Modifications and additions to that source code contained
 in this file are Copyright (c) TrueCrypt Foundation and are covered by the
 TrueCrypt License 2.2 the full text of which is contained in the file
 License.txt included in TrueCrypt binary and source code distribution
 packages. */

#include "TCdefs.h"
#include "Crypto.h"
#include "Volumes.h"

#include "Apidrvr.h"
#include "Ntdriver.h"
#include "Ntvol.h"

#include "Cache.h"

#if 0 && _DEBUG
#define EXTRA_INFO 1
#endif

#pragma warning( disable : 4127 )

NTSTATUS
TCOpenVolume (PDEVICE_OBJECT DeviceObject,
	       PEXTENSION Extension,
	       MOUNT_STRUCT *mount,
	       PWSTR pwszMountVolume,
	       BOOL bRawDevice)
{
	FILE_STANDARD_INFORMATION FileStandardInfo;
	FILE_BASIC_INFORMATION FileBasicInfo;
	OBJECT_ATTRIBUTES oaFileAttributes;
	UNICODE_STRING FullFileName;
	IO_STATUS_BLOCK IoStatusBlock;
	PCRYPTO_INFO cryptoInfoPtr = NULL;
	PCRYPTO_INFO tmpCryptoInfo = NULL;
	LARGE_INTEGER lDiskLength;
	LARGE_INTEGER hiddenVolHeaderOffset;
	int volumeType;
	char *readBuffer = 0;
	NTSTATUS ntStatus = 0;

	Extension->pfoDeviceFile = NULL;
	Extension->hDeviceFile = NULL;
	Extension->bTimeStampValid = FALSE;

	RtlInitUnicodeString (&FullFileName, pwszMountVolume);
	InitializeObjectAttributes (&oaFileAttributes, &FullFileName, OBJ_CASE_INSENSITIVE,	NULL, NULL);
	KeInitializeEvent (&Extension->keVolumeEvent, NotificationEvent, FALSE);

	// If we are opening a device, query its size first
	if (bRawDevice)
	{
		PARTITION_INFORMATION pi;
		PARTITION_INFORMATION_EX pix;
		DISK_GEOMETRY dg;

		ntStatus = IoGetDeviceObjectPointer (&FullFileName,
			FILE_READ_DATA,
			&Extension->pfoDeviceFile,
			&Extension->pFsdDevice);

		if (!NT_SUCCESS (ntStatus))
			goto error;

		DeviceObject->StackSize = (CCHAR) (Extension->pFsdDevice->StackSize + 1);

		if (NT_SUCCESS (TCSendDeviceIoControlRequest (DeviceObject, Extension, IOCTL_DISK_GET_DRIVE_GEOMETRY, (char *) &dg, sizeof (dg))))
		{
			lDiskLength.QuadPart = dg.Cylinders.QuadPart * dg.SectorsPerTrack * dg.TracksPerCylinder * dg.BytesPerSector;
			mount->BytesPerSector = dg.BytesPerSector;
		}
		else
			lDiskLength.QuadPart = 0;

		// Drive geometry is used only when IOCTL_DISK_GET_PARTITION_INFO fails
		if (NT_SUCCESS (TCSendDeviceIoControlRequest (DeviceObject, Extension, IOCTL_DISK_GET_PARTITION_INFO_EX, (char *) &pix, sizeof (pix))))
			lDiskLength.QuadPart = pix.PartitionLength.QuadPart;
		// Windows 2000 does not support IOCTL_DISK_GET_PARTITION_INFO_EX
		else if (NT_SUCCESS (TCSendDeviceIoControlRequest (DeviceObject, Extension, IOCTL_DISK_GET_PARTITION_INFO, (char *) &pi, sizeof (pi))))
			lDiskLength.QuadPart = pi.PartitionLength.QuadPart;

		if (!mount->bMountReadOnly && TCDeviceIoControl (pwszMountVolume, IOCTL_DISK_IS_WRITABLE, NULL, 0, NULL, 0) == STATUS_MEDIA_WRITE_PROTECTED)
		{
			mount->bMountReadOnly = TRUE;
			DeviceObject->Characteristics |= FILE_READ_ONLY_DEVICE;
		}
	}

	if (mount->BytesPerSector == 0)
		mount->BytesPerSector = SECTOR_SIZE;

	Extension->HostBytesPerSector = mount->BytesPerSector;

	// Open the volume hosting file/device
	if (!mount->bMountReadOnly)
	{
		ntStatus = ZwCreateFile (&Extension->hDeviceFile,
			GENERIC_READ | GENERIC_WRITE | SYNCHRONIZE,
			&oaFileAttributes,
			&IoStatusBlock,
			NULL,
			FILE_ATTRIBUTE_NORMAL |
			FILE_ATTRIBUTE_SYSTEM,
			mount->bExclusiveAccess ? 0 : FILE_SHARE_READ | FILE_SHARE_WRITE,
			FILE_OPEN,
			FILE_RANDOM_ACCESS |
			FILE_WRITE_THROUGH |
			(Extension->HostBytesPerSector == SECTOR_SIZE ? FILE_NO_INTERMEDIATE_BUFFERING : 0) |
			FILE_SYNCHRONOUS_IO_NONALERT,
			NULL,
			0);
	}

	/* 26-4-99 NT for some partitions returns this code, it is really a	access denied */
	if (ntStatus == 0xc000001b)
		ntStatus = STATUS_ACCESS_DENIED;
	
	if (mount->bMountReadOnly || ntStatus == STATUS_ACCESS_DENIED)
	{
		ntStatus = ZwCreateFile (&Extension->hDeviceFile,
			GENERIC_READ | SYNCHRONIZE,
			&oaFileAttributes,
			&IoStatusBlock,
			NULL,
			FILE_ATTRIBUTE_NORMAL |
			FILE_ATTRIBUTE_SYSTEM,
			mount->bExclusiveAccess ? FILE_SHARE_READ : FILE_SHARE_READ | FILE_SHARE_WRITE,
			FILE_OPEN,
			FILE_RANDOM_ACCESS |
			FILE_WRITE_THROUGH |
			FILE_NO_INTERMEDIATE_BUFFERING |
			FILE_SYNCHRONOUS_IO_NONALERT,
			NULL,
			0);
		Extension->bReadOnly = TRUE;
	}
	else
		Extension->bReadOnly = FALSE;

	/* 26-4-99 NT for some partitions returns this code, it is really a
	access denied */
	if (ntStatus == 0xc000001b)
	{
		/* Partitions which return this code can still be opened with
		FILE_SHARE_READ but this causes NT problems elsewhere in
		particular if you do FILE_SHARE_READ NT will die later if
		anyone even tries to open the partition  (or file for that
		matter...)  */
		ntStatus = STATUS_SHARING_VIOLATION;
	}

	if (!NT_SUCCESS (ntStatus))
	{
		goto error;
	}

	// If we have opened a file, query its size now
	if (bRawDevice == FALSE)
	{
		ntStatus = ZwQueryInformationFile (Extension->hDeviceFile,
			&IoStatusBlock,
			&FileBasicInfo,
			sizeof (FileBasicInfo),
			FileBasicInformation);

		if (NT_SUCCESS (ntStatus))
		{
			if (mount->bPreserveTimestamp)
			{
				/* Remember the container timestamp. (Used to reset access/modification file date/time
				of file-hosted volumes upon dismount or after unsuccessful mount attempt to preserve
				plausible deniability of hidden volumes.) */
				Extension->fileCreationTime = FileBasicInfo.CreationTime;
				Extension->fileLastAccessTime = FileBasicInfo.LastAccessTime;
				Extension->fileLastWriteTime = FileBasicInfo.LastWriteTime;
				Extension->fileLastChangeTime = FileBasicInfo.ChangeTime;
				Extension->bTimeStampValid = TRUE;
			}

			ntStatus = ZwQueryInformationFile (Extension->hDeviceFile,
				&IoStatusBlock,
				&FileStandardInfo,
				sizeof (FileStandardInfo),
				FileStandardInformation);
		}

		if (!NT_SUCCESS (ntStatus))
		{
			Dump ("ZwQueryInformationFile failed while opening file: NTSTATUS 0x%08x\n",
				ntStatus);
			goto error;
		}

		lDiskLength.QuadPart = FileStandardInfo.EndOfFile.QuadPart;

		if (FileBasicInfo.FileAttributes & FILE_ATTRIBUTE_COMPRESSED)
		{
			Dump ("File \"%ls\" is marked as compressed - not supported!\n", pwszMountVolume);
			mount->nReturnCode = ERR_COMPRESSION_NOT_SUPPORTED;
			ntStatus = STATUS_SUCCESS;
			goto error;
		}

		ntStatus = ObReferenceObjectByHandle (Extension->hDeviceFile,
			FILE_ALL_ACCESS,
			*IoFileObjectType,
			KernelMode,
			&Extension->pfoDeviceFile,
			0);

		if (!NT_SUCCESS (ntStatus))
		{
			goto error;
		}

		/* Get the FSD device for the file (probably either NTFS or	FAT) */
		Extension->pFsdDevice = IoGetRelatedDeviceObject (Extension->pfoDeviceFile);

		DeviceObject->StackSize = (CCHAR) (Extension->pFsdDevice->StackSize + 1);
	}

	// Check volume size
	if (lDiskLength.QuadPart < MIN_VOLUME_SIZE || lDiskLength.QuadPart > MAX_VOLUME_SIZE)
	{
		mount->nReturnCode = ERR_VOL_SIZE_WRONG;
		ntStatus = STATUS_SUCCESS;
		goto error;
	}

	Extension->DiskLength = lDiskLength.QuadPart;

	hiddenVolHeaderOffset.QuadPart = lDiskLength.QuadPart - HIDDEN_VOL_HEADER_OFFSET;

	readBuffer = TCalloc (HEADER_SIZE);
	if (readBuffer == NULL)
	{
		ntStatus = STATUS_INSUFFICIENT_RESOURCES;
		goto error;
	}

	// Go through all volume types (e.g., normal, hidden)
	for (volumeType = VOLUME_TYPE_NORMAL;
		volumeType < NBR_VOLUME_TYPES;
		volumeType++)	
	{
		/* Read the volume header */

		ntStatus = ZwReadFile (Extension->hDeviceFile,
			NULL,
			NULL,
			NULL,
			&IoStatusBlock,
			readBuffer,
			HEADER_SIZE,
			volumeType == VOLUME_TYPE_HIDDEN ? &hiddenVolHeaderOffset : NULL,
			NULL);

		if (!NT_SUCCESS (ntStatus))
		{
			Dump ("Read failed: NTSTATUS 0x%08x\n", ntStatus);
		}
		else if (IoStatusBlock.Information != HEADER_SIZE)
		{
			Dump ("Read didn't read enough data in: %lu / %lu\n", IoStatusBlock.Information, HEADER_SIZE);
			ntStatus = STATUS_UNSUCCESSFUL;
		}

		if (!NT_SUCCESS (ntStatus))
		{
			goto error;
		}

		/* Attempt to recognize the volume (decrypt the header) */

		if (volumeType == VOLUME_TYPE_HIDDEN && mount->bProtectHiddenVolume)
		{
			mount->nReturnCode = VolumeReadHeaderCache (
				mount->bCache,
				readBuffer,
				&mount->ProtectedHidVolPassword,
				&tmpCryptoInfo);
		}
		else
		{
			mount->nReturnCode = VolumeReadHeaderCache (
				mount->bCache,
				readBuffer,
				&mount->VolumePassword,
				&Extension->cryptoInfo);
		}

		if (mount->nReturnCode == 0 || mount->nReturnCode == ERR_CIPHER_INIT_WEAK_KEY)
		{
			/* Volume header successfully decrypted */

			Extension->cryptoInfo->bProtectHiddenVolume = FALSE;
			Extension->cryptoInfo->bHiddenVolProtectionAction = FALSE;

			switch (volumeType)
			{
			case VOLUME_TYPE_NORMAL:

				// Correct the volume size for this volume type. Later on, this must be undone
				// if Extension->DiskLength is used in deriving hidden volume offset
				Extension->DiskLength -= HEADER_SIZE;	
				Extension->cryptoInfo->hiddenVolume = FALSE;

				break;

			case VOLUME_TYPE_HIDDEN:

				cryptoInfoPtr = mount->bProtectHiddenVolume ? tmpCryptoInfo : Extension->cryptoInfo;

				// Validate the size of the hidden volume specified in the header
				if (Extension->DiskLength < (__int64) cryptoInfoPtr->hiddenVolumeSize + HIDDEN_VOL_HEADER_OFFSET + HEADER_SIZE
					|| cryptoInfoPtr->hiddenVolumeSize <= 0)
				{
					mount->nReturnCode = ERR_VOL_SIZE_WRONG;
					ntStatus = STATUS_SUCCESS;
					goto error;
				}

				// Determine the offset of the hidden volume
				Extension->cryptoInfo->hiddenVolumeOffset = Extension->DiskLength - cryptoInfoPtr->hiddenVolumeSize - HIDDEN_VOL_HEADER_OFFSET;

				Dump("Hidden volume size = %I64d", cryptoInfoPtr->hiddenVolumeSize);
				Dump("Hidden volume offset = %I64d", Extension->cryptoInfo->hiddenVolumeOffset);

				// Validate the offset
				if (Extension->cryptoInfo->hiddenVolumeOffset % SECTOR_SIZE != 0)
				{
					mount->nReturnCode = ERR_VOL_SIZE_WRONG;
					ntStatus = STATUS_SUCCESS;
					goto error;
				}

				// If we are supposed to actually mount the hidden volume (not just to protect it)
				if (!mount->bProtectHiddenVolume)	
				{
					Extension->DiskLength = cryptoInfoPtr->hiddenVolumeSize;
					Extension->cryptoInfo->hiddenVolume = TRUE;
				}
				else
				{
					// Hidden volume protection
					Extension->cryptoInfo->hiddenVolume = FALSE;
					Extension->cryptoInfo->bProtectHiddenVolume = TRUE;
					Extension->cryptoInfo->hiddenVolumeOffset += HEADER_SIZE;	// Offset was incorrect due to loop processing
					Dump("Hidden volume protection active (offset = %I64d)", Extension->cryptoInfo->hiddenVolumeOffset);
				}

				break;
			}

			// If this is a hidden volume, make sure we are supposed to actually
			// mount it (i.e. not just to protect it)
			if (!(volumeType == VOLUME_TYPE_HIDDEN && mount->bProtectHiddenVolume))	
			{
				// Calculate virtual volume geometry
				Extension->TracksPerCylinder = 1;
				Extension->SectorsPerTrack = 1;
				Extension->BytesPerSector = SECTOR_SIZE;
				Extension->NumberOfCylinders = Extension->DiskLength / SECTOR_SIZE;
				Extension->PartitionType = 0;

				Extension->bRawDevice = bRawDevice;
				
				memset (Extension->wszVolume, 0, sizeof (Extension->wszVolume));
				if (wcsstr (pwszMountVolume, WIDE ("\\??\\UNC\\")) == pwszMountVolume)
				{
					/* UNC path */
					_snwprintf (Extension->wszVolume,
						sizeof (Extension->wszVolume) / sizeof (WCHAR) - 1,
						WIDE ("\\??\\\\%s"),
						pwszMountVolume + 7);
				}
				else
				{
					wcsncpy (Extension->wszVolume, pwszMountVolume, sizeof (Extension->wszVolume) / sizeof (WCHAR) - 1);
				}
			}

			// If we are to protect a hidden volume we cannot exit yet, for we must also
			// decrypt the hidden volume header.
			if (!(volumeType == VOLUME_TYPE_NORMAL && mount->bProtectHiddenVolume))
			{
				TCfree (readBuffer);

				if (tmpCryptoInfo != NULL)
					crypto_close (tmpCryptoInfo);
				
				return STATUS_SUCCESS;
			}
		}
		else if (mount->bProtectHiddenVolume
			  || mount->nReturnCode != ERR_PASSWORD_WRONG)
		{
			 /* If we are not supposed to protect a hidden volume, the only error that is
				tolerated is ERR_PASSWORD_WRONG (to allow mounting a possible hidden volume). 

				If we _are_ supposed to protect a hidden volume, we do not tolerate any error
				(both volume headers must be successfully decrypted). */

			break;
		}
	}

	/* Failed due to some non-OS reason so we drop through and return NT
	   SUCCESS then nReturnCode is checked later in user-mode */

	if (mount->nReturnCode == ERR_OUTOFMEMORY)
		ntStatus = STATUS_INSUFFICIENT_RESOURCES;
	else
		ntStatus = STATUS_SUCCESS;

error:
	if (Extension->bTimeStampValid)
	{
		/* Restore the container timestamp to preserve plausible deniability of possible hidden volume. */
		RestoreTimeStamp (Extension);
	}

	/* Close the hDeviceFile */
	if (Extension->hDeviceFile != NULL)
		ZwClose (Extension->hDeviceFile);

	/* The cryptoInfo pointer is deallocated if the readheader routines
	   fail so there is no need to deallocate here  */

	/* Dereference the user-mode file object */
	if (Extension->pfoDeviceFile != NULL)
		ObDereferenceObject (Extension->pfoDeviceFile);

	/* Free the tmp IO buffers */
	if (readBuffer != NULL)
		TCfree (readBuffer);

	return ntStatus;
}

void
TCCloseVolume (PDEVICE_OBJECT DeviceObject, PEXTENSION Extension)
{
	if (DeviceObject);	/* Remove compiler warning */

	if (Extension->hDeviceFile != NULL)
	{
		if (Extension->bRawDevice == FALSE
			&& Extension->bTimeStampValid)
		{
			/* Restore the container timestamp to preserve plausible deniability of possible hidden volume. */
			RestoreTimeStamp (Extension);
		}
		ZwClose (Extension->hDeviceFile);
	}
	ObDereferenceObject (Extension->pfoDeviceFile);
	crypto_close (Extension->cryptoInfo);
}


NTSTATUS
TCReadWrite (PDEVICE_OBJECT DeviceObject, PEXTENSION Extension, PIRP Irp)
{
	PIO_STACK_LOCATION irpSp = IoGetCurrentIrpStackLocation (Irp);
	PUCHAR currentAddress;
	PUCHAR tmpBuffer;
	NTSTATUS ntStatus;
	BOOL lowerPriority = (OsMajorVersion >= 6 && KeNumberProcessors == 1);

#if EXTRA_INFO
	Dump ("USER BUFFER IS 0x%08x MDL ADDRESS IS 0x%08x\n", Irp->UserBuffer, Irp->MdlAddress);
	Dump ("Irp->Tail.Overlay.OriginalFileObject = 0x%08x\n", Irp->Tail.Overlay.OriginalFileObject);
	Dump ("irpSp->FileObject = 0x%08x\n", irpSp->FileObject);

	if (Irp->Tail.Overlay.OriginalFileObject != NULL)
	{
		if (Irp->Tail.Overlay.OriginalFileObject->FileName.Length != 0)
			Dump ("Irp->Tail.Overlay.OriginalFileObject = %ls\n", Irp->Tail.Overlay.OriginalFileObject->FileName.Buffer);
		else
			Dump ("Irp->Tail.Overlay.OriginalFileObject = %ls\n", WIDE ("null value"));

	}

	if (irpSp->FileObject != NULL)
	{
		if (irpSp->FileObject->FileName.Length != 0)
			Dump ("irpSp->FileObject = %ls\n", irpSp->FileObject->FileName.Buffer);
		else
			Dump ("irpSp->FileObject = %ls\n", WIDE ("null value"));

	}
#endif

	currentAddress = (PUCHAR) MmGetSystemAddressForMdlSafe (Irp->MdlAddress, HighPagePriority);
	if (currentAddress == NULL)
		return COMPLETE_IRP (DeviceObject, Irp, STATUS_INSUFFICIENT_RESOURCES, 0);

	if (irpSp->MajorFunction == IRP_MJ_READ)
	{
		LARGE_INTEGER readOffset;

		readOffset.QuadPart = irpSp->Parameters.Read.ByteOffset.QuadPart;

		if (irpSp->Parameters.Read.Length == 0
			|| (irpSp->Parameters.Read.Length & (SECTOR_SIZE - 1))
			|| readOffset.QuadPart + irpSp->Parameters.Read.Length > Extension->DiskLength)
		{
			return COMPLETE_IRP (DeviceObject, Irp, STATUS_INVALID_PARAMETER, 0);
		}

		if (Extension->cryptoInfo->hiddenVolume)
			readOffset.QuadPart += Extension->cryptoInfo->hiddenVolumeOffset;
		else
			readOffset.QuadPart += HEADER_SIZE;  

		tmpBuffer = TCalloc (irpSp->Parameters.Read.Length);
		if (tmpBuffer == NULL)
			return COMPLETE_IRP (DeviceObject, Irp, STATUS_INSUFFICIENT_RESOURCES, 0);

		ntStatus = ZwReadFile (Extension->hDeviceFile,
			NULL,
			NULL,
			NULL,
			&Irp->IoStatus,
			tmpBuffer,
			irpSp->Parameters.Read.Length,
			&readOffset,
			NULL);

		Irp->IoStatus.Status = ntStatus;

		if (NT_SUCCESS(ntStatus))
		{
			Extension->TotalBytesRead += irpSp->Parameters.Read.Length;

			memcpy (currentAddress, tmpBuffer, irpSp->Parameters.Read.Length);

			if (lowerPriority)
				KeSetPriorityThread (KeGetCurrentThread (), LOW_REALTIME_PRIORITY - 5);

			DecryptSectors ((ULONG *) currentAddress,
				readOffset.QuadPart / SECTOR_SIZE,
				irpSp->Parameters.Read.Length / SECTOR_SIZE,
				Extension->cryptoInfo);

			if (lowerPriority)
				KeSetPriorityThread (KeGetCurrentThread (), LOW_REALTIME_PRIORITY);
		}

		TCfree (tmpBuffer);
	}
	else if (irpSp->MajorFunction == IRP_MJ_WRITE)
	{
		LARGE_INTEGER writeOffset;

		if (Extension->bReadOnly)
			return COMPLETE_IRP (DeviceObject, Irp, STATUS_MEDIA_WRITE_PROTECTED, 0);

		writeOffset.QuadPart = irpSp->Parameters.Write.ByteOffset.QuadPart;

		if (irpSp->Parameters.Write.Length == 0
			|| (irpSp->Parameters.Write.Length & (SECTOR_SIZE - 1))
			|| writeOffset.QuadPart + irpSp->Parameters.Write.Length > Extension->DiskLength)
		{
			return COMPLETE_IRP (DeviceObject, Irp, STATUS_INVALID_PARAMETER, 0);
		}

		// Hidden volume protection
		if (Extension->cryptoInfo->bProtectHiddenVolume)
		{
			// If there has already been a write operation denied in order to protect the
			// hidden volume (since the volume mount time)
			if (Extension->cryptoInfo->bHiddenVolProtectionAction)	
			{
				// Do not allow writing to this volume anymore. This is to fake a complete volume
				// or system failure (otherwise certain kinds of inconsistency within the file
				// system could indicate that this volume has used hidden volume protection).
				return COMPLETE_IRP (DeviceObject, Irp, STATUS_INVALID_PARAMETER, 0);
			}

			// Verify that no byte is going to be written to the hidden volume area
			if (RegionsOverlap ((unsigned __int64) irpSp->Parameters.Write.ByteOffset.QuadPart + HEADER_SIZE,
								(unsigned __int64) irpSp->Parameters.Write.ByteOffset.QuadPart + HEADER_SIZE + irpSp->Parameters.Write.Length - 1,
								Extension->cryptoInfo->hiddenVolumeOffset,
								(unsigned __int64) Extension->DiskLength + HEADER_SIZE - (HIDDEN_VOL_HEADER_OFFSET - HEADER_SIZE) - 1))
			{
				Extension->cryptoInfo->bHiddenVolProtectionAction = TRUE;

				// Deny this write operation to prevent the hidden volume from being overwritten
				return COMPLETE_IRP (DeviceObject, Irp, STATUS_INVALID_PARAMETER, 0);
			}
		}

		if (Extension->cryptoInfo->hiddenVolume)
			writeOffset.QuadPart += Extension->cryptoInfo->hiddenVolumeOffset;
		else
			writeOffset.QuadPart += HEADER_SIZE;

		tmpBuffer = TCalloc (irpSp->Parameters.Write.Length);
		if (tmpBuffer == NULL)
			return COMPLETE_IRP (DeviceObject, Irp, STATUS_INSUFFICIENT_RESOURCES, 0);

		memcpy (tmpBuffer, currentAddress, irpSp->Parameters.Write.Length);

		if (lowerPriority)
 			KeSetPriorityThread (KeGetCurrentThread (), LOW_REALTIME_PRIORITY - 5);

		EncryptSectors ((ULONG *) tmpBuffer,
			writeOffset.QuadPart / SECTOR_SIZE,
			irpSp->Parameters.Write.Length / SECTOR_SIZE,
			Extension->cryptoInfo);
		
		if (lowerPriority)
 			KeSetPriorityThread (KeGetCurrentThread (), LOW_REALTIME_PRIORITY);

		ntStatus = ZwWriteFile (Extension->hDeviceFile,
			NULL,
			NULL,
			NULL,
			&Irp->IoStatus,
			tmpBuffer,
			irpSp->Parameters.Write.Length,
			&writeOffset,
			NULL);

		Irp->IoStatus.Status = ntStatus;

		if (NT_SUCCESS(ntStatus))
			Extension->TotalBytesWritten += irpSp->Parameters.Write.Length;

		TCfree (tmpBuffer);
	}
	else
		return COMPLETE_IRP (DeviceObject, Irp, STATUS_INVALID_PARAMETER, 0);

	IoCompleteRequest (Irp, NT_SUCCESS(ntStatus) ? IO_DISK_INCREMENT : IO_NO_INCREMENT);
	return ntStatus;
}


NTSTATUS
TCSendDeviceIoControlRequest (PDEVICE_OBJECT DeviceObject,
			       PEXTENSION Extension,
			       ULONG IoControlCode,
			       char *OutputBuffer,
			       int OutputBufferSize)
{
	IO_STATUS_BLOCK IoStatusBlock;
	NTSTATUS ntStatus;
	PIRP Irp;

	if (DeviceObject);	/* Remove compiler warning */

	KeClearEvent (&Extension->keVolumeEvent);

	Irp = IoBuildDeviceIoControlRequest (IoControlCode,
					     Extension->pFsdDevice,
					     NULL, 0,
					     OutputBuffer, OutputBufferSize,
					     FALSE,
					     &Extension->keVolumeEvent,
					     &IoStatusBlock);

	if (Irp == NULL)
	{
		Dump ("IRP allocation failed\n");
		return STATUS_INSUFFICIENT_RESOURCES;
	}

	// Disk device may be used by filesystem driver which needs file object
	IoGetNextIrpStackLocation (Irp) -> FileObject = Extension->pfoDeviceFile;

	ntStatus = IoCallDriver (Extension->pFsdDevice, Irp);
	if (ntStatus == STATUS_PENDING)
	{
		KeWaitForSingleObject (&Extension->keVolumeEvent, UserRequest, UserMode, FALSE, NULL);
		ntStatus = IoStatusBlock.Status;
	}

	return ntStatus;
}

NTSTATUS
COMPLETE_IRP (PDEVICE_OBJECT DeviceObject,
	      PIRP Irp,
	      NTSTATUS IrpStatus,
	      ULONG_PTR IrpInformation)
{
	Irp->IoStatus.Status = IrpStatus;
	Irp->IoStatus.Information = IrpInformation;

	if (DeviceObject);	/* Remove compiler warning */

#if EXTRA_INFO
	if (!NT_SUCCESS (IrpStatus))
	{
		PIO_STACK_LOCATION irpSp = IoGetCurrentIrpStackLocation (Irp);
		Dump ("COMPLETE_IRP FAILING IRP %ls Flags 0x%08x vpb 0x%08x NTSTATUS 0x%08x\n", TCTranslateCode (irpSp->MajorFunction),
		      (ULONG) DeviceObject->Flags, (ULONG) DeviceObject->Vpb->Flags, IrpStatus);
	}
	else
	{
		PIO_STACK_LOCATION irpSp = IoGetCurrentIrpStackLocation (Irp);
		Dump ("COMPLETE_IRP SUCCESS IRP %ls Flags 0x%08x vpb 0x%08x NTSTATUS 0x%08x\n", TCTranslateCode (irpSp->MajorFunction),
		      (ULONG) DeviceObject->Flags, (ULONG) DeviceObject->Vpb->Flags, IrpStatus);
	}
#endif
	IoCompleteRequest (Irp, IO_NO_INCREMENT);
	return IrpStatus;
}

// Restores the container timestamp to preserve plausible deniability of possible hidden volume.
static void RestoreTimeStamp (PEXTENSION Extension)
{
	NTSTATUS ntStatus;
	FILE_BASIC_INFORMATION FileBasicInfo;
	IO_STATUS_BLOCK IoStatusBlock;

	if (Extension->hDeviceFile != NULL 
		&& Extension->bRawDevice == FALSE 
		&& Extension->bReadOnly == FALSE
		&& Extension->bTimeStampValid)
	{
		ntStatus = ZwQueryInformationFile (Extension->hDeviceFile,
			&IoStatusBlock,
			&FileBasicInfo,
			sizeof (FileBasicInfo),
			FileBasicInformation); 

		if (!NT_SUCCESS (ntStatus))
		{
			Dump ("ZwQueryInformationFile failed in RestoreTimeStamp: NTSTATUS 0x%08x\n",
				ntStatus);
		}
		else
		{
			FileBasicInfo.CreationTime = Extension->fileCreationTime;
			FileBasicInfo.LastAccessTime = Extension->fileLastAccessTime;
			FileBasicInfo.LastWriteTime = Extension->fileLastWriteTime;
			FileBasicInfo.ChangeTime = Extension->fileLastChangeTime;

			ntStatus = ZwSetInformationFile(
				Extension->hDeviceFile,
				&IoStatusBlock,
				&FileBasicInfo,
				sizeof (FileBasicInfo),
				FileBasicInformation); 

			if (!NT_SUCCESS (ntStatus))
				Dump ("ZwSetInformationFile failed in RestoreTimeStamp: NTSTATUS 0x%08x\n",ntStatus);
		}
	}
}
