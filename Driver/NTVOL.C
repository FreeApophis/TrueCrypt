/* Legal Notice: The source code contained in this file has been derived from
   the source code of Encryption for the Masses 2.02a, which is Copyright (c)
   1998-99 Paul Le Roux and which is covered by the 'License Agreement for
   Encryption for the Masses'. Modifications and additions to that source code
   contained in this file are Copyright (c) 2004-2006 TrueCrypt Foundation and
   Copyright (c) 2004 TrueCrypt Team, and are covered by TrueCrypt License 2.0
   the full text of which is contained in the file License.txt included in
   TrueCrypt binary and source code distribution archives.  */

#include "TCdefs.h"
#include "Crypto.h"
#include "Volumes.h"

#include "Apidrvr.h"
#include "Ntdriver.h"
#include "Ntvol.h"
#include "Ntrawdv.h"
#include "Ntfiledv.h"

#include "Cache.h"

//#ifdef _DEBUG
//#define EXTRA_INFO 1
//#endif

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
		DISK_GEOMETRY dg;

		ntStatus = IoGetDeviceObjectPointer (&FullFileName,
			FILE_READ_DATA,
			&Extension->pfoDeviceFile,
			&Extension->pFsdDevice);

		if (!NT_SUCCESS (ntStatus))
		{
			goto error;
		}

		DeviceObject->StackSize = (CCHAR) (Extension->pFsdDevice->StackSize + 1);

		// Query partition size
		ntStatus = TCSendDeviceIoControlRequest (DeviceObject,
			Extension, IOCTL_DISK_GET_PARTITION_INFO,
			(char *) &pi, sizeof (pi));

		if (NT_SUCCESS (ntStatus))
		{
			lDiskLength.QuadPart = pi.PartitionLength.QuadPart;
		}
		else
		{
			// Drive geometry info is used only when IOCTL_DISK_GET_PARTITION_INFO fails
			ntStatus = TCSendDeviceIoControlRequest (DeviceObject,
				Extension, IOCTL_DISK_GET_DRIVE_GEOMETRY,
				(char *) &dg, sizeof (dg));

			if (!NT_SUCCESS (ntStatus))
				goto error;

			lDiskLength.QuadPart = dg.Cylinders.QuadPart * dg.SectorsPerTrack *
				dg.TracksPerCylinder * dg.BytesPerSector;
		}
	}

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
			FILE_WRITE_THROUGH |
			FILE_NO_INTERMEDIATE_BUFFERING |
			FILE_SYNCHRONOUS_IO_NONALERT,
			NULL,
			0);
	}

	/* 26-4-99 NT for some partitions returns this code, it is really a
	access denied */
	if (ntStatus == 0xc000001b)
	{
		ntStatus = STATUS_ACCESS_DENIED;
	}
	
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
				Extension->BytesPerSector = 512;
				Extension->NumberOfCylinders = Extension->DiskLength / 512;
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

/* This rountine can be called at any IRQL so we need to tread carefully. Not
   even DbgPrint or KdPrint are called here as the kernel sometimes faults if
   they are called at high IRQL */

NTSTATUS
TCCompletion (PDEVICE_OBJECT DeviceObject, PIRP Irp, PVOID pUserBuffer)
{
	PIO_STACK_LOCATION irpSp;
	PEXTENSION Extension;
	NTSTATUS ntStatus;

	Extension = (PEXTENSION) DeviceObject->DeviceExtension;

	/* Check to make sure the DeviceObject passed in is actually ours! */
	if (Extension->lMagicNumber != 0xabfeacde)
		KeBugCheck ((ULONG) 0xabfeacde);

	ASSERT (Extension->nDosDriveNo >= 0 && Extension->nDosDriveNo <= 0x19);

#ifdef USE_KERNEL_MUTEX
	KeWaitForMutexObject (&Extension->KernelMutex, Executive, KernelMode,
			      FALSE, NULL);
#endif

#if EXTRA_INFO
	Dump ("Completing IRP...BEGIN\n");
	Dump ("COMPLETION USER BUFFER IS 0x%08x MDL ADDRESS IS 0x%08x\n", Irp->UserBuffer, Irp->MdlAddress);
	Dump ("COMPLETION Irp->Tail.Overlay.OriginalFileObject = 0x%08x\n", Irp->Tail.Overlay.OriginalFileObject);
	Dump ("Completing DeviceObject 0x%08x Irp 0x%08x\n", DeviceObject, Irp);
#endif

	/* Note: The Irp stack location we get back here is our one, we setup
	   the next stack location with a copy of this stack data in the send
	   function... here we always get back our own stack location, so
	   it's possible to use Read.Key to store extra pointers if needed. */
	irpSp = IoGetCurrentIrpStackLocation (Irp);

	ntStatus = Irp->IoStatus.Status;

	if (ntStatus == STATUS_TOO_LATE)
		KeBugCheck ((ULONG) 0x50ff);

	if (Irp->PendingReturned)	/* From Windows NT File System
					   Internals */
		IoMarkIrpPending (Irp);

	if (Extension->bRawDevice == FALSE)
	{
		/* Note: For some reason even though we used DIRECT_IO
		   sometimes the Irp's come back to use with MDLs !! if we
		   get an MDL here we need to free it up otherwise later when
		   we call IoFreeIrp the system will trap */

		PMDL pMdl, pNextMdl;

		pMdl = Irp->MdlAddress;

		while (pMdl != NULL)
		{
			pNextMdl = pMdl->Next;

			MmUnmapLockedPages (MmGetSystemAddressForMdlSafe (pMdl, HighPagePriority), pMdl);
			MmUnlockPages (pMdl);
			IoFreeMdl (pMdl);

			pMdl = pNextMdl;
		}
	}

	if (NT_SUCCESS (Irp->IoStatus.Status) && irpSp->MajorFunction == IRP_MJ_READ)
	{
		__int64 tmpOffset = irpSp->Parameters.Read.ByteOffset.QuadPart;
		ULONG tmpLength = irpSp->Parameters.Read.Length;
		PUCHAR CurrentAddress;

		if (Extension->bRawDevice)
			CurrentAddress = MmGetSystemAddressForMdlSafe (Irp->MdlAddress, HighPagePriority);
		else
			CurrentAddress = Irp->UserBuffer;

		if (tmpLength > 0)
		{
			/* Decrypt the data on read */
			DecryptSectors ((ULONG *) CurrentAddress,
				tmpOffset / SECTOR_SIZE,
				tmpLength / SECTOR_SIZE,
				Extension->cryptoInfo);
		}

		if (Extension->bRawDevice == FALSE)
		{
			PIRP OldIrp = (PIRP) pUserBuffer;
			PUCHAR OriginalAddress;
			CurrentAddress = Irp->UserBuffer;
			OriginalAddress = MmGetSystemAddressForMdlSafe (OldIrp->MdlAddress, HighPagePriority);
			memcpy (OriginalAddress, CurrentAddress, Irp->IoStatus.Information);
		}

	}

	if (NT_SUCCESS (Irp->IoStatus.Status) && irpSp->MajorFunction == IRP_MJ_WRITE)
	{
		PUCHAR CurrentAddress;
		PUCHAR OriginalAddress;

		if (Extension->bRawDevice)
		{
			CurrentAddress = MmGetSystemAddressForMdlSafe (Irp->MdlAddress, HighPagePriority);
			OriginalAddress = MmGetSystemAddressForMdlSafe ((PMDL) pUserBuffer, HighPagePriority);
		}
		else
		{
			PIRP OldIrp = (PIRP) pUserBuffer;
			CurrentAddress = Irp->UserBuffer;
			OriginalAddress = MmGetSystemAddressForMdlSafe (OldIrp->MdlAddress, HighPagePriority);
		}
	}

	if (Extension->bRawDevice && irpSp->MajorFunction == IRP_MJ_WRITE)
	{
		PUCHAR tmpBuffer = MmGetSystemAddressForMdlSafe (Irp->MdlAddress, HighPagePriority);
		/* Free the temp buffer we allocated */
		TCfree (tmpBuffer);
		/* Free the Mdl we allocated */
		IoFreeMdl (Irp->MdlAddress);
		/* Reset the Irp */
		Irp->MdlAddress = pUserBuffer;
	}

	if (Extension->bRawDevice && irpSp->MajorFunction == IRP_MJ_READ)
	{
		/* Nothing to do */
	}

#if EXTRA_INFO
	Dump ("COMPLETION OLD USER BUFFER IS 0x%08x MDL ADDRESS IS 0x%08x\n", Irp->UserBuffer, Irp->MdlAddress);
	Dump ("COMPLETION OLD Irp->Tail.Overlay.OriginalFileObject = 0x%08x\n", Irp->Tail.Overlay.OriginalFileObject);
	Dump ("Completing IRP 0x%08x NTSTATUS 0x%08x information %lu END\n", (ULONG) irpSp->MajorFunction,
	      Irp->IoStatus.Status, Irp->IoStatus.Information);
#endif

	if (Extension->bRawDevice == FALSE)
	{
		PIRP OldIrp = (PIRP) pUserBuffer;
		PVOID tmpBuffer = Irp->UserBuffer;
		BOOL bFreeBuffer = irpSp->MajorFunction == IRP_MJ_WRITE || irpSp->MajorFunction == IRP_MJ_READ;

		OldIrp->IoStatus.Status = Irp->IoStatus.Status;
		OldIrp->IoStatus.Information = Irp->IoStatus.Information;

		IoCompleteRequest (OldIrp, IO_DISK_INCREMENT);

#if EXTRA_INFO
		Dump ("About to free allocated IRP\n");
#endif

		Irp->UserBuffer = NULL;

		/* Free the allocated IRP. Note: This must be done before we
		   free tmpBuffer! */
		IoFreeIrp (Irp);

		/* Note: From here on we cannot touch the Irp or irpSp */

#if EXTRA_INFO
		Dump ("Free allocated buffer = %d\n", bFreeBuffer);
#endif

		if (bFreeBuffer)
			TCfree (tmpBuffer);

		ntStatus = STATUS_MORE_PROCESSING_REQUIRED;
	}

#ifdef USE_KERNEL_MUTEX
	KeReleaseMutex (&Extension->KernelMutex, FALSE);
#endif

	return ntStatus;
}

NTSTATUS
TCReadWrite (PDEVICE_OBJECT DeviceObject, PEXTENSION Extension, PIRP Irp)
{
	PIO_STACK_LOCATION irpSp = IoGetCurrentIrpStackLocation (Irp);
	PUCHAR tmpBuffer = NULL;/* Remove compiler warning */
	NTSTATUS ntStatus;

//	Dump ("TCReadWrite BEGIN\n");

	/* Check for invalid parameters.  It is an error for the starting
	   offset + length to go past the end of the buffer, or for the
	   length to not be a proper multiple of the sector size. Others are
	   possible, but we don't check them since we trust the file system
	   and they aren't deadly.  */
	if (irpSp->Parameters.Read.ByteOffset.QuadPart + irpSp->Parameters.Read.Length > Extension->DiskLength
		|| (irpSp->Parameters.Read.Length & (Extension->BytesPerSector - 1)))
	{
		return COMPLETE_IRP (DeviceObject, Irp, STATUS_INVALID_PARAMETER, 0);
	}
	else
	{
		if (irpSp->Parameters.Read.Length == 0)
		{
			return COMPLETE_IRP (DeviceObject, Irp, STATUS_INVALID_PARAMETER, 0);
		}
	}

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

	// Volume protection
	if (irpSp->MajorFunction == IRP_MJ_WRITE)
	{
		// Read-only mode
		if (Extension->bReadOnly)
			return COMPLETE_IRP (DeviceObject, Irp, STATUS_MEDIA_WRITE_PROTECTED, 0);

		// Hidden volume protection
		if (Extension->cryptoInfo->bProtectHiddenVolume)
		{
			// If there has already been a write operation denied in order to protect the
			// hidden volume (since the volume mount time)
			if (Extension->cryptoInfo->bHiddenVolProtectionAction)	
			{
				Dump("Write operation denied due to a previous hidden volume protection action");

				// Do not allow writing to this volume anymore. This is to fake a complete volume
				// or system failure (otherwise certain kinds of inconsistency within the file
				// system could indicate that this volume has used hidden volume protection).
				return COMPLETE_IRP (DeviceObject, Irp, STATUS_INVALID_PARAMETER, 0);
			}

			// Verify that no byte is going to be written to the hidden volume area
			if (RegionsOverlap ((unsigned __int64) irpSp->Parameters.Read.ByteOffset.QuadPart + HEADER_SIZE,
								(unsigned __int64) irpSp->Parameters.Read.ByteOffset.QuadPart + HEADER_SIZE + irpSp->Parameters.Read.Length - 1,
								Extension->cryptoInfo->hiddenVolumeOffset,
								(unsigned __int64) Extension->DiskLength + HEADER_SIZE - (HIDDEN_VOL_HEADER_OFFSET - HEADER_SIZE) - 1))
			{
				Extension->cryptoInfo->bHiddenVolProtectionAction = TRUE;
				Dump("Write operation denied (offset = %I64d) to protect hidden volume", irpSp->Parameters.Read.ByteOffset.QuadPart);

				// Deny this write operation to prevent the hidden volume from being overwritten
				return COMPLETE_IRP (DeviceObject, Irp, STATUS_INVALID_PARAMETER, 0);
			}

		}
	}

	if (Extension->bRawDevice == FALSE || irpSp->MajorFunction == IRP_MJ_WRITE)
	{
		tmpBuffer = TCalloc (irpSp->Parameters.Read.Length);
		if (tmpBuffer == NULL)
			return COMPLETE_IRP (DeviceObject, Irp, STATUS_INSUFFICIENT_RESOURCES, 0);
	}

	if (irpSp->MajorFunction == IRP_MJ_READ)
	{
//		Dump ("Read: 0x%08x for %lu bytes...\n", irpSp->Parameters.Read.ByteOffset.LowPart,
//		      irpSp->Parameters.Read.Length);

		Extension->TotalBytesRead += irpSp->Parameters.Read.Length;

		if (Extension->cryptoInfo->hiddenVolume)
		{
			/* Hidden volume offset */
			irpSp->Parameters.Read.ByteOffset.QuadPart += Extension->cryptoInfo->hiddenVolumeOffset;
		}
		else
		{
			/* Fixup the parameters to handle this particular volume type */
			irpSp->Parameters.Read.ByteOffset.QuadPart += HEADER_SIZE;  
		}

		if (Extension->bRawDevice)
			ntStatus = TCSendIRP_RawDevice (DeviceObject, Extension,
				     NULL, IRP_READ_OPERATION | IRP_NOCACHE,
						       irpSp->MajorFunction, Irp);
		else
			ntStatus = TCSendIRP_FileDevice (DeviceObject, Extension,
				tmpBuffer, IRP_READ_OPERATION | IRP_NOCACHE,
						       irpSp->MajorFunction, Irp);
	}
	else
	{
		PUCHAR CurrentAddress;

//		Dump ("Write: 0x%08x for %lu bytes...\n", irpSp->Parameters.Read.ByteOffset.LowPart,
//		      irpSp->Parameters.Read.Length);

		Extension->TotalBytesWritten += irpSp->Parameters.Read.Length;

		CurrentAddress = (PUCHAR) MmGetSystemAddressForMdlSafe (Irp->MdlAddress, HighPagePriority);

		if (Extension->cryptoInfo->hiddenVolume)
		{
			/* Hidden volume offset */
			irpSp->Parameters.Read.ByteOffset.QuadPart += Extension->cryptoInfo->hiddenVolumeOffset;
		}
		else
		{
			/* Fixup the parameters to handle this particular volume type */
			irpSp->Parameters.Read.ByteOffset.QuadPart += HEADER_SIZE;
		}

		memcpy (tmpBuffer, CurrentAddress, irpSp->Parameters.Read.Length);

		/* Encrypt the data */
		EncryptSectors ((ULONG *) tmpBuffer,
			irpSp->Parameters.Read.ByteOffset.QuadPart / SECTOR_SIZE,
			irpSp->Parameters.Read.Length / SECTOR_SIZE,
			Extension->cryptoInfo);

		if (Extension->bRawDevice)
		{
			PMDL tmpBufferMdl = IoAllocateMdl (tmpBuffer, irpSp->Parameters.Read.Length, FALSE, FALSE, NULL);
			PMDL pTrueMdl = Irp->MdlAddress;

			if (tmpBufferMdl == NULL)
			{
				TCfree (tmpBuffer);
				return COMPLETE_IRP (DeviceObject, Irp, STATUS_INSUFFICIENT_RESOURCES, 0);
			}

			MmBuildMdlForNonPagedPool (tmpBufferMdl);

			Irp->MdlAddress = tmpBufferMdl;

#if EXTRA_INFO
			Dump ("NEW MDL ADDRESS IS 0x%08x UserBuffer = 0x%08x\n", Irp->MdlAddress, Irp->UserBuffer);
#endif

			ntStatus = TCSendIRP_RawDevice (DeviceObject, Extension,
				pTrueMdl, IRP_WRITE_OPERATION | IRP_NOCACHE,
						       irpSp->MajorFunction, Irp);
		}
		else
		{
			ntStatus = TCSendIRP_FileDevice (DeviceObject, Extension,
			       tmpBuffer, IRP_WRITE_OPERATION | IRP_NOCACHE,
						       irpSp->MajorFunction, Irp);
		}
	}

//	Dump ("TCReadWrite END\n");
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

#ifdef _DEBUG
	//if (!NT_SUCCESS (IrpStatus))
	//{
	//	PIO_STACK_LOCATION irpSp = IoGetCurrentIrpStackLocation (Irp);
	//	Dump ("COMPLETE_IRP FAILING IRP %ls Flags 0x%08x vpb 0x%08x NTSTATUS 0x%08x\n", TCTranslateCode (irpSp->MajorFunction),
	//	      (ULONG) DeviceObject->Flags, (ULONG) DeviceObject->Vpb->Flags, IrpStatus);
	//}
	//else
	//{
	//	PIO_STACK_LOCATION irpSp = IoGetCurrentIrpStackLocation (Irp);
	//	Dump ("COMPLETE_IRP SUCCESS IRP %ls Flags 0x%08x vpb 0x%08x NTSTATUS 0x%08x\n", TCTranslateCode (irpSp->MajorFunction),
	//	      (ULONG) DeviceObject->Flags, (ULONG) DeviceObject->Vpb->Flags, IrpStatus);
	//}
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
