/*
 Copyright (c) 2008 TrueCrypt Foundation. All rights reserved.

 Governed by the TrueCrypt License 2.5 the full text of which is contained
 in the file License.txt included in TrueCrypt binary and source code
 distribution packages.
*/

#include "TCdefs.h"
#include <ntddk.h>
#include <ntddvol.h>
#include "Crc.h"
#include "Crypto.h"
#include "Apidrvr.h"
#include "EncryptedIoQueue.h"
#include "Endian.h"
#include "Ntdriver.h"
#include "Ntvol.h"
#include "Volumes.h"
#include "VolumeFilter.h"
#include "Wipe.h"
#include "DriveFilter.h"
#include "Boot/Windows/BootCommon.h"

static BOOL DeviceFilterActive = FALSE;

BOOL BootArgsValid = FALSE;
BootArguments BootArgs;

static BOOL BootDriveFound = FALSE;
static DriveFilterExtension *BootDriveFilterExtension = NULL;
static LARGE_INTEGER BootDriveLength;

static BOOL HibernationDriverFilterActive = FALSE;
static byte *HibernationWriteBuffer = NULL;
static MDL *HibernationWriteBufferMdl = NULL;
static uint32 HibernationPreventionCount = 0;

static BootEncryptionSetupRequest SetupRequest;
static volatile BOOL SetupInProgress = FALSE;
static PKTHREAD EncryptionSetupThread;
static volatile BOOL EncryptionSetupThreadAbortRequested;
static KSPIN_LOCK SetupStatusSpinLock;
static int64 SetupStatusEncryptedAreaEnd;
static BOOL TransformWaitingForIdle;
static NTSTATUS SetupResult;


NTSTATUS LoadBootArguments ()
{
	NTSTATUS status = STATUS_UNSUCCESSFUL;
	PHYSICAL_ADDRESS bootArgsAddr;
	byte *mappedBootArgs;

	bootArgsAddr.QuadPart = (TC_BOOT_LOADER_SEGMENT << 4) + TC_BOOT_LOADER_ARGS_OFFSET;
	mappedBootArgs = MmMapIoSpace (bootArgsAddr, sizeof (BootArguments), MmCached);
	if (!mappedBootArgs)
		return STATUS_INSUFFICIENT_RESOURCES;

	DumpMem (mappedBootArgs, sizeof (BootArguments));

	if (TC_IS_BOOT_ARGUMENTS_SIGNATURE (mappedBootArgs))
	{
		BootArguments *bootArguments = (BootArguments *) mappedBootArgs;
		Dump ("BootArguments at 0x%x\n", bootArgsAddr.LowPart);

		if (bootArguments->BootLoaderVersion == VERSION_NUM
			&& bootArguments->BootArgumentsCrc32 != GetCrc32 ((byte *) bootArguments, (int) ((byte *) &bootArguments->BootArgumentsCrc32 - (byte *) bootArguments)))
		{
			Dump ("BootArguments CRC incorrect\n");
			TC_BUG_CHECK (STATUS_CRC_ERROR);
		}

		BootArgs = *bootArguments;
		BootArgsValid = TRUE;
		memset (bootArguments, 0, sizeof (*bootArguments));

		if (BootArgs.BootLoaderVersion < 0x600)
		{
			BootArgs.HiddenSystemPartitionStart = 0;
			BootArgs.DecoySystemPartitionStart = 0;
		}

		Dump ("BootLoaderVersion = %x\n", (int) BootArgs.BootLoaderVersion);
		Dump ("HeaderSaltCrc32 = %x\n", (int) BootArgs.HeaderSaltCrc32);
		Dump ("CryptoInfoOffset = %x\n", (int) BootArgs.CryptoInfoOffset);
		Dump ("CryptoInfoLength = %d\n", (int) BootArgs.CryptoInfoLength);
		Dump ("HiddenSystemPartitionStart = %I64u\n", BootArgs.HiddenSystemPartitionStart);
		Dump ("DecoySystemPartitionStart = %I64u\n", BootArgs.DecoySystemPartitionStart);
		Dump ("BootArgumentsCrc32 = %x\n", BootArgs.BootArgumentsCrc32);

		status = STATUS_SUCCESS;
	}

	MmUnmapIoSpace (mappedBootArgs, sizeof (BootArguments));

	return status;
}


NTSTATUS DriveFilterAddDevice (PDRIVER_OBJECT driverObject, PDEVICE_OBJECT pdo)
{
	DriveFilterExtension *Extension;
	NTSTATUS status;
	PDEVICE_OBJECT filterDeviceObject = NULL;

	Dump ("DriveFilterAddDevice pdo=%p\n", pdo);

	DriverMutexWait();
	status = IoCreateDevice (driverObject, sizeof (DriveFilterExtension), NULL, FILE_DEVICE_DISK, 0, FALSE, &filterDeviceObject);  // Using pdo->DeviceType instead of FILE_DEVICE_DISK induces a bug in Disk Management console on Vista
	DriverMutexRelease();

	if (!NT_SUCCESS (status))
	{
		filterDeviceObject = NULL;
		goto err;
	}

	Extension = (DriveFilterExtension *) filterDeviceObject->DeviceExtension;
	memset (Extension, 0, sizeof (DriveFilterExtension));

	Extension->LowerDeviceObject = IoAttachDeviceToDeviceStack (filterDeviceObject, pdo);  // IoAttachDeviceToDeviceStackSafe() is not required in AddDevice routine and is also unavailable on Windows 2000 SP4
	if (!Extension->LowerDeviceObject)
	{
		status = STATUS_DEVICE_REMOVED;
		goto err;
	}

	Extension->IsDriveFilterDevice = Extension->Queue.IsFilterDevice = TRUE;
	Extension->DeviceObject = Extension->Queue.DeviceObject = filterDeviceObject;
	Extension->Pdo = pdo;
	
	Extension->Queue.LowerDeviceObject = Extension->LowerDeviceObject;
	IoInitializeRemoveLock (&Extension->Queue.RemoveLock, 'LRCT', 0, 0);

	Extension->ConfiguredEncryptedAreaStart = -1;
	Extension->ConfiguredEncryptedAreaEnd = -1;
	Extension->Queue.EncryptedAreaStart = -1;
	Extension->Queue.EncryptedAreaEnd = -1;

	if (!BootDriveFound)
	{
		status = EncryptedIoQueueStart (&Extension->Queue, NULL);
		if (!NT_SUCCESS (status))
			goto err;

		Extension->QueueStarted = TRUE;
	}

	filterDeviceObject->Flags |= Extension->LowerDeviceObject->Flags & (DO_DIRECT_IO | DO_BUFFERED_IO | DO_POWER_PAGABLE);
	filterDeviceObject->Flags &= ~DO_DEVICE_INITIALIZING;

	DeviceFilterActive = TRUE;
	return status;

err:
	if (filterDeviceObject)
	{
		if (Extension->LowerDeviceObject)
			IoDetachDevice (Extension->LowerDeviceObject);

		DriverMutexWait();
		IoDeleteDevice (filterDeviceObject);
		DriverMutexRelease();
	}

	return status;
}


static void DismountDrive (DriveFilterExtension *Extension)
{
	Dump ("Dismounting drive\n");
	ASSERT (Extension->DriveMounted);

	crypto_close (Extension->Queue.CryptoInfo);
	Extension->Queue.CryptoInfo = NULL;

	crypto_close (Extension->HeaderCryptoInfo);
	Extension->HeaderCryptoInfo = NULL;

	Extension->DriveMounted = FALSE;
}


static NTSTATUS MountDrive (DriveFilterExtension *Extension, Password *password, uint32 *headerSaltCrc32)
{
	BOOL hiddenVolume = (BootArgs.HiddenSystemPartitionStart != 0);
	int64 hiddenHeaderOffset = BootArgs.HiddenSystemPartitionStart + TC_HIDDEN_VOLUME_HEADER_OFFSET;
	NTSTATUS status;
	LARGE_INTEGER offset;
	char *header;

	Dump ("MountDrive pdo=%p\n", Extension->Pdo);
	ASSERT (KeGetCurrentIrql() == PASSIVE_LEVEL);

	header = TCalloc (TC_BOOT_ENCRYPTION_VOLUME_HEADER_SIZE);
	if (!header)
		return STATUS_INSUFFICIENT_RESOURCES;

	offset.QuadPart = hiddenVolume ? hiddenHeaderOffset : TC_BOOT_VOLUME_HEADER_SECTOR_OFFSET;
	Dump ("Reading volume header at %I64u\n", offset.QuadPart);

	status = TCReadDevice (Extension->LowerDeviceObject, header, offset, TC_BOOT_ENCRYPTION_VOLUME_HEADER_SIZE);
	if (!NT_SUCCESS (status))
	{
		Dump ("TCReadDevice error %x\n", status);
		goto ret;
	}

	if (headerSaltCrc32)
	{
		uint32 saltCrc = GetCrc32 (header, PKCS5_SALT_SIZE);

		if (saltCrc != *headerSaltCrc32)
		{
			status = STATUS_UNSUCCESSFUL;
			goto ret;
		}

		Extension->VolumeHeaderSaltCrc32 = saltCrc;
	}

	Extension->HeaderCryptoInfo = crypto_open();
	if (!Extension->HeaderCryptoInfo)
	{
		status = STATUS_INSUFFICIENT_RESOURCES;
		goto ret;
	}

	if (VolumeReadHeader (!hiddenVolume, header, password, &Extension->Queue.CryptoInfo, Extension->HeaderCryptoInfo) == 0)
	{
		// Header decrypted
		status = STATUS_SUCCESS;
		Dump ("Header decrypted\n");
			
		if (Extension->Queue.CryptoInfo->hiddenVolume)
		{
			int64 hiddenPartitionOffset = BootArgs.HiddenSystemPartitionStart;
			Dump ("Hidden volume start offset = %I64d\n", Extension->Queue.CryptoInfo->EncryptedAreaStart.Value + hiddenPartitionOffset);
			
			Extension->HiddenSystem = TRUE;

			Extension->Queue.RemapEncryptedArea = TRUE;
			Extension->Queue.RemappedAreaOffset = hiddenPartitionOffset + Extension->Queue.CryptoInfo->EncryptedAreaStart.Value - BootArgs.DecoySystemPartitionStart;
			Extension->Queue.RemappedAreaDataUnitOffset = Extension->Queue.CryptoInfo->EncryptedAreaStart.Value / ENCRYPTION_DATA_UNIT_SIZE - BootArgs.DecoySystemPartitionStart / ENCRYPTION_DATA_UNIT_SIZE;
			
			Extension->Queue.CryptoInfo->EncryptedAreaStart.Value = BootArgs.DecoySystemPartitionStart;
			
			if (Extension->Queue.CryptoInfo->VolumeSize.Value > hiddenPartitionOffset - BootArgs.DecoySystemPartitionStart)
				TC_THROW_FATAL_EXCEPTION;

			Dump ("RemappedAreaOffset = %I64d\n", Extension->Queue.RemappedAreaOffset);
			Dump ("RemappedAreaDataUnitOffset = %I64d\n", Extension->Queue.RemappedAreaDataUnitOffset);
		}
		else
		{
			Extension->HiddenSystem = FALSE;
			Extension->Queue.RemapEncryptedArea = FALSE;
		}

		Extension->ConfiguredEncryptedAreaStart = Extension->Queue.CryptoInfo->EncryptedAreaStart.Value;
		Extension->ConfiguredEncryptedAreaEnd = Extension->Queue.CryptoInfo->EncryptedAreaStart.Value + Extension->Queue.CryptoInfo->VolumeSize.Value - 1;

		Extension->Queue.EncryptedAreaStart = Extension->Queue.CryptoInfo->EncryptedAreaStart.Value;
		Extension->Queue.EncryptedAreaEnd = Extension->Queue.CryptoInfo->EncryptedAreaStart.Value + Extension->Queue.CryptoInfo->EncryptedAreaLength.Value - 1;

		if (Extension->Queue.CryptoInfo->EncryptedAreaLength.Value == 0)
		{
			Extension->Queue.EncryptedAreaStart = -1;
			Extension->Queue.EncryptedAreaEnd = -1;
		}

		Dump ("Loaded: ConfiguredEncryptedAreaStart=%I64d (%I64d)  ConfiguredEncryptedAreaEnd=%I64d (%I64d)\n", Extension->ConfiguredEncryptedAreaStart / 1024 / 1024, Extension->ConfiguredEncryptedAreaStart, Extension->ConfiguredEncryptedAreaEnd / 1024 / 1024, Extension->ConfiguredEncryptedAreaEnd);
		Dump ("Loaded: EncryptedAreaStart=%I64d (%I64d)  EncryptedAreaEnd=%I64d (%I64d)\n", Extension->Queue.EncryptedAreaStart / 1024 / 1024, Extension->Queue.EncryptedAreaStart, Extension->Queue.EncryptedAreaEnd / 1024 / 1024, Extension->Queue.EncryptedAreaEnd);

		// Erase boot loader scheduled keys
		if (BootArgs.CryptoInfoLength > 0)
		{
			PHYSICAL_ADDRESS cryptoInfoAddress;
			byte *mappedCryptoInfo;
			
			cryptoInfoAddress.QuadPart = (TC_BOOT_LOADER_SEGMENT << 4) + BootArgs.CryptoInfoOffset;
			mappedCryptoInfo = MmMapIoSpace (cryptoInfoAddress, BootArgs.CryptoInfoLength, MmCached);
			
			if (mappedCryptoInfo)
			{
				Dump ("Wiping memory %x %d\n", cryptoInfoAddress.LowPart, BootArgs.CryptoInfoLength);
				memset (mappedCryptoInfo, 0, BootArgs.CryptoInfoLength);
				MmUnmapIoSpace (mappedCryptoInfo, BootArgs.CryptoInfoLength);
			}
		}

		BootDriveFilterExtension = Extension;
		BootDriveFound = Extension->BootDrive = Extension->DriveMounted = Extension->VolumeHeaderPresent = TRUE;

		burn (&BootArgs.BootPassword, sizeof (BootArgs.BootPassword));

		// Get drive length
		status =  SendDeviceIoControlRequest (Extension->LowerDeviceObject, IOCTL_DISK_GET_LENGTH_INFO, NULL, 0, &BootDriveLength, sizeof (BootDriveLength));
		
		if (!NT_SUCCESS (status))
		{
			Dump ("Failed to get drive length - error %x\n", status);
			BootDriveLength.QuadPart = 0;
		}

		if (!HibernationDriverFilterActive)
			StartHibernationDriverFilter();
	}
	else
	{
		Dump ("Header not decrypted\n");
		crypto_close (Extension->HeaderCryptoInfo);
		Extension->HeaderCryptoInfo = NULL;

		status = STATUS_UNSUCCESSFUL;
	}

ret:
	TCfree (header);
	return status;
}


static NTSTATUS SaveDriveVolumeHeader (DriveFilterExtension *Extension)
{
	NTSTATUS status = STATUS_SUCCESS;
	LARGE_INTEGER offset;
	byte *header;

	header = TCalloc (TC_BOOT_ENCRYPTION_VOLUME_HEADER_SIZE);
	if (!header)
		return STATUS_INSUFFICIENT_RESOURCES;

	offset.QuadPart = TC_BOOT_VOLUME_HEADER_SECTOR_OFFSET;

	status = TCReadDevice (Extension->LowerDeviceObject, header, offset, TC_BOOT_ENCRYPTION_VOLUME_HEADER_SIZE);
	if (!NT_SUCCESS (status))
	{
		Dump ("TCReadDevice error %x", status);
		goto ret;
	}

	Dump ("Saving: ConfiguredEncryptedAreaStart=%I64d (%I64d)  ConfiguredEncryptedAreaEnd=%I64d (%I64d)\n", Extension->ConfiguredEncryptedAreaStart / 1024 / 1024, Extension->ConfiguredEncryptedAreaStart, Extension->ConfiguredEncryptedAreaEnd / 1024 / 1024, Extension->ConfiguredEncryptedAreaEnd);
	Dump ("Saving: EncryptedAreaStart=%I64d (%I64d)  EncryptedAreaEnd=%I64d (%I64d)\n", Extension->Queue.EncryptedAreaStart / 1024 / 1024, Extension->Queue.EncryptedAreaStart, Extension->Queue.EncryptedAreaEnd / 1024 / 1024, Extension->Queue.EncryptedAreaEnd);
	
	if (Extension->Queue.EncryptedAreaStart == -1 || Extension->Queue.EncryptedAreaEnd == -1
		|| Extension->Queue.EncryptedAreaEnd <= Extension->Queue.EncryptedAreaStart)
	{
		if (SetupRequest.SetupMode == SetupDecryption)
		{
			memset (header, 0, TC_BOOT_ENCRYPTION_VOLUME_HEADER_SIZE);
			Extension->VolumeHeaderPresent = FALSE;
		}
	}
	else
	{
		uint32 headerCrc32;
		uint64 encryptedAreaLength = Extension->Queue.EncryptedAreaEnd + 1 - Extension->Queue.EncryptedAreaStart;
		byte *fieldPos = header + TC_HEADER_OFFSET_ENCRYPTED_AREA_LENGTH;

		DecryptBuffer (header + HEADER_ENCRYPTED_DATA_OFFSET, HEADER_ENCRYPTED_DATA_SIZE, Extension->HeaderCryptoInfo);

		if (GetHeaderField32 (header, TC_HEADER_OFFSET_MAGIC) != 0x54525545)
		{
			Dump ("Header not decrypted");
			status = STATUS_UNSUCCESSFUL;
			goto ret;
		}

		mputInt64 (fieldPos, encryptedAreaLength);

		headerCrc32 = GetCrc32 (header + TC_HEADER_OFFSET_MAGIC, TC_HEADER_OFFSET_HEADER_CRC - TC_HEADER_OFFSET_MAGIC);
		fieldPos = header + TC_HEADER_OFFSET_HEADER_CRC;
		mputLong (fieldPos, headerCrc32);

		EncryptBuffer (header + HEADER_ENCRYPTED_DATA_OFFSET, HEADER_ENCRYPTED_DATA_SIZE, Extension->HeaderCryptoInfo);
	}

	status = TCWriteDevice (Extension->LowerDeviceObject, header, offset, TC_BOOT_ENCRYPTION_VOLUME_HEADER_SIZE);
	if (!NT_SUCCESS (status))
	{
		Dump ("TCWriteDevice error %x", status);
		goto ret;
	}

ret:
	TCfree (header);
	return status;
}


static NTSTATUS PassIrp (PDEVICE_OBJECT deviceObject, PIRP irp)
{
	IoSkipCurrentIrpStackLocation (irp);
	return IoCallDriver (deviceObject, irp);
}


static NTSTATUS PassFilteredIrp (PDEVICE_OBJECT deviceObject, PIRP irp, PIO_COMPLETION_ROUTINE completionRoutine, PVOID completionRoutineArg)
{
	IoCopyCurrentIrpStackLocationToNext (irp);

	if (completionRoutine)
		IoSetCompletionRoutine (irp, completionRoutine, completionRoutineArg, TRUE, TRUE, TRUE);

	return IoCallDriver (deviceObject, irp);
}


static NTSTATUS OnDeviceUsageNotificationCompleted (PDEVICE_OBJECT filterDeviceObject, PIRP Irp, DriveFilterExtension *Extension)
{
	if (Irp->PendingReturned)
		IoMarkIrpPending (Irp);

	if (!(Extension->LowerDeviceObject->Flags & DO_POWER_PAGABLE))
		filterDeviceObject->Flags &= ~DO_POWER_PAGABLE;

	IoReleaseRemoveLock (&Extension->Queue.RemoveLock, Irp);
	return STATUS_CONTINUE_COMPLETION;
}


static BOOL IsVolumeDevice (PDEVICE_OBJECT deviceObject)
{
	VOLUME_NUMBER volNumber;
	VOLUME_DISK_EXTENTS extents[16];

	return NT_SUCCESS (SendDeviceIoControlRequest (deviceObject, IOCTL_VOLUME_SUPPORTS_ONLINE_OFFLINE, NULL, 0,  NULL, 0))
		|| NT_SUCCESS (SendDeviceIoControlRequest (deviceObject, IOCTL_VOLUME_IS_OFFLINE, NULL, 0,  NULL, 0))
		|| NT_SUCCESS (SendDeviceIoControlRequest (deviceObject, IOCTL_VOLUME_IS_IO_CAPABLE, NULL, 0,  NULL, 0))
		|| NT_SUCCESS (SendDeviceIoControlRequest (deviceObject, IOCTL_VOLUME_IS_PARTITION, NULL, 0,  NULL, 0))
		|| NT_SUCCESS (SendDeviceIoControlRequest (deviceObject, IOCTL_VOLUME_QUERY_VOLUME_NUMBER, NULL, 0, &volNumber, sizeof (volNumber)))
		|| NT_SUCCESS (SendDeviceIoControlRequest (deviceObject, IOCTL_VOLUME_GET_VOLUME_DISK_EXTENTS, NULL, 0, extents, sizeof (extents)));
}


static void CheckDeviceTypeAndMount (DriveFilterExtension *filterExtension)
{
	if (BootArgsValid)
	{
		if (BootArgs.HiddenSystemPartitionStart != 0 && IsVolumeDevice (filterExtension->LowerDeviceObject))
		{
			Dump ("Drive filter attached to a volume pdo=%p", filterExtension->Pdo);

			if (filterExtension->QueueStarted && EncryptedIoQueueIsRunning (&filterExtension->Queue))
				EncryptedIoQueueStop (&filterExtension->Queue);

			filterExtension->IsVolumeFilterDevice = TRUE;
			filterExtension->IsDriveFilterDevice = FALSE;
		}
		else if (!BootDriveFound)
		{
			MountDrive (filterExtension, &BootArgs.BootPassword, &BootArgs.HeaderSaltCrc32);
		}
	}
}


static VOID MountDriveWorkItemRoutine (PDEVICE_OBJECT deviceObject, DriveFilterExtension *filterExtension)
{
	CheckDeviceTypeAndMount (filterExtension);
	KeSetEvent (&filterExtension->MountWorkItemCompletedEvent, IO_NO_INCREMENT, FALSE);
}


static NTSTATUS OnStartDeviceCompleted (PDEVICE_OBJECT filterDeviceObject, PIRP Irp, DriveFilterExtension *Extension)
{
	if (Irp->PendingReturned)
		IoMarkIrpPending (Irp);

	if (Extension->LowerDeviceObject->Characteristics & FILE_REMOVABLE_MEDIA)
		filterDeviceObject->Characteristics |= FILE_REMOVABLE_MEDIA;

	if (KeGetCurrentIrql() == PASSIVE_LEVEL)
	{
		CheckDeviceTypeAndMount (Extension);
	}
	else
	{
		PIO_WORKITEM workItem = IoAllocateWorkItem (filterDeviceObject);
		if (!workItem)
		{
			IoReleaseRemoveLock (&Extension->Queue.RemoveLock, Irp);
			return STATUS_INSUFFICIENT_RESOURCES;
		}

		KeInitializeEvent (&Extension->MountWorkItemCompletedEvent, SynchronizationEvent, FALSE);
		IoQueueWorkItem (workItem, MountDriveWorkItemRoutine, DelayedWorkQueue, Extension); 

		KeWaitForSingleObject (&Extension->MountWorkItemCompletedEvent, Executive, KernelMode, FALSE, NULL);
		IoFreeWorkItem (workItem);
	}

	IoReleaseRemoveLock (&Extension->Queue.RemoveLock, Irp);
	return STATUS_CONTINUE_COMPLETION;
}


static NTSTATUS DispatchPnp (PDEVICE_OBJECT DeviceObject, PIRP Irp, DriveFilterExtension *Extension, PIO_STACK_LOCATION irpSp)
{
	NTSTATUS status;

	status = IoAcquireRemoveLock (&Extension->Queue.RemoveLock, Irp);
	if (!NT_SUCCESS (status))
		return TCCompleteIrp (Irp, status, Irp->IoStatus.Information);

	switch (irpSp->MinorFunction)
	{
	case IRP_MN_START_DEVICE:
		Dump ("IRP_MN_START_DEVICE pdo=%p\n", Extension->Pdo);
		return PassFilteredIrp (Extension->LowerDeviceObject, Irp, OnStartDeviceCompleted, Extension);


	case IRP_MN_DEVICE_USAGE_NOTIFICATION:
		Dump ("IRP_MN_DEVICE_USAGE_NOTIFICATION type=%d\n", (int) irpSp->Parameters.UsageNotification.Type);

		{
			PDEVICE_OBJECT attachedDevice = IoGetAttachedDeviceReference (DeviceObject);

			if (attachedDevice == DeviceObject || (attachedDevice->Flags & DO_POWER_PAGABLE))
				DeviceObject->Flags |= DO_POWER_PAGABLE;

			if (attachedDevice != DeviceObject)
				ObDereferenceObject (attachedDevice);
		}

		// Prevent creation of hibernation and crash dump files
		if (irpSp->Parameters.UsageNotification.InPath
			&& (irpSp->Parameters.UsageNotification.Type == DeviceUsageTypeDumpFile
			|| (irpSp->Parameters.UsageNotification.Type == DeviceUsageTypeHibernation && !HibernationDriverFilterActive)))
		{
			IoReleaseRemoveLock (&Extension->Queue.RemoveLock, Irp);

			if (irpSp->Parameters.UsageNotification.Type == DeviceUsageTypeHibernation)
				++HibernationPreventionCount;

			return TCCompleteIrp (Irp, STATUS_UNSUCCESSFUL, Irp->IoStatus.Information);
		}

		return PassFilteredIrp (Extension->LowerDeviceObject, Irp, OnDeviceUsageNotificationCompleted, Extension);


	case IRP_MN_REMOVE_DEVICE:
		Dump ("IRP_MN_REMOVE_DEVICE pdo=%p\n", Extension->Pdo);

		IoReleaseRemoveLockAndWait (&Extension->Queue.RemoveLock, Irp);
		status = PassIrp (Extension->LowerDeviceObject, Irp);

		IoDetachDevice (Extension->LowerDeviceObject);

		if (Extension->QueueStarted && EncryptedIoQueueIsRunning (&Extension->Queue))
			EncryptedIoQueueStop (&Extension->Queue);

		if (Extension->DriveMounted)
			DismountDrive (Extension);

		if (Extension->BootDrive)
		{
			BootDriveFound = FALSE;
			BootDriveFilterExtension = NULL;
		}

		DriverMutexWait();
		IoDeleteDevice (DeviceObject);
		DriverMutexRelease();

		return status;


	default:
		status = PassIrp (Extension->LowerDeviceObject, Irp);
		IoReleaseRemoveLock (&Extension->Queue.RemoveLock, Irp);
	}
	return status;
}


static NTSTATUS DispatchPower (PDEVICE_OBJECT DeviceObject, PIRP Irp, DriveFilterExtension *Extension, PIO_STACK_LOCATION irpSp)
{
	NTSTATUS status;
	Dump ("IRP_MJ_POWER minor=%d type=%d shutdown=%d\n", (int) irpSp->MinorFunction, (int) irpSp->Parameters.Power.Type, (int) irpSp->Parameters.Power.ShutdownType);

	if (SetupInProgress
		&& irpSp->MinorFunction == IRP_MN_SET_POWER
		&& irpSp->Parameters.Power.Type == DevicePowerState
		&& irpSp->Parameters.Power.ShutdownType == PowerActionHibernate)
	{
		EncryptionSetupThreadAbortRequested = TRUE;
		ObDereferenceObject (EncryptionSetupThread);
		
		while (SetupInProgress)
			TCSleep (200);
	}

	if (DriverShuttingDown
		&& Extension->DriveMounted
		&& irpSp->MinorFunction == IRP_MN_SET_POWER
		&& irpSp->Parameters.Power.Type == DevicePowerState)
	{
		Dump ("IRP_MN_SET_POWER\n");

		if (Extension->QueueStarted && EncryptedIoQueueIsRunning (&Extension->Queue))
			EncryptedIoQueueStop (&Extension->Queue);

		if (Extension->DriveMounted)
			DismountDrive (Extension);
	}

	PoStartNextPowerIrp (Irp);

	status = IoAcquireRemoveLock (&Extension->Queue.RemoveLock, Irp);
	if (!NT_SUCCESS (status))
		return TCCompleteIrp (Irp, status, Irp->IoStatus.Information);

	IoSkipCurrentIrpStackLocation (Irp);
	status = PoCallDriver (Extension->LowerDeviceObject, Irp);

	IoReleaseRemoveLock (&Extension->Queue.RemoveLock, Irp);
	return status;
}


NTSTATUS DriveFilterDispatchIrp (PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
	DriveFilterExtension *Extension = (DriveFilterExtension *) DeviceObject->DeviceExtension;
	PIO_STACK_LOCATION irpSp = IoGetCurrentIrpStackLocation (Irp);

	ASSERT (!Extension->bRootDevice && Extension->IsDriveFilterDevice);

	switch (irpSp->MajorFunction)
	{
	case IRP_MJ_READ:
	case IRP_MJ_WRITE:
		if (BootDriveFound && !Extension->BootDrive)
		{
			return PassIrp (Extension->LowerDeviceObject, Irp);
		}
		else
		{
			NTSTATUS status = EncryptedIoQueueAddIrp (&Extension->Queue, Irp);
			
			if (status != STATUS_PENDING)
				TCCompleteDiskIrp (Irp, status, 0);

			return status;
		}

	case IRP_MJ_PNP:
		return DispatchPnp (DeviceObject, Irp, Extension, irpSp);

	case IRP_MJ_POWER:
		return DispatchPower (DeviceObject, Irp, Extension, irpSp);

	default:
		return PassIrp (Extension->LowerDeviceObject, Irp);
	}
}


void ReopenBootVolumeHeader (PIRP irp, PIO_STACK_LOCATION irpSp)
{
	LARGE_INTEGER offset;
	char *header;
	ReopenBootVolumeHeaderRequest *request = (ReopenBootVolumeHeaderRequest *) irp->AssociatedIrp.SystemBuffer;

	irp->IoStatus.Information = 0;

	if (!IoIsSystemThread (PsGetCurrentThread()) && !UserCanAccessDriveDevice())
	{
		irp->IoStatus.Status = STATUS_ACCESS_DENIED;
		return;
	}

	if (irpSp->Parameters.DeviceIoControl.InputBufferLength < sizeof (ReopenBootVolumeHeaderRequest))
	{
		irp->IoStatus.Status = STATUS_BUFFER_TOO_SMALL;
		return;
	}

	if (!BootDriveFound || !BootDriveFilterExtension || !BootDriveFilterExtension->DriveMounted || !BootDriveFilterExtension->HeaderCryptoInfo
		|| request->VolumePassword.Length > MAX_PASSWORD)
	{
		irp->IoStatus.Status = STATUS_INVALID_PARAMETER;
		goto wipe;
	}

	header = TCalloc (TC_BOOT_ENCRYPTION_VOLUME_HEADER_SIZE);
	if (!header)
	{
		irp->IoStatus.Status = STATUS_INSUFFICIENT_RESOURCES;
		goto wipe;
	}

	if (BootDriveFilterExtension->HiddenSystem)
		offset.QuadPart = BootArgs.HiddenSystemPartitionStart + TC_HIDDEN_VOLUME_HEADER_OFFSET;
	else
		offset.QuadPart = TC_BOOT_VOLUME_HEADER_SECTOR_OFFSET;

	irp->IoStatus.Status = TCReadDevice (BootDriveFilterExtension->LowerDeviceObject, header, offset, TC_BOOT_ENCRYPTION_VOLUME_HEADER_SIZE);
	if (!NT_SUCCESS (irp->IoStatus.Status))
	{
		Dump ("TCReadDevice error %x\n", irp->IoStatus.Status);
		goto ret;
	}

	if (VolumeReadHeader (!BootDriveFilterExtension->HiddenSystem, header, &request->VolumePassword, NULL, BootDriveFilterExtension->HeaderCryptoInfo) == 0)
	{
		Dump ("Header reopened\n");
		
		BootDriveFilterExtension->Queue.CryptoInfo->header_creation_time = BootDriveFilterExtension->HeaderCryptoInfo->header_creation_time;
		BootDriveFilterExtension->Queue.CryptoInfo->pkcs5 = BootDriveFilterExtension->HeaderCryptoInfo->pkcs5;
		BootDriveFilterExtension->Queue.CryptoInfo->noIterations = BootDriveFilterExtension->HeaderCryptoInfo->noIterations;

		irp->IoStatus.Status = STATUS_SUCCESS;
	}
	else
	{
		crypto_close (BootDriveFilterExtension->HeaderCryptoInfo);
		BootDriveFilterExtension->HeaderCryptoInfo = NULL;

		Dump ("Header not reopened\n");
		irp->IoStatus.Status = STATUS_INVALID_PARAMETER;
	}

ret:
	TCfree (header);
wipe:
	burn (request, sizeof (*request));
}


typedef NTSTATUS (*HiberDriverWriteFunctionA) (ULONG arg0, PLARGE_INTEGER writeOffset, PMDL dataMdl, PVOID arg3);
typedef NTSTATUS (*HiberDriverWriteFunctionB) (PLARGE_INTEGER writeOffset, PMDL dataMdl);

typedef struct
{
	// Until MS releases an API for filtering hibernation drivers, we have to resort to this.
#ifdef _WIN64
	byte FieldPad1[64];
	HiberDriverWriteFunctionB WriteFunctionB;
	byte FieldPad2[56];
#else
	byte FieldPad1[48];
	HiberDriverWriteFunctionB WriteFunctionB;
	byte FieldPad2[32];
#endif
	HiberDriverWriteFunctionA WriteFunctionA;
	byte FieldPad3[24];
	LARGE_INTEGER PartitionStartOffset;
} HiberDriverContext;

typedef NTSTATUS (*HiberDriverEntry) (PVOID arg0, HiberDriverContext *hiberDriverContext);

typedef struct
{
	LIST_ENTRY ModuleList;
#ifdef _WIN64
	byte FieldPad1[32];
#else
	byte FieldPad1[16];
#endif
	PVOID ModuleBaseAddress;
	HiberDriverEntry ModuleEntryAddress;
#ifdef _WIN64
	byte FieldPad2[24];
#else
	byte FieldPad2[12];
#endif
	UNICODE_STRING ModuleName;
} ModuleTableItem;


#define TC_MAX_HIBER_FILTER_COUNT 3
static int LastHiberFilterNumber = 0;

static HiberDriverEntry OriginalHiberDriverEntries[TC_MAX_HIBER_FILTER_COUNT];
static HiberDriverWriteFunctionA OriginalHiberDriverWriteFunctionsA[TC_MAX_HIBER_FILTER_COUNT];
static HiberDriverWriteFunctionB OriginalHiberDriverWriteFunctionsB[TC_MAX_HIBER_FILTER_COUNT];

static LARGE_INTEGER HiberPartitionOffset;


static NTSTATUS HiberDriverWriteFunctionFilter (int filterNumber, PLARGE_INTEGER writeOffset, PMDL dataMdl, BOOL writeB, ULONG arg0WriteA, PVOID arg3WriteA)
{
	MDL *encryptedDataMdl = dataMdl;

	if (writeOffset && dataMdl && BootDriveFilterExtension && BootDriveFilterExtension->DriveMounted)
	{
		ULONG dataLength = MmGetMdlByteCount (dataMdl);

		if (dataMdl->MappedSystemVa && dataLength > 0)
		{
			uint64 offset = HiberPartitionOffset.QuadPart + writeOffset->QuadPart;
			uint64 intersectStart;
			uint32 intersectLength;

			if (dataLength > TC_HIBERNATION_WRITE_BUFFER_SIZE)
				TC_BUG_CHECK (STATUS_BUFFER_OVERFLOW);

			if ((dataLength & (ENCRYPTION_DATA_UNIT_SIZE - 1)) != 0)
				TC_BUG_CHECK (STATUS_INVALID_PARAMETER);

			if ((offset & (ENCRYPTION_DATA_UNIT_SIZE - 1)) != 0)
				TC_BUG_CHECK (STATUS_INVALID_PARAMETER);

			GetIntersection (offset,
				dataLength,
				BootDriveFilterExtension->Queue.EncryptedAreaStart,
				BootDriveFilterExtension->Queue.EncryptedAreaEnd,
				&intersectStart,
				&intersectLength);

			if (intersectLength > 0)
			{
				UINT64_STRUCT dataUnit;
				dataUnit.Value = intersectStart / ENCRYPTION_DATA_UNIT_SIZE;

				memcpy (HibernationWriteBuffer, dataMdl->MappedSystemVa, dataLength);

				if (BootDriveFilterExtension->Queue.RemapEncryptedArea)
					dataUnit.Value += BootDriveFilterExtension->Queue.RemappedAreaDataUnitOffset;

				EncryptDataUnitsCurrentThread (HibernationWriteBuffer + (intersectStart - offset),
					&dataUnit,
					intersectLength / ENCRYPTION_DATA_UNIT_SIZE,
					BootDriveFilterExtension->Queue.CryptoInfo);

				encryptedDataMdl = HibernationWriteBufferMdl;
				MmInitializeMdl (encryptedDataMdl, HibernationWriteBuffer, dataLength);
				encryptedDataMdl->MdlFlags = dataMdl->MdlFlags;
			}
		}
	}

	if (writeB)
		return (*OriginalHiberDriverWriteFunctionsB[filterNumber]) (writeOffset, encryptedDataMdl);
	
	return (*OriginalHiberDriverWriteFunctionsA[filterNumber]) (arg0WriteA, writeOffset, encryptedDataMdl, arg3WriteA);
}


static NTSTATUS HiberDriverWriteFunctionAFilter0 (ULONG arg0, PLARGE_INTEGER writeOffset, PMDL dataMdl, PVOID arg3)
{
	return HiberDriverWriteFunctionFilter (0, writeOffset, dataMdl, FALSE, arg0, arg3);
}

static NTSTATUS HiberDriverWriteFunctionAFilter1 (ULONG arg0, PLARGE_INTEGER writeOffset, PMDL dataMdl, PVOID arg3)
{
	return HiberDriverWriteFunctionFilter (1, writeOffset, dataMdl, FALSE, arg0, arg3);
}

static NTSTATUS HiberDriverWriteFunctionAFilter2 (ULONG arg0, PLARGE_INTEGER writeOffset, PMDL dataMdl, PVOID arg3)
{
	return HiberDriverWriteFunctionFilter (2, writeOffset, dataMdl, FALSE, arg0, arg3);
}


static NTSTATUS HiberDriverWriteFunctionBFilter0 (PLARGE_INTEGER writeOffset, PMDL dataMdl)
{
	return HiberDriverWriteFunctionFilter (0, writeOffset, dataMdl, TRUE, 0, NULL);
}

static NTSTATUS HiberDriverWriteFunctionBFilter1 (PLARGE_INTEGER writeOffset, PMDL dataMdl)
{
	return HiberDriverWriteFunctionFilter (1, writeOffset, dataMdl, TRUE, 0, NULL);
}

static NTSTATUS HiberDriverWriteFunctionBFilter2 (PLARGE_INTEGER writeOffset, PMDL dataMdl)
{
	return HiberDriverWriteFunctionFilter (2, writeOffset, dataMdl, TRUE, 0, NULL);
}


static NTSTATUS HiberDriverEntryFilter (int filterNumber, PVOID arg0, HiberDriverContext *hiberDriverContext)
{
	BOOL filterInstalled = FALSE;
	NTSTATUS status;

	if (!OriginalHiberDriverEntries[filterNumber])
		return STATUS_UNSUCCESSFUL;

	status = (*OriginalHiberDriverEntries[filterNumber]) (arg0, hiberDriverContext);

	if (!NT_SUCCESS (status) || !hiberDriverContext)
		return status;

	if (SetupInProgress)
		TC_BUG_CHECK (STATUS_INVALID_PARAMETER);

	if (hiberDriverContext->WriteFunctionA)
	{
		Dump ("Filtering WriteFunctionA %d\n", filterNumber);
		OriginalHiberDriverWriteFunctionsA[filterNumber] = hiberDriverContext->WriteFunctionA;

		switch (filterNumber)
		{
		case 0: hiberDriverContext->WriteFunctionA = HiberDriverWriteFunctionAFilter0; break;
		case 1: hiberDriverContext->WriteFunctionA = HiberDriverWriteFunctionAFilter1; break;
		case 2: hiberDriverContext->WriteFunctionA = HiberDriverWriteFunctionAFilter2; break;
		default: TC_THROW_FATAL_EXCEPTION;
		}

		filterInstalled = TRUE;
	}

	if (hiberDriverContext->WriteFunctionB)
	{
		Dump ("Filtering WriteFunctionB %d\n", filterNumber);
		OriginalHiberDriverWriteFunctionsB[filterNumber] = hiberDriverContext->WriteFunctionB;

		switch (filterNumber)
		{
		case 0: hiberDriverContext->WriteFunctionB = HiberDriverWriteFunctionBFilter0; break;
		case 1: hiberDriverContext->WriteFunctionB = HiberDriverWriteFunctionBFilter1; break;
		case 2: hiberDriverContext->WriteFunctionB = HiberDriverWriteFunctionBFilter2; break;
		default: TC_THROW_FATAL_EXCEPTION;
		}

		filterInstalled = TRUE;
	}

	if (filterInstalled && hiberDriverContext->PartitionStartOffset.QuadPart != 0)
	{
		HiberPartitionOffset = hiberDriverContext->PartitionStartOffset;

		if (BootDriveFilterExtension->Queue.RemapEncryptedArea)
			hiberDriverContext->PartitionStartOffset.QuadPart += BootDriveFilterExtension->Queue.RemappedAreaOffset;
	}

	return STATUS_SUCCESS;
}


static NTSTATUS HiberDriverEntryFilter0 (PVOID arg0, HiberDriverContext *hiberDriverContext)
{
	return HiberDriverEntryFilter (0, arg0, hiberDriverContext);
}


static NTSTATUS HiberDriverEntryFilter1 (PVOID arg0, HiberDriverContext *hiberDriverContext)
{
	return HiberDriverEntryFilter (1, arg0, hiberDriverContext);
}


static NTSTATUS HiberDriverEntryFilter2 (PVOID arg0, HiberDriverContext *hiberDriverContext)
{
	return HiberDriverEntryFilter (2, arg0, hiberDriverContext);
}


static VOID LoadImageNotifyRoutine (PUNICODE_STRING fullImageName, HANDLE processId, PIMAGE_INFO imageInfo)
{
	ModuleTableItem *moduleItem;
	LIST_ENTRY *listEntry;
	KIRQL origIrql;

	if (!imageInfo || !imageInfo->SystemModeImage || !imageInfo->ImageBase || !TCDriverObject->DriverSection)
		return;

	moduleItem = *(ModuleTableItem **) TCDriverObject->DriverSection;
	if (!moduleItem || !moduleItem->ModuleList.Flink)
		return;

	// Search loaded system modules for hibernation driver
	origIrql = KeRaiseIrqlToDpcLevel();

	for (listEntry = moduleItem->ModuleList.Flink->Blink;
		listEntry && listEntry != TCDriverObject->DriverSection;
		listEntry = listEntry->Flink)
	{
		moduleItem = CONTAINING_RECORD (listEntry, ModuleTableItem, ModuleList);

		if (moduleItem && imageInfo->ImageBase == moduleItem->ModuleBaseAddress)
		{
			if (moduleItem->ModuleName.Buffer && moduleItem->ModuleName.Length >= 5 * sizeof (wchar_t))
			{
				// Skip MS BitLocker filter
				if (moduleItem->ModuleName.Length >= 13 * sizeof (wchar_t)
					&& memcmp (moduleItem->ModuleName.Buffer, L"hiber_dumpfve", 13 * sizeof (wchar_t)) == 0)
					break;

				if (memcmp (moduleItem->ModuleName.Buffer, L"hiber", 5 * sizeof (wchar_t)) == 0
					|| memcmp (moduleItem->ModuleName.Buffer, L"Hiber", 5 * sizeof (wchar_t)) == 0
					|| memcmp (moduleItem->ModuleName.Buffer, L"HIBER", 5 * sizeof (wchar_t)) == 0)
				{
					HiberDriverEntry filterEntry;

					switch (LastHiberFilterNumber)
					{
					case 0: filterEntry = HiberDriverEntryFilter0; break;
					case 1: filterEntry = HiberDriverEntryFilter1; break;
					case 2: filterEntry = HiberDriverEntryFilter2; break;
					default: TC_THROW_FATAL_EXCEPTION;
					}

					if (moduleItem->ModuleEntryAddress != filterEntry)
					{
						// Install filter
						OriginalHiberDriverEntries[LastHiberFilterNumber] = moduleItem->ModuleEntryAddress;
						moduleItem->ModuleEntryAddress = filterEntry;

						if (++LastHiberFilterNumber > TC_MAX_HIBER_FILTER_COUNT - 1)
							LastHiberFilterNumber = 0;
					}
				}
			}
			break;
		}
	}

	KeLowerIrql (origIrql);
}


void StartHibernationDriverFilter ()
{
	PHYSICAL_ADDRESS highestAcceptableWriteBufferAddr;
	NTSTATUS status;

	ASSERT (KeGetCurrentIrql() == PASSIVE_LEVEL);

	if (!TCDriverObject->DriverSection || !*(ModuleTableItem **) TCDriverObject->DriverSection)
		goto err;

	// All buffers required for hibernation must be allocated here
#ifdef _WIN64
	highestAcceptableWriteBufferAddr.QuadPart = 0x7FFffffFFFFULL;
#else
	highestAcceptableWriteBufferAddr.QuadPart = 0xffffFFFFULL;
#endif

	HibernationWriteBuffer = MmAllocateContiguousMemory (TC_HIBERNATION_WRITE_BUFFER_SIZE, highestAcceptableWriteBufferAddr);
	if (!HibernationWriteBuffer)
		goto err;

	HibernationWriteBufferMdl = IoAllocateMdl (HibernationWriteBuffer, TC_HIBERNATION_WRITE_BUFFER_SIZE, FALSE, FALSE, NULL);
	if (!HibernationWriteBufferMdl)
		goto err;

	MmBuildMdlForNonPagedPool (HibernationWriteBufferMdl);

	status = PsSetLoadImageNotifyRoutine (LoadImageNotifyRoutine);
	if (!NT_SUCCESS (status))
		goto err;

	HibernationDriverFilterActive = TRUE;
	return;

err:
	HibernationDriverFilterActive = FALSE;
	
	if (HibernationWriteBufferMdl)
	{
		IoFreeMdl (HibernationWriteBufferMdl);
		HibernationWriteBufferMdl = NULL;
	}

	if (HibernationWriteBuffer)
	{
		MmFreeContiguousMemory (HibernationWriteBuffer);
		HibernationWriteBuffer = NULL;
	}
}


static VOID SetupThreadProc (PVOID threadArg)
{
	DriveFilterExtension *Extension = BootDriveFilterExtension;

	LARGE_INTEGER offset;
	UINT64_STRUCT dataUnit;
	ULONG setupBlockSize = TC_ENCRYPTION_SETUP_IO_BLOCK_SIZE;
	BOOL headerUpdateRequired = FALSE;
	int64 bytesWrittenSinceHeaderUpdate = 0;

	byte *buffer = NULL;
	byte *wipeBuffer = NULL;
	byte wipeRandChars[TC_WIPE_RAND_CHAR_COUNT];
	byte wipeRandCharsUpdate[TC_WIPE_RAND_CHAR_COUNT];
	
	KIRQL irql;
	NTSTATUS status;

	SetupResult = STATUS_UNSUCCESSFUL;

	// Make sure volume header can be updated
	if (Extension->HeaderCryptoInfo == NULL)
	{
		SetupResult = STATUS_INVALID_PARAMETER;
		goto ret;
	}

	buffer = TCalloc (TC_ENCRYPTION_SETUP_IO_BLOCK_SIZE);
	if (!buffer)
	{
		SetupResult = STATUS_INSUFFICIENT_RESOURCES;
		goto ret;
	}

	if (SetupRequest.SetupMode == SetupEncryption && SetupRequest.WipeAlgorithm != TC_WIPE_NONE)
	{
		wipeBuffer = TCalloc (TC_ENCRYPTION_SETUP_IO_BLOCK_SIZE);
		if (!wipeBuffer)
		{
			SetupResult = STATUS_INSUFFICIENT_RESOURCES;
			goto ret;
		}
	}

	while (!NT_SUCCESS (EncryptedIoQueueHoldWhenIdle (&Extension->Queue, 1000)))
	{
		if (EncryptionSetupThreadAbortRequested)
			goto abort;

		TransformWaitingForIdle = TRUE;
	}
	TransformWaitingForIdle = FALSE;

	switch (SetupRequest.SetupMode)
	{
	case SetupEncryption:
		Dump ("Encrypting...\n");
		if (Extension->Queue.EncryptedAreaStart == -1 || Extension->Queue.EncryptedAreaEnd == -1)
		{
			// Start encryption
			Extension->Queue.EncryptedAreaStart = Extension->ConfiguredEncryptedAreaStart;
			Extension->Queue.EncryptedAreaEnd = -1;
			offset.QuadPart = Extension->ConfiguredEncryptedAreaStart;
		}
		else
		{
			// Resume aborted encryption
			if (Extension->Queue.EncryptedAreaEnd == Extension->ConfiguredEncryptedAreaEnd)
				goto err;

			offset.QuadPart = Extension->Queue.EncryptedAreaEnd + 1;
		}

		break;

	case SetupDecryption:
		Dump ("Decrypting...\n");
		if (Extension->Queue.EncryptedAreaStart == -1 || Extension->Queue.EncryptedAreaEnd == -1)
		{
			SetupResult = STATUS_SUCCESS;
			goto abort;
		}

		offset.QuadPart = Extension->Queue.EncryptedAreaEnd + 1;
		break;

	default:
		goto err;
	}

	EncryptedIoQueueResumeFromHold (&Extension->Queue);
		
	Dump ("EncryptedAreaStart=%I64d\n", Extension->Queue.EncryptedAreaStart);
	Dump ("EncryptedAreaEnd=%I64d\n", Extension->Queue.EncryptedAreaEnd);
	Dump ("ConfiguredEncryptedAreaStart=%I64d\n", Extension->ConfiguredEncryptedAreaStart);
	Dump ("ConfiguredEncryptedAreaEnd=%I64d\n", Extension->ConfiguredEncryptedAreaEnd);
	Dump ("offset=%I64d\n", offset.QuadPart);
	Dump ("EncryptedAreaStart=%I64d (%I64d)  EncryptedAreaEnd=%I64d\n", Extension->Queue.EncryptedAreaStart / 1024 / 1024, Extension->Queue.EncryptedAreaStart, Extension->Queue.EncryptedAreaEnd / 1024 / 1024);

	while (!EncryptionSetupThreadAbortRequested)
	{
		if (SetupRequest.SetupMode == SetupEncryption)
		{

			if (offset.QuadPart + setupBlockSize > Extension->ConfiguredEncryptedAreaEnd + 1)
				setupBlockSize = (ULONG) (Extension->ConfiguredEncryptedAreaEnd + 1 - offset.QuadPart);

			if (offset.QuadPart > Extension->ConfiguredEncryptedAreaEnd)
				break;
		}
		else
		{
			if (offset.QuadPart - setupBlockSize < Extension->Queue.EncryptedAreaStart)
				setupBlockSize = (ULONG) (offset.QuadPart - Extension->Queue.EncryptedAreaStart);

			offset.QuadPart -= setupBlockSize;

			if (setupBlockSize == 0 || offset.QuadPart < Extension->Queue.EncryptedAreaStart)
				break;
		}

		while (!NT_SUCCESS (EncryptedIoQueueHoldWhenIdle (&Extension->Queue, 500)))
		{
			if (EncryptionSetupThreadAbortRequested)
				goto abort;

			TransformWaitingForIdle = TRUE;
		}
		TransformWaitingForIdle = FALSE;

		status = TCReadDevice (BootDriveFilterExtension->LowerDeviceObject, buffer, offset, setupBlockSize);
		if (!NT_SUCCESS (status))
		{
			Dump ("TCReadDevice error %x  offset=%I64d\n", status, offset.QuadPart);
			SetupResult = status;
			goto err;
		}

		dataUnit.Value = offset.QuadPart / ENCRYPTION_DATA_UNIT_SIZE;

		if (SetupRequest.SetupMode == SetupEncryption)
		{
			EncryptDataUnits (buffer, &dataUnit, setupBlockSize / ENCRYPTION_DATA_UNIT_SIZE, Extension->Queue.CryptoInfo);

			if (SetupRequest.WipeAlgorithm != TC_WIPE_NONE)
			{
				byte wipePass;
				for (wipePass = 1; wipePass <= GetWipePassCount (SetupRequest.WipeAlgorithm); ++wipePass)
				{
					if (!WipeBuffer (SetupRequest.WipeAlgorithm, wipeRandChars, wipePass, wipeBuffer, setupBlockSize))
					{
						ULONG i;
						for (i = 0; i < setupBlockSize; ++i)
						{
							wipeBuffer[i] = buffer[i] + wipePass;
						}

						EncryptDataUnits (wipeBuffer, &dataUnit, setupBlockSize / ENCRYPTION_DATA_UNIT_SIZE, Extension->Queue.CryptoInfo);
						memcpy (wipeRandCharsUpdate, wipeBuffer, sizeof (wipeRandCharsUpdate)); 
					}

					status = TCWriteDevice (BootDriveFilterExtension->LowerDeviceObject, wipeBuffer, offset, setupBlockSize);
					if (!NT_SUCCESS (status))
					{
						SetupResult = status;
						goto err;
					}
				}

				memcpy (wipeRandChars, wipeRandCharsUpdate, sizeof (wipeRandCharsUpdate)); 
			}
		}
		else
		{
			DecryptDataUnits (buffer, &dataUnit, setupBlockSize / ENCRYPTION_DATA_UNIT_SIZE, Extension->Queue.CryptoInfo);
		}

		status = TCWriteDevice (BootDriveFilterExtension->LowerDeviceObject, buffer, offset, setupBlockSize);
		if (!NT_SUCCESS (status))
		{
			Dump ("TCWriteDevice error %x\n", status);
			SetupResult = status;
			goto err;
		}

		if (SetupRequest.SetupMode == SetupEncryption)
			offset.QuadPart += setupBlockSize;

		Extension->Queue.EncryptedAreaEnd = offset.QuadPart - 1;
		headerUpdateRequired = TRUE;

		EncryptedIoQueueResumeFromHold (&Extension->Queue);

		KeAcquireSpinLock (&SetupStatusSpinLock, &irql);
		SetupStatusEncryptedAreaEnd = Extension->Queue.EncryptedAreaEnd;
		KeReleaseSpinLock (&SetupStatusSpinLock, irql);

		// Update volume header
		bytesWrittenSinceHeaderUpdate += setupBlockSize;
		if (bytesWrittenSinceHeaderUpdate >= TC_ENCRYPTION_SETUP_HEADER_UPDATE_THRESHOLD)
		{
			status = SaveDriveVolumeHeader (Extension);

			if (!NT_SUCCESS (status))
			{
				SetupResult = status;
				goto err;
			}

			headerUpdateRequired = FALSE;
			bytesWrittenSinceHeaderUpdate = 0;
		}
	}

abort:
	SetupResult = STATUS_SUCCESS;
err:

	if (EncryptedIoQueueIsSuspended (&Extension->Queue))
		EncryptedIoQueueResumeFromHold (&Extension->Queue);

	if (SetupRequest.SetupMode == SetupDecryption && Extension->Queue.EncryptedAreaStart >= Extension->Queue.EncryptedAreaEnd)
	{
		while (!NT_SUCCESS (EncryptedIoQueueHoldWhenIdle (&Extension->Queue, 0)));

		Extension->ConfiguredEncryptedAreaStart = Extension->ConfiguredEncryptedAreaEnd = -1;
		Extension->Queue.EncryptedAreaStart = Extension->Queue.EncryptedAreaEnd = -1;

		EncryptedIoQueueResumeFromHold (&Extension->Queue);

		headerUpdateRequired = TRUE;
	}

	Dump ("Setup completed:  EncryptedAreaStart=%I64d (%I64d)  EncryptedAreaEnd=%I64d (%I64d)\n", Extension->Queue.EncryptedAreaStart / 1024 / 1024, Extension->Queue.EncryptedAreaStart, Extension->Queue.EncryptedAreaEnd / 1024 / 1024, Extension->Queue.EncryptedAreaEnd);

	if (headerUpdateRequired)
	{
		status = SaveDriveVolumeHeader (Extension);

		if (!NT_SUCCESS (status) && NT_SUCCESS (SetupResult))
			SetupResult = status;
	}

	if (SetupRequest.SetupMode == SetupDecryption && Extension->ConfiguredEncryptedAreaEnd == -1 && Extension->DriveMounted)
	{
		DismountDrive (Extension);
	}

ret:
	if (buffer)
		TCfree (buffer);
	if (wipeBuffer)
		TCfree (wipeBuffer);

	SetupInProgress = FALSE;
	PsTerminateSystemThread (SetupResult);
}


NTSTATUS StartBootEncryptionSetup (PDEVICE_OBJECT DeviceObject, PIRP irp, PIO_STACK_LOCATION irpSp)
{
	NTSTATUS status;

	if (!UserCanAccessDriveDevice())
		return STATUS_ACCESS_DENIED;

	if (SetupInProgress || !BootDriveFound || !BootDriveFilterExtension
		|| BootDriveFilterExtension->HiddenSystem
		|| irpSp->Parameters.DeviceIoControl.InputBufferLength < sizeof (BootEncryptionSetupRequest))
		return STATUS_INVALID_PARAMETER;

	SetupRequest = *(BootEncryptionSetupRequest *) irp->AssociatedIrp.SystemBuffer;

	EncryptionSetupThreadAbortRequested = FALSE;
	KeInitializeSpinLock (&SetupStatusSpinLock);
	SetupStatusEncryptedAreaEnd = BootDriveFilterExtension ? BootDriveFilterExtension->Queue.EncryptedAreaEnd : -1;

	SetupInProgress = TRUE;
	status = TCStartThread (SetupThreadProc, DeviceObject, &EncryptionSetupThread);
	
	if (!NT_SUCCESS (status))
		SetupInProgress = FALSE;

	return status;
}


void GetBootDriveVolumeProperties (PIRP irp, PIO_STACK_LOCATION irpSp)
{
	if (irpSp->Parameters.DeviceIoControl.OutputBufferLength < sizeof (VOLUME_PROPERTIES_STRUCT))
	{
		irp->IoStatus.Status = STATUS_BUFFER_TOO_SMALL;
		irp->IoStatus.Information = 0;
	}
	else
	{
		DriveFilterExtension *Extension = BootDriveFilterExtension;
		VOLUME_PROPERTIES_STRUCT *prop = (VOLUME_PROPERTIES_STRUCT *) irp->AssociatedIrp.SystemBuffer;
		memset (prop, 0, sizeof (*prop));

		if (!BootDriveFound || !Extension)
		{
			irp->IoStatus.Status = STATUS_INVALID_PARAMETER;
			irp->IoStatus.Information = 0;
		}
		else
		{
			prop->hiddenVolume = Extension->Queue.CryptoInfo->hiddenVolume;
			prop->diskLength = Extension->ConfiguredEncryptedAreaEnd + 1 - Extension->ConfiguredEncryptedAreaStart;
			prop->ea = Extension->Queue.CryptoInfo->ea;
			prop->mode = Extension->Queue.CryptoInfo->mode;
			prop->pkcs5 = Extension->Queue.CryptoInfo->pkcs5;
			prop->pkcs5Iterations = Extension->Queue.CryptoInfo->noIterations;
			prop->volumeCreationTime = Extension->Queue.CryptoInfo->volume_creation_time;
			prop->headerCreationTime = Extension->Queue.CryptoInfo->header_creation_time;
			prop->volFormatVersion = Extension->Queue.CryptoInfo->LegacyVolume ? TC_VOLUME_FORMAT_VERSION_PRE_6_0 : TC_VOLUME_FORMAT_VERSION;

			prop->totalBytesRead = Extension->Queue.TotalBytesRead;
			prop->totalBytesWritten = Extension->Queue.TotalBytesWritten;

			irp->IoStatus.Information = sizeof (VOLUME_PROPERTIES_STRUCT);
			irp->IoStatus.Status = STATUS_SUCCESS;
		}
	}
}


void GetBootEncryptionStatus (PIRP irp, PIO_STACK_LOCATION irpSp)
{
	if (irpSp->Parameters.DeviceIoControl.OutputBufferLength < sizeof (BootEncryptionStatus))
	{
		irp->IoStatus.Status = STATUS_BUFFER_TOO_SMALL;
		irp->IoStatus.Information = 0;
	}
	else
	{
		DriveFilterExtension *Extension = BootDriveFilterExtension;
		BootEncryptionStatus *bootEncStatus = (BootEncryptionStatus *) irp->AssociatedIrp.SystemBuffer;
		memset (bootEncStatus, 0, sizeof (*bootEncStatus));

		if (BootArgsValid)
			bootEncStatus->BootLoaderVersion = BootArgs.BootLoaderVersion;

		bootEncStatus->DeviceFilterActive = DeviceFilterActive;
		bootEncStatus->SetupInProgress = SetupInProgress;
		bootEncStatus->SetupMode = SetupRequest.SetupMode;
		bootEncStatus->TransformWaitingForIdle = TransformWaitingForIdle;

		if (!BootDriveFound || !Extension)
		{
			bootEncStatus->DriveEncrypted = FALSE;
			bootEncStatus->DriveMounted = FALSE;
			bootEncStatus->VolumeHeaderPresent = FALSE;
		}
		else
		{
			bootEncStatus->DriveMounted = Extension->DriveMounted;
			bootEncStatus->VolumeHeaderPresent = Extension->VolumeHeaderPresent;
			bootEncStatus->DriveEncrypted = Extension->Queue.EncryptedAreaStart != -1;
			bootEncStatus->BootDriveLength = BootDriveLength;

			bootEncStatus->ConfiguredEncryptedAreaStart = Extension->ConfiguredEncryptedAreaStart;
			bootEncStatus->ConfiguredEncryptedAreaEnd = Extension->ConfiguredEncryptedAreaEnd;
			bootEncStatus->EncryptedAreaStart = Extension->Queue.EncryptedAreaStart;

			if (SetupInProgress)
			{
				KIRQL irql;
				KeAcquireSpinLock (&SetupStatusSpinLock, &irql);
				bootEncStatus->EncryptedAreaEnd = SetupStatusEncryptedAreaEnd;
				KeReleaseSpinLock (&SetupStatusSpinLock, irql);
			}
			else
				bootEncStatus->EncryptedAreaEnd = Extension->Queue.EncryptedAreaEnd;

			bootEncStatus->VolumeHeaderSaltCrc32 = Extension->VolumeHeaderSaltCrc32;
			bootEncStatus->HibernationPreventionCount = HibernationPreventionCount;
			bootEncStatus->HiddenSysLeakProtectionCount = HiddenSysLeakProtectionCount;

			bootEncStatus->HiddenSystem = Extension->HiddenSystem;
			
			if (Extension->HiddenSystem)
				bootEncStatus->HiddenSystemPartitionStart = BootArgs.HiddenSystemPartitionStart;
		}

		irp->IoStatus.Information = sizeof (BootEncryptionStatus);
		irp->IoStatus.Status = STATUS_SUCCESS;
	}
}


void GetBootLoaderVersion (PIRP irp, PIO_STACK_LOCATION irpSp)
{
	if (irpSp->Parameters.DeviceIoControl.OutputBufferLength < sizeof (uint16))
	{
		irp->IoStatus.Status = STATUS_BUFFER_TOO_SMALL;
		irp->IoStatus.Information = 0;
	}
	else
	{
		if (BootArgsValid)
		{
			*(uint16 *) irp->AssociatedIrp.SystemBuffer = BootArgs.BootLoaderVersion;
			irp->IoStatus.Information = sizeof (uint16);
			irp->IoStatus.Status = STATUS_SUCCESS;
		}
		else
		{
			irp->IoStatus.Status = STATUS_INVALID_PARAMETER;
			irp->IoStatus.Information = 0;
		}
	}
}


void GetBootEncryptionAlgorithmName (PIRP irp, PIO_STACK_LOCATION irpSp)
{
	if (irpSp->Parameters.DeviceIoControl.OutputBufferLength < sizeof (GetBootEncryptionAlgorithmNameRequest))
	{
		irp->IoStatus.Status = STATUS_BUFFER_TOO_SMALL;
		irp->IoStatus.Information = 0;
	}
	else
	{
		if (BootDriveFilterExtension && BootDriveFilterExtension->DriveMounted)
		{
			GetBootEncryptionAlgorithmNameRequest *request = (GetBootEncryptionAlgorithmNameRequest *) irp->AssociatedIrp.SystemBuffer;
			EAGetName (request->BootEncryptionAlgorithmName, BootDriveFilterExtension->Queue.CryptoInfo->ea);

			irp->IoStatus.Information = sizeof (GetBootEncryptionAlgorithmNameRequest);
			irp->IoStatus.Status = STATUS_SUCCESS;
		}
		else
		{
			irp->IoStatus.Status = STATUS_INVALID_PARAMETER;
			irp->IoStatus.Information = 0;
		}
	}
}


NTSTATUS GetSetupResult()
{
	return SetupResult;
}


BOOL IsBootDriveMounted ()
{
	return BootDriveFilterExtension && BootDriveFilterExtension->DriveMounted;
}


BOOL IsBootEncryptionSetupInProgress ()
{
	return SetupInProgress;
}


BOOL IsHiddenSystemRunning ()
{
	return BootDriveFilterExtension && BootDriveFilterExtension->HiddenSystem;
}


CRYPTO_INFO *GetSystemDriveCryptoInfo ()
{
	return BootDriveFilterExtension->Queue.CryptoInfo;
}


NTSTATUS AbortBootEncryptionSetup ()
{
	if (!IoIsSystemThread (PsGetCurrentThread()) && !UserCanAccessDriveDevice())
		return STATUS_ACCESS_DENIED;

	if (!SetupInProgress)
		return STATUS_SUCCESS;
		
	EncryptionSetupThreadAbortRequested = TRUE;
	TCStopThread (EncryptionSetupThread, NULL);

	return STATUS_SUCCESS;
}
