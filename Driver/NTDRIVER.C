/* Legal Notice: The source code contained in this file has been derived from
   the source code of Encryption for the Masses 2.02a, which is Copyright (c)
   1998-99 Paul Le Roux and which is covered by the 'License Agreement for
   Encryption for the Masses'. Modifications and additions to that source code
   contained in this file are Copyright (c) 2004-2006 TrueCrypt Foundation and
   Copyright (c) 2004 TrueCrypt Team, and are covered by TrueCrypt License 2.1
   the full text of which is contained in the file License.txt included in
   TrueCrypt binary and source code distribution archives.  */

#include "TCdefs.h"
#include "Crypto.h"
#include "Fat.h"
#include "Tests.h"

#include "Apidrvr.h"
#include "Ntdriver.h"
#include "Ntvol.h"
#include "Ntrawdv.h"
#include "Ntfiledv.h"
#include "Cache.h"

#include <tchar.h>
#include <initguid.h>
#include <mountmgr.h>
#include <mountdev.h>
#include <ntddvol.h>

/* Init section, which is thrown away as soon as DriverEntry returns */
#pragma alloc_text(INIT,DriverEntry)
#pragma alloc_text(INIT,TCCreateRootDeviceObject)

KMUTEX driverMutex;			/* Sync mutex for the entire driver */
BOOL SelfTestsPassed;
int LastUniqueVolumeId;

/* DriverEntry initialize's the dispatch addresses to be passed back to NT.
   RUNS AT IRQL = PASSIVE_LEVEL(0) */
NTSTATUS
DriverEntry (PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath)
{
	if (RegistryPath);	/* Remove warning */

	DriverObject->MajorFunction[IRP_MJ_CREATE] = TCDispatchQueueIRP;
	DriverObject->MajorFunction[IRP_MJ_CLOSE] = TCDispatchQueueIRP;
	DriverObject->MajorFunction[IRP_MJ_CLEANUP] = TCDispatchQueueIRP;
	DriverObject->MajorFunction[IRP_MJ_FLUSH_BUFFERS] = TCDispatchQueueIRP;
	DriverObject->MajorFunction[IRP_MJ_SHUTDOWN] = TCDispatchQueueIRP;
	DriverObject->MajorFunction[IRP_MJ_PNP] = TCDispatchQueueIRP;
	DriverObject->MajorFunction[IRP_MJ_READ] = TCDispatchQueueIRP;
	DriverObject->MajorFunction[IRP_MJ_WRITE] = TCDispatchQueueIRP;
	DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = TCDispatchQueueIRP;

	DriverObject->DriverUnload = TCUnloadDriver;

	KeInitializeMutex (&driverMutex, 1);

	SelfTestsPassed = AutoTestAlgorithms ();

	return TCCreateRootDeviceObject (DriverObject);
}

#ifdef _DEBUG
// Dumps a memory region to debug output
void DumpMem(void *mem, int len)
{
	unsigned char str[20];
	unsigned char *m = mem;
	int i,j;

	for (j=0; j<len/8; j++)
	{
		memset (str,0,sizeof str);
		for (i=0; i<8; i++) 
		{
			if (m[i] > ' ' && m[i] < '~')
				str[i]=m[i];
			else
				str[i]='.';
		}

		Dump ("0x%08x  %02x %02x %02x %02x %02x %02x %02x %02x  %s\n",
			m, m[0], m[1], m[2], m[3], m[4], m[5], m[6], m[7], str);

		m+=8;
	}
}
#endif

/* TCDispatchQueueIRP queues any IRP's so that they can be processed later
   by the thread -- or in some cases handles them immediately! */
NTSTATUS
TCDispatchQueueIRP (PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
	PEXTENSION Extension = (PEXTENSION) DeviceObject->DeviceExtension;
	PIO_STACK_LOCATION irpSp = IoGetCurrentIrpStackLocation (Irp);
	NTSTATUS ntStatus;

#ifdef USE_KERNEL_MUTEX
	if (Extension->bRootDevice == FALSE)
		KeWaitForMutexObject (&Extension->KernelMutex, Executive, KernelMode,
				      FALSE, NULL);
#endif

#ifdef _DEBUG
	if (irpSp->MajorFunction == IRP_MJ_DEVICE_CONTROL)
		Dump ("TCDispatchQueueIRP BEGIN MajorFunction = %ls 0x%08x IoControlCode = %ls 0x%08x\n",
		      TCTranslateCode (irpSp->MajorFunction), (int) irpSp->MajorFunction,
		      TCTranslateCode (irpSp->Parameters.DeviceIoControl.IoControlCode),
		      (int) irpSp->Parameters.DeviceIoControl.IoControlCode);
	//else
	//	Dump ("TCDispatchQueueIRP BEGIN MajorFunction = %ls 0x%08x\n",
	//	      TCTranslateCode (irpSp->MajorFunction), (int) irpSp->MajorFunction);
#endif

	if (Extension->bRootDevice == FALSE)
	{
		if (irpSp->MajorFunction == IRP_MJ_READ || irpSp->MajorFunction == IRP_MJ_WRITE ||
		    irpSp->MajorFunction == IRP_MJ_DEVICE_CONTROL)
		{
			if ((DeviceObject->Flags & DO_VERIFY_VOLUME))
			{
				if (!(irpSp->Flags & SL_OVERRIDE_VERIFY_VOLUME))
				{
					Irp->IoStatus.Status = STATUS_VERIFY_REQUIRED;
					Irp->IoStatus.Information = 0;
					if (!NT_SUCCESS (Irp->IoStatus.Status) &&
					    IoIsErrorUserInduced (Irp->IoStatus.Status))
					{
						IoSetHardErrorOrVerifyDevice (Irp, DeviceObject);
					}
					ntStatus = Irp->IoStatus.Status;
					IoCompleteRequest (Irp, IO_NO_INCREMENT);
					//Dump ("TCDispatchQueueIRP NTSTATUS = 0x%08x END\n", ntStatus);
#ifdef USE_KERNEL_MUTEX
					if (Extension->bRootDevice == FALSE)
						KeReleaseMutex (&Extension->KernelMutex, FALSE);
#endif
					return ntStatus;
				}
				else if (Extension->bShuttingDown)
				{
					Irp->IoStatus.Status = STATUS_IO_DEVICE_ERROR;
					Irp->IoStatus.Information = 0;
					if (!NT_SUCCESS (Irp->IoStatus.Status) &&
					    IoIsErrorUserInduced (Irp->IoStatus.Status))
					{
						IoSetHardErrorOrVerifyDevice (Irp, DeviceObject);
					}
					ntStatus = Irp->IoStatus.Status;
					IoCompleteRequest (Irp, IO_NO_INCREMENT);
					//Dump ("TCDispatchQueueIRP NTSTATUS = 0x%08x END\n", ntStatus);
#ifdef USE_KERNEL_MUTEX
					if (Extension->bRootDevice == FALSE)
						KeReleaseMutex (&Extension->KernelMutex, FALSE);
#endif
					return ntStatus;
				}
			}
			else if (Extension->bShuttingDown)
			{
				Dump ("Device %d shut down -> STATUS_IO_DEVICE_ERROR\n", Extension->nDosDriveNo);
				if (DeviceObject->Vpb && DeviceObject->Vpb->Flags & VPB_MOUNTED)
				{
					Irp->IoStatus.Status = STATUS_NO_MEDIA_IN_DEVICE;
					Irp->IoStatus.Information = 0;
					if (!NT_SUCCESS (Irp->IoStatus.Status) &&
					    IoIsErrorUserInduced (Irp->IoStatus.Status))
					{
						IoSetHardErrorOrVerifyDevice (Irp, DeviceObject);
					}
					DeviceObject->Flags |= DO_VERIFY_VOLUME;
				}
				else
				{
					Irp->IoStatus.Status = STATUS_IO_DEVICE_ERROR;
					Irp->IoStatus.Information = 0;
				}

				ntStatus = Irp->IoStatus.Status;
				IoCompleteRequest (Irp, IO_NO_INCREMENT);
				//Dump ("TCDispatchQueueIRP NTSTATUS = 0x%08x END\n", ntStatus);
#ifdef USE_KERNEL_MUTEX
				if (Extension->bRootDevice == FALSE)
					KeReleaseMutex (&Extension->KernelMutex, FALSE);
#endif
				return ntStatus;
			}
		}
		else if ((DeviceObject->Flags & DO_VERIFY_VOLUME))
		{		/* If shutting down or media removed */
			if (Extension->bShuttingDown)
			{
				Irp->IoStatus.Status = STATUS_VERIFY_REQUIRED;
				Irp->IoStatus.Information = 0;
				if (!NT_SUCCESS (Irp->IoStatus.Status) &&
				IoIsErrorUserInduced (Irp->IoStatus.Status))
				{
					IoSetHardErrorOrVerifyDevice (Irp, DeviceObject);
				}
				ntStatus = Irp->IoStatus.Status;
				IoCompleteRequest (Irp, IO_NO_INCREMENT);
				//Dump ("TCDispatchQueueIRP NTSTATUS = 0x%08x END\n", ntStatus);
#ifdef USE_KERNEL_MUTEX
				if (Extension->bRootDevice == FALSE)
					KeReleaseMutex (&Extension->KernelMutex, FALSE);
#endif
				return ntStatus;
			}
			else
			{
				Irp->IoStatus.Status = STATUS_IO_DEVICE_ERROR;
				Irp->IoStatus.Information = 0;
				ntStatus = Irp->IoStatus.Status;
				IoCompleteRequest (Irp, IO_NO_INCREMENT);
				//Dump ("TCDispatchQueueIRP NTSTATUS = 0x%08x END\n", ntStatus);
#ifdef USE_KERNEL_MUTEX
				if (Extension->bRootDevice == FALSE)
					KeReleaseMutex (&Extension->KernelMutex, FALSE);
#endif
				return ntStatus;
			}
		}
	}

	switch (irpSp->MajorFunction)
	{
	case IRP_MJ_CLOSE:
	case IRP_MJ_CREATE:
	case IRP_MJ_CLEANUP:
#ifdef USE_KERNEL_MUTEX
		if (Extension->bRootDevice == FALSE)
			KeReleaseMutex (&Extension->KernelMutex, FALSE);
#endif
		return COMPLETE_IRP (DeviceObject, Irp, STATUS_SUCCESS, 0);

	case IRP_MJ_SHUTDOWN:
#ifdef USE_KERNEL_MUTEX
		if (Extension->bRootDevice == FALSE)
			KeReleaseMutex (&Extension->KernelMutex, FALSE);
#endif
		if (Extension->bRootDevice)
			UnmountAllDevices (DeviceObject, TRUE, FALSE, TRUE);

		return COMPLETE_IRP (DeviceObject, Irp, STATUS_SUCCESS, 0);

	case IRP_MJ_FLUSH_BUFFERS:
	case IRP_MJ_READ:
	case IRP_MJ_WRITE:
	case IRP_MJ_DEVICE_CONTROL:
		if (Extension->bRootDevice == FALSE)
		{
			ASSERT (Extension->bShuttingDown == FALSE);

			IoMarkIrpPending (Irp);

			ASSERT (KeGetCurrentIrql ()== PASSIVE_LEVEL ||
				KeGetCurrentIrql ()== APC_LEVEL);

			ExInterlockedInsertTailList (
						      &Extension->ListEntry,
					       &Irp->Tail.Overlay.ListEntry,
						  &Extension->ListSpinLock);

			ASSERT (KeGetCurrentIrql ()== PASSIVE_LEVEL ||
				KeGetCurrentIrql ()== APC_LEVEL);

			KeReleaseSemaphore (
					       &Extension->RequestSemaphore,
						   (KPRIORITY) 0,
						   1,
						   FALSE);

			//Dump ("TCDispatchQueueIRP STATUS_PENDING END\n");
#ifdef USE_KERNEL_MUTEX
			if (Extension->bRootDevice == FALSE)
				KeReleaseMutex (&Extension->KernelMutex, FALSE);
#endif
			return STATUS_PENDING;
		}
		else
		{
			if (irpSp->Parameters.DeviceIoControl.IoControlCode >= TC_FIRST_PRIVATE &&
			    irpSp->Parameters.DeviceIoControl.IoControlCode <= TC_LAST_PRIVATE)
			{
				ntStatus = TCDeviceControl (DeviceObject, Extension, Irp);
				//Dump ("TCDispatchQueueIRP NTSTATUS = 0x%08x END\n", ntStatus);
#ifdef USE_KERNEL_MUTEX
				if (Extension->bRootDevice == FALSE)
					KeReleaseMutex (&Extension->KernelMutex, FALSE);
#endif
				return ntStatus;
			}

			if (irpSp->MajorFunction == IRP_MJ_FLUSH_BUFFERS)
			{
#ifdef USE_KERNEL_MUTEX
				if (Extension->bRootDevice == FALSE)
					KeReleaseMutex (&Extension->KernelMutex, FALSE);
#endif
				return COMPLETE_IRP (DeviceObject, Irp, STATUS_SUCCESS, 0);
			}
		}

#ifdef USE_KERNEL_MUTEX
		if (Extension->bRootDevice == FALSE)
			KeReleaseMutex (&Extension->KernelMutex, FALSE);
#endif

		return COMPLETE_IRP (DeviceObject, Irp, STATUS_DRIVER_INTERNAL_ERROR, 0);

	case IRP_MJ_PNP:
		if (irpSp->MinorFunction == IRP_MN_DEVICE_USAGE_NOTIFICATION)
		{
			if (!Extension->bRootDevice && Extension->bSystemVolume)
			{
				Dump ("IRP_MN_DEVICE_USAGE_NOTIFICATION OK\n");
				return COMPLETE_IRP (DeviceObject, Irp, STATUS_SUCCESS, 0);
			}

			Dump ("IRP_MN_DEVICE_USAGE_NOTIFICATION UNSUCCESSFUL\n");
			return COMPLETE_IRP (DeviceObject, Irp, STATUS_UNSUCCESSFUL, 0);
		}
	}

#ifdef _DEBUG
	Dump ("ERROR: Unknown irpSp->MajorFunction in TCDispatchQueueIRP %ls 0x%08x END\n",
	TCTranslateCode (irpSp->MajorFunction), (int) irpSp->MajorFunction);
#endif

#ifdef USE_KERNEL_MUTEX
	if (Extension->bRootDevice == FALSE)
		KeReleaseMutex (&Extension->KernelMutex, FALSE);
#endif
	return COMPLETE_IRP (DeviceObject, Irp, STATUS_DRIVER_INTERNAL_ERROR, 0);
}

NTSTATUS
TCCreateRootDeviceObject (PDRIVER_OBJECT DriverObject)
{
	UNICODE_STRING Win32NameString, ntUnicodeString;
	WCHAR dosname[32], ntname[32];
	PDEVICE_OBJECT DeviceObject;
	NTSTATUS ntStatus;
	BOOL *bRootExtension;

	Dump ("TCCreateRootDeviceObject BEGIN\n");

	wcscpy (dosname, (LPWSTR) DOS_ROOT_PREFIX);
	wcscpy (ntname, (LPWSTR) NT_ROOT_PREFIX);
	RtlInitUnicodeString (&ntUnicodeString, ntname);
	RtlInitUnicodeString (&Win32NameString, dosname);

	Dump ("Creating root device nt=%ls dos=%ls\n", ntname, dosname);
	
	ntStatus = IoCreateDevice (
					  DriverObject,		/* Our Driver Object */
					  sizeof (BOOL),	/* Size of state information */
					  &ntUnicodeString,	/* Device name "\Device\Name" */
					  FILE_DEVICE_UNKNOWN, /* Device type */
					  0,				/* Device characteristics */
					  FALSE,			/* Exclusive device */
					  &DeviceObject);	/* Returned ptr to Device Object */

	if (!NT_SUCCESS (ntStatus))
	{
		Dump ("TCCreateRootDeviceObject NTSTATUS = 0x%08x END\n", ntStatus);
		return ntStatus;/* Failed to create DeviceObject */
	}

	DeviceObject->Flags |= DO_DIRECT_IO;
	DeviceObject->AlignmentRequirement = FILE_WORD_ALIGNMENT;

	/* Setup the device extension */
	bRootExtension = (BOOL *) DeviceObject->DeviceExtension;
	*bRootExtension = TRUE;

	/* The symlinks for mount devices are created from user-mode */
	ntStatus = IoCreateSymbolicLink (&Win32NameString, &ntUnicodeString);

	if (!NT_SUCCESS (ntStatus))
	{
		Dump ("TCCreateRootDeviceObject NTSTATUS = 0x%08x END\n", ntStatus);
		IoDeleteDevice (DeviceObject);
		return ntStatus;
	}

	IoRegisterShutdownNotification (DeviceObject);

	ASSERT (KeGetCurrentIrql ()== PASSIVE_LEVEL);
	Dump ("TCCreateRootDeviceObject STATUS_SUCCESS END\n");
	return STATUS_SUCCESS;
}

NTSTATUS
TCCreateDeviceObject (PDRIVER_OBJECT DriverObject,
		       PDEVICE_OBJECT * ppDeviceObject,
		       MOUNT_STRUCT * mount)
{
	UNICODE_STRING Win32NameString, ntUnicodeString;
	WCHAR dosname[32], ntname[32];
	PEXTENSION Extension;
	NTSTATUS ntStatus;
	ULONG devChars = 0;

	Dump ("TCCreateDeviceObject BEGIN\n");

	TCGetDosNameFromNumber (dosname, mount->nDosDriveNo);
	TCGetNTNameFromNumber (ntname, mount->nDosDriveNo);
	RtlInitUnicodeString (&ntUnicodeString, ntname);
	RtlInitUnicodeString (&Win32NameString, dosname);

	devChars = mount->bMountReadOnly ? FILE_READ_ONLY_DEVICE : 0;
	devChars |= mount->bMountRemovable ? FILE_REMOVABLE_MEDIA : 0;

	Dump ("Creating device nt=%ls dos=%ls\n", ntname, dosname);

	ntStatus = IoCreateDevice (
					  DriverObject,			/* Our Driver Object */
					  sizeof (EXTENSION),	/* Size of state information */
					  &ntUnicodeString,		/* Device name "\Device\Name" */
					  FILE_DEVICE_DISK,		/* Device type */
					  devChars,				/* Device characteristics */
					  FALSE,				/* Exclusive device */
					  ppDeviceObject);		/* Returned ptr to Device Object */

	if (!NT_SUCCESS (ntStatus))
	{
		Dump ("TCCreateDeviceObject NTSTATUS = 0x%08x END\n", ntStatus);
		return ntStatus;/* Failed to create DeviceObject */
	}
	/* Initialize device object and extension. */

	(*ppDeviceObject)->Flags |= DO_DIRECT_IO;
	(*ppDeviceObject)->AlignmentRequirement = FILE_WORD_ALIGNMENT;

	/* Setup the device extension */
	Extension = (PEXTENSION) (*ppDeviceObject)->DeviceExtension;
	memset (Extension, 0, sizeof (EXTENSION));

	Extension->lMagicNumber = 0xabfeacde;
	Extension->nDosDriveNo = mount->nDosDriveNo;
	Extension->bRemovable = mount->bMountRemovable;

	KeInitializeEvent (&Extension->keCreateEvent, SynchronizationEvent, FALSE);
	KeInitializeSemaphore (&Extension->RequestSemaphore, 0L, MAXLONG);
#ifdef USE_KERNEL_MUTEX
	KeInitializeMutex (&Extension->KernelMutex, 1);
#endif
	KeInitializeSpinLock (&Extension->ListSpinLock);
	InitializeListHead (&Extension->ListEntry);

	ASSERT (KeGetCurrentIrql ()== PASSIVE_LEVEL);
	Dump ("TCCreateDeviceObject STATUS_SUCCESS END\n");

	return STATUS_SUCCESS;
}


void DriverMutexWait ()
{
	KeWaitForMutexObject (&driverMutex, Executive, KernelMode, FALSE, NULL);
}


void DriverMutexRelease ()
{
	KeReleaseMutex (&driverMutex, FALSE);
}


/* TCDeviceControl handles certain requests from NT, these are needed for NT
   to recognize the drive, also this function handles our device specific
   function codes, such as mount/unmount */
NTSTATUS
TCDeviceControl (PDEVICE_OBJECT DeviceObject, PEXTENSION Extension, PIRP Irp)
{
	PIO_STACK_LOCATION irpSp = IoGetCurrentIrpStackLocation (Irp);
	NTSTATUS ntStatus;

#ifdef _DEBUG
	 Dump ("TCDeviceControl BEGIN IoControlCode = %ls 0x%08x\n",
	 TCTranslateCode (irpSp->Parameters.DeviceIoControl.IoControlCode),
	      irpSp->Parameters.DeviceIoControl.IoControlCode);
#endif

	Irp->IoStatus.Status = STATUS_INVALID_DEVICE_REQUEST;	/* Assume failure. */

	/* Determine which I/O control code was specified.  */
	switch (irpSp->Parameters.DeviceIoControl.IoControlCode)
	{

	case IOCTL_MOUNTDEV_QUERY_DEVICE_NAME:
		if(irpSp->Parameters.DeviceIoControl.OutputBufferLength < sizeof (MOUNTDEV_NAME))
		{
			Irp->IoStatus.Information = sizeof (MOUNTDEV_NAME);
			Irp->IoStatus.Status = STATUS_BUFFER_OVERFLOW;
		}
		else
		{
			ULONG outLength;
			UNICODE_STRING ntUnicodeString;
			WCHAR ntName[256];
			PMOUNTDEV_NAME outputBuffer = (PMOUNTDEV_NAME) Irp->AssociatedIrp.SystemBuffer;

			Dump("IOCTL_MOUNTDEV_QUERY_DEVICE_NAME:");

			TCGetNTNameFromNumber (ntName, Extension->nDosDriveNo);
			RtlInitUnicodeString (&ntUnicodeString, ntName);

			outputBuffer->NameLength = ntUnicodeString.Length;
			outLength = ntUnicodeString.Length + sizeof(USHORT);

			if (irpSp->Parameters.DeviceIoControl.OutputBufferLength < outLength)
			{
				Irp->IoStatus.Information = sizeof (MOUNTDEV_NAME);
				Irp->IoStatus.Status = STATUS_BUFFER_OVERFLOW;

				break;
			}

			RtlCopyMemory ((PCHAR)outputBuffer->Name,ntUnicodeString.Buffer, ntUnicodeString.Length);

			Irp->IoStatus.Status = STATUS_SUCCESS;
			Irp->IoStatus.Information = outLength;

			Dump ("name = %ls\n",ntName);
		}
		break;

	case IOCTL_MOUNTDEV_QUERY_UNIQUE_ID:
		if(irpSp->Parameters.DeviceIoControl.OutputBufferLength < sizeof (MOUNTDEV_UNIQUE_ID))
		{
			Irp->IoStatus.Information = sizeof (MOUNTDEV_UNIQUE_ID);
			Irp->IoStatus.Status = STATUS_BUFFER_OVERFLOW;
		}
		else
		{
			ULONG outLength;
			UCHAR volId[128], tmp[] = { 0,0 };
			PMOUNTDEV_UNIQUE_ID outputBuffer = (PMOUNTDEV_UNIQUE_ID) Irp->AssociatedIrp.SystemBuffer;

			Dump("IOCTL_MOUNTDEV_QUERY_UNIQUE_ID:");

			strcpy (volId, TC_UNIQUE_ID_PREFIX); 
			tmp[0] = 'A' + Extension->nDosDriveNo;
			strcat (volId, tmp);
			
			outputBuffer->UniqueIdLength = (USHORT) strlen (volId);
			outLength = strlen (volId) + sizeof(USHORT);

			if (irpSp->Parameters.DeviceIoControl.OutputBufferLength < outLength)
			{
				Irp->IoStatus.Information = sizeof (MOUNTDEV_UNIQUE_ID);
				Irp->IoStatus.Status = STATUS_BUFFER_OVERFLOW;
				break;
			}

			RtlCopyMemory ((PCHAR)outputBuffer->UniqueId, volId, strlen (volId));

			Irp->IoStatus.Status = STATUS_SUCCESS;
			Irp->IoStatus.Information = outLength;

			Dump ("id = %s\n",volId);
		}
		break;

		case IOCTL_MOUNTDEV_QUERY_SUGGESTED_LINK_NAME:
		{
			ULONG outLength;
			UNICODE_STRING ntUnicodeString;
			WCHAR ntName[256];
			PMOUNTDEV_SUGGESTED_LINK_NAME outputBuffer = (PMOUNTDEV_SUGGESTED_LINK_NAME) Irp->AssociatedIrp.SystemBuffer;
			
			Dump("IOCTL_MOUNTDEV_QUERY_SUGGESTED_LINK_NAME:");

			TCGetDosNameFromNumber (ntName, Extension->nDosDriveNo);
			RtlInitUnicodeString (&ntUnicodeString, ntName);

			outLength = FIELD_OFFSET(MOUNTDEV_SUGGESTED_LINK_NAME,Name) + ntUnicodeString.Length;

			outputBuffer->UseOnlyIfThereAreNoOtherLinks = FALSE;
			outputBuffer->NameLength = ntUnicodeString.Length;

			if(irpSp->Parameters.DeviceIoControl.OutputBufferLength < outLength)
			{
				Irp->IoStatus.Information = sizeof (MOUNTDEV_SUGGESTED_LINK_NAME);
				Irp->IoStatus.Status = STATUS_BUFFER_OVERFLOW;
				break;
			}

			RtlCopyMemory ((PCHAR)outputBuffer->Name,ntUnicodeString.Buffer, ntUnicodeString.Length);
		
			Irp->IoStatus.Status = STATUS_SUCCESS;
			Irp->IoStatus.Information = outLength;

			Dump ("link = %ls\n",ntName);
		}
		break;


	case IOCTL_DISK_GET_MEDIA_TYPES:
	case IOCTL_DISK_GET_DRIVE_GEOMETRY:
		/* Return the drive geometry for the disk.  Note that we
		   return values which were made up to suit the disk size.  */
		if (irpSp->Parameters.DeviceIoControl.OutputBufferLength <
		    sizeof (DISK_GEOMETRY))
		{
			Irp->IoStatus.Status = STATUS_INVALID_PARAMETER;
			Irp->IoStatus.Information = 0;
		}
		else
		{
			PDISK_GEOMETRY outputBuffer = (PDISK_GEOMETRY)
			Irp->AssociatedIrp.SystemBuffer;

			outputBuffer->MediaType = Extension->bRemovable ? RemovableMedia : FixedMedia;
			outputBuffer->Cylinders.QuadPart = Extension->NumberOfCylinders;
			outputBuffer->TracksPerCylinder = Extension->TracksPerCylinder;
			outputBuffer->SectorsPerTrack = Extension->SectorsPerTrack;
			outputBuffer->BytesPerSector = Extension->BytesPerSector;
			Irp->IoStatus.Status = STATUS_SUCCESS;
			Irp->IoStatus.Information = sizeof (DISK_GEOMETRY);
		}
		break;

	case IOCTL_DISK_GET_PARTITION_INFO:
		if (irpSp->Parameters.DeviceIoControl.OutputBufferLength <
		    sizeof (PARTITION_INFORMATION))
		{
			Irp->IoStatus.Status = STATUS_INVALID_PARAMETER;
			Irp->IoStatus.Information = 0;
		}
		else
		{
			PPARTITION_INFORMATION outputBuffer = (PPARTITION_INFORMATION)
			Irp->AssociatedIrp.SystemBuffer;

			outputBuffer->PartitionType = Extension->PartitionType;
			outputBuffer->BootIndicator = FALSE;
			outputBuffer->RecognizedPartition = TRUE;
			outputBuffer->RewritePartition = FALSE;
			outputBuffer->StartingOffset = RtlConvertUlongToLargeInteger (0);
			outputBuffer->PartitionLength.QuadPart= Extension->DiskLength;
			outputBuffer->HiddenSectors = 1L;
			Irp->IoStatus.Status = STATUS_SUCCESS;
			Irp->IoStatus.Information = sizeof (PARTITION_INFORMATION);
		}
		break;
		
	case IOCTL_DISK_GET_DRIVE_LAYOUT:
		if (irpSp->Parameters.DeviceIoControl.OutputBufferLength <
		    sizeof (DRIVE_LAYOUT_INFORMATION))
		{
			Irp->IoStatus.Status = STATUS_INVALID_PARAMETER;
			Irp->IoStatus.Information = 0;
		}
		else
		{
			PDRIVE_LAYOUT_INFORMATION outputBuffer = (PDRIVE_LAYOUT_INFORMATION)
			Irp->AssociatedIrp.SystemBuffer;

			outputBuffer->PartitionCount = 1;
			outputBuffer->Signature = 0;

			outputBuffer->PartitionEntry->PartitionType = Extension->PartitionType;
			outputBuffer->PartitionEntry->BootIndicator = FALSE;
			outputBuffer->PartitionEntry->RecognizedPartition = TRUE;
			outputBuffer->PartitionEntry->RewritePartition = FALSE;
			outputBuffer->PartitionEntry->StartingOffset = RtlConvertUlongToLargeInteger (0);
			outputBuffer->PartitionEntry->PartitionLength.QuadPart= Extension->DiskLength;
			outputBuffer->PartitionEntry->HiddenSectors = 1L;

			Irp->IoStatus.Status = STATUS_SUCCESS;
			Irp->IoStatus.Information = sizeof (PARTITION_INFORMATION);
		}
		break;

	case IOCTL_DISK_GET_LENGTH_INFO:
		if (irpSp->Parameters.DeviceIoControl.OutputBufferLength < sizeof (GET_LENGTH_INFORMATION))
		{
			Irp->IoStatus.Status = STATUS_BUFFER_OVERFLOW;
			Irp->IoStatus.Information = sizeof (GET_LENGTH_INFORMATION);
		}
		else
		{
			PGET_LENGTH_INFORMATION outputBuffer = (PGET_LENGTH_INFORMATION) Irp->AssociatedIrp.SystemBuffer;

			outputBuffer->Length.QuadPart = Extension->DiskLength;
			Irp->IoStatus.Status = STATUS_SUCCESS;
			Irp->IoStatus.Information = sizeof (GET_LENGTH_INFORMATION);
		}
		break;

	case IOCTL_DISK_VERIFY:
		{
			PVERIFY_INFORMATION pVerifyInformation;
			pVerifyInformation = (PVERIFY_INFORMATION) Irp->AssociatedIrp.SystemBuffer;
			irpSp->Parameters.Read.ByteOffset.LowPart =
				pVerifyInformation->StartingOffset.LowPart;
			irpSp->Parameters.Read.ByteOffset.HighPart =
				pVerifyInformation->StartingOffset.HighPart;
			irpSp->Parameters.Read.Length = pVerifyInformation->Length;
			Irp->IoStatus.Status = STATUS_SUCCESS;
			Irp->IoStatus.Information = pVerifyInformation->Length;
		}
		break;

	case IOCTL_DISK_CHECK_VERIFY:
	case IOCTL_STORAGE_CHECK_VERIFY:
		{
			Irp->IoStatus.Status = STATUS_SUCCESS;
			Irp->IoStatus.Information = 0;
		}
		break;

	case IOCTL_DISK_IS_WRITABLE:
		{
			if (Extension->bReadOnly)
				Irp->IoStatus.Status = STATUS_MEDIA_WRITE_PROTECTED;
			else
				Irp->IoStatus.Status = STATUS_SUCCESS;
			Irp->IoStatus.Information = 0;

		}
		break;

	// Private IOCTLs 

	case DRIVER_VERSION:
		if (irpSp->Parameters.DeviceIoControl.OutputBufferLength < sizeof (LONG))
		{
			Irp->IoStatus.Status = STATUS_INVALID_PARAMETER;
			Irp->IoStatus.Information = 0;
		}
		else
		{
			LONG tmp = VERSION_NUM;
			memcpy (Irp->AssociatedIrp.SystemBuffer, &tmp, 4);
			Irp->IoStatus.Information = sizeof (LONG);
			Irp->IoStatus.Status = STATUS_SUCCESS;
		}
		break;

	case DEVICE_REFCOUNT:
		if (irpSp->Parameters.DeviceIoControl.OutputBufferLength < sizeof (int))
		{
			Irp->IoStatus.Status = STATUS_INVALID_PARAMETER;
			Irp->IoStatus.Information = 0;
		}
		else
		{
			*(int *) Irp->AssociatedIrp.SystemBuffer = DeviceObject->ReferenceCount;
			Irp->IoStatus.Information = sizeof (int);
			Irp->IoStatus.Status = STATUS_SUCCESS;
		}
		break;

	case OPEN_TEST:
		{
			OPEN_TEST_STRUCT *opentest = (OPEN_TEST_STRUCT *) Irp->AssociatedIrp.SystemBuffer;
			OBJECT_ATTRIBUTES ObjectAttributes;
			HANDLE NtFileHandle;
			UNICODE_STRING FullFileName;
			IO_STATUS_BLOCK IoStatus;

			RtlInitUnicodeString (&FullFileName, opentest->wszFileName);

			InitializeObjectAttributes (&ObjectAttributes, &FullFileName, OBJ_CASE_INSENSITIVE,
						    NULL, NULL);

			ntStatus = ZwCreateFile (&NtFileHandle,
						 SYNCHRONIZE | GENERIC_READ, &ObjectAttributes, &IoStatus, NULL /* alloc size = none  */ ,
						 FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ | FILE_SHARE_WRITE, FILE_OPEN, FILE_SYNCHRONOUS_IO_NONALERT |
			FILE_NO_INTERMEDIATE_BUFFERING | FILE_RANDOM_ACCESS,
				  NULL /* eabuffer  */ , 0 /* ealength */ );

			if (NT_SUCCESS (ntStatus))
			{
				ZwClose (NtFileHandle);
				Dump ("Open test on file %ls success.\n", opentest->wszFileName);
			}
			else
			{
				Dump ("Open test on file %ls failed NTSTATUS 0x%08x\n", opentest->wszFileName, ntStatus);
			}

			Irp->IoStatus.Information = 0;
			Irp->IoStatus.Status = ntStatus;
		}
		break;

	case WIPE_CACHE:
		DriverMutexWait ();
		WipeCache ();
		DriverMutexRelease ();

		Irp->IoStatus.Status = STATUS_SUCCESS;
		Irp->IoStatus.Information = 0;
		break;

	case CACHE_STATUS:
		Irp->IoStatus.Status = cacheEmpty ? STATUS_PIPE_EMPTY : STATUS_SUCCESS;
		Irp->IoStatus.Information = 0;
		break;

#ifdef DEBUG
	case HALT_SYSTEM:
		KeBugCheck ((ULONG) 0x5050);
		break;
#endif

	case MOUNT_LIST:
		if (irpSp->Parameters.DeviceIoControl.OutputBufferLength < sizeof (MOUNT_LIST_STRUCT)
			|| !DeviceObject || !DeviceObject->DriverObject)
		{
			Irp->IoStatus.Status = STATUS_INVALID_PARAMETER;
			Irp->IoStatus.Information = 0;
		}
		else
		{
			MOUNT_LIST_STRUCT *list = (MOUNT_LIST_STRUCT *) Irp->AssociatedIrp.SystemBuffer;
			PDEVICE_OBJECT ListDevice;

			DriverMutexWait ();

			list->ulMountedDrives = 0;
			for (ListDevice = DeviceObject->DriverObject->DeviceObject;
			     ListDevice != (PDEVICE_OBJECT) NULL; ListDevice = ListDevice->NextDevice)
			{

				PEXTENSION ListExtension = (PEXTENSION) ListDevice->DeviceExtension;
				if (ListExtension->lMagicNumber == 0xabfeacde
					&& ListExtension->bRootDevice == FALSE
					&& !ListExtension->bSystemVolume
					&& !ListExtension->bPersistentVolume
					&& !ListExtension->bShuttingDown)
				{
					list->ulMountedDrives |= (1 << ListExtension->nDosDriveNo);
					wcscpy (list->wszVolume[ListExtension->nDosDriveNo], ListExtension->wszVolume);
					list->diskLength[ListExtension->nDosDriveNo] = ListExtension->DiskLength;
					list->ea[ListExtension->nDosDriveNo] = ListExtension->cryptoInfo->ea;
					if (ListExtension->cryptoInfo->hiddenVolume)
						list->volumeType[ListExtension->nDosDriveNo] = PROP_VOL_TYPE_HIDDEN;	// Hidden volume
					else if (ListExtension->cryptoInfo->bHiddenVolProtectionAction)
						list->volumeType[ListExtension->nDosDriveNo] = PROP_VOL_TYPE_OUTER_VOL_WRITE_PREVENTED;	// Normal/outer volume (hidden volume protected AND write already prevented)
					else if (ListExtension->cryptoInfo->bProtectHiddenVolume)
						list->volumeType[ListExtension->nDosDriveNo] = PROP_VOL_TYPE_OUTER;	// Normal/outer volume (hidden volume protected)
					else
						list->volumeType[ListExtension->nDosDriveNo] = PROP_VOL_TYPE_NORMAL;	// Normal volume
				}
			}

			DriverMutexRelease ();

			Irp->IoStatus.Status = STATUS_SUCCESS;
			Irp->IoStatus.Information = sizeof (MOUNT_LIST_STRUCT);
		}
		break;

	case VOLUME_PROPERTIES:
		if (irpSp->Parameters.DeviceIoControl.OutputBufferLength < sizeof (VOLUME_PROPERTIES_STRUCT)
			|| !DeviceObject || !DeviceObject->DriverObject)
		{
			Irp->IoStatus.Status = STATUS_INVALID_PARAMETER;
			Irp->IoStatus.Information = 0;
		}
		else
		{
			VOLUME_PROPERTIES_STRUCT *prop = (VOLUME_PROPERTIES_STRUCT *) Irp->AssociatedIrp.SystemBuffer;
			PDEVICE_OBJECT ListDevice;

			Irp->IoStatus.Status = STATUS_INVALID_PARAMETER;
			Irp->IoStatus.Information = 0;

			DriverMutexWait ();

			for (ListDevice = DeviceObject->DriverObject->DeviceObject;
			     ListDevice != (PDEVICE_OBJECT) NULL; ListDevice = ListDevice->NextDevice)
			{

				PEXTENSION ListExtension = (PEXTENSION) ListDevice->DeviceExtension;
				if (ListExtension->bRootDevice == FALSE
					&& !ListExtension->bShuttingDown
					&& ListExtension->nDosDriveNo == prop->driveNo)
				{
					prop->uniqueId = ListExtension->UniqueVolumeId;
					wcscpy (prop->wszVolume, ListExtension->wszVolume);
					prop->diskLength = ListExtension->DiskLength;
					prop->ea = ListExtension->cryptoInfo->ea;
					prop->mode = ListExtension->cryptoInfo->mode;
					prop->pkcs5 = ListExtension->cryptoInfo->pkcs5;
					prop->pkcs5Iterations = ListExtension->cryptoInfo->noIterations;
					prop->volumeCreationTime = ListExtension->cryptoInfo->volume_creation_time;
					prop->headerCreationTime = ListExtension->cryptoInfo->header_creation_time;
					prop->readOnly = ListExtension->bReadOnly;
					prop->hiddenVolume = ListExtension->cryptoInfo->hiddenVolume;
					prop->systemVolume = ListExtension->bSystemVolume;
					prop->persistentVolume = ListExtension->bPersistentVolume;

					if (ListExtension->cryptoInfo->bProtectHiddenVolume)
						prop->hiddenVolProtection = ListExtension->cryptoInfo->bHiddenVolProtectionAction ? HIDVOL_PROT_STATUS_ACTION_TAKEN : HIDVOL_PROT_STATUS_ACTIVE;
					else
						prop->hiddenVolProtection = HIDVOL_PROT_STATUS_NONE;

					prop->totalBytesRead = ListExtension->TotalBytesRead;
					prop->totalBytesWritten = ListExtension->TotalBytesWritten;

					Irp->IoStatus.Status = STATUS_SUCCESS;
					Irp->IoStatus.Information = sizeof (VOLUME_PROPERTIES_STRUCT);
					break;
				}
			}

			DriverMutexRelease ();
		}
		break;

	case RESOLVE_SYMLINK:
		if (irpSp->Parameters.DeviceIoControl.OutputBufferLength < sizeof (RESOLVE_SYMLINK_STRUCT))
		{
			Irp->IoStatus.Status = STATUS_INVALID_PARAMETER;
			Irp->IoStatus.Information = 0;
		}
		else
		{
			RESOLVE_SYMLINK_STRUCT *resolve = (RESOLVE_SYMLINK_STRUCT *) Irp->AssociatedIrp.SystemBuffer;
			{
				NTSTATUS ntStatus;

				ntStatus = SymbolicLinkToTarget (resolve->symLinkName,
					resolve->targetName,
					sizeof (resolve->targetName));

				Irp->IoStatus.Information = sizeof (RESOLVE_SYMLINK_STRUCT);
				Irp->IoStatus.Status = ntStatus;
			}

		}
		break;

	case MOUNT:
		if (irpSp->Parameters.DeviceIoControl.OutputBufferLength < sizeof (MOUNT_STRUCT))
		{
			Irp->IoStatus.Status = STATUS_INVALID_PARAMETER;
			Irp->IoStatus.Information = 0;
		}
		else
		{
			MOUNT_STRUCT *mount = (MOUNT_STRUCT *) Irp->AssociatedIrp.SystemBuffer;

			DriverMutexWait ();

			Irp->IoStatus.Information = sizeof (MOUNT_STRUCT);
			Irp->IoStatus.Status = MountDevice (DeviceObject, mount);
			DriverMutexRelease ();

			burn (&mount->VolumePassword, sizeof (mount->VolumePassword));
			burn (&mount->ProtectedHidVolPassword, sizeof (mount->ProtectedHidVolPassword));
		}
		break;

	case UNMOUNT:
		if (irpSp->Parameters.DeviceIoControl.OutputBufferLength < sizeof (UNMOUNT_STRUCT)
			|| !DeviceObject || !DeviceObject->DriverObject)
		{
			Irp->IoStatus.Status = STATUS_INVALID_PARAMETER;
			Irp->IoStatus.Information = 0;
		}
		else
		{
			UNMOUNT_STRUCT *unmount = (UNMOUNT_STRUCT *) Irp->AssociatedIrp.SystemBuffer;
			PDEVICE_OBJECT ListDevice;

			unmount->nReturnCode = ERR_DRIVE_NOT_FOUND;

			for (ListDevice = DeviceObject->DriverObject->DeviceObject;
			     ListDevice != (PDEVICE_OBJECT) NULL;
			     ListDevice = ListDevice->NextDevice)
			{
				PEXTENSION ListExtension = (PEXTENSION) ListDevice->DeviceExtension;

				if (ListExtension->bRootDevice == FALSE
					&& !ListExtension->bShuttingDown
					&& unmount->nDosDriveNo == ListExtension->nDosDriveNo)
				{
					DriverMutexWait ();
					unmount->nReturnCode = UnmountDevice (ListDevice, unmount->ignoreOpenFiles);
					DriverMutexRelease ();
					break;
				}

				if (ListDevice == NULL)
					break;
			}

			Irp->IoStatus.Information = sizeof (UNMOUNT_STRUCT);
			Irp->IoStatus.Status = STATUS_SUCCESS;
		}
		break;

	case UNMOUNT_ALL:
		if (irpSp->Parameters.DeviceIoControl.OutputBufferLength < sizeof (UNMOUNT_STRUCT))
		{
			Irp->IoStatus.Status = STATUS_INVALID_PARAMETER;
			Irp->IoStatus.Information = 0;
		}
		else
		{
			UNMOUNT_STRUCT *unmount = (UNMOUNT_STRUCT *) Irp->AssociatedIrp.SystemBuffer;

			unmount->nReturnCode = UnmountAllDevices (DeviceObject, unmount->ignoreOpenFiles, FALSE, FALSE);

			Irp->IoStatus.Information = sizeof (UNMOUNT_STRUCT);
			Irp->IoStatus.Status = STATUS_SUCCESS;
		}
		break;
	}

	/* Finish the I/O operation by simply completing the packet and
	   returning the same NTSTATUS as in the packet itself.  */
	ntStatus = COMPLETE_IRP (DeviceObject, Irp, Irp->IoStatus.Status, Irp->IoStatus.Information);
	Dump ("TCDeviceControl NTSTATUS = 0x%08x END\n", ntStatus);
	return ntStatus;
}


NTSTATUS
TCStartThread (PDEVICE_OBJECT DeviceObject, PEXTENSION Extension, MOUNT_STRUCT * mount)
{
	PTHREAD_BLOCK pThreadBlock = TCalloc (sizeof (THREAD_BLOCK));
	HANDLE hThread;
	NTSTATUS ntStatus;
	HANDLE process;

	Dump ("Starting thread...\n");

	if (pThreadBlock == NULL)
	{
		return STATUS_INSUFFICIENT_RESOURCES;
	}
	else
	{
		pThreadBlock->DeviceObject = DeviceObject;
		pThreadBlock->mount = mount;
	}

	if (mount->bUserContext)
	{
		ntStatus = ObOpenObjectByPointer (IoGetCurrentProcess (), 0, NULL, 0, NULL, KernelMode, &process);
		if (!NT_SUCCESS (ntStatus))
		{
			Dump ("ObOpenObjectByPointer Failed\n");
			goto ret;
		}
	}
	else
		process = NULL;

	Extension->bSystemVolume = mount->bSystemVolume;
	Extension->bPersistentVolume = mount->bPersistentVolume;

	Extension->bThreadShouldQuit = FALSE;

	ntStatus = PsCreateSystemThread (&hThread,
					 THREAD_ALL_ACCESS,
					 NULL,
					 process,
					 NULL,
					 TCThreadIRP,
					 pThreadBlock);

	if (!NT_SUCCESS (ntStatus))
	{
		Dump ("PsCreateSystemThread Failed END\n");
		goto ret;
	}

	ObReferenceObjectByHandle (hThread,
				   THREAD_ALL_ACCESS,
				   NULL,
				   KernelMode,
				   &Extension->peThread,
				   NULL);
	ZwClose (hThread);

	Dump ("Waiting for thread to initialize...\n");

	KeWaitForSingleObject (&Extension->keCreateEvent,
			       UserRequest,
			       UserMode,
			       FALSE,
			       NULL);

	Dump ("Waiting completed! Thread returns 0x%08x\n", pThreadBlock->ntCreateStatus);
	ntStatus = pThreadBlock->ntCreateStatus;

ret:
	TCfree (pThreadBlock);
	return ntStatus;
}

void
TCStopThread (PDEVICE_OBJECT DeviceObject, PEXTENSION Extension)
{
	NTSTATUS ntStatus;

	if (DeviceObject);	/* Remove compiler warning */

	Dump ("Signalling thread to quit...\n");

	Extension->bThreadShouldQuit = TRUE;

	KeReleaseSemaphore (&Extension->RequestSemaphore,
			    0,
			    1,
			    TRUE);

	ntStatus = KeWaitForSingleObject (Extension->peThread,
					  UserRequest,
					  UserMode,
					  FALSE,
					  NULL);
	if (ntStatus != STATUS_SUCCESS)
		Dump ("Failed waiting for crypto thread to quit: 0x%08x...\n",
		      ntStatus);

	ObDereferenceObject (Extension->peThread);
	Extension->peThread = NULL;

	Dump ("Thread exited!\n");
}


// Suspend current thread for a number of milliseconds
void TCSleep (int milliSeconds)
{
	PKTIMER timer = (PKTIMER) TCalloc (sizeof (KTIMER));
	LARGE_INTEGER duetime;

	duetime.QuadPart = (__int64) milliSeconds * -10000;
	KeInitializeTimerEx(timer, NotificationTimer);
	KeSetTimerEx(timer, duetime, 0, NULL);

	KeWaitForSingleObject (timer, UserRequest, UserMode, FALSE, NULL);

	TCfree (timer);
}


/* TCThreadIRP does all the work of processing IRP's, and dispatching them
   to either the ReadWrite function or the DeviceControl function */
VOID
TCThreadIRP (PVOID Context)
{
	PTHREAD_BLOCK pThreadBlock = (PTHREAD_BLOCK) Context;
	PDEVICE_OBJECT DeviceObject = pThreadBlock->DeviceObject;
	PEXTENSION Extension = (PEXTENSION) DeviceObject->DeviceExtension;
	LARGE_INTEGER queueWait;
	BOOL bDevice;

	/* Set thread priority to lowest realtime level. */

	KeSetPriorityThread (KeGetCurrentThread (), LOW_REALTIME_PRIORITY);

	queueWait.QuadPart = -WAIT_SECONDS (1);

	Dump ("Mount THREAD OPENING VOLUME BEGIN\n");

#ifdef USE_KERNEL_MUTEX
	KeWaitForMutexObject (&Extension->KernelMutex, Executive, KernelMode,
			      FALSE, NULL);
#endif

	if (memcmp (pThreadBlock->mount->wszVolume, WIDE ("\\Device"), 14) != 0)
	{
		wcscpy (pThreadBlock->wszMountVolume, WIDE ("\\??\\"));
		wcsncat (pThreadBlock->wszMountVolume, pThreadBlock->mount->wszVolume,
			sizeof (pThreadBlock->wszMountVolume) / 2 - 5);
		bDevice = FALSE;
	}
	else
	{
		pThreadBlock->wszMountVolume[0] = 0;
		wcsncat (pThreadBlock->wszMountVolume, pThreadBlock->mount->wszVolume,
			sizeof (pThreadBlock->wszMountVolume) / 2 - 1);
		bDevice = TRUE;
	}

	Dump ("Mount THREAD request for File %ls DriveNumber %d Device = %d\n",
	      pThreadBlock->wszMountVolume, pThreadBlock->mount->nDosDriveNo, bDevice);

	pThreadBlock->ntCreateStatus = TCOpenVolume (DeviceObject,
		Extension,
		pThreadBlock->mount,
		pThreadBlock->wszMountVolume,
		bDevice);

#ifdef USE_KERNEL_MUTEX
	KeReleaseMutex (&Extension->KernelMutex, FALSE);
#endif

	if (!NT_SUCCESS (pThreadBlock->ntCreateStatus) || pThreadBlock->mount->nReturnCode != 0)
	{
		KeSetEvent (&Extension->keCreateEvent, 0, FALSE);
		PsTerminateSystemThread (STATUS_SUCCESS);
	}
	else
	{
		KeSetEvent (&Extension->keCreateEvent, 0, FALSE);
		/* From this point on pThreadBlock cannot be used as it will
		   have been released! */
		pThreadBlock = NULL;
	}


	for (;;)
	{
		NTSTATUS ntStatus;

		ASSERT (KeGetCurrentIrql ()== PASSIVE_LEVEL);

		/* Wait for a request from the dispatch routines. */
		ntStatus = KeWaitForSingleObject ((PVOID) & Extension->RequestSemaphore,
				  Executive, KernelMode, FALSE, &queueWait);

		if (ntStatus != STATUS_TIMEOUT)
		{

#ifdef USE_KERNEL_MUTEX
			KeWaitForMutexObject (&Extension->KernelMutex, Executive, KernelMode,
					      FALSE, NULL);
#endif

		//	Dump ("DRIVER THREAD PROCESSING DEVICEOBJECT 0x%08x \n", DeviceObject);

			for (;;)
			{
				PIO_STACK_LOCATION irpSp;
				PLIST_ENTRY request;
				PIRP Irp;

				request = ExInterlockedRemoveHeadList (&Extension->ListEntry,
						  &Extension->ListSpinLock);
				if (request == NULL)
					break;

				ASSERT (KeGetCurrentIrql ()== PASSIVE_LEVEL);

				Irp = CONTAINING_RECORD (request, IRP, Tail.Overlay.ListEntry);
				irpSp = IoGetCurrentIrpStackLocation (Irp);

				switch (irpSp->MajorFunction)
				{
				case IRP_MJ_READ:
				case IRP_MJ_WRITE:
					TCReadWrite (DeviceObject, Extension, Irp);
					break;

				case IRP_MJ_FLUSH_BUFFERS:
					if (Extension->bRawDevice == FALSE)
						TCSendIRP_FileDevice (DeviceObject, Extension, NULL, Irp->Flags, IRP_MJ_FLUSH_BUFFERS, Irp);
					else
					{
						COMPLETE_IRP (DeviceObject, Irp, STATUS_SUCCESS, 0);
					}
					break;

				case IRP_MJ_SHUTDOWN:
					COMPLETE_IRP (DeviceObject, Irp, STATUS_SUCCESS, 0);
					break;

				case IRP_MJ_DEVICE_CONTROL:
					if (irpSp->Parameters.DeviceIoControl.IoControlCode != IOCTL_DISK_CHECK_VERIFY)
						TCDeviceControl (DeviceObject, Extension, Irp);
					else
					{
						if (Extension->bRawDevice)
							TCSendIRP_RawDevice (DeviceObject, Extension, NULL, 0, IRP_MJ_DEVICE_CONTROL, Irp);
						else
							TCDeviceControl (DeviceObject, Extension, Irp);
					}
					break;
				}	/* end of switch on
					   irpSp->MajorFunction */
			}	/* for any remaining IRP's for this device */

#ifdef USE_KERNEL_MUTEX
			KeReleaseMutex (&Extension->KernelMutex, FALSE);
#endif

			if (Extension->bThreadShouldQuit)
			{
			//	Dump ("END PROCESSING DEVICEOBJECT THREAD ENDING 0x%08x Number = %d\n",
			//	      DeviceObject, Extension->nDosDriveNo);
				Dump ("Closing volume along with Thread!\n");
				TCCloseVolume (DeviceObject, Extension);
				PsTerminateSystemThread (STATUS_SUCCESS);
			}
			//else
			//{
			//	Dump ("END PROCESSING DEVICEOBJECT 0x%08x Number = %d\n",
			//	      DeviceObject, Extension->nDosDriveNo);
			//}
		}

	}			/* outermost for */
}

void
TCGetNTNameFromNumber (LPWSTR ntname, int nDriveNo)
{
	WCHAR tmp[3] =
	{0, ':', 0};
	int j = nDriveNo + (WCHAR) 'A';

	tmp[0] = (short) j;
	wcscpy (ntname, (LPWSTR) NT_MOUNT_PREFIX);
	wcsncat (ntname, tmp, 1);
}

void
TCGetDosNameFromNumber (LPWSTR dosname, int nDriveNo)
{
	WCHAR tmp[3] =
	{0, ':', 0};
	int j = nDriveNo + (WCHAR) 'A';

	tmp[0] = (short) j;
	wcscpy (dosname, (LPWSTR) DOS_MOUNT_PREFIX);
	wcscat (dosname, tmp);
}

#ifdef _DEBUG
LPWSTR
TCTranslateCode (ULONG ulCode)
{
	if (ulCode ==			 IOCTL_DISK_GET_DRIVE_GEOMETRY)
		return (LPWSTR) _T ("IOCTL_DISK_GET_DRIVE_GEOMETRY");
	else if (ulCode ==		 IOCTL_DISK_GET_DRIVE_GEOMETRY_EX)
		return (LPWSTR) _T ("IOCTL_DISK_GET_DRIVE_GEOMETRY_EX");
	else if (ulCode ==		 IOCTL_MOUNTDEV_QUERY_DEVICE_NAME)
		return (LPWSTR) _T ("IOCTL_MOUNTDEV_QUERY_DEVICE_NAME");
	else if (ulCode ==		 IOCTL_MOUNTDEV_QUERY_SUGGESTED_LINK_NAME)
		return (LPWSTR) _T ("IOCTL_MOUNTDEV_QUERY_SUGGESTED_LINK_NAME");
	else if (ulCode ==		 IOCTL_MOUNTDEV_QUERY_UNIQUE_ID)
		return (LPWSTR) _T ("IOCTL_MOUNTDEV_QUERY_UNIQUE_ID");
	else if (ulCode ==		 IOCTL_MOUNTDEV_UNIQUE_ID_CHANGE_NOTIFY)
		return (LPWSTR) _T ("IOCTL_MOUNTDEV_UNIQUE_ID_CHANGE_NOTIFY");
	else if (ulCode ==		 IOCTL_VOLUME_ONLINE)
		return (LPWSTR) _T ("IOCTL_VOLUME_ONLINE");
	else if (ulCode ==		 IOCTL_MOUNTDEV_LINK_CREATED)
		return (LPWSTR) _T ("IOCTL_MOUNTDEV_LINK_CREATED");
	else if (ulCode ==		 IOCTL_MOUNTDEV_LINK_DELETED)
		return (LPWSTR) _T ("IOCTL_MOUNTDEV_LINK_DELETED");
	else if (ulCode ==		 IOCTL_MOUNTMGR_QUERY_POINTS)
		return (LPWSTR) _T ("IOCTL_MOUNTMGR_QUERY_POINTS");
	else if (ulCode ==		 IOCTL_MOUNTMGR_VOLUME_MOUNT_POINT_CREATED)
		return (LPWSTR) _T ("IOCTL_MOUNTMGR_VOLUME_MOUNT_POINT_CREATED");
	else if (ulCode ==		 IOCTL_MOUNTMGR_VOLUME_MOUNT_POINT_DELETED)
		return (LPWSTR) _T ("IOCTL_MOUNTMGR_VOLUME_MOUNT_POINT_DELETED");
	else if (ulCode ==		 IOCTL_DISK_GET_LENGTH_INFO)
		return (LPWSTR) _T ("IOCTL_DISK_GET_LENGTH_INFO");
	else if (ulCode ==		 IOCTL_STORAGE_GET_DEVICE_NUMBER)
		return (LPWSTR) _T ("IOCTL_STORAGE_GET_DEVICE_NUMBER");
	else if (ulCode ==		 IOCTL_DISK_GET_PARTITION_INFO)
		return (LPWSTR) _T ("IOCTL_DISK_GET_PARTITION_INFO");
	else if (ulCode ==		 IOCTL_DISK_GET_PARTITION_INFO_EX)
		return (LPWSTR) _T ("IOCTL_DISK_GET_PARTITION_INFO_EX");
	else if (ulCode ==		 IOCTL_DISK_SET_PARTITION_INFO)
		return (LPWSTR) _T ("IOCTL_DISK_SET_PARTITION_INFO");
	else if (ulCode ==		 IOCTL_DISK_GET_DRIVE_LAYOUT)
		return (LPWSTR) _T ("IOCTL_DISK_GET_DRIVE_LAYOUT");
	else if (ulCode ==		 IOCTL_DISK_SET_DRIVE_LAYOUT_EX)
		return (LPWSTR) _T ("IOCTL_DISK_SET_DRIVE_LAYOUT_EX");
	else if (ulCode ==		 IOCTL_DISK_VERIFY)
		return (LPWSTR) _T ("IOCTL_DISK_VERIFY");
	else if (ulCode == IOCTL_DISK_FORMAT_TRACKS)
		return (LPWSTR) _T ("IOCTL_DISK_FORMAT_TRACKS");
	else if (ulCode == IOCTL_DISK_REASSIGN_BLOCKS)
		return (LPWSTR) _T ("IOCTL_DISK_REASSIGN_BLOCKS");
	else if (ulCode == IOCTL_DISK_PERFORMANCE)
		return (LPWSTR) _T ("IOCTL_DISK_PERFORMANCE");
	else if (ulCode == IOCTL_DISK_IS_WRITABLE)
		return (LPWSTR) _T ("IOCTL_DISK_IS_WRITABLE");
	else if (ulCode == IOCTL_DISK_LOGGING)
		return (LPWSTR) _T ("IOCTL_DISK_LOGGING");
	else if (ulCode == IOCTL_DISK_FORMAT_TRACKS_EX)
		return (LPWSTR) _T ("IOCTL_DISK_FORMAT_TRACKS_EX");
	else if (ulCode == IOCTL_DISK_HISTOGRAM_STRUCTURE)
		return (LPWSTR) _T ("IOCTL_DISK_HISTOGRAM_STRUCTURE");
	else if (ulCode == IOCTL_DISK_HISTOGRAM_DATA)
		return (LPWSTR) _T ("IOCTL_DISK_HISTOGRAM_DATA");
	else if (ulCode == IOCTL_DISK_HISTOGRAM_RESET)
		return (LPWSTR) _T ("IOCTL_DISK_HISTOGRAM_RESET");
	else if (ulCode == IOCTL_DISK_REQUEST_STRUCTURE)
		return (LPWSTR) _T ("IOCTL_DISK_REQUEST_STRUCTURE");
	else if (ulCode == IOCTL_DISK_REQUEST_DATA)
		return (LPWSTR) _T ("IOCTL_DISK_REQUEST_DATA");
	else if (ulCode == IOCTL_DISK_CONTROLLER_NUMBER)
		return (LPWSTR) _T ("IOCTL_DISK_CONTROLLER_NUMBER");
	else if (ulCode == SMART_GET_VERSION)
		return (LPWSTR) _T ("SMART_GET_VERSION");
	else if (ulCode == SMART_SEND_DRIVE_COMMAND)
		return (LPWSTR) _T ("SMART_SEND_DRIVE_COMMAND");
	else if (ulCode == SMART_RCV_DRIVE_DATA)
		return (LPWSTR) _T ("SMART_RCV_DRIVE_DATA");
	else if (ulCode == IOCTL_DISK_INTERNAL_SET_VERIFY)
		return (LPWSTR) _T ("IOCTL_DISK_INTERNAL_SET_VERIFY");
	else if (ulCode == IOCTL_DISK_INTERNAL_CLEAR_VERIFY)
		return (LPWSTR) _T ("IOCTL_DISK_INTERNAL_CLEAR_VERIFY");
	else if (ulCode == IOCTL_DISK_CHECK_VERIFY)
		return (LPWSTR) _T ("IOCTL_DISK_CHECK_VERIFY");
	else if (ulCode == IOCTL_DISK_MEDIA_REMOVAL)
		return (LPWSTR) _T ("IOCTL_DISK_MEDIA_REMOVAL");
	else if (ulCode == IOCTL_DISK_EJECT_MEDIA)
		return (LPWSTR) _T ("IOCTL_DISK_EJECT_MEDIA");
	else if (ulCode == IOCTL_DISK_LOAD_MEDIA)
		return (LPWSTR) _T ("IOCTL_DISK_LOAD_MEDIA");
	else if (ulCode == IOCTL_DISK_RESERVE)
		return (LPWSTR) _T ("IOCTL_DISK_RESERVE");
	else if (ulCode == IOCTL_DISK_RELEASE)
		return (LPWSTR) _T ("IOCTL_DISK_RELEASE");
	else if (ulCode == IOCTL_DISK_FIND_NEW_DEVICES)
		return (LPWSTR) _T ("IOCTL_DISK_FIND_NEW_DEVICES");
	else if (ulCode == IOCTL_DISK_GET_MEDIA_TYPES)
		return (LPWSTR) _T ("IOCTL_DISK_GET_MEDIA_TYPES");
	else if (ulCode == IOCTL_STORAGE_SET_HOTPLUG_INFO)
		return (LPWSTR) _T ("IOCTL_STORAGE_SET_HOTPLUG_INFO");
	else if (ulCode == IRP_MJ_READ)
		return (LPWSTR) _T ("IRP_MJ_READ");
	else if (ulCode == IRP_MJ_WRITE)
		return (LPWSTR) _T ("IRP_MJ_WRITE");
	else if (ulCode == IRP_MJ_CREATE)
		return (LPWSTR) _T ("IRP_MJ_CREATE");
	else if (ulCode == IRP_MJ_CLOSE)
		return (LPWSTR) _T ("IRP_MJ_CLOSE");
	else if (ulCode == IRP_MJ_CLEANUP)
		return (LPWSTR) _T ("IRP_MJ_CLEANUP");
	else if (ulCode == IRP_MJ_FLUSH_BUFFERS)
		return (LPWSTR) _T ("IRP_MJ_FLUSH_BUFFERS");
	else if (ulCode == IRP_MJ_SHUTDOWN)
		return (LPWSTR) _T ("IRP_MJ_SHUTDOWN");
	else if (ulCode == IRP_MJ_DEVICE_CONTROL)
		return (LPWSTR) _T ("IRP_MJ_DEVICE_CONTROL");
	else if (ulCode == MOUNT)
		return (LPWSTR) _T ("MOUNT");
	else if (ulCode == UNMOUNT)
		return (LPWSTR) _T ("UNMOUNT");
	else if (ulCode == UNMOUNT_ALL)
		return (LPWSTR) _T ("UNMOUNT_ALL");
	else if (ulCode == MOUNT_LIST)
		return (LPWSTR) _T ("MOUNT_LIST");
	else if (ulCode == OPEN_TEST)
		return (LPWSTR) _T ("OPEN_TEST");
	else if (ulCode == VOLUME_PROPERTIES)
		return (LPWSTR) _T ("VOLUME_PROPERTIES");
	else if (ulCode == DRIVER_VERSION)
		return (LPWSTR) _T ("DRIVER_VERSION");
	else if (ulCode == CACHE_STATUS)
		return (LPWSTR) _T ("CACHE_STATUS");
	else if (ulCode == WIPE_CACHE)
		return (LPWSTR) _T ("WIPE_CACHE");
	else if (ulCode == RESOLVE_SYMLINK)
		return (LPWSTR) _T ("RESOLVE_SYMLINK");
	else
	{
		Dump("Unknown IOCTL recieved: DeviceType = 0x%x Function = 0x%x\n", (int)(ulCode>>16), (int)((ulCode&0x1FFF)>>2));
		return (LPWSTR) _T ("UNKNOWN");
	}
}

#endif

PDEVICE_OBJECT
TCDeleteDeviceObject (PDEVICE_OBJECT DeviceObject, PEXTENSION Extension)
{
	PDEVICE_OBJECT OldDeviceObject = DeviceObject;
	UNICODE_STRING Win32NameString;
	NTSTATUS ntStatus;

	Dump ("TCDeleteDeviceObject BEGIN\n");

	if (Extension->bRootDevice)
	{
		RtlInitUnicodeString (&Win32NameString, (LPWSTR) DOS_ROOT_PREFIX);
		ntStatus = IoDeleteSymbolicLink (&Win32NameString);
		if (!NT_SUCCESS (ntStatus))
			Dump ("IoDeleteSymbolicLink failed ntStatus = 0x%08x\n", ntStatus);
	}
	else
	{
		if (Extension->peThread != NULL)
			TCStopThread (DeviceObject, Extension);
	}

	if (DeviceObject != NULL)
		DeviceObject = DeviceObject->NextDevice;

	IoDeleteDevice (OldDeviceObject);

	Dump ("TCDeleteDeviceObject END\n");
	return DeviceObject;
}


VOID
TCUnloadDriver (PDRIVER_OBJECT DriverObject)
{
	PDEVICE_OBJECT DeviceObject = DriverObject->DeviceObject;

	Dump ("TCUnloadDriver BEGIN\n");

	UnmountAllDevices (DeviceObject, TRUE, TRUE, TRUE);

	/* Now walk the list of driver objects and get rid of them */
	while (DeviceObject != (PDEVICE_OBJECT) NULL)
	{
		DeviceObject = TCDeleteDeviceObject (DeviceObject,
				(PEXTENSION) DeviceObject->DeviceExtension);
	}

	Dump ("TCUnloadDriver END\n");
}


NTSTATUS
TCDeviceIoControl (PWSTR deviceName, ULONG IoControlCode,
				   void *InputBuffer, int InputBufferSize, void *OutputBuffer, int OutputBufferSize)
{
	IO_STATUS_BLOCK ioStatusBlock;
	NTSTATUS ntStatus;
	PIRP irp;
	PFILE_OBJECT fileObject;
	PDEVICE_OBJECT deviceObject;
	KEVENT event;
	UNICODE_STRING name;

	RtlInitUnicodeString(&name, deviceName);
    ntStatus = IoGetDeviceObjectPointer(&name, FILE_READ_ATTRIBUTES, &fileObject, &deviceObject);

	if (ntStatus != STATUS_SUCCESS)
		return ntStatus;

	KeInitializeEvent(&event, NotificationEvent, FALSE);

	irp = IoBuildDeviceIoControlRequest (IoControlCode,
					     deviceObject,
					     InputBuffer, InputBufferSize,
					     OutputBuffer, OutputBufferSize,
					     FALSE,
					     &event,
					     &ioStatusBlock);

	if (irp == NULL)
	{
		Dump ("IRP allocation failed\n");
		return STATUS_INSUFFICIENT_RESOURCES;
	}

	ntStatus = IoCallDriver (deviceObject, irp);
	if (ntStatus == STATUS_PENDING)
	{
		KeWaitForSingleObject (&event, UserRequest, UserMode, FALSE, NULL);
		ntStatus = ioStatusBlock.Status;
	}

	return ntStatus;
}


// Opens a mounted TC volume on filesystem level
NTSTATUS
TCOpenFsVolume (PEXTENSION Extension, PHANDLE volumeHandle, PFILE_OBJECT * fileObject)
{
	NTSTATUS ntStatus;
	OBJECT_ATTRIBUTES objectAttributes;
	UNICODE_STRING fullFileName;
	IO_STATUS_BLOCK ioStatus;
	WCHAR volumeName[TC_MAX_PATH];

	TCGetDosNameFromNumber (volumeName, Extension->nDosDriveNo);
	RtlInitUnicodeString (&fullFileName, volumeName);
	InitializeObjectAttributes (&objectAttributes, &fullFileName, OBJ_CASE_INSENSITIVE, NULL, NULL);

	ntStatus = ZwCreateFile (volumeHandle,
		SYNCHRONIZE | GENERIC_READ,
		&objectAttributes,
		&ioStatus,
		NULL,
		FILE_ATTRIBUTE_NORMAL,
		FILE_SHARE_READ | FILE_SHARE_WRITE,
		FILE_OPEN,
		FILE_SYNCHRONOUS_IO_NONALERT,
		NULL,
		0);

	Dump ("Volume %ls open NTSTATUS 0x%08x\n", volumeName, ntStatus);

	if (!NT_SUCCESS (ntStatus))
		return ntStatus;

	ntStatus = ObReferenceObjectByHandle (*volumeHandle,
		FILE_READ_DATA,
		NULL,
		KernelMode,
		fileObject,
		NULL);

	Dump ("ObReferenceObjectByHandle NTSTATUS 0x%08x\n", ntStatus);

	if (!NT_SUCCESS (ntStatus))
	{
		ZwClose(*volumeHandle);
		return ntStatus;
	}

	return ntStatus;
}


void
TCCloseFsVolume (HANDLE volumeHandle, PFILE_OBJECT fileObject)
{
	ObDereferenceObject (fileObject);
	ZwClose (volumeHandle);
}


NTSTATUS
TCFsctlCall (PFILE_OBJECT fileObject, LONG IoControlCode,
	void *InputBuffer, int InputBufferSize, void *OutputBuffer, int OutputBufferSize)
{
	IO_STATUS_BLOCK ioStatusBlock;
	NTSTATUS ntStatus;
	PIRP irp;
	KEVENT event;
	PIO_STACK_LOCATION stack;
	PDEVICE_OBJECT deviceObject = IoGetRelatedDeviceObject (fileObject);

	Dump ("IoGetRelatedDeviceObject = 0x%08x\n", deviceObject);

	KeInitializeEvent(&event, NotificationEvent, FALSE);

	irp = IoBuildDeviceIoControlRequest (IoControlCode,
					     deviceObject,
					     InputBuffer, InputBufferSize,
					     OutputBuffer, OutputBufferSize,
					     FALSE,
					     &event,
					     &ioStatusBlock);

	if (irp == NULL)
	{
		Dump ("IRP allocation failed\n");
		return STATUS_INSUFFICIENT_RESOURCES;
	}

	stack = IoGetNextIrpStackLocation(irp);
	
	stack->MajorFunction = IRP_MJ_FILE_SYSTEM_CONTROL;
	stack->MinorFunction = IRP_MN_USER_FS_REQUEST;
	stack->FileObject = fileObject;

	Dump("TCFsctlCall IoCallDriver\n");

	ntStatus = IoCallDriver (deviceObject, irp);
	if (ntStatus == STATUS_PENDING)
	{
		KeWaitForSingleObject (&event, UserRequest, UserMode, FALSE, NULL);
		ntStatus = ioStatusBlock.Status;
	}

	return ntStatus;
}


NTSTATUS
CreateDriveLink (int nDosDriveNo)
{
	WCHAR dev[256], link[256];
	UNICODE_STRING deviceName, symLink;
	NTSTATUS ntStatus;

	TCGetNTNameFromNumber (dev, nDosDriveNo);
	TCGetDosNameFromNumber (link, nDosDriveNo);

	RtlInitUnicodeString (&deviceName, dev);
	RtlInitUnicodeString (&symLink, link);

	ntStatus = IoCreateSymbolicLink (&symLink, &deviceName);
	Dump ("IoCreateSymbolicLink returned %X\n", ntStatus);
	return ntStatus;
}


NTSTATUS
RemoveDriveLink (int nDosDriveNo)
{
	WCHAR link[256];
	UNICODE_STRING symLink;
	NTSTATUS ntStatus;

	TCGetDosNameFromNumber (link, nDosDriveNo);
	RtlInitUnicodeString (&symLink, link);

	ntStatus = IoDeleteSymbolicLink (&symLink);
	Dump ("IoDeleteSymbolicLink returned %X\n", ntStatus);
	return ntStatus;
}


NTSTATUS
MountManagerMount (MOUNT_STRUCT *mount)
{
	NTSTATUS ntStatus; 
	WCHAR arrVolume[256];
	char buf[200];
	PMOUNTMGR_TARGET_NAME in = (PMOUNTMGR_TARGET_NAME) buf;
	PMOUNTMGR_CREATE_POINT_INPUT point = (PMOUNTMGR_CREATE_POINT_INPUT) buf;
	UNICODE_STRING symName, devName;

	TCGetNTNameFromNumber (arrVolume, mount->nDosDriveNo);
	in->DeviceNameLength = (USHORT) wcslen (arrVolume) * 2;
	wcscpy(in->DeviceName, arrVolume);

	ntStatus = TCDeviceIoControl (MOUNTMGR_DEVICE_NAME, IOCTL_MOUNTMGR_VOLUME_ARRIVAL_NOTIFICATION,
		in, sizeof (in->DeviceNameLength) + wcslen (arrVolume) * 2, 0, 0);

	memset (buf, 0, sizeof buf);
	TCGetDosNameFromNumber ((PWSTR) &point[1], mount->nDosDriveNo);

	point->SymbolicLinkNameOffset = sizeof (MOUNTMGR_CREATE_POINT_INPUT);
	point->SymbolicLinkNameLength = (USHORT) wcslen ((PWSTR) &point[1]) * 2;

	RtlInitUnicodeString(&symName, (PWSTR) (buf + point->SymbolicLinkNameOffset));

	point->DeviceNameOffset = point->SymbolicLinkNameOffset + point->SymbolicLinkNameLength;
	TCGetNTNameFromNumber ((PWSTR) (buf + point->DeviceNameOffset), mount->nDosDriveNo);
	point->DeviceNameLength = (USHORT) wcslen ((PWSTR) (buf + point->DeviceNameOffset)) * 2;

	RtlInitUnicodeString(&devName, (PWSTR) (buf + point->DeviceNameOffset));

	ntStatus = TCDeviceIoControl (MOUNTMGR_DEVICE_NAME, IOCTL_MOUNTMGR_CREATE_POINT, point,
		point->DeviceNameOffset + point->DeviceNameLength, 0, 0);

	return ntStatus;
}


NTSTATUS
MountManagerUnmount (int nDosDriveNo)
{
	NTSTATUS ntStatus; 
	char buf[256], out[300];
	PMOUNTMGR_MOUNT_POINT in = (PMOUNTMGR_MOUNT_POINT) buf;

	memset (buf, 0, sizeof buf);

	TCGetDosNameFromNumber ((PWSTR) &in[1], nDosDriveNo);

	in->SymbolicLinkNameOffset = sizeof (MOUNTMGR_MOUNT_POINT);
	in->SymbolicLinkNameLength = (USHORT) wcslen ((PWCHAR) &in[1]) * 2;

	ntStatus = TCDeviceIoControl (MOUNTMGR_DEVICE_NAME, IOCTL_MOUNTMGR_DELETE_POINTS,
		in, sizeof(MOUNTMGR_MOUNT_POINT) + in->SymbolicLinkNameLength, out, sizeof out);

	Dump ("IOCTL_MOUNTMGR_DELETE_POINTS returned 0x%08x\n", ntStatus);

	return ntStatus;
}


NTSTATUS
MountDevice (PDEVICE_OBJECT DeviceObject, MOUNT_STRUCT *mount)
{
	PDEVICE_OBJECT NewDeviceObject;
	NTSTATUS ntStatus;

	/* Make sure the user is asking for a reasonable 
	nDosDriveNo */
	if (mount->nDosDriveNo >= 0 && mount->nDosDriveNo <= 25)
	{
		Dump ("Mount request looks valid\n");
	}
	else
	{
		Dump ("WARNING: MOUNT DRIVE LETTER INVALID\n");
		mount->nReturnCode = ERR_BAD_DRIVE_LETTER;
		return ERR_BAD_DRIVE_LETTER;
	}

	if (!SelfTestsPassed)
	{
		mount->nReturnCode = ERR_SELF_TESTS_FAILED;
		return ERR_SELF_TESTS_FAILED;
	}

	ntStatus = TCCreateDeviceObject (DeviceObject->DriverObject, &NewDeviceObject,
		mount);
	if (!NT_SUCCESS (ntStatus))
	{
		Dump ("Mount CREATE DEVICE ERROR, ntStatus = 0x%08x\n", ntStatus);
		return ntStatus;
	}
	else
	{
		PEXTENSION NewExtension = (PEXTENSION) NewDeviceObject->DeviceExtension;
		ntStatus = TCStartThread (NewDeviceObject, NewExtension, mount);
		if (!NT_SUCCESS (ntStatus))
		{
			Dump ("Mount FAILURE NT ERROR, ntStatus = 0x%08x\n", ntStatus);
			TCDeleteDeviceObject (NewDeviceObject, NewExtension);
			return ntStatus;
		}
		else
		{
			if (mount->nReturnCode == 0)
			{
				Dump ("Mount SUCCESS TC code = 0x%08x READ-ONLY = %d\n", mount->nReturnCode,
					NewExtension->bReadOnly);
				if (NewExtension->bReadOnly)
					NewDeviceObject->Characteristics |= FILE_READ_ONLY_DEVICE;
				NewDeviceObject->Flags &= ~DO_DEVICE_INITIALIZING;

				NewExtension->UniqueVolumeId = LastUniqueVolumeId++;

				if (mount->bMountManager)
					MountManagerMount (mount);

				NewExtension->bMountManager = mount->bMountManager;

				// We create symbolic link even if mount manager is notified of
				// arriving volume as it apparently sometimes fails to create the link
				CreateDriveLink (mount->nDosDriveNo);
			}
			else
			{
				Dump ("Mount FAILURE TC code = 0x%08x\n", mount->nReturnCode);
				TCDeleteDeviceObject (NewDeviceObject, NewExtension);
			}
			
			return STATUS_SUCCESS;
		}
	}
}

NTSTATUS
UnmountDevice (PDEVICE_OBJECT deviceObject, BOOL ignoreOpenFiles)
{
	PEXTENSION extension = deviceObject->DeviceExtension;
	NTSTATUS ntStatus;
	HANDLE volumeHandle;
	PFILE_OBJECT volumeFileObject;

	Dump ("UnmountDevice %d\n", extension->nDosDriveNo);

	ntStatus = TCOpenFsVolume (extension, &volumeHandle, &volumeFileObject);
	if (!NT_SUCCESS (ntStatus))
	{
		// User may have deleted symbolic link
		CreateDriveLink (extension->nDosDriveNo);

		ntStatus = TCOpenFsVolume (extension, &volumeHandle, &volumeFileObject);
	}

	if (NT_SUCCESS (ntStatus))
	{
		// Lock volume
		ntStatus = TCFsctlCall (volumeFileObject, FSCTL_LOCK_VOLUME, 0, 0, 0, 0);
		Dump ("FSCTL_LOCK_VOLUME returned %X\n", ntStatus);

		if (!NT_SUCCESS (ntStatus) && !ignoreOpenFiles)
		{
			TCCloseFsVolume (volumeHandle, volumeFileObject);
			return ERR_FILES_OPEN;
		}

		// Dismount volume
		ntStatus = TCFsctlCall (volumeFileObject, FSCTL_DISMOUNT_VOLUME, 0, 0, 0, 0);
		Dump ("FSCTL_DISMOUNT_VOLUME returned %X\n", ntStatus);
	}
	else 
	{
		// Volume cannot be opened => force dismount if allowed
		if (!ignoreOpenFiles)
			return ERR_FILES_OPEN;
		else
			volumeHandle = NULL;
	}

	extension->bShuttingDown = TRUE;
	if (deviceObject->Vpb && deviceObject->Vpb->Flags & VPB_MOUNTED)
	{
		deviceObject->Flags |= DO_VERIFY_VOLUME;
	}

	if (extension->bMountManager)
		MountManagerUnmount (extension->nDosDriveNo);

	// We always remove symbolic link as mount manager might fail to do so
	RemoveDriveLink (extension->nDosDriveNo);

	if (volumeHandle != NULL)
		TCCloseFsVolume (volumeHandle, volumeFileObject);

	Dump ("Deleting DeviceObject with ref count %ld\n", deviceObject->ReferenceCount);
	deviceObject->ReferenceCount = 0;
	TCDeleteDeviceObject (deviceObject, (PEXTENSION) deviceObject->DeviceExtension);
	return 0;
}

NTSTATUS
UnmountAllDevices (PDEVICE_OBJECT DeviceObject, BOOL ignoreOpenFiles, BOOL unmountSystem, BOOL unmountPersistent)
{
	NTSTATUS status = 0;
	PDEVICE_OBJECT ListDevice;

	Dump ("Unmounting all volumes\n");

	if (!DeviceObject || !DeviceObject->DriverObject)
		return STATUS_INVALID_PARAMETER;

	DriverMutexWait ();

	for (ListDevice = DeviceObject->DriverObject->DeviceObject;
		ListDevice != (PDEVICE_OBJECT) NULL;
		ListDevice = ListDevice->NextDevice)
	{
		PEXTENSION ListExtension = (PEXTENSION) ListDevice->DeviceExtension;
		if (ListExtension->bRootDevice == FALSE)
		{
			if (!ListExtension->bShuttingDown
				&& (unmountSystem || !ListExtension->bSystemVolume)
				&& (unmountPersistent || !ListExtension->bPersistentVolume))
			{
				NTSTATUS ntStatus = UnmountDevice (ListDevice, ignoreOpenFiles);
				status = ntStatus == 0 ? status : ntStatus;
			}
			else if (unmountPersistent
				&& ListExtension->bSystemVolume
				&& !ListExtension->bShuttingDown)
			{
				// If the driver is shutting down, set system volumes to reject
				// all IO requests so that OS does not complain because of paging files
				Dump ("System volume %d shutdown\n", ListExtension->nDosDriveNo);
				ListExtension->bShuttingDown = TRUE;
			}
		}

		if (ListDevice == NULL)
			break;
	}

	DriverMutexRelease ();

	return status;
}

// Resolves symbolic link name to its target name
NTSTATUS
SymbolicLinkToTarget (PWSTR symlinkName, PWSTR targetName, USHORT maxTargetNameLength)
{
	NTSTATUS ntStatus;
	OBJECT_ATTRIBUTES objectAttributes;
	UNICODE_STRING fullFileName;
	HANDLE handle;

	RtlInitUnicodeString (&fullFileName, symlinkName);
	InitializeObjectAttributes (&objectAttributes, &fullFileName, OBJ_CASE_INSENSITIVE, NULL, NULL);

	ntStatus = ZwOpenSymbolicLinkObject (&handle, GENERIC_READ, &objectAttributes);

	if (NT_SUCCESS (ntStatus))
	{
		UNICODE_STRING target;
		target.Buffer = targetName;
		target.Length = 0;
		target.MaximumLength = maxTargetNameLength;
		memset (targetName, 0, maxTargetNameLength);

		ntStatus = ZwQuerySymbolicLinkObject (handle, &target, NULL);

		ZwClose (handle);
	}

	return ntStatus;
}

// Checks if two regions overlap (borders are parts of regions)
BOOL RegionsOverlap (unsigned __int64 start1, unsigned __int64 end1, unsigned __int64 start2, unsigned __int64 end2)
{
	return (start1 < start2) ? (end1 >= start2) : (start1 <= end2);
}
