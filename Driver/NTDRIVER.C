/* Copyright (C) 2004 TrueCrypt Foundation
   This product uses components written by Paul Le Roux <pleroux@swprofessionals.com> */

#include "TCdefs.h"
#include "crypto.h"
#include "fat.h"

#include "apidrvr.h"
#include "ntdriver.h"
#include "ntvol.h"
#include "ntrawdv.h"
#include "ntfiledv.h"
#include "cache.h"

#include <tchar.h>
#include <initguid.h>
#include <mountmgr.h>
#include <mountdev.h>
#include <ntddvol.h>

/* Init section, which is thrown away as soon as DriverEntry returns */
#pragma alloc_text(INIT,DriverEntry)
#pragma alloc_text(INIT,TCCreateRootDeviceObject)

/* Sync. mutex for above password data */
KMUTEX driverMutex;

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
	DriverObject->MajorFunction[IRP_MJ_READ] = TCDispatchQueueIRP;
	DriverObject->MajorFunction[IRP_MJ_WRITE] = TCDispatchQueueIRP;
	DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = TCDispatchQueueIRP;

	DriverObject->DriverUnload = TCUnloadDriver;

	KeInitializeMutex (&driverMutex, 1);

	return TCCreateRootDeviceObject (DriverObject);
}

#ifdef _DEBUG
// Dumps a memory region to debug output
void DumpMem(unsigned char *mem, int len)
{
	unsigned char str[20];
	unsigned char *m = mem;
	int i,j;

	for (j=0;j<len/8;j++)
	{
		memset (str,0,sizeof str);
		for (i=0;i<8;i++) 
		{
			if (m[i] > ' ' && m[i] < '~')
				str[i]=m[i];
			else
				str[i]='.';
		}

		Dump ("0x%08x  %02x %02x %02x %02x %02x %02x %02x %02x  %s",
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
				else if (Extension->bShuttingDown == TRUE)
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
			else if (Extension->bShuttingDown == TRUE)
			{
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
			if (Extension->bShuttingDown == TRUE)
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

			if (irpSp->MajorFunction == IRP_MJ_FLUSH_BUFFERS || irpSp->MajorFunction == IRP_MJ_SHUTDOWN)
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
					  FILE_DEVICE_DISK,	/* Device type */
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

	ASSERT (KeGetCurrentIrql ()== PASSIVE_LEVEL);
	Dump ("TCCreateRootDeviceObject STATUS_SUCCESS END\n");
	return STATUS_SUCCESS;
}

NTSTATUS
TCCreateDeviceObject (PDRIVER_OBJECT DriverObject,
		       PDEVICE_OBJECT * ppDeviceObject,
		       int nDosDriveNo)
{
	UNICODE_STRING Win32NameString, ntUnicodeString;
	WCHAR dosname[32], ntname[32];
	PEXTENSION Extension;
	NTSTATUS ntStatus;

	Dump ("TCCreateDeviceObject BEGIN\n");

	TCGetDosNameFromNumber (dosname, nDosDriveNo);
	TCGetNTNameFromNumber (ntname, nDosDriveNo);
	RtlInitUnicodeString (&ntUnicodeString, ntname);
	RtlInitUnicodeString (&Win32NameString, dosname);

	Dump ("Creating device nt=%ls dos=%ls\n", ntname, dosname);

	ntStatus = IoCreateDevice (
					  DriverObject,			/* Our Driver Object */
					  sizeof (EXTENSION),	/* Size of state information */
					  &ntUnicodeString,		/* Device name "\Device\Name" */
					  FILE_DEVICE_DISK,		/* Device type */
					  0,					/* Device characteristics */
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
	Extension->nDosDriveNo = nDosDriveNo;

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

/* TCDeviceControl handles certain requests from NT, these are needed for NT
   to recognize the drive, also this function handles  our device specific
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
			WCHAR ntName[64];
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
			
			outputBuffer->UniqueIdLength = (USHORT) strlen(volId);
			outLength = strlen(volId) + sizeof(USHORT);

			if (irpSp->Parameters.DeviceIoControl.OutputBufferLength < outLength)
			{
				Irp->IoStatus.Information = sizeof (MOUNTDEV_UNIQUE_ID);
				Irp->IoStatus.Status = STATUS_BUFFER_OVERFLOW;
				break;
			}

			RtlCopyMemory ((PCHAR)outputBuffer->UniqueId, volId, strlen(volId));

			Irp->IoStatus.Status = STATUS_SUCCESS;
			Irp->IoStatus.Information = outLength;

			Dump ("id = %s\n",volId);
		}
		break;

		case IOCTL_MOUNTDEV_QUERY_SUGGESTED_LINK_NAME:
		{
			ULONG outLength;
			UNICODE_STRING ntUnicodeString;
			WCHAR ntName[64];
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

			outputBuffer->MediaType = FixedMedia;
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
		{
			Irp->IoStatus.Status = STATUS_SUCCESS;
			Irp->IoStatus.Information = 0;
		}
		break;

	case IOCTL_DISK_IS_WRITABLE:
		{
			if (Extension->bReadOnly == TRUE)
				Irp->IoStatus.Status = STATUS_MEDIA_WRITE_PROTECTED;
			else
				Irp->IoStatus.Status = STATUS_SUCCESS;
			Irp->IoStatus.Information = 0;

		}
		break;

	case DRIVER_VERSION:
		if (irpSp->Parameters.DeviceIoControl.OutputBufferLength < 4)
		{
			Irp->IoStatus.Status = STATUS_INVALID_PARAMETER;
			Irp->IoStatus.Information = 0;
		}
		else
		{
			LONG tmp = VERSION_NUM;
			memcpy (Irp->AssociatedIrp.SystemBuffer, &tmp, 4);
			Irp->IoStatus.Information = 4;
			Irp->IoStatus.Status = STATUS_SUCCESS;
		}
		break;

	case OPEN_TEST:
		if (irpSp->Parameters.DeviceIoControl.OutputBufferLength < sizeof (OPEN_TEST_STRUCT))
		{
			Irp->IoStatus.Status = STATUS_INVALID_PARAMETER;
			Irp->IoStatus.Information = 0;
		}
		else
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
						 FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ, FILE_OPEN, FILE_SYNCHRONOUS_IO_NONALERT |
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
		KeWaitForMutexObject (&driverMutex, Executive, KernelMode,
				      FALSE, NULL);

		WipeCache ();

		KeReleaseMutex (&driverMutex, FALSE);

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
		if (irpSp->Parameters.DeviceIoControl.OutputBufferLength < sizeof (MOUNT_LIST_STRUCT))
		{
			Irp->IoStatus.Status = STATUS_INVALID_PARAMETER;
			Irp->IoStatus.Information = 0;
		}
		else
		{
			MOUNT_LIST_STRUCT *list = (MOUNT_LIST_STRUCT *) Irp->AssociatedIrp.SystemBuffer;
			PDEVICE_OBJECT ListDevice;

			list->ulMountedDrives = 0;
			for (ListDevice = DeviceObject->DriverObject->DeviceObject;
			     ListDevice != (PDEVICE_OBJECT) NULL; ListDevice = ListDevice->NextDevice)
			{

				PEXTENSION ListExtension = (PEXTENSION) ListDevice->DeviceExtension;
				if (ListExtension->bRootDevice == FALSE)
				{
					list->ulMountedDrives |= (1 << ListExtension->nDosDriveNo);
					wcscpy (list->wszVolume[ListExtension->nDosDriveNo], ListExtension->wszVolume);
					list->diskLength[ListExtension->nDosDriveNo] = ListExtension->DiskLength;
					list->cipher[ListExtension->nDosDriveNo] = ListExtension->cryptoInfo->cipher;
				}
			}

			Irp->IoStatus.Status = STATUS_SUCCESS;
			Irp->IoStatus.Information = sizeof (MOUNT_LIST_STRUCT);
		}
		break;

	case VOLUME_PROPERTIES:
		if (irpSp->Parameters.DeviceIoControl.OutputBufferLength < sizeof (VOLUME_PROPERTIES_STRUCT))
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

			for (ListDevice = DeviceObject->DriverObject->DeviceObject;
			     ListDevice != (PDEVICE_OBJECT) NULL; ListDevice = ListDevice->NextDevice)
			{

				PEXTENSION ListExtension = (PEXTENSION) ListDevice->DeviceExtension;
				if (ListExtension->bRootDevice == FALSE && ListExtension->nDosDriveNo == prop->driveNo)
				{
					wcscpy (prop->wszVolume, ListExtension->wszVolume);
					prop->diskLength = ListExtension->DiskLength;
					prop->cipher = ListExtension->cryptoInfo->cipher;
					prop->pkcs5 = ListExtension->cryptoInfo->pkcs5;
					prop->pkcs5Iterations = ListExtension->cryptoInfo->noIterations;
					prop->volumeCreationTime = ListExtension->cryptoInfo->volume_creation_time;
					prop->headerCreationTime = ListExtension->cryptoInfo->header_creation_time;

					Irp->IoStatus.Status = STATUS_SUCCESS;
					Irp->IoStatus.Information = sizeof (VOLUME_PROPERTIES_STRUCT);
					break;
				}
			}
		}
		break;

	case UNMOUNT_PENDING:
		Extension->bShuttingDown = TRUE;
		Irp->IoStatus.Status = STATUS_NO_MEDIA_IN_DEVICE;
		Irp->IoStatus.Information = 0;
		if (DeviceObject->Vpb && DeviceObject->Vpb->Flags & VPB_MOUNTED)
		{
			IoSetHardErrorOrVerifyDevice (Irp, DeviceObject);
			DeviceObject->Flags |= DO_VERIFY_VOLUME;
		}
		break;

	case UNMOUNT:
		if (irpSp->Parameters.DeviceIoControl.OutputBufferLength < sizeof (UNMOUNT_STRUCT))
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

				if (ListExtension->bRootDevice == FALSE)
				{
					if (unmount->nDosDriveNo == ListExtension->nDosDriveNo)
					{
						if (ListDevice->Vpb && ListDevice->Vpb->ReferenceCount == 0 && (ListDevice->Vpb->Flags & VPB_MOUNTED) == 0)
						{
							Dump ("Deleting DeviceObject with ref count %ld\n", ListDevice->ReferenceCount);
							ListDevice->ReferenceCount = 0;
							TCDeleteDeviceObject (ListDevice, (PEXTENSION) ListDevice->DeviceExtension);
							unmount->nReturnCode = 0;
							break;
						}
						else
						{
							unmount->nReturnCode = ERR_FILES_OPEN;
							break;
						}
					}	/* if the drive numbers are
						   equal */
				}	/* if it's not the root device */
			}	/* for all the device objects the driver
				   knows about */

			Irp->IoStatus.Information = sizeof (unmount->nReturnCode);
			Irp->IoStatus.Status = STATUS_SUCCESS;
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
			ULONG *outputBuffer = (ULONG *) Irp->AssociatedIrp.SystemBuffer;
			PDEVICE_OBJECT NewDeviceObject;

			/* Make sure the user is asking for a resonable
			   nDosDriveNo */
			if (mount->nDosDriveNo >= 0 && mount->nDosDriveNo <= 25)
			{
				Dump ("Mount request looks valid\n");
			}
			else
			{
				Dump ("WARNING: MOUNT DRIVE LETTER INVALID\n");
				Irp->IoStatus.Information = sizeof (mount->nReturnCode);
				Irp->IoStatus.Status = STATUS_SUCCESS;
				mount->nReturnCode = ERR_BAD_DRIVE_LETTER;
				break;
			}

			ntStatus = TCCreateDeviceObject (DeviceObject->DriverObject, &NewDeviceObject,
							mount->nDosDriveNo);
			if (!NT_SUCCESS (ntStatus))
			{
				Dump ("Mount CREATE DEVICE ERROR, ntStatus = 0x%08x\n", ntStatus);
				Irp->IoStatus.Information = 0;
				Irp->IoStatus.Status = ntStatus;
				break;
			}
			else
			{
				PEXTENSION NewExtension = (PEXTENSION) NewDeviceObject->DeviceExtension;
				ntStatus = TCStartThread (NewDeviceObject, NewExtension, mount);
				if (!NT_SUCCESS (ntStatus))
				{
					Dump ("Mount FAILURE NT ERROR, ntStatus = 0x%08x\n", ntStatus);
					Irp->IoStatus.Information = 0;
					Irp->IoStatus.Status = ntStatus;
					TCDeleteDeviceObject (NewDeviceObject, NewExtension);
					break;
				}
				else
				{
					if (mount->nReturnCode == 0)
					{
						Dump ("Mount SUCCESS TC code = 0x%08x READ-ONLY = %d\n", mount->nReturnCode,
						   NewExtension->bReadOnly);
						if (NewExtension->bReadOnly == TRUE)
							NewDeviceObject->Characteristics |= FILE_READ_ONLY_DEVICE;
						NewDeviceObject->Flags &= ~DO_DEVICE_INITIALIZING;
					}
					else
					{
						Dump ("Mount FAILURE TC code = 0x%08x\n", mount->nReturnCode);
						TCDeleteDeviceObject (NewDeviceObject, NewExtension);
					}
					Irp->IoStatus.Information = sizeof (mount->nReturnCode);
					Irp->IoStatus.Status = STATUS_SUCCESS;
					break;
				}
			}
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

	Extension->bThreadShouldQuit = FALSE;

	ntStatus = PsCreateSystemThread (&hThread,
					 THREAD_ALL_ACCESS,
					 NULL,
					 NULL,
					 NULL,
					 TCThreadIRP,
					 pThreadBlock);

	if (!NT_SUCCESS (ntStatus))
	{
		Dump ("PsCreateSystemThread Failed END\n");
		TCfree (pThreadBlock);
		return ntStatus;
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

	ntStatus = KeWaitForSingleObject (&Extension->peThread,
					  UserRequest,
					  UserMode,
					  FALSE,
					  NULL);
	if (ntStatus != STATUS_SUCCESS)
		Dump ("Failed waiting for crypto thread to quit: 0x%08x...\n",
		      ntStatus);

	ObDereferenceObject (&Extension->peThread);
	Extension->peThread = NULL;

	Dump ("Thread exited!\n");
}

/* TCThreadIRP does all the work of processing IRP's, and dispatching them
   to either the ReadWrite function or the DeviceControl function */
VOID
TCThreadIRP (PVOID Context)
{
	PTHREAD_BLOCK pThreadBlock = (PTHREAD_BLOCK) Context;
	PDEVICE_OBJECT DeviceObject = pThreadBlock->DeviceObject;
	PDRIVER_OBJECT DriverObject = DeviceObject->DriverObject;
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
		wcscat (pThreadBlock->wszMountVolume, pThreadBlock->mount->wszVolume);
		bDevice = FALSE;
	}
	else
	{
		wcscpy (pThreadBlock->wszMountVolume, pThreadBlock->mount->wszVolume);
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
						if (Extension->bRawDevice == TRUE)
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
	else if (ulCode == MOUNT_LIST)
		return (LPWSTR) _T ("MOUNT_LIST");
	else if (ulCode == OPEN_TEST)
		return (LPWSTR) _T ("OPEN_TEST");
	else if (ulCode == UNMOUNT_PENDING)
		return (LPWSTR) _T ("UNMOUNT_PENDING");
	else
	{
		Dump("Unknown IOCTL recieved: DeviceType = 0x%x Function = 0x%x", (int)(ulCode>>16), (int)((ulCode&0x1FFF)>>2));
		return (LPWSTR) _T ("UNKNOWN");
	}
}

#endif

PDEVICE_OBJECT
TCDeleteDeviceObject (PDEVICE_OBJECT DeviceObject, PEXTENSION Extension)
{
	PDEVICE_OBJECT OldDeviceObject = DeviceObject;
	UNICODE_STRING Win32NameString;
	WCHAR dosname[32];
	NTSTATUS ntStatus;

	Dump ("TCDeleteDeviceObject BEGIN\n");

	if (Extension->bRootDevice == TRUE)
	{
		RtlInitUnicodeString (&Win32NameString, (LPWSTR) DOS_ROOT_PREFIX);
	}
	else
	{
		if (Extension->peThread != NULL)
			TCStopThread (DeviceObject, Extension);
		TCGetDosNameFromNumber (dosname, Extension->nDosDriveNo);
		RtlInitUnicodeString (&Win32NameString, dosname);
	}

	ntStatus = IoDeleteSymbolicLink (&Win32NameString);
	if (!NT_SUCCESS (ntStatus))
	{
		Dump ("IoDeleteSymbolicLink failed ntStatus = 0x%08x\n", ntStatus);
	}

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

	/* Now walk the list of driver objects and get rid of them */
	while (DeviceObject != (PDEVICE_OBJECT) NULL)
	{
		DeviceObject = TCDeleteDeviceObject (DeviceObject,
				(PEXTENSION) DeviceObject->DeviceExtension);
	}

	Dump ("TCUnloadDriver END\n");
}
