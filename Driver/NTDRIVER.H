/*
 Legal Notice: Some portions of the source code contained in this file were
 derived from the source code of Encryption for the Masses 2.02a, which is
 Copyright (c) 1998-2000 Paul Le Roux and which is governed by the 'License
 Agreement for Encryption for the Masses'. Modifications and additions to
 the original source code (contained in this file) and all other portions of
 this file are Copyright (c) 2003-2008 TrueCrypt Foundation and are governed
 by the TrueCrypt License 2.4 the full text of which is contained in the
 file License.txt included in TrueCrypt binary and source code distribution
 packages. */

#ifndef TC_HEADER_NTDRIVER
#define TC_HEADER_NTDRIVER

#include "EncryptedIoQueue.h"

/* This structure is used to start new threads */
typedef struct _THREAD_BLOCK_
{
	PDEVICE_OBJECT DeviceObject;
	NTSTATUS ntCreateStatus;
	WCHAR wszMountVolume[TC_MAX_PATH + 8];
	MOUNT_STRUCT *mount;
} THREAD_BLOCK, *PTHREAD_BLOCK;


/* This structure is allocated for non-root devices! WARNING: bRootDevice
   must be the first member of the structure! */
typedef struct EXTENSION
{
	BOOL bRootDevice;	/* Is this the root device ? which the user-mode apps talk to */
	BOOL IsDriveFilterDevice;

	ULONG lMagicNumber;	/* To ensure the completion routine is not sending us bad IRP's */

	int UniqueVolumeId;
	int nDosDriveNo;	/* Drive number this extension is mounted against */

	BOOL bShuttingDown;			/* Is the driver shutting down ? */
	BOOL bThreadShouldQuit;		/* Instruct per device worker thread to quit */
	PETHREAD peThread;			/* Thread handle */
	KEVENT keCreateEvent;		/* Device creation event */
	KSPIN_LOCK ListSpinLock;	/* IRP spinlock */
	LIST_ENTRY ListEntry;		/* IRP listentry */
	KSEMAPHORE RequestSemaphore;	/* IRP list request  Semaphore */

	HANDLE hDeviceFile;			/* Device handle for this device */
	PFILE_OBJECT pfoDeviceFile;	/* Device fileobject for this device */
	PDEVICE_OBJECT pFsdDevice;	/* lower level device handle */

	CRYPTO_INFO *cryptoInfo;	/* Cryptographic and other information for this device */

	__int64 DiskLength;			/* The length of the disk referred to by this device */  
	__int64 NumberOfCylinders;		/* Partition info */
	ULONG TracksPerCylinder;	/* Partition info */
	ULONG SectorsPerTrack;		/* Partition info */
	ULONG BytesPerSector;		/* Partition info */
	UCHAR PartitionType;		/* Partition info */
	
	int HostBytesPerSector;

	KEVENT keVolumeEvent;		/* Event structure used when setting up a device */

	EncryptedIoQueue Queue;

	BOOL bReadOnly;				/* Is this device read-only ? */
	BOOL bRemovable;			/* Is this device removable media ? */
	BOOL bRawDevice;			/* Is this a raw-partition or raw-floppy device ? */
	BOOL bMountManager;			/* Mount manager knows about volume */

	WCHAR wszVolume[TC_MAX_PATH];	/*  DONT change this size without also changing MOUNT_LIST_STRUCT! */

	// Container file date/time (used to reset date and time of file-hosted volumes after dismount or unsuccessful mount attempt, to preserve plausible deniability of hidden volumes).
	LARGE_INTEGER fileCreationTime;
	LARGE_INTEGER fileLastAccessTime;
	LARGE_INTEGER fileLastWriteTime;
	LARGE_INTEGER fileLastChangeTime;
	BOOL bTimeStampValid;

} EXTENSION, *PEXTENSION;

extern PDRIVER_OBJECT TCDriverObject;
extern BOOL DriverShuttingDown;
extern ULONG OsMajorVersion;
extern ULONG OsMinorVersion;

/* Helper macro returning x seconds in units of 100 nanoseconds */
#define WAIT_SECONDS(x) ((x)*10000000)

/* In order to see any debug output you will need to run a checked build of
   NT */
#ifdef DEBUG
#	if 1 // DbgPrintEx is not available on Windows 2000
#		define Dump DbgPrint
#	else
#		define Dump(...) DbgPrintEx (DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, __VA_ARGS__)
#	endif
#		define DumpMem(...) DumpMemory (__VA_ARGS__)
#else
#	define Dump(...) ((void) 0)
#	define DumpMem(...) ((void) 0)
#endif

NTSTATUS DriverEntry (PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath);
void DumpMemory (void *memory, int size);
BOOL IsAccessibleByUser (PUNICODE_STRING objectFileName, BOOL readOnly);
NTSTATUS ProcessMainDeviceControlIrp (PDEVICE_OBJECT DeviceObject, PEXTENSION Extension, PIRP Irp);
NTSTATUS ProcessVolumeDeviceControlIrp (PDEVICE_OBJECT DeviceObject, PEXTENSION Extension, PIRP Irp);
NTSTATUS SendDeviceIoControlRequest (PDEVICE_OBJECT deviceObject, ULONG ioControlCode, void *inputBuffer, int inputBufferSize, void *outputBuffer, int outputBufferSize);
NTSTATUS TCDispatchQueueIRP (PDEVICE_OBJECT DeviceObject, PIRP Irp);
NTSTATUS TCCreateRootDeviceObject (PDRIVER_OBJECT DriverObject);
NTSTATUS TCCreateDeviceObject (PDRIVER_OBJECT DriverObject, PDEVICE_OBJECT * ppDeviceObject, MOUNT_STRUCT * mount);
NTSTATUS TCReadDevice (PDEVICE_OBJECT deviceObject, PVOID buffer, LARGE_INTEGER offset, ULONG length);
NTSTATUS TCWriteDevice (PDEVICE_OBJECT deviceObject, PVOID buffer, LARGE_INTEGER offset, ULONG length);
NTSTATUS TCStartThread (PKSTART_ROUTINE threadProc, PVOID threadArg, PKTHREAD *kThread);
NTSTATUS TCStartThreadInProcess (PKSTART_ROUTINE threadProc, PVOID threadArg, PKTHREAD *kThread, PEPROCESS process);
NTSTATUS TCStartVolumeThread (PDEVICE_OBJECT DeviceObject, PEXTENSION Extension, MOUNT_STRUCT * mount);
void TCStopThread (PKTHREAD kThread, PKEVENT wakeUpEvent);
void TCStopVolumeThread (PDEVICE_OBJECT DeviceObject, PEXTENSION Extension);
VOID VolumeThreadProc (PVOID Context);
void TCSleep (int milliSeconds);
void TCGetNTNameFromNumber (LPWSTR ntname, int nDriveNo);
void TCGetDosNameFromNumber (LPWSTR dosname, int nDriveNo);
LPWSTR TCTranslateCode (ULONG ulCode);
PDEVICE_OBJECT TCDeleteDeviceObject (PDEVICE_OBJECT DeviceObject, PEXTENSION Extension);
VOID TCUnloadDriver (PDRIVER_OBJECT DriverObject);
NTSTATUS TCDeviceIoControl (PWSTR deviceName, ULONG IoControlCode, void *InputBuffer, int InputBufferSize, void *OutputBuffer, int OutputBufferSize);
NTSTATUS TCOpenFsVolume (PEXTENSION Extension, PHANDLE volumeHandle, PFILE_OBJECT * fileObject);
void TCCloseFsVolume (HANDLE volumeHandle, PFILE_OBJECT fileObject);
NTSTATUS TCFsctlCall (PFILE_OBJECT fileObject, LONG IoControlCode, void *InputBuffer, int InputBufferSize, void *OutputBuffer, int OutputBufferSize);
NTSTATUS CreateDriveLink (int nDosDriveNo);
NTSTATUS RemoveDriveLink (int nDosDriveNo);
NTSTATUS MountManagerMount (MOUNT_STRUCT *mount);
NTSTATUS MountManagerUnmount (int nDosDriveNo);
NTSTATUS MountDevice (PDEVICE_OBJECT deviceObject, MOUNT_STRUCT *mount);
NTSTATUS UnmountDevice (PDEVICE_OBJECT deviceObject, BOOL ignoreOpenFiles);
NTSTATUS UnmountAllDevices (PDEVICE_OBJECT DeviceObject, BOOL ignoreOpenFiles);
NTSTATUS SymbolicLinkToTarget (PWSTR symlinkName, PWSTR targetName, USHORT maxTargetNameLength);
void DriverMutexWait ();
void DriverMutexRelease ();
BOOL RegionsOverlap (unsigned __int64 start1, unsigned __int64 end1, unsigned __int64 start2, unsigned __int64 end2);
void GetIntersection (uint64 start1, uint32 length1, uint64 start2, uint64 end2, uint64 *intersectStart, uint32 *intersectLength);
NTSTATUS TCCompleteIrp (PIRP irp, NTSTATUS status, ULONG_PTR information);
NTSTATUS TCCompleteDiskIrp (PIRP irp, NTSTATUS status, ULONG_PTR information);
NTSTATUS ProbeRealDriveSize (PDEVICE_OBJECT driveDeviceObject, LARGE_INTEGER *driveSize);
BOOL UserCanAccessDriveDevice ();

#define TC_TO_STRING2(n) #n
#define TC_TO_STRING(n) TC_TO_STRING2(n)

#define trace_point Dump (__FUNCTION__ ":" TC_TO_STRING(__LINE__) "\n")

#define TC_BUG_CHECK(status) KeBugCheckEx (SECURITY_SYSTEM, __LINE__, status, 0, 'TC')

#endif // TC_HEADER_NTDRIVER
