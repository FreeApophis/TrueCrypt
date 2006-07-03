/* Legal Notice: The source code contained in this file has been derived from
   the source code of Encryption for the Masses 2.02a, which is Copyright (c)
   1998-99 Paul Le Roux and which is covered by the 'License Agreement for
   Encryption for the Masses'. Modifications and additions to that source code
   contained in this file are Copyright (c) 2004-2006 TrueCrypt Foundation and
   Copyright (c) 2004 TrueCrypt Team, and are covered by TrueCrypt License 2.1
   the full text of which is contained in the file License.txt included in
   TrueCrypt binary and source code distribution archives.  */

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
	BOOL bRootDevice;	/* Is this the root device ? which the
				   user-mode apps talk to */

	ULONG lMagicNumber;	/* To ensure the completion routine is not
				   sending us bad IRP's */

	int UniqueVolumeId;
	int nDosDriveNo;	/* Drive number this extension is mounted
				   against */
	BOOL bShuttingDown;			/* Is the driver shutting down ? */
	BOOL bThreadShouldQuit;		/* Instruct per device worker thread to quit */
	PETHREAD peThread;			/* Thread handle */
	KEVENT keCreateEvent;		/* Device creation event */
	KSPIN_LOCK ListSpinLock;	/* IRP spinlock */
	LIST_ENTRY ListEntry;		/* IRP listentry */
	KSEMAPHORE RequestSemaphore;	/* IRP list request  Semaphore */

#ifdef USE_KERNEL_MUTEX
	KMUTEX KernelMutex;			/* Sync. mutex for entire thread */
#endif

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

	KEVENT keVolumeEvent;		/* Event structure used when setting up a device */

	BOOL bSystemVolume;			/* System volume is hidden from user and supports system files (paging, hibernation). */
	BOOL bPersistentVolume;		/* Persistent volume is hidden from user. */

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

	unsigned __int64 TotalBytesRead;	// Bytes read from volume
	unsigned __int64 TotalBytesWritten;	// Bytes written to volume

} EXTENSION, *PEXTENSION;

/* Helper macro returning x seconds in units of 100 nanoseconds */
#define WAIT_SECONDS(x) ((x)*10000000)

/* In order to see any debug output you will need to run a checked build of
   NT */
#ifdef DEBUG
#define Dump DbgPrint
#else
#define Dump
#endif

#ifdef USE_KERNEL_MUTEX
#pragma message ("Compiling " __FILE__ " with USE_KERNEL_MUTEX on")
#endif

#define FSCTL_LOCK_VOLUME               CTL_CODE(FILE_DEVICE_FILE_SYSTEM,  6, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define FSCTL_UNLOCK_VOLUME             CTL_CODE(FILE_DEVICE_FILE_SYSTEM,  7, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define FSCTL_DISMOUNT_VOLUME           CTL_CODE(FILE_DEVICE_FILE_SYSTEM,  8, METHOD_BUFFERED, FILE_ANY_ACCESS)
NTKERNELAPI NTSTATUS ObOpenObjectByPointer (IN PVOID Object, IN ULONG HandleAttributes, IN PACCESS_STATE PassedAccessState OPTIONAL, IN ACCESS_MASK DesiredAccess OPTIONAL, IN POBJECT_TYPE ObjectType OPTIONAL, IN KPROCESSOR_MODE AccessMode, OUT PHANDLE Handle);

NTSTATUS DriverEntry (PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath);
NTSTATUS TCDispatchQueueIRP (PDEVICE_OBJECT DeviceObject, PIRP Irp);
NTSTATUS TCCreateRootDeviceObject (PDRIVER_OBJECT DriverObject);
NTSTATUS TCCreateDeviceObject (PDRIVER_OBJECT DriverObject, PDEVICE_OBJECT * ppDeviceObject, MOUNT_STRUCT * mount);
NTSTATUS TCDeviceControl (PDEVICE_OBJECT DeviceObject, PEXTENSION Extension, PIRP Irp);
NTSTATUS TCStartThread (PDEVICE_OBJECT DeviceObject, PEXTENSION Extension, MOUNT_STRUCT * mount);
void TCStopThread (PDEVICE_OBJECT DeviceObject, PEXTENSION Extension);
VOID TCThreadIRP (PVOID Context);
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
NTSTATUS UnmountAllDevices (PDEVICE_OBJECT DeviceObject, BOOL ignoreOpenFiles, BOOL unmountSystem, BOOL unmountPersistent);
NTSTATUS SymbolicLinkToTarget (PWSTR symlinkName, PWSTR targetName, USHORT maxTargetNameLength);
void DriverMutexWait ();
void DriverMutexRelease ();
BOOL RegionsOverlap (unsigned __int64 start1, unsigned __int64 end1, unsigned __int64 start2, unsigned __int64 end2);
