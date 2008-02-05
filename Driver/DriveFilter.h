/*
 Copyright (c) 2008 TrueCrypt Foundation. All rights reserved.

 Governed by the TrueCrypt License 2.4 the full text of which is contained
 in the file License.txt included in TrueCrypt binary and source code
 distribution packages.
*/

#ifndef TC_HEADER_DRIVER_DRIVE_FILTER
#define TC_HEADER_DRIVER_DRIVE_FILTER

#include "TCdefs.h"
#include "EncryptedIoQueue.h"

typedef struct
{
	BOOL bRootDevice;
	BOOL IsDriveFilterDevice;
	PDEVICE_OBJECT DeviceObject;
	PDEVICE_OBJECT LowerDeviceObject;
	PDEVICE_OBJECT Pdo;
	
	int64 ConfiguredEncryptedAreaStart;
	int64 ConfiguredEncryptedAreaEnd;

	uint32 VolumeHeaderSaltCrc32;
	EncryptedIoQueue Queue;
	BOOL QueueStarted;

	BOOL BootDrive;
	BOOL VolumeHeaderPresent;
	BOOL DriveMounted;

	CRYPTO_INFO *HeaderCryptoInfo;
} DriveFilterExtension;


NTSTATUS AbortBootEncryptionSetup ();
NTSTATUS DriveFilterAddDevice (PDRIVER_OBJECT driverObject, PDEVICE_OBJECT pdo);
NTSTATUS DriveFilterDispatchIrp (PDEVICE_OBJECT DeviceObject, PIRP Irp);
void GetBootDriveVolumeProperties (PIRP irp, PIO_STACK_LOCATION irpSp);
void GetBootEncryptionStatus (PIRP irp, PIO_STACK_LOCATION irpSp);
void GetBootLoaderVersion (PIRP irp, PIO_STACK_LOCATION irpSp);
NTSTATUS GetSetupResult ();
BOOL IsBootDriveMounted ();
BOOL IsBootEncryptionSetupInProgress ();
NTSTATUS LoadBootArguments ();
static NTSTATUS SaveDriveVolumeHeader (DriveFilterExtension *Extension);
NTSTATUS StartBootEncryptionSetup (PDEVICE_OBJECT DeviceObject, PIRP irp, PIO_STACK_LOCATION irpSp);
void ReopenBootVolumeHeader (PIRP irp, PIO_STACK_LOCATION irpSp);
static BOOL UserCanAccessDriveDevice ();

#define TC_ENCRYPTION_SETUP_IO_BLOCK_SIZE (1280 * 1024)
#define TC_ENCRYPTION_SETUP_HEADER_UPDATE_THRESHOLD (64 * 1024 * 1024)

#endif // TC_HEADER_DRIVER_DRIVE_FILTER
