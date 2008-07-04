/*
 Copyright (c) 2008 TrueCrypt Foundation. All rights reserved.

 Governed by the TrueCrypt License 2.5 the full text of which is contained
 in the file License.txt included in TrueCrypt binary and source code
 distribution packages.
*/

#ifndef TC_HEADER_DRIVER_VOLUME_FILTER
#define TC_HEADER_DRIVER_VOLUME_FILTER

#include "TCdefs.h"

typedef struct
{
	BOOL bRootDevice;
	BOOL IsVolumeDevice;
	BOOL IsDriveFilterDevice;
	BOOL IsVolumeFilterDevice;
	
	BOOL AttachedToDrive;

	PDEVICE_OBJECT DeviceObject;
	PDEVICE_OBJECT LowerDeviceObject;
	PDEVICE_OBJECT Pdo;
	
	IO_REMOVE_LOCK RemoveLock;

} VolumeFilterExtension;

extern uint32 HiddenSysLeakProtectionCount;


NTSTATUS VolumeFilterAddDevice (PDRIVER_OBJECT driverObject, PDEVICE_OBJECT pdo);
NTSTATUS VolumeFilterDispatchIrp (PDEVICE_OBJECT DeviceObject, PIRP Irp);

#endif // TC_HEADER_DRIVER_VOLUME_FILTER
