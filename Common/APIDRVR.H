/* Legal Notice: The source code contained in this file has been derived from
   the source code of Encryption for the Masses 2.02a, which is Copyright (c)
   1998-99 Paul Le Roux and which is covered by the 'License Agreement for
   Encryption for the Masses'. Modifications and additions to that source code
   contained in this file are Copyright (c) 2004-2005 TrueCrypt Foundation and
   Copyright (c) 2004 TrueCrypt Team, and are covered by TrueCrypt License 2.0
   the full text of which is contained in the file License.txt included in
   TrueCrypt binary and source code distribution archives.  */

/* DeviceIoControl values.

*/

#pragma once

#include "Tcdefs.h"
#include "Common.h"
#include "Crypto.h"

#ifdef _WIN32

#ifndef CTL_CODE

/* A macro from the NT DDK */

#define CTL_CODE( DeviceType, Function, Method, Access ) ( \
    ((DeviceType) << 16) | ((Access) << 14) | ((Function) << 2) | (Method) \
)

#endif

/* More macros from the NT DDK */

#ifndef METHOD_BUFFERED
#define METHOD_BUFFERED 0
#endif

#ifndef FILE_ANY_ACCESS
#define FILE_ANY_ACCESS 0
#endif

#ifndef FILE_DEVICE_DISK
#define FILE_DEVICE_DISK 0x00000007
#endif

#ifndef IOCTL_DISK_BASE
#define IOCTL_DISK_BASE FILE_DEVICE_DISK
#endif

/* These values originate from the following NT DDK macro :

#define ANYNAME CTL_CODE(IOCTL_DISK_BASE, 0x800, METHOD_BUFFERED, \
   FILE_ANY_ACCESS)

#define ANYNAME2 CTL_CODE(IOCTL_DISK_BASE, 0x801, METHOD_BUFFERED, \
   FILE_ANY_ACCESS)

etc... */

/* Public driver interface codes */

#define MOUNT			466944	/* Mount a volume or partition */
#define MOUNT_LIST		466948	/* Return list of mounted volumes */
#define OPEN_TEST		466952	/* Open a file at ring0 */
#define UNMOUNT			466956	/* Unmount a volume */
#define WIPE_CACHE		466960	/* Wipe the driver password cache */
#define HALT_SYSTEM		466964	/* Halt system; (only NT when compiled with debug) */
#define DRIVER_VERSION		466968	/* Current driver version */
#define CACHE_STATUS		466988	/* Get password cache status */
#define VOLUME_PROPERTIES	466992	/* Get mounted volume properties */
#define RESOLVE_SYMLINK		466996	/* Resolve symbolic link to target */
#define DEVICE_REFCOUNT		467000	/* Return reference count of root device object */
#define UNMOUNT_ALL			475112	/* Unmount all volumes */

#define TC_FIRST_PRIVATE	MOUNT	/* First private control code */
#define TC_LAST_PRIVATE	UNMOUNT_ALL	/* Last private control code */

/* Start of driver interface structures, the size of these structures may
   change between versions; so make sure you first send DRIVER_VERSION to
   check that it's the correct device driver */

#pragma pack (push)
#pragma pack(1)

typedef struct
{
	int nReturnCode;					/* Return code back from driver */
	short wszVolume[TC_MAX_PATH];		/* Volume to be mounted */
	Password VolumePassword;			/* User password */
	BOOL bCache;						/* Cache passwords in driver */
	int nDosDriveNo;					/* Drive number to mount */
	BOOL bMountReadOnly;				/* Mount volume in read-only mode */
	BOOL bMountRemovable;				/* Mount volume as removable media */
	BOOL bExclusiveAccess;				/* Open host file/device in exclusive access mode */
	BOOL bMountManager;					/* Announce volume to mount manager */
	BOOL bUserContext;					/* Mount volume in user process context */
	BOOL bPreserveTimestamp;			/* Preserve file container timestamp */
	// Hidden volume protection
	BOOL bProtectHiddenVolume;			/* TRUE if the user wants the hidden volume within this volume to be protected against being overwritten (damaged) */
	Password ProtectedHidVolPassword;	/* Password to the hidden volume to be protected against overwriting */
} MOUNT_STRUCT;

typedef struct
{
	int nDosDriveNo;	/* Drive letter to unmount */
	BOOL ignoreOpenFiles;
	int nReturnCode;	/* Return code back from driver */
} UNMOUNT_STRUCT;

typedef struct
{
	unsigned __int32 ulMountedDrives;	/* Bitfield of all mounted drive letters */
	short wszVolume[26][TC_MAX_PATH];	/* Volume names of mounted volumes */
	unsigned __int64 diskLength[26];
	int ea[26];
	int volumeType[26];	/* Volume type (e.g. PROP_VOL_TYPE_OUTER, PROP_VOL_TYPE_OUTER_VOL_WRITE_PREVENTED, etc.) */
} MOUNT_LIST_STRUCT;

typedef struct
{
	int driveNo;
	int uniqueId;
	short wszVolume[TC_MAX_PATH];
	unsigned __int64 diskLength;
	int ea;
	int mode;
	int pkcs5;
	int pkcs5Iterations;
	BOOL hiddenVolume;
	BOOL readOnly;
	unsigned __int64 volumeCreationTime;
	unsigned __int64 headerCreationTime;
	unsigned __int64 totalBytesRead;
	unsigned __int64 totalBytesWritten;
	int hiddenVolProtection;	/* Hidden volume protection status (e.g. HIDVOL_PROT_STATUS_NONE, HIDVOL_PROT_STATUS_ACTIVE, etc.) */
} VOLUME_PROPERTIES_STRUCT;

typedef struct
{
	WCHAR symLinkName[TC_MAX_PATH];
	WCHAR targetName[TC_MAX_PATH];
} RESOLVE_SYMLINK_STRUCT;

typedef struct
{
	short wszFileName[TC_MAX_PATH];	/* Volume to be "open tested" */
} OPEN_TEST_STRUCT;


#pragma pack (pop)

#ifdef NT4_DRIVER
#define DRIVER_STR WIDE
#else
#define DRIVER_STR
#endif

/* NT only */

#define TC_UNIQUE_ID_PREFIX "TrueCrypt"
#define TC_MOUNT_PREFIX L"\\Device\\TrueCryptVolume"

#define NT_MOUNT_PREFIX DRIVER_STR("\\Device\\TrueCryptVolume")
#define NT_ROOT_PREFIX DRIVER_STR("\\Device\\TrueCrypt")
#define DOS_MOUNT_PREFIX DRIVER_STR("\\DosDevices\\")
#define DOS_ROOT_PREFIX DRIVER_STR("\\DosDevices\\TrueCrypt")
#define WIN32_ROOT_PREFIX DRIVER_STR("\\\\.\\TrueCrypt")

#endif		/* _WIN32 */
