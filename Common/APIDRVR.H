/*
 Legal Notice: Some portions of the source code contained in this file were
 derived from the source code of Encryption for the Masses 2.02a, which is
 Copyright (c) 1998-2000 Paul Le Roux and which is governed by the 'License
 Agreement for Encryption for the Masses'. Modifications and additions to
 the original source code (contained in this file) and all other portions of
 this file are Copyright (c) 2003-2008 TrueCrypt Foundation and are governed
 by the TrueCrypt License 2.6 the full text of which is contained in the
 file License.txt included in TrueCrypt binary and source code distribution
 packages. */

#pragma once

#include "Tcdefs.h"
#include "Boot/Windows/BootDefs.h"
#include "Common.h"
#include "Crypto.h"
#include "Wipe.h"

#ifdef _WIN32

/* WARNING: Modifying the following values or their meanings can introduce incompatibility with previous versions. */

#define TC_IOCTL(CODE) (CTL_CODE (FILE_DEVICE_UNKNOWN, 0x800 + (CODE), METHOD_BUFFERED, FILE_ANY_ACCESS))

#define TC_IOCTL_GET_DRIVER_VERSION						TC_IOCTL (1)
#define TC_IOCTL_GET_BOOT_LOADER_VERSION				TC_IOCTL (2)
#define TC_IOCTL_MOUNT_VOLUME							TC_IOCTL (3)
#define TC_IOCTL_DISMOUNT_VOLUME						TC_IOCTL (4)
#define TC_IOCTL_DISMOUNT_ALL_VOLUMES					TC_IOCTL (5)
#define TC_IOCTL_GET_MOUNTED_VOLUMES					TC_IOCTL (6)
#define TC_IOCTL_GET_VOLUME_PROPERTIES					TC_IOCTL (7)
#define TC_IOCTL_GET_DEVICE_REFCOUNT					TC_IOCTL (8)
#define TC_IOCTL_WAS_REFERENCED_DEVICE_DELETED			TC_IOCTL (9)
#define TC_IOCTL_IS_ANY_VOLUME_MOUNTED					TC_IOCTL (10)
#define TC_IOCTL_GET_PASSWORD_CACHE_STATUS				TC_IOCTL (11)
#define TC_IOCTL_WIPE_PASSWORD_CACHE					TC_IOCTL (12)
#define TC_IOCTL_OPEN_TEST								TC_IOCTL (13)
#define TC_IOCTL_GET_DRIVE_PARTITION_INFO				TC_IOCTL (14)
#define TC_IOCTL_GET_DRIVE_GEOMETRY						TC_IOCTL (15)
#define TC_IOCTL_PROBE_REAL_DRIVE_SIZE					TC_IOCTL (16)
#define TC_IOCTL_GET_RESOLVED_SYMLINK					TC_IOCTL (17)
#define TC_IOCTL_GET_BOOT_ENCRYPTION_STATUS				TC_IOCTL (18)
#define TC_IOCTL_BOOT_ENCRYPTION_SETUP					TC_IOCTL (19)
#define TC_IOCTL_ABORT_BOOT_ENCRYPTION_SETUP			TC_IOCTL (20)
#define TC_IOCTL_GET_BOOT_ENCRYPTION_SETUP_RESULT		TC_IOCTL (21)
#define TC_IOCTL_GET_BOOT_DRIVE_VOLUME_PROPERTIES		TC_IOCTL (22)
#define TC_IOCTL_REOPEN_BOOT_VOLUME_HEADER				TC_IOCTL (23)
#define TC_IOCTL_GET_BOOT_ENCRYPTION_ALGORITHM_NAME		TC_IOCTL (24)
#define TC_IOCTL_GET_TRAVELER_MODE_STATUS				TC_IOCTL (25)
#define TC_IOCTL_SET_TRAVELER_MODE_STATUS				TC_IOCTL (26)
#define TC_IOCTL_IS_HIDDEN_SYSTEM_RUNNING				TC_IOCTL (27)
#define TC_IOCTL_GET_SYSTEM_DRIVE_CONFIG				TC_IOCTL (28)
#define TC_IOCTL_DISK_IS_WRITABLE						TC_IOCTL (29)
#define TC_IOCTL_START_DECOY_SYSTEM_WIPE				TC_IOCTL (30)
#define TC_IOCTL_ABORT_DECOY_SYSTEM_WIPE				TC_IOCTL (31)
#define TC_IOCTL_GET_DECOY_SYSTEM_WIPE_STATUS			TC_IOCTL (32)
#define TC_IOCTL_GET_DECOY_SYSTEM_WIPE_RESULT			TC_IOCTL (33)
#define TC_IOCTL_WRITE_BOOT_DRIVE_SECTOR				TC_IOCTL (34)

// Legacy IOCTLs used before version 5.0
#define TC_IOCTL_LEGACY_GET_DRIVER_VERSION		466968
#define TC_IOCTL_LEGACY_GET_MOUNTED_VOLUMES		466948


/* Start of driver interface structures, the size of these structures may
   change between versions; so make sure you first send DRIVER_VERSION to
   check that it's the correct device driver */

#pragma pack (push)
#pragma pack(1)

typedef struct
{
	int nReturnCode;					/* Return code back from driver */
	BOOL FilesystemDirty;

	short wszVolume[TC_MAX_PATH];		/* Volume to be mounted */
	Password VolumePassword;			/* User password */
	BOOL bCache;						/* Cache passwords in driver */
	int nDosDriveNo;					/* Drive number to mount */
	int BytesPerSector;
	BOOL bMountReadOnly;				/* Mount volume in read-only mode */
	BOOL bMountRemovable;				/* Mount volume as removable media */
	BOOL bExclusiveAccess;				/* Open host file/device in exclusive access mode */
	BOOL bMountManager;					/* Announce volume to mount manager */
	BOOL bPreserveTimestamp;			/* Preserve file container timestamp */
	BOOL bPartitionInInactiveSysEncScope;		/* If TRUE, we are to attempt to mount a partition located on an encrypted system drive without pre-boot authentication. */
	int nPartitionInInactiveSysEncScopeDriveNo;	/* If bPartitionInInactiveSysEncScope is TRUE, this contains the drive number of the system drive on which the partition is located. */
	// Hidden volume protection
	BOOL bProtectHiddenVolume;			/* TRUE if the user wants the hidden volume within this volume to be protected against being overwritten (damaged) */
	Password ProtectedHidVolPassword;	/* Password to the hidden volume to be protected against overwriting */
	BOOL UseBackupHeader;
	BOOL RecoveryMode;
} MOUNT_STRUCT;

typedef struct
{
	int nDosDriveNo;	/* Drive letter to unmount */
	BOOL ignoreOpenFiles;
	BOOL HiddenVolumeProtectionTriggered;
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
#if 0
	unsigned __int64 volumeCreationTime;	// Deprecated in v6.0
	unsigned __int64 headerCreationTime;	// Deprecated in v6.0
#endif
	uint32 volumeHeaderFlags;
	unsigned __int64 totalBytesRead;
	unsigned __int64 totalBytesWritten;
	int hiddenVolProtection;	/* Hidden volume protection status (e.g. HIDVOL_PROT_STATUS_NONE, HIDVOL_PROT_STATUS_ACTIVE, etc.) */
	int volFormatVersion;
} VOLUME_PROPERTIES_STRUCT;

typedef struct
{
	WCHAR symLinkName[TC_MAX_PATH];
	WCHAR targetName[TC_MAX_PATH];
} RESOLVE_SYMLINK_STRUCT;

typedef struct
{
	WCHAR deviceName[TC_MAX_PATH];
	PARTITION_INFORMATION partInfo;
	BOOL IsGPT;
	BOOL IsDynamic;
}
DISK_PARTITION_INFO_STRUCT;

typedef struct
{
	WCHAR deviceName[TC_MAX_PATH];
	DISK_GEOMETRY diskGeometry;
}
DISK_GEOMETRY_STRUCT;

typedef struct
{
	WCHAR DeviceName[TC_MAX_PATH];
	LARGE_INTEGER RealDriveSize;
	BOOL TimeOut;
} ProbeRealDriveSizeRequest;

typedef struct
{
	short wszFileName[TC_MAX_PATH];		// Volume to be "open tested"
	BOOL bDetectTCBootLoader;			// Whether the driver is to determine if the first sector contains a portion of the TrueCrypt Boot Loader
} OPEN_TEST_STRUCT;


typedef enum
{
	SetupNone = 0,
	SetupEncryption,
	SetupDecryption
} BootEncryptionSetupMode;


typedef struct
{
	// New fields must be added at the end of the structure to maintain compatibility with previous versions
	BOOL DeviceFilterActive;

	uint16 BootLoaderVersion;

	BOOL DriveMounted;
	BOOL VolumeHeaderPresent;
	BOOL DriveEncrypted;

	LARGE_INTEGER BootDriveLength;

	int64 ConfiguredEncryptedAreaStart;
	int64 ConfiguredEncryptedAreaEnd;
	int64 EncryptedAreaStart;
	int64 EncryptedAreaEnd;

	uint32 VolumeHeaderSaltCrc32;

	BOOL SetupInProgress;
	BootEncryptionSetupMode SetupMode;
	BOOL TransformWaitingForIdle;

	uint32 HibernationPreventionCount;

	BOOL HiddenSystem;
	int64 HiddenSystemPartitionStart;

	// Number of times the filter driver answered that an unencrypted volume
	// is read-only (or mounted an outer/normal TrueCrypt volume as read only)
	uint32 HiddenSysLeakProtectionCount;

} BootEncryptionStatus;


typedef struct
{
	BootEncryptionSetupMode SetupMode;
	WipeAlgorithmId WipeAlgorithm;
	BOOL ZeroUnreadableSectors;
} BootEncryptionSetupRequest;


typedef struct
{
	Password VolumePassword;
} ReopenBootVolumeHeaderRequest;


typedef struct
{
	char BootEncryptionAlgorithmName[256];
} GetBootEncryptionAlgorithmNameRequest;

typedef struct
{
	wchar_t DevicePath[TC_MAX_PATH];
	byte Configuration;
	BOOL DriveIsDynamic;
	uint16 BootLoaderVersion;
	byte UserConfiguration;
	char CustomUserMessage[TC_BOOT_SECTOR_USER_MESSAGE_MAX_LENGTH + 1];
} GetSystemDriveConfigurationRequest;

typedef struct
{
	WipeAlgorithmId WipeAlgorithm;
	byte WipeKey[MASTER_KEYDATA_SIZE];
} WipeDecoySystemRequest;

typedef struct
{
	BOOL WipeInProgress;
	WipeAlgorithmId WipeAlgorithm;
	int64 WipedAreaEnd;
} DecoySystemWipeStatus;

typedef struct
{
	LARGE_INTEGER Offset;
	byte Data[SECTOR_SIZE];
} WriteBootDriveSectorRequest;

#pragma pack (pop)

#ifdef NT4_DRIVER
#define DRIVER_STR WIDE
#else
#define DRIVER_STR
#endif

/* NT only */

#define TC_UNIQUE_ID_PREFIX "TrueCryptVolume"
#define TC_MOUNT_PREFIX L"\\Device\\TrueCryptVolume"

#define NT_MOUNT_PREFIX DRIVER_STR("\\Device\\TrueCryptVolume")
#define NT_ROOT_PREFIX DRIVER_STR("\\Device\\TrueCrypt")
#define DOS_MOUNT_PREFIX DRIVER_STR("\\DosDevices\\")
#define DOS_ROOT_PREFIX DRIVER_STR("\\DosDevices\\TrueCrypt")
#define WIN32_ROOT_PREFIX DRIVER_STR("\\\\.\\TrueCrypt")

#define TC_DRIVER_CONFIG_REG_VALUE_NAME DRIVER_STR("TrueCryptConfig")

#define TC_DRIVER_CONFIG_CACHE_BOOT_PASSWORD	0x1

#endif		/* _WIN32 */
