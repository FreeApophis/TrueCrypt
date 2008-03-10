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

#ifndef TCDEFS_H
#define TCDEFS_H

#define TC_APP_NAME						"TrueCrypt"

// Version displayed to user 
#define VERSION_STRING					"5.1"

// Version number to compare against driver
#define VERSION_NUM						0x0510

// Version number written to volume header during format,
// specifies the minimum program version required to mount the volume
#define VOL_REQ_PROG_VERSION			0x0500

// Volume header version
#define VOLUME_HEADER_VERSION			0x0003 

// Sector size of encrypted filesystem, which may differ from sector size 
// of host filesystem/device (this is fully supported since v4.3). 
#define SECTOR_SIZE                     512

#define BYTES_PER_KB                    1024LL
#define BYTES_PER_MB                    1048576LL
#define BYTES_PER_GB                    1073741824LL
#define BYTES_PER_TB                    1099511627776LL
#define BYTES_PER_PB                    1125899906842624LL

/* GUI/driver errors */

#define MAX_128BIT_BLOCK_VOLUME_SIZE	BYTES_PER_PB			// Security bound (128-bit block XTS mode)
#define MAX_VOLUME_SIZE_GENERAL			0x7fffFFFFffffFFFFLL	// Signed 64-bit integer file offset values
#define MAX_VOLUME_SIZE                 MAX_128BIT_BLOCK_VOLUME_SIZE
#define MIN_FAT_VOLUME_SIZE				19456
#define MAX_FAT_VOLUME_SIZE				0x20000000000LL
#define MIN_NTFS_VOLUME_SIZE			2634752
#define OPTIMAL_MIN_NTFS_VOLUME_SIZE	(4 * BYTES_PER_GB)
#define MAX_NTFS_VOLUME_SIZE			(128LL * BYTES_PER_TB)	// NTFS volume can theoretically be up to 16 exabytes, but Windows XP and 2003 limit the size to that addressable with 32-bit clusters, i.e. max size is 128 TB (if 64-KB clusters are used).
#define MAX_HIDDEN_VOLUME_HOST_SIZE     MAX_NTFS_VOLUME_SIZE
#define MAX_HIDDEN_VOLUME_SIZE          ( MAX_HIDDEN_VOLUME_HOST_SIZE - HIDDEN_VOL_HEADER_OFFSET - HEADER_SIZE )
#define MIN_VOLUME_SIZE                 MIN_FAT_VOLUME_SIZE
#define MIN_HIDDEN_VOLUME_HOST_SIZE     ( MIN_VOLUME_SIZE * 2 + HIDDEN_VOL_HEADER_OFFSET + HEADER_SIZE )

#ifndef TC_NO_COMPILER_INT64
#if MAX_VOLUME_SIZE > MAX_VOLUME_SIZE_GENERAL
#error MAX_VOLUME_SIZE must be less than or equal to MAX_VOLUME_SIZE_GENERAL
#endif
#endif

#define WIDE(x) (LPWSTR)L##x

typedef __int8 int8;
typedef __int16 int16;
typedef __int32 int32;
typedef unsigned __int8 byte;
typedef unsigned __int16 uint16;
typedef unsigned __int32 uint32;

#ifdef TC_NO_COMPILER_INT64
typedef unsigned __int32	TC_LARGEST_COMPILER_UINT;
#else
typedef unsigned __int64	TC_LARGEST_COMPILER_UINT;
typedef __int64 int64;
typedef unsigned __int64 uint64;
#endif

// Needed by Cryptolib
typedef unsigned __int8 uint_8t;
typedef unsigned __int16 uint_16t;
typedef unsigned __int32 uint_32t;
#ifndef TC_NO_COMPILER_INT64
typedef unsigned __int64 uint_64t;
#endif

typedef union 
{
	struct 
	{
		unsigned __int32 LowPart;
		unsigned __int32 HighPart;
	};
#ifndef TC_NO_COMPILER_INT64
	unsigned __int64 Value;
#endif

} UINT64_STRUCT;

#ifdef TC_WINDOWS_BOOT
#	define TC_THROW_FATAL_EXCEPTION	do { __asm hlt } while (1)
#elif defined (NT4_DRIVER)
#	define TC_THROW_FATAL_EXCEPTION KeBugCheckEx (SECURITY_SYSTEM, __LINE__, 0, 0, 'TC')
#else
#	define TC_THROW_FATAL_EXCEPTION	*(char *) 0 = 0
#endif

#ifdef NT4_DRIVER

#pragma warning( disable : 4201 )
#pragma warning( disable : 4214 )
#pragma warning( disable : 4115 )
#pragma warning( disable : 4100 )
#pragma warning( disable : 4101 )
#pragma warning( disable : 4057 )
#pragma warning( disable : 4244 )
#pragma warning( disable : 4514 )
#pragma warning( disable : 4127 )


#include <ntifs.h>
#include <ntddk.h>		/* Standard header file for nt drivers */

#undef _WIN32_WINNT
#define	_WIN32_WINNT 0x0501
#include <ntdddisk.h>		/* Standard I/O control codes  */
#include <ntiologc.h>

#pragma warning( default : 4201 )
#pragma warning( default : 4214 )
#pragma warning( default : 4115 )
#pragma warning( default : 4100 )
#pragma warning( default : 4101 )
#pragma warning( default : 4057 )
#pragma warning( default : 4244 )
#pragma warning( default : 4127 )

/* #pragma warning( default : 4514 ) this warning remains disabled */

#define TCalloc(size) ((void *) ExAllocatePoolWithTag( NonPagedPool, size, 'MMCT' ))
#define TCfree(memblock) ExFreePoolWithTag( memblock, 'MMCT' )

#define DEVICE_DRIVER

#ifndef BOOL
typedef int BOOL;
#endif

#ifndef TRUE
#define TRUE 1
#endif

#ifndef FALSE
#define FALSE !TRUE
#endif

/* Define dummies for the drivers */
typedef int HFILE;
typedef unsigned int WPARAM;
typedef unsigned __int32 LPARAM;
#define CALLBACK

#ifndef UINT
typedef unsigned int UINT;
#endif

#ifndef LRESULT
typedef unsigned __int32 LRESULT;
#endif
/* NT4_DRIVER */

#else

#define TCalloc malloc
#define TCfree free

#ifdef _WIN32

#pragma warning( disable : 4201 )
#pragma warning( disable : 4214 )
#pragma warning( disable : 4115 )
#pragma warning( disable : 4514 )

#undef _WIN32_WINNT
#define	_WIN32_WINNT 0x0501
#include <windows.h>		/* Windows header */
#include <commctrl.h>		/* The common controls */
#include <process.h>		/* Process control */
#include <winioctl.h>
#include <stdio.h>		/* For sprintf */

#pragma warning( default : 4201 )
#pragma warning( default : 4214 )
#pragma warning( default : 4115 )

/* #pragma warning( default : 4514 ) this warning remains disabled */

/* This is needed to fix a bug with VC 5, the TCHAR macro _ttoi64 maps
   incorrectly to atoLL when it should be _atoi64 */
#define atoi64 _atoi64

#endif				/* _WIN32 */

#endif				/* NT4_DRIVER */

#ifdef _WIN32
#define burn(mem,size) do { volatile char *burnm = (volatile char *)(mem); int burnc = size; RtlSecureZeroMemory (mem, size); while (burnc--) *burnm++ = 0; } while (0)
#else
#define burn(mem,size) do { volatile char *burnm = (volatile char *)(mem); int burnc = size; while (burnc--) *burnm++ = 0; } while (0)
#endif

// The size of the memory area to wipe is in bytes amd it must be a multiple of 8.
#ifndef TC_NO_COMPILER_INT64
#	define FAST_ERASE64(mem,size) do { volatile unsigned __int64 *burnm = (volatile unsigned __int64 *)(mem); int burnc = size >> 3; while (burnc--) *burnm++ = 0; } while (0)
#else
#	define FAST_ERASE64(mem,size) do { volatile unsigned __int32 *burnm = (volatile unsigned __int32 *)(mem); int burnc = size >> 2; while (burnc--) *burnm++ = 0; } while (0)
#endif

#ifdef TC_WINDOWS_BOOT
#undef burn
#define burn EraseMemory
#endif

#ifdef MAX_PATH
#define TC_MAX_PATH		MAX_PATH
#else
#define TC_MAX_PATH		260	/* Includes the null terminator */
#endif

#define MAX_URL_LENGTH	2084 /* Internet Explorer limit. Includes the terminating null character. */

#define TC_APPLINK "http://www.truecrypt.org/applink.php?version=" VERSION_STRING
#define TC_APPLINK_SECURE "https://www.truecrypt.org/applink.php?version=" VERSION_STRING

enum
{
	/* WARNING: Add any new codes at the end (do NOT insert them between existing). Do NOT delete any 
	existing codes. Changing these values or their meanings may cause incompatibility with other 
	versions (for example, if a new version of the TrueCrypt installer receives an error code from
	an installed driver whose version is lower, it will interpret the error incorrectly). */

	ERR_SUCCESS = 0,
	ERR_OS_ERROR = 1,
	ERR_OUTOFMEMORY,
	ERR_PASSWORD_WRONG,
	ERR_VOL_FORMAT_BAD,
	ERR_DRIVE_NOT_FOUND,
	ERR_FILES_OPEN,
	ERR_VOL_SIZE_WRONG,
	ERR_COMPRESSION_NOT_SUPPORTED,
	ERR_PASSWORD_CHANGE_VOL_TYPE,
	ERR_PASSWORD_CHANGE_VOL_VERSION,
	ERR_VOL_SEEKING,
	ERR_VOL_WRITING,
	ERR_FILES_OPEN_LOCK,
	ERR_VOL_READING,
	ERR_DRIVER_VERSION,
	ERR_NEW_VERSION_REQUIRED,
	ERR_CIPHER_INIT_FAILURE,
	ERR_CIPHER_INIT_WEAK_KEY,
	ERR_SELF_TESTS_FAILED,
	ERR_SECTOR_SIZE_INCOMPATIBLE,
	ERR_VOL_ALREADY_MOUNTED,
	ERR_NO_FREE_DRIVES,
	ERR_FILE_OPEN_FAILED,
	ERR_VOL_MOUNT_FAILED,
	ERR_INVALID_DEVICE,
	ERR_ACCESS_DENIED,
	ERR_MODE_INIT_FAILED,
	ERR_DONT_REPORT,
	ERR_ENCRYPTION_NOT_COMPLETED,
	ERR_PARAMETER_INCORRECT
};

#endif 	// #ifndef TCDEFS_H
