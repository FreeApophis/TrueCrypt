/*
 Legal Notice: The source code contained in this file has been derived from
 the source code of Encryption for the Masses 2.02a, which is Copyright (c)
 Paul Le Roux and which is covered by the 'License Agreement for Encryption
 for the Masses'. Modifications and additions to that source code contained
 in this file are Copyright (c) TrueCrypt Foundation and are covered by the
 TrueCrypt License 2.2 the full text of which is contained in the file
 License.txt included in TrueCrypt binary and source code distribution
 packages. */

// Version displayed to user 
#define VERSION_STRING                  "4.3"

// Version number to compare against driver
#define VERSION_NUM						0x0430

// Version number written to volume header during format,
// specifies the minimum program version required to mount the volume
#define VOL_REQ_PROG_VERSION			0x0410

// Volume header version
#define VOLUME_HEADER_VERSION			0x0002 

// Sector size of encrypted filesystem, which may differ from sector size of host filesystem/device (this 
// is fully supported since v4.3). To retain maximum portability and compatibility, it should always be 512.
#define SECTOR_SIZE                     512

#define BYTES_PER_KB                    1024LL
#define BYTES_PER_MB                    1048576LL
#define BYTES_PER_GB                    1073741824LL
#define BYTES_PER_TB                    1099511627776LL
#define BYTES_PER_PB                    1125899906842624LL

/* GUI/driver errors */

#define ERR_SUCCESS                     0
#define ERR_OS_ERROR                    1
#define ERR_OUTOFMEMORY                 2
#define ERR_PASSWORD_WRONG              3
#define ERR_VOL_FORMAT_BAD              4
#define ERR_DRIVE_NOT_FOUND             6
#define ERR_FILES_OPEN                  7
#define ERR_VOL_SIZE_WRONG              8
#define ERR_COMPRESSION_NOT_SUPPORTED   9
#define ERR_PASSWORD_CHANGE_VOL_TYPE    10
#define ERR_PASSWORD_CHANGE_VOL_VERSION 11
#define ERR_VOL_SEEKING                 12
#define ERR_VOL_WRITING                 13
#define ERR_FILES_OPEN_LOCK             14
#define ERR_VOL_READING                 15
#define ERR_DRIVER_VERSION				16
#define ERR_NEW_VERSION_REQUIRED		17
#define ERR_CIPHER_INIT_FAILURE			18
#define ERR_CIPHER_INIT_WEAK_KEY		19
#define ERR_SELF_TESTS_FAILED			20
#define ERR_SECTOR_SIZE_INCOMPATIBLE	21

#define ERR_VOL_ALREADY_MOUNTED         32
#define ERR_NO_FREE_DRIVES              34
#define ERR_FILE_OPEN_FAILED            35
#define ERR_VOL_MOUNT_FAILED            36
#define ERR_INVALID_DEVICE              37
#define ERR_ACCESS_DENIED               38
#define ERR_MODE_INIT_FAILED            39

#define ERR_DONT_REPORT                 100

#define MIN_VOLUME_SIZE                 19456
#define MIN_HIDDEN_VOLUME_HOST_SIZE     ( MIN_VOLUME_SIZE * 2 + HIDDEN_VOL_HEADER_OFFSET + HEADER_SIZE )
#define MAX_VOLUME_SIZE                 0x7fffFFFFffffFFFFLL
#define MAX_FAT_VOLUME_SIZE				0x20000000000LL
#define MAX_HIDDEN_VOLUME_HOST_SIZE     MAX_FAT_VOLUME_SIZE
#define MAX_HIDDEN_VOLUME_SIZE          ( MAX_HIDDEN_VOLUME_HOST_SIZE - HIDDEN_VOL_HEADER_OFFSET - HEADER_SIZE )

#define WIDE(x) (LPWSTR)L##x

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

#elif defined(LINUX_DRIVER)	

#define TCalloc(size) (kmalloc( size, GFP_KERNEL ))
#define TCfree(memblock) kfree( memblock )

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

#ifdef MAX_PATH
#define TC_MAX_PATH		MAX_PATH
#else
#define TC_MAX_PATH		260	/* Includes the null terminator */
#endif

#define MAX_URL_LENGTH	2084 /* Internet Explorer limit. Includes the terminating null character. */

#define TC_APPLINK "http://www.truecrypt.org/applink.php?version=" VERSION_STRING
#define TC_APPLINK_SECURE "https://www.truecrypt.org/applink.php?version=" VERSION_STRING
