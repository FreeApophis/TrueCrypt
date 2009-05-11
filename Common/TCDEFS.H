/*
 Legal Notice: Some portions of the source code contained in this file were
 derived from the source code of Encryption for the Masses 2.02a, which is
 Copyright (c) 1998-2000 Paul Le Roux and which is governed by the 'License
 Agreement for Encryption for the Masses'. Modifications and additions to
 the original source code (contained in this file) and all other portions of
 this file are Copyright (c) 2003-2009 TrueCrypt Foundation and are governed
 by the TrueCrypt License 2.6 the full text of which is contained in the
 file License.txt included in TrueCrypt binary and source code distribution
 packages. */

#ifndef TCDEFS_H
#define TCDEFS_H

#define TC_APP_NAME						"TrueCrypt"

// Version displayed to user 
#define VERSION_STRING					"6.2"

// Version number to compare against driver
#define VERSION_NUM						0x0620

// Sector size of encrypted filesystem, which may differ from sector size of host filesystem/device
#define SECTOR_SIZE                     512

// "Second generation standard" sector size
#define SECTOR_SIZE_GEN2_STANDARD		4096

#define BYTES_PER_KB                    1024LL
#define BYTES_PER_MB                    1048576LL
#define BYTES_PER_GB                    1073741824LL
#define BYTES_PER_TB                    1099511627776LL
#define BYTES_PER_PB                    1125899906842624LL

/* GUI/driver errors */

#define WIDE(x) (LPWSTR)L##x

#ifdef _MSC_VER

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

#else // !_MSC_VER

#include <inttypes.h>
#include <limits.h>

typedef int8_t int8;
typedef int16_t int16;
typedef int32_t int32;
typedef int64_t int64;
typedef uint8_t byte;
typedef uint16_t uint16;
typedef uint32_t uint32;
typedef uint64_t uint64;

#if UCHAR_MAX != 0xffU
#error UCHAR_MAX != 0xff
#endif
#define __int8 char

#if USHRT_MAX != 0xffffU
#error USHRT_MAX != 0xffff
#endif
#define __int16 short

#if UINT_MAX != 0xffffffffU
#error UINT_MAX != 0xffffffff
#endif
#define __int32 int

typedef uint64 TC_LARGEST_COMPILER_UINT;

#define BOOL int
#ifndef FALSE
#define FALSE 0
#define TRUE 1
#endif

#endif // !_MSC_VER

#define TC_INT_TYPES_DEFINED

// Integer types required by Cryptolib
typedef unsigned __int8 uint_8t;
typedef unsigned __int16 uint_16t;
typedef unsigned __int32 uint_32t;
#ifndef TC_NO_COMPILER_INT64
typedef uint64 uint_64t;
#endif

typedef union 
{
	struct 
	{
		unsigned __int32 LowPart;
		unsigned __int32 HighPart;
	};
#ifndef TC_NO_COMPILER_INT64
	uint64 Value;
#endif

} UINT64_STRUCT;

#ifdef TC_WINDOWS_BOOT
#	define TC_THROW_FATAL_EXCEPTION	ThrowFatalException (__LINE__)
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

#ifndef TC_LOCAL_WIN32_WINNT_OVERRIDE
#	undef _WIN32_WINNT
#	define	_WIN32_WINNT 0x0501	/* Does not apply to user-space apps */
#endif

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

#ifndef TC_LOCAL_WIN32_WINNT_OVERRIDE
#	undef _WIN32_WINNT
#	define	_WIN32_WINNT 0x0501	/* Does not apply to the driver */
#endif

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

#ifndef TC_TO_STRING
#	define TC_TO_STRING2(n) #n
#	define TC_TO_STRING(n) TC_TO_STRING2(n)
#endif

#ifdef DEVICE_DRIVER
#	if defined (DEBUG) || 0
#		if 1 // DbgPrintEx is not available on Windows 2000
#			define Dump DbgPrint
#		else
#			define Dump(...) DbgPrintEx (DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, __VA_ARGS__)
#		endif
#		define DumpMem(...) DumpMemory (__VA_ARGS__)
#	else
#		define Dump(...) ((void) 0)
#		define DumpMem(...) ((void) 0)
#	endif
#endif

#if !defined (trace_msg) && !defined (TC_WINDOWS_BOOT)
#	ifdef DEBUG
#		ifdef DEVICE_DRIVER
#			define trace_msg Dump
#		elif defined (_WIN32)
#			define trace_msg(...) do { char msg[2048]; _snprintf (msg, sizeof (msg), __VA_ARGS__); OutputDebugString (msg); } while (0)
#		endif
#		define trace_point trace_msg (__FUNCTION__ ":" TC_TO_STRING(__LINE__) "\n")
#	else
#		define trace_msg(...)
#		define trace_point
#	endif
#endif

#ifdef DEVICE_DRIVER
#	define TC_EVENT KEVENT
#	define TC_WAIT_EVENT(EVENT) KeWaitForSingleObject (&EVENT, Executive, KernelMode, FALSE, NULL)
#elif defined (_WIN32)
#	define TC_EVENT HANDLE
#	define TC_WAIT_EVENT(EVENT) WaitForSingleObject (EVENT, INFINITE)
#endif

#ifdef _WIN32
#define burn(mem,size) do { volatile char *burnm = (volatile char *)(mem); int burnc = size; RtlSecureZeroMemory (mem, size); while (burnc--) *burnm++ = 0; } while (0)
#else
#define burn(mem,size) do { volatile char *burnm = (volatile char *)(mem); int burnc = size; while (burnc--) *burnm++ = 0; } while (0)
#endif

// The size of the memory area to wipe is in bytes amd it must be a multiple of 8.
#ifndef TC_NO_COMPILER_INT64
#	define FAST_ERASE64(mem,size) do { volatile uint64 *burnm = (volatile uint64 *)(mem); int burnc = size >> 3; while (burnc--) *burnm++ = 0; } while (0)
#else
#	define FAST_ERASE64(mem,size) do { volatile unsigned __int32 *burnm = (volatile unsigned __int32 *)(mem); int burnc = size >> 2; while (burnc--) *burnm++ = 0; } while (0)
#endif

#ifdef TC_WINDOWS_BOOT
#	ifndef max
#		define max(a,b) (((a) > (b)) ? (a) : (b))
#	endif
#	undef burn
#	define burn EraseMemory
#endif

#ifdef MAX_PATH
#define TC_MAX_PATH		MAX_PATH
#else
#define TC_MAX_PATH		260	/* Includes the null terminator */
#endif

#define MAX_URL_LENGTH	2084 /* Internet Explorer limit. Includes the terminating null character. */

#define TC_APPLINK "http://www.truecrypt.org/applink?version=" VERSION_STRING
#define TC_APPLINK_SECURE "https://www.truecrypt.org/applink?version=" VERSION_STRING

enum
{
	/* WARNING: ADD ANY NEW CODES AT THE END (DO NOT INSERT THEM BETWEEN EXISTING). DO *NOT* DELETE ANY 
	EXISTING CODES! Changing these values or their meanings may cause incompatibility with other versions
	(for example, if a new version of the TrueCrypt installer receives an error code from an installed 
	driver whose version is lower, it will report and interpret the error incorrectly). */

	ERR_SUCCESS								= 0,
	ERR_OS_ERROR							= 1,
	ERR_OUTOFMEMORY							= 2,
	ERR_PASSWORD_WRONG						= 3,
	ERR_VOL_FORMAT_BAD						= 4,
	ERR_DRIVE_NOT_FOUND						= 5,
	ERR_FILES_OPEN							= 6,
	ERR_VOL_SIZE_WRONG						= 7,
	ERR_COMPRESSION_NOT_SUPPORTED			= 8,
	ERR_PASSWORD_CHANGE_VOL_TYPE			= 9,
	ERR_PASSWORD_CHANGE_VOL_VERSION			= 10,
	ERR_VOL_SEEKING							= 11,
	ERR_VOL_WRITING							= 12,
	ERR_FILES_OPEN_LOCK						= 13,
	ERR_VOL_READING							= 14,
	ERR_DRIVER_VERSION						= 15,
	ERR_NEW_VERSION_REQUIRED				= 16,
	ERR_CIPHER_INIT_FAILURE					= 17,
	ERR_CIPHER_INIT_WEAK_KEY				= 18,
	ERR_SELF_TESTS_FAILED					= 19,
	ERR_SECTOR_SIZE_INCOMPATIBLE			= 20,
	ERR_VOL_ALREADY_MOUNTED					= 21,
	ERR_NO_FREE_DRIVES						= 22,
	ERR_FILE_OPEN_FAILED					= 23,
	ERR_VOL_MOUNT_FAILED					= 24,
	DEPRECATED_ERR_INVALID_DEVICE			= 25,
	ERR_ACCESS_DENIED						= 26,
	ERR_MODE_INIT_FAILED					= 27,
	ERR_DONT_REPORT							= 28,
	ERR_ENCRYPTION_NOT_COMPLETED			= 29,
	ERR_PARAMETER_INCORRECT					= 30,
	ERR_SYS_HIDVOL_HEAD_REENC_MODE_WRONG	= 31,
	ERR_NONSYS_INPLACE_ENC_INCOMPLETE		= 32,
	ERR_USER_ABORT							= 33
};

#endif 	// #ifndef TCDEFS_H
