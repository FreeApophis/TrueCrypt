/* Copyright (C) 2004 TrueCrypt Foundation
   This product uses components written by Paul Le Roux <pleroux@swprofessionals.com> */

/* WARNING: The code for unmounting volumes is ugly for all Windows versions;
   becarefull what you change here as there might be unintended side effects
   in the device drivers */

/* For Windows NT the part of the system that actually unmounts drives is the
   TrueCryptService, this is because of NT security. Users don't normally have
   enough access to open raw partitions, but services do, TrueCryptService still
   calls this code however. */

#include "TCdefs.h"
#include "crypto.h"
#include "apidrvr.h"

#include "dismount.h"

extern HANDLE hDriver;

#ifdef NTSERVICE
extern void handleWin32Error (HWND dummy);
#else
#include "dlgcode.h"
#endif

/* NT support routines -----------------------------------> */

BOOL
UnmountAllVolumes (HWND hwndDlg, DWORD * os_error, int *err)
{
	MOUNT_LIST_STRUCT driver;
	DWORD dwResult;
	BOOL bResult, bOK = TRUE;
	int i;

	*os_error = 0;
	*err = 0;

	bResult = DeviceIoControl (hDriver, MOUNT_LIST, &driver, sizeof (driver), &driver,
				   sizeof (driver), &dwResult, NULL);

	if (bResult == FALSE)
	{
		*os_error = GetLastError ();
		*err = ERR_OS_ERROR;
		return FALSE;
	}

	for (i = 0; i < 26; i++)
	{
		if ((driver.ulMountedDrives & 1 << i))
		{
			UnmountVolume (i, os_error, err);

			if (*err != 0)
				bOK = FALSE;

			if (*err != 0 && *err == ERR_OS_ERROR)
				handleWin32Error (hwndDlg);
		}
	}

	return bOK;
}

BOOL
UnmountVolume (int nDosDriveNo, DWORD * os_error, int *err)
{
	UNMOUNT_STRUCT tcUnmount;
	char volMountName[32];
	char dosName[3];
	DWORD dwResult;
	BOOL bResult;

	*os_error = 0;
	*err = 0;

	tcUnmount.nDosDriveNo = nDosDriveNo;

	dosName[0] = (char) (tcUnmount.nDosDriveNo + 'A');
	dosName[1] = ':';
	dosName[2] = 0;

	sprintf (volMountName, "\\\\.\\%s", dosName);

	if (DismountVolume (volMountName, os_error, err) == FALSE)
		return FALSE;

	bResult = DeviceIoControl (hDriver, UNMOUNT, &tcUnmount,
				   sizeof (tcUnmount), &tcUnmount, sizeof (tcUnmount), &dwResult, NULL);

	if (bResult == FALSE)
	{
		*os_error = GetLastError ();
		*err = ERR_OS_ERROR;
		return FALSE;
	}

	if (tcUnmount.nReturnCode == 0)
	{
		bResult = DefineDosDevice (DDD_REMOVE_DEFINITION, dosName, NULL);

		if (bResult == FALSE)
		{
			*os_error = GetLastError ();
			*err = ERR_OS_ERROR;
			return FALSE;
		}
	}
	else
		*err = tcUnmount.nReturnCode;

	return TRUE;
}

BOOL
DismountVolume (char *lpszVolMountName, DWORD * os_error, int *err)
{
	HANDLE hVolume = INVALID_HANDLE_VALUE;
	BOOL bRetry = FALSE;
	DWORD dwResult;
	int i;

	*os_error = 0;
	*err = 0;

      retry:

#ifdef _DEBUG
	OutputDebugString ("mount: dismount volume ----------------->...\n");
#endif

	for (i = 0; i < 16; i++)
	{
		BOOL bResult;

#ifdef _DEBUG
		OutputDebugString ("mount: trying to open the volume...\n");
#endif
		/* Try to open a handle to the mounted volume */
		hVolume = CreateFile (lpszVolMountName, GENERIC_READ | GENERIC_WRITE,
				      FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
		if (hVolume == INVALID_HANDLE_VALUE)
		{
			*os_error = GetLastError ();
			*err = ERR_OS_ERROR;
			return FALSE;
		}

#ifdef _DEBUG
		OutputDebugString ("mount: trying to lock the volume...\n");
#endif
		bResult = DeviceIoControl (hVolume, FSCTL_LOCK_VOLUME, NULL, 0, NULL, 0, &dwResult, NULL);
		if (bResult == FALSE)
		{
			DWORD dwError = GetLastError ();
			if (dwError != ERROR_ACCESS_DENIED)
			{
				*os_error = GetLastError ();
				*err = ERR_OS_ERROR;
				CloseHandle (hVolume);
				return FALSE;
			}
			else
			{
				CloseHandle (hVolume);
				hVolume = INVALID_HANDLE_VALUE;
			}
		}
		else
			break;
	}

	if (hVolume == INVALID_HANDLE_VALUE)
	{
		if (bRetry == FALSE)
		{
			bRetry = TRUE;
			Sleep (1000);
			goto retry;
		}

		*err = ERR_FILES_OPEN_LOCK;

		return FALSE;
	}

#ifdef _DEBUG
	OutputDebugString ("mount: trying to dismount the volume...\n");
#endif
	DeviceIoControl (hVolume, FSCTL_DISMOUNT_VOLUME, NULL, 0, NULL, 0, &dwResult, NULL);
#ifdef _DEBUG
	OutputDebugString ("mount: trying to unmount the volume...\n");
#endif

	DeviceIoControl (hVolume, UNMOUNT_PENDING, NULL, 0, NULL, 0, &dwResult, NULL);
	CloseHandle (hVolume);

#ifdef _DEBUG
	OutputDebugString ("<-------------------------------- mount: dismount volume!\n");
#endif

	return TRUE;
}


/* Windows 9x support routines -----------------------------------> */

typedef struct _DIOC_REGISTERS
{
	DWORD reg_EBX;
	DWORD reg_EDX;
	DWORD reg_ECX;
	DWORD reg_EAX;
	DWORD reg_EDI;
	DWORD reg_ESI;
	DWORD reg_Flags;
} DIOC_REGISTERS, *PDIOC_REGISTERS;

#define VWIN32_DIOC_DOS_IOCTL 1

typedef struct PARAMBLOCK
{
	char Operation;
	char NumLocks;
} PARAMBLOCK;


BOOL
DoDeviceClose (int slot, int *err)
{
	MOUNT_LIST_N_STRUCT mount_list;
	UNMOUNT_STRUCT unmount;
	int tries;
	int c;

	mount_list.nDosDriveNo = slot;
	if (DeviceIoControl (hDriver, MOUNT_LIST_N, &mount_list, sizeof (mount_list), NULL, 0, NULL, NULL) == FALSE)
	{
		*err = ERR_OS_ERROR;
		return FALSE;
	}
	else
	{
		if (mount_list.nReturnCode != 0)
		{
			*err = mount_list.nReturnCode;
			return TRUE;
		}
	}

	if (mount_list.mountfilehandle)
		EjectStop ((char)toupper(*((char *) mount_list.wszVolume)), FALSE);

	unmount.nDosDriveNo = slot;
	if (DeviceIoControl (hDriver, UNMOUNT_PENDING, &unmount, sizeof (unmount), NULL, 0, NULL, NULL) == FALSE)
	{
		*err = ERR_OS_ERROR;
		return FALSE;
	}
	else
	{
		if (mount_list.nReturnCode != 0)
		{
			*err = mount_list.nReturnCode;
			return TRUE;
		}
	}

	for (c = 0; c < 20; c++)
	{
		DeviceIoControl (hDriver, RELEASE_TIME_SLICE, NULL, 0, NULL, 0, NULL, NULL);
	}

	for (tries=0;tries<32;tries++)
	{
		DeviceIoControl (hDriver, RELEASE_TIME_SLICE, NULL, 0, NULL, 0, NULL, NULL);
		if (DeviceIoControl (hDriver, UNMOUNT, &unmount, sizeof (UNMOUNT), NULL, 0, NULL, NULL) == FALSE)
		{
			*err = ERR_OS_ERROR;
			return FALSE;
		}
		else
		{
			if (mount_list.nReturnCode == 0)
			{
				*err = 0;
				return TRUE;
			}
		}
	}

	*err = ERR_FILES_OPEN_LOCK;
	return TRUE;
}

int
ioctllock (unsigned int nDrive, int permissions, int function)
{
	HANDLE hDevice;
	DIOC_REGISTERS reg;
	BOOL fResult;
	DWORD cb;
	int lockfunc;

	if (function)
		lockfunc = 0x4a;
	else
		lockfunc = 0x6a;

	hDevice = CreateFile ("\\\\.\\vwin32",
			    0, 0, NULL, 0, FILE_FLAG_DELETE_ON_CLOSE, NULL);

	reg.reg_EAX = 0x440D;
	reg.reg_EBX = nDrive;
	reg.reg_ECX = 0x0800 | lockfunc;
	reg.reg_EDX = permissions;
	reg.reg_Flags = 0x0001;

	fResult = DeviceIoControl (hDevice,
				   VWIN32_DIOC_DOS_IOCTL,
				   &reg, sizeof (reg),
				   &reg, sizeof (reg),
				   &cb, 0);

	CloseHandle (hDevice);

	return reg.reg_Flags & 1;	/* error if carry flag is set */
}

int
locklogdrive (int drivenum, int mode)	/* error if true returned.... */
{
	int a;

	if (mode)
	{
		a = ioctllock (drivenum, 0, 1);
		a = ioctllock (drivenum, 4, 1);
	}
	else
	{
		a = 0;
		ioctllock (drivenum, 0, 0);
		ioctllock (drivenum, 0, 0);
	}

	return a;
}



int
ld (char *d, int mode)
{
	int drivelett = d[0];
	int a = 1;

	drivelett -= 'A';
	drivelett += 1;

	if ((drivelett > 1) && drivelett < 27)
		a = (locklogdrive (drivelett, mode));

	return a;

}

BOOL
CloseSlot (int slot, int brutal, int *err)
{
	char dr[3];
	BOOL bResult;

	if (brutal);		/* Remove warning */

	dr[0] = (char) (slot + 'A');
	dr[1] = ':';
	dr[2] = 0;

	if (ld (dr, 1))
	{
		bResult = TRUE;
		*err = ERR_FILES_OPEN_LOCK;
	}
	else
	{
		bResult = DoDeviceClose (slot, err);
		ld (dr, 0);
	}

	return bResult;
}


int
EjectStop (char Driveletter, BOOL function)
{
	HANDLE hDevice;
	DIOC_REGISTERS reg;
	BOOL fResult;
	DWORD cb;
	int lockfunc;
	PARAMBLOCK p;

	if (Driveletter == 0)
		return 0;

	Driveletter -= 'A';
	Driveletter++;

	lockfunc = 0x48;

	if (function == TRUE)
		p.Operation = 0;/* lock */
	else
		p.Operation = 1;

	hDevice = CreateFile ("\\\\.\\vwin32", 0, 0, NULL, 0,
			      FILE_FLAG_DELETE_ON_CLOSE, NULL);

	reg.reg_EAX = 0x440D;
	reg.reg_EBX = Driveletter;
	reg.reg_ECX = 0x0800 | lockfunc;
	reg.reg_EDX = (unsigned long) &p;
	reg.reg_Flags = 0x0001;

	fResult = DeviceIoControl (hDevice,
				   VWIN32_DIOC_DOS_IOCTL,
				   &reg, sizeof (reg),
				   &reg, sizeof (reg),
				   &cb, 0);

	CloseHandle (hDevice);

	return reg.reg_Flags & 1;	/* error if carry flag is set */
}
