/* Copyright (C) 2004 TrueCrypt Foundation
   This product uses components written by Paul Le Roux <pleroux@swprofessionals.com> */

#include "TCdefs.h"

#include "crypto.h"
#include "fat.h"
#include "format.h"
#include "volumes.h"
#include "password.h"
#include "apidrvr.h"
#include "dlgcode.h"
#include "pkcs5.h"
#include "endian.h"

#include <io.h>

void
VerifyPasswordAndUpdate (HWND hwndDlg, HWND hButton, HWND hPassword,
			 HWND hVerify, char *szPassword,
			 char *szVerify)
{
	char szTmp1[MAX_PASSWORD + 1];
	char szTmp2[MAX_PASSWORD + 1];
	int k = GetWindowTextLength (hPassword);
	BOOL bEnable = FALSE;

	if (hwndDlg);		/* Remove warning */

	GetWindowText (hPassword, szTmp1, sizeof (szTmp1));
	GetWindowText (hVerify, szTmp2, sizeof (szTmp2));

	if (strcmp (szTmp1, szTmp2) != 0)
		bEnable = FALSE;
	else
	{
		if (k >= MIN_PASSWORD)
			bEnable = TRUE;
		else
			bEnable = FALSE;
	}

	if (szPassword != NULL)
		memcpy (szPassword, szTmp1, sizeof (szTmp1));

	if (szVerify != NULL)
		memcpy (szVerify, szTmp2, sizeof (szTmp2));

	burn (szTmp1, sizeof (szTmp1));
	burn (szTmp2, sizeof (szTmp2));

	EnableWindow (hButton, bEnable);
}

int
ChangePwd (char *lpszVolume, char *lpszOldPassword, char *lpszPassword)
{
	int nDosLinkCreated = 0, nStatus;
	char szDiskFile[TC_MAX_PATH], szCFDevice[TC_MAX_PATH];
	char szDosDevice[TC_MAX_PATH];
	char buffer[SECTOR_SIZE], boot[SECTOR_SIZE];
	PCRYPTO_INFO cryptoInfo = NULL, ci = NULL;
	void *dev = INVALID_HANDLE_VALUE;
	OPEN_TEST_STRUCT driver;
	DISKIO_STRUCT win9x_r0;
	diskio_f write, read;
	DWORD dwError;
	BOOL bDevice;
	
	if (Randinit ()) return 1;

	CreateFullVolumePath (szDiskFile, lpszVolume, &bDevice);

	if (nCurrentOS == WIN_NT || bDevice == FALSE)
	{
		write = (diskio_f) _lwrite;
		read = (diskio_f) _lread;

		if (bDevice == FALSE)
		{
			strcpy (szCFDevice, szDiskFile);
		}
		else
		{
			nDosLinkCreated = FakeDosNameForDevice (szDiskFile, szDosDevice, szCFDevice, FALSE);
			if (nDosLinkCreated != 0)
			{
				return nDosLinkCreated;
			}
		}

		dev = CreateFile (szCFDevice, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
	}
	else
	{
		write = (diskio_f) win9x_io;
		read = (diskio_f) win9x_io;

		if (OpenDevice (lpszVolume, &driver) == FALSE)
		{
			return ERR_OS_ERROR;
		}
		else if (driver.secstart == driver.seclast)
		{
			return ERR_ACCESS_DENIED;
		}

		win9x_r0.devicenum = driver.device;
		win9x_r0.sectorstart = driver.secstart;

		dev = &win9x_r0;
	}

	if (dev == INVALID_HANDLE_VALUE)
	{
		return ERR_OS_ERROR;
	}


	WaitCursor ();

	win9x_r0.mode = 0;

	/* Read in volume */
	nStatus = (*read) ((HFILE) dev, buffer, sizeof (buffer));
	if (nStatus != sizeof (buffer))
	{
		nStatus = ERR_VOL_SIZE_WRONG;
		goto error;
	}

	memcpy (boot, buffer, SECTOR_SIZE);

	/* Parse header */
	nStatus = VolumeReadHeader (buffer, lpszOldPassword, &cryptoInfo);
	if (nStatus != 0)
	{
		cryptoInfo = NULL;
		goto error;
	}

	/* Change password now */ 

	if (dev != &win9x_r0)
	{
		nStatus = _llseek ((HFILE) dev, 0, FILE_BEGIN);

		if (nStatus != 0)
		{
			nStatus = ERR_VOL_SEEKING;
			goto error;
		}
	}

	win9x_r0.mode = 1;
	win9x_r0.sectorstart -= 1;

	VolumeWriteHeader (boot,
		cryptoInfo->cipher,
		lpszPassword,
		cryptoInfo->pkcs5,
		cryptoInfo->master_decrypted_key,
		cryptoInfo->volume_creation_time,
		&ci);

	crypto_close (ci);

	/* Write out new encrypted key + key check */
	nStatus = (*write) ((HFILE) dev, boot, SECTOR_SIZE);

	if (nStatus != SECTOR_SIZE)
	{
		nStatus = ERR_VOL_WRITING;
		goto error;
	}

	/* That's it done... */
	nStatus = 0;

      error:

	burn (buffer, sizeof (buffer));

	if (cryptoInfo != NULL)
		crypto_close (cryptoInfo);

	dwError = GetLastError ();

	if (dev != &win9x_r0)
	{
		CloseHandle ((HANDLE) dev);

		if (bDevice == TRUE && nDosLinkCreated != 0)
		{
			int x = RemoveFakeDosName (szDiskFile, szDosDevice);
			if (x != 0)
			{
				dwError = GetLastError ();
				nStatus = x;
			}
		}
	}

	SetLastError (dwError);

	NormalCursor ();

	return nStatus;
}
