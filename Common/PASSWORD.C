/* The source code contained in this file has been derived from the source code
   of Encryption for the Masses 2.02a by Paul Le Roux. Modifications and
   additions to that source code contained in this file are Copyright (c) 2004
   TrueCrypt Foundation and Copyright (c) 2004 TrueCrypt Team. Unmodified
   parts are Copyright (c) 1998-99 Paul Le Roux. This is a TrueCrypt Foundation
   release. Please see the file license.txt for full license details. */

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
#include "resource.h"

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
ChangePwd (char *lpszVolume, char *lpszOldPassword, char *lpszPassword, int pkcs5, HWND hwndDlg)
{
	int nDosLinkCreated = 0, nStatus;
	char szDiskFile[TC_MAX_PATH], szCFDevice[TC_MAX_PATH];
	char szDosDevice[TC_MAX_PATH];
	char buffer[HEADER_SIZE], bufferHiddenVolume[HEADER_SIZE];
	PCRYPTO_INFO cryptoInfo = NULL, ci = NULL;
	void *dev = INVALID_HANDLE_VALUE;
	OPEN_TEST_STRUCT driver;
	diskio_f write, read;
	DWORD dwError;
	BOOL bDevice;
	unsigned __int64 volSize = 0;
	FILETIME ftCreationTime;
	FILETIME ftLastWriteTime;
	FILETIME ftLastAccessTime;
	BOOL bTimeStampValid = FALSE;
	
	if (Randinit ()) return 1;

	CreateFullVolumePath (szDiskFile, lpszVolume, &bDevice);

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

	dev = CreateFile (szCFDevice, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);

	if (bDevice == TRUE)
	{
		/* necessary to determine the hidden volume header offset */

		if (dev == INVALID_HANDLE_VALUE)
		{
			return ERR_OS_ERROR;
		}
		else
		{
			DISK_GEOMETRY driveInfo;
			DWORD dwResult;
			int nStatus;
			BOOL bResult;

			bResult = DeviceIoControl (dev, IOCTL_DISK_GET_DRIVE_GEOMETRY, NULL, 0,
				&driveInfo, sizeof (driveInfo), &dwResult, NULL);

			if (driveInfo.MediaType == FixedMedia)
			{
				PARTITION_INFORMATION diskInfo;

				bResult = DeviceIoControl (dev, IOCTL_DISK_GET_PARTITION_INFO, NULL, 0,
					&diskInfo, sizeof (diskInfo), &dwResult, NULL);

				if (bResult == TRUE)
				{
					volSize = diskInfo.PartitionLength.QuadPart;

					if (volSize == 0)
					{
						CloseHandle (dev);
						return ERR_VOL_SIZE_WRONG;
					}
				}
				else
				{
					CloseHandle (dev);
					return ERR_OS_ERROR;
				}
			}
			else
			{
				volSize = driveInfo.Cylinders.QuadPart * driveInfo.BytesPerSector *
					driveInfo.SectorsPerTrack * driveInfo.TracksPerCylinder;
			}
		}
	}

	if (dev == INVALID_HANDLE_VALUE) return ERR_OS_ERROR;

	WaitCursor ();

	if (!bDevice)
	{
		/* Remember the container modification/creation date and time, (used to reset file date and time of
		file-hosted containers after password change (or attempt to), in order preserve plausible deniability
		of hidden volumes (last password change time is stored in the volume header). */

		if (GetFileTime ((HANDLE) dev, &ftCreationTime, &ftLastAccessTime, &ftLastWriteTime) == 0)
		{
			bTimeStampValid = FALSE;
			MessageBox (hwndDlg, getstr (IDS_GETFILETIME_FAILED_PW), "TrueCrypt", MB_OK | MB_ICONEXCLAMATION);
		}
		else
			bTimeStampValid = TRUE;
	}

	/* Read in volume header */

	nStatus = (*read) ((HFILE) dev, buffer, sizeof (buffer));
	if (nStatus != sizeof (buffer))
	{
		nStatus = ERR_VOL_SIZE_WRONG;
		goto error;
	}


	/* Read in possible hidden volume header */

	if (!SeekHiddenVolHeader ((HFILE) dev, volSize, bDevice))
		return ERR_VOL_SEEKING;

	nStatus = (*read) ((HFILE) dev, bufferHiddenVolume, sizeof (bufferHiddenVolume));
	if (nStatus != sizeof (bufferHiddenVolume))
	{
		nStatus = ERR_VOL_SIZE_WRONG;
		goto error;
	}


	/* Try to decrypt either of the headers */

	nStatus = VolumeReadHeader (buffer, bufferHiddenVolume, lpszOldPassword, &cryptoInfo);
	if (nStatus != 0)
	{
		cryptoInfo = NULL;
		goto error;
	}

	/* Change password now */ 

	if (cryptoInfo->hiddenVolume)
	{
		if (!SeekHiddenVolHeader ((HFILE) dev, volSize, bDevice))
			return ERR_VOL_SEEKING;
	}
	else
	{
		nStatus = _llseek ((HFILE) dev, 0, FILE_BEGIN);

		if (nStatus != 0)
		{
			nStatus = ERR_VOL_SEEKING;
			goto error;
		}
	}

	// Change PRF if requested by user
	if (pkcs5 != 0)
		cryptoInfo->pkcs5 = pkcs5;

	VolumeWriteHeader (cryptoInfo->hiddenVolume ? buffer : bufferHiddenVolume,
		cryptoInfo->ea,
		lpszPassword,
		cryptoInfo->pkcs5,
		cryptoInfo->master_decrypted_key,
		cryptoInfo->volume_creation_time,
		&ci,
		cryptoInfo->hiddenVolume ? cryptoInfo->hiddenVolumeSize : 0);

	crypto_close (ci);

	/* Write out new encrypted key + key check */

	nStatus = (*write) ((HFILE) dev, cryptoInfo->hiddenVolume ? buffer : bufferHiddenVolume, HEADER_SIZE);

	if (nStatus != HEADER_SIZE)
	{
		nStatus = ERR_VOL_WRITING;
		goto error;
	}

	/* That's it done... */

	nStatus = 0;

      error:

	burn (buffer, sizeof (buffer));
	burn (bufferHiddenVolume, sizeof (bufferHiddenVolume));

	if (cryptoInfo != NULL)
		crypto_close (cryptoInfo);

	dwError = GetLastError ();

	if (bTimeStampValid)
	{
		// Restore the container timestamp (to preserve plausible deniability of possible hidden volume). 
		if (SetFileTime (dev, &ftCreationTime, &ftLastAccessTime, &ftLastWriteTime) == 0)
			MessageBox (hwndDlg, getstr (IDS_SETFILETIME_FAILED_PW), "TrueCrypt", MB_OK | MB_ICONEXCLAMATION);
	}

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

	SetLastError (dwError);

	NormalCursor ();

	return nStatus;
}

