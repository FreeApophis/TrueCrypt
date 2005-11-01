/* Legal Notice: The source code contained in this file has been derived from
   the source code of Encryption for the Masses 2.02a, which is Copyright (c)
   1998-99 Paul Le Roux and which is covered by the 'License Agreement for
   Encryption for the Masses'. Modifications and additions to that source code
   contained in this file are Copyright (c) 2004-2005 TrueCrypt Foundation and
   Copyright (c) 2004 TrueCrypt Team, and are covered by TrueCrypt License 2.0
   the full text of which is contained in the file License.txt included in
   TrueCrypt binary and source code distribution archives.  */

#include "Tcdefs.h"

#include "Crypto.h"
#include "Fat.h"
#include "Format.h"
#include "Volumes.h"
#include "Password.h"
#include "Apidrvr.h"
#include "Dlgcode.h"
#include "Language.h"
#include "Pkcs5.h"
#include "Endian.h"
#include "Resource.h"
#include "Random.h"

#include <io.h>

void
VerifyPasswordAndUpdate (HWND hwndDlg, HWND hButton, HWND hPassword,
			 HWND hVerify, char *szPassword,
			 char *szVerify,
			 BOOL keyFilesEnabled)
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
		if (k >= MIN_PASSWORD || keyFilesEnabled)
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


BOOL CheckPasswordCharEncoding (HWND hPassword, Password *ptrPw)
{
	char szTmp[MAX_PASSWORD + 1];
	unsigned char *pw;
	int i;
	int len;
	
	if (hPassword == NULL)
	{
		len = ptrPw->Length;
		pw = (unsigned char *) ptrPw->Text;
	}
	else
	{
		len = GetWindowTextLength (hPassword);
		GetWindowText (hPassword, szTmp, sizeof (szTmp));
		pw = (unsigned char *) szTmp;
	}

	for (i = 0; i < len; i++)
	{
		if (pw[i] >= 0x7f || pw[i] < 0x20)	// A non-ASCII or non-printable character?
			return FALSE;
	}
	return TRUE;
}


BOOL CheckPasswordLength (HWND hwndDlg, HWND hwndItem)
{
	if (GetWindowTextLength (hwndItem) < PASSWORD_LEN_WARNING)
	{
		if (MessageBoxW (hwndDlg, GetString ("PASSWORD_LENGTH_WARNING"), lpszTitle, MB_YESNO|MB_ICONWARNING|MB_DEFBUTTON2) != IDYES)
			return FALSE;
	}
	return TRUE;
}

int
ChangePwd (char *lpszVolume, Password *oldPassword, Password *newPassword, int pkcs5, HWND hwndDlg)
{
	int nDosLinkCreated = 0, nStatus;
	char szDiskFile[TC_MAX_PATH], szCFDevice[TC_MAX_PATH];
	char szDosDevice[TC_MAX_PATH];
	char buffer[HEADER_SIZE];
	PCRYPTO_INFO cryptoInfo = NULL, ci = NULL;
	void *dev = INVALID_HANDLE_VALUE;
	diskio_f write, read;
	DWORD dwError;
	BOOL bDevice;
	unsigned __int64 volSize = 0;
	int volumeType;
	int wipePass;
	FILETIME ftCreationTime;
	FILETIME ftLastWriteTime;
	FILETIME ftLastAccessTime;
	BOOL bTimeStampValid = FALSE;
	
	if (oldPassword->Length == 0 || newPassword->Length == 0) return -1;

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

	if (bDevice)
	{
		/* This is necessary to determine the hidden volume header offset */

		if (dev == INVALID_HANDLE_VALUE)
		{
			return ERR_OS_ERROR;
		}
		else
		{
			PARTITION_INFORMATION diskInfo;
			DWORD dwResult;
			BOOL bResult;

			bResult = DeviceIoControl (dev, IOCTL_DISK_GET_PARTITION_INFO, NULL, 0,
				&diskInfo, sizeof (diskInfo), &dwResult, NULL);

			if (bResult)
			{
				volSize = diskInfo.PartitionLength.QuadPart;
			}
			else
			{
				DISK_GEOMETRY driveInfo;

				bResult = DeviceIoControl (dev, IOCTL_DISK_GET_DRIVE_GEOMETRY, NULL, 0,
					&driveInfo, sizeof (driveInfo), &dwResult, NULL);

				if (!bResult)
				{
					CloseHandle (dev);
					return ERR_OS_ERROR;
				}

				volSize = driveInfo.Cylinders.QuadPart * driveInfo.BytesPerSector *
					driveInfo.SectorsPerTrack * driveInfo.TracksPerCylinder;
			}

			if (volSize == 0)
			{
				CloseHandle (dev);
				return ERR_VOL_SIZE_WRONG;
			}
		}
	}

	if (dev == INVALID_HANDLE_VALUE) 
		return ERR_OS_ERROR;

	WaitCursor ();

	if (Randinit ())
		return -1;

	if (!bDevice && bPreserveTimestamp)
	{
		/* Remember the container modification/creation date and time, (used to reset file date and time of
		file-hosted volumes after password change (or attempt to), in order to preserve plausible deniability
		of hidden volumes (last password change time is stored in the volume header). */

		if (GetFileTime ((HANDLE) dev, &ftCreationTime, &ftLastAccessTime, &ftLastWriteTime) == 0)
		{
			bTimeStampValid = FALSE;
			MessageBoxW (hwndDlg, GetString ("GETFILETIME_FAILED_PW"), L"TrueCrypt", MB_OK | MB_ICONEXCLAMATION);
		}
		else
			bTimeStampValid = TRUE;
	}

	for (volumeType = VOLUME_TYPE_NORMAL; volumeType < NBR_VOLUME_TYPES; volumeType++)
	{

		/* Read in volume header */

		if (volumeType == VOLUME_TYPE_HIDDEN)
		{
			if (!SeekHiddenVolHeader ((HFILE) dev, volSize, bDevice))
			{
				nStatus = ERR_VOL_SEEKING;
				goto error;
			}
		}

		nStatus = (*read) ((HFILE) dev, buffer, sizeof (buffer));
		if (nStatus != sizeof (buffer))
		{
			nStatus = ERR_VOL_SIZE_WRONG;
			goto error;
		}

		/* Try to decrypt the header */

		nStatus = VolumeReadHeader (buffer, oldPassword, &cryptoInfo);
		if (nStatus == ERR_CIPHER_INIT_WEAK_KEY)
			nStatus = 0;	// We can ignore this error here

		if (nStatus == ERR_PASSWORD_WRONG)
		{
			continue;		// Try next volume type
		}
		else if (nStatus != 0)
		{
			cryptoInfo = NULL;
			goto error;
		}
		else 
			break;
	}

	if (nStatus != 0)
	{
		cryptoInfo = NULL;
		goto error;
	}

	// Change the PKCS-5 PRF if requested by user
	if (pkcs5 != 0)
		cryptoInfo->pkcs5 = pkcs5;


	/* Re-encrypt the volume header */ 

	/* The header will be re-encrypted DISK_WIPE_PASSES times to prevent adversaries from using 
	   techniques such as magnetic force microscopy or magnetic force scanning tunnelling microscopy
	   to recover the overwritten header. According to Peter Gutmann, data should be overwritten 22
	   times (ideally, 35 times). As users might impatiently interupt the process (e.g. on slow media)
	   we will not wipe with just random data. Instead, during each pass we will write a valid working
	   header. Each pass will use the same master key, and also the same header key, IV, etc. derived
	   from the new password. The only item that will be different for each pass will be the salt.
	   This is sufficient to cause each "version" of the header to differ substantially and in a
	   random manner from the versions written during the other passes. */
	for (wipePass = 0; wipePass < DISK_WIPE_PASSES; wipePass++)
	{
		// Seek the volume header
		if (volumeType == VOLUME_TYPE_HIDDEN)
		{
			if (!SeekHiddenVolHeader ((HFILE) dev, volSize, bDevice))
			{
				nStatus = ERR_VOL_SEEKING;
				goto error;
			}
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

		// Prepare new volume header
		nStatus = VolumeWriteHeader (buffer,
			cryptoInfo->ea,
			newPassword,
			cryptoInfo->pkcs5,
			cryptoInfo->master_key,
			cryptoInfo->volume_creation_time,
			&ci,
			volumeType == VOLUME_TYPE_HIDDEN ? cryptoInfo->hiddenVolumeSize : 0,
			wipePass < DISK_WIPE_PASSES - 1);

		if (ci != NULL)
			crypto_close (ci);

		if (nStatus != 0)
			goto error;

		// Write the new header 
		nStatus = (*write) ((HFILE) dev, buffer, HEADER_SIZE);
		if (nStatus != HEADER_SIZE)
		{
			nStatus = ERR_VOL_WRITING;
			goto error;
		}
		FlushFileBuffers (dev);
	}

	/* Password successfully changed */
	nStatus = 0;

error:
	burn (buffer, sizeof (buffer));

	if (cryptoInfo != NULL)
		crypto_close (cryptoInfo);

	dwError = GetLastError ();

	if (bTimeStampValid)
	{
		// Restore the container timestamp (to preserve plausible deniability of possible hidden volume). 
		if (SetFileTime (dev, &ftCreationTime, &ftLastAccessTime, &ftLastWriteTime) == 0)
			MessageBoxW (hwndDlg, GetString ("SETFILETIME_FAILED_PW"), L"TrueCrypt", MB_OK | MB_ICONEXCLAMATION);
	}

	CloseHandle ((HANDLE) dev);

	if (bDevice && nDosLinkCreated != 0)
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

	Randfree ();

	return nStatus;
}

