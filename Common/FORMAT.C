/*
 Legal Notice: The source code contained in this file has been derived from
 the source code of Encryption for the Masses 2.02a, which is Copyright (c)
 Paul Le Roux and which is covered by the 'License Agreement for Encryption
 for the Masses'. Modifications and additions to that source code contained
 in this file are Copyright (c) TrueCrypt Foundation and are covered by the
 TrueCrypt License 2.2 the full text of which is contained in the file
 License.txt included in TrueCrypt binary and source code distribution
 packages. */

#include <stdlib.h>
#include <string.h>

#include "Tcdefs.h"

#include "Common.h"
#include "Crypto.h"
#include "Fat.h"
#include "Format.h"
#include "Random.h"
#include "Volumes.h"

#ifdef _WIN32
#include "Apidrvr.h"
#include "Dlgcode.h"
#include "Language.h"
#include "Progress.h"
#include "Resource.h"
#include "../Format/FormatCom.h"

int
FormatVolume (char *volumePath,
	      BOOL bDevice,
	      unsigned __int64 size,
		  unsigned __int64 hiddenVolHostSize,
	      Password *password,
	      int ea,
	      int pkcs5,
		  BOOL quickFormat,
		  BOOL sparseFileSwitch,
		  int fileSystem,
		  int clusterSize,
	      HWND hwndDlg,
		  BOOL hiddenVol,
		  int *realClusterSize,
		  BOOL uac)
{
	int nStatus;
	PCRYPTO_INFO cryptoInfo;
	HANDLE dev = INVALID_HANDLE_VALUE;
	DWORD dwError;
	char header[HEADER_SIZE];
	unsigned __int64 num_sectors, startSector;
	fatparams ft;
	FILETIME ftCreationTime;
	FILETIME ftLastWriteTime;
	FILETIME ftLastAccessTime;
	BOOL bTimeStampValid = FALSE;
	char dosDev[TC_MAX_PATH] = { 0 };
	char devName[MAX_PATH] = { 0 };
	int driveLetter = -1;
	WCHAR deviceName[MAX_PATH];

	if (!hiddenVol)
		size -= HEADER_SIZE;	

	num_sectors = size / SECTOR_SIZE;

	if (bDevice)
	{
		strcpy ((char *)deviceName, volumePath);
		ToUNICODE ((char *)deviceName);

		driveLetter = GetDiskDeviceDriveLetter (deviceName);
	}

	VirtualLock (header, sizeof (header));

	/* Copies any header structures into header, but does not do any
	   disk io */
	nStatus = VolumeWriteHeader (header,
				     ea,
					 LRW, // The only supported mode of operation when creating new volumes
				     password,
				     pkcs5,
					 0,
					 0,
				     &cryptoInfo,
					 hiddenVol ? size : 0,
					 FALSE);

	if (nStatus != 0)
	{
		burn (header, sizeof (header));
		VirtualUnlock (header, sizeof (header));
		return nStatus;
	}

	if (bDevice)
	{
		/* Device-hosted volume */
		int nPass;

		if (FakeDosNameForDevice (volumePath, dosDev, devName, FALSE) != 0)
		{
			handleWin32Error (hwndDlg);
			return ERR_DONT_REPORT;
		}

		if (IsDeviceMounted (devName))
		{
			if ((dev = DismountDrive (devName)) == INVALID_HANDLE_VALUE)
			{
				if (driveLetter > 2) // If a drive letter is assigned to the device, but not A:, B:, or C:
				{
					char rootPath[] = { driveLetter + 'A', ':', '\\', 0 };

					// Remove the assigned drive letter so that dismount will have a higher chance of success 
					if (!DeleteVolumeMountPoint (rootPath))
					{
						// Drive letter could not be removed
						Error ("FORMAT_CANT_DISMOUNT_FILESYS");
						nStatus = ERR_DONT_REPORT; 
						goto error;
					}
					else
					{
						// Drive letter successfully removed, retry dismount
						driveLetter = -1;

						if ((dev = DismountDrive (devName)) == INVALID_HANDLE_VALUE)
						{
							Error ("FORMAT_CANT_DISMOUNT_FILESYS_W_DRIVE_LETTER");
							nStatus = ERR_DONT_REPORT; 
							goto error;
						}
					}
				}
				else
				{
					Error ("FORMAT_CANT_DISMOUNT_FILESYS");
					nStatus = ERR_DONT_REPORT; 
					goto error;
				}
			}
		}
		else if (nCurrentOS == WIN_VISTA_OR_LATER && driveLetter == -1)
		{
			// Windows Vista doesn't allow overwriting sectors belonging to an unformatted partition 
			// to which no drive letter has been assigned under the system. This problem can be worked
			// around by assigning a drive letter to the partition temporarily.

			char szDriveLetter[] = { 'A', ':', 0 };
			char rootPath[] = { 'A', ':', '\\', 0 };
			char uniqVolName[MAX_PATH+1] = { 0 };
			int tmpDriveLetter = -1;
			BOOL bResult = FALSE;

			tmpDriveLetter = GetFirstAvailableDrive ();
 
			if (tmpDriveLetter != -1)
			{
				rootPath[0] += tmpDriveLetter;
				szDriveLetter[0] += tmpDriveLetter;

				if (DefineDosDevice (DDD_RAW_TARGET_PATH, szDriveLetter, volumePath))
				{
					bResult = GetVolumeNameForVolumeMountPoint (rootPath, uniqVolName, MAX_PATH);

					DefineDosDevice (DDD_RAW_TARGET_PATH|DDD_REMOVE_DEFINITION|DDD_EXACT_MATCH_ON_REMOVE,
						szDriveLetter,
						volumePath);

					if (bResult 
						&& SetVolumeMountPoint (rootPath, uniqVolName))
					{
						// The drive letter can be removed immediately
						DeleteVolumeMountPoint (rootPath);
					}
				}
			}
		}


		// Perform open - 'quick format' - close - open to prevent Windows from restoring NTFS boot sector backup
		for (nPass = 0; nPass < 2; nPass++)
		{
			// Try exclusive access mode first
			if (dev == INVALID_HANDLE_VALUE)
				dev = CreateFile (devName, GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);

			if (dev == INVALID_HANDLE_VALUE)
			{
				// Retry in shared mode
				dev = CreateFile (devName, GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
				if (dev != INVALID_HANDLE_VALUE)
				{
					DWORD dwResult;

					if (IDNO == MessageBoxW (hwndDlg, GetString ("DEVICE_IN_USE_FORMAT"), lpszTitle, MB_YESNO|MB_ICONWARNING|MB_DEFBUTTON2))
					{
						CloseHandle (dev);
						dev = INVALID_HANDLE_VALUE;
						nStatus = ERR_DONT_REPORT; 
						goto error;
					}

					DeviceIoControl (dev, FSCTL_DISMOUNT_VOLUME, NULL, 0, NULL, 0, &dwResult, NULL);
				}
				else
				{
					handleWin32Error (hwndDlg);
					nStatus = ERR_DONT_REPORT; 
					goto error;
				}
			}

			if (hiddenVol)
				break;	// The following "quick format" operation would damage the outer volume

			if (nPass == 0)
			{
				char buf[65536];
				DWORD bw;

				// Pseudo "quick format" to prevent Windows from restoring NTFS boot sector backup
				memset (buf, 0, sizeof (buf));
				WriteFile (dev, buf, sizeof (buf), &bw, NULL);
				FlushFileBuffers (dev);
				CloseHandle (dev);
				dev = INVALID_HANDLE_VALUE;
			}
		}
	}
	else
	{
		/* File-hosted volume */

		// We could support FILE_ATTRIBUTE_HIDDEN as an option
		// (Now if the container has hidden or system file attribute, the OS will not allow
		// overwritting it; so the user will have to delete it manually).
		dev = CreateFile (volumePath, GENERIC_WRITE,
			hiddenVol ? (FILE_SHARE_READ | FILE_SHARE_WRITE) : 0,
			NULL, hiddenVol ? OPEN_EXISTING : CREATE_ALWAYS, 0, NULL);

		if (dev == INVALID_HANDLE_VALUE)
		{
			handleWin32Error (hwndDlg);
			nStatus = ERR_DONT_REPORT; 
			goto error;
		}

		if (!hiddenVol)
		{
			LARGE_INTEGER volumeSize;
			volumeSize.QuadPart = size + HEADER_SIZE;

			if (sparseFileSwitch && quickFormat)
			{
				// Create as sparse file container
				DWORD tmp;
				if (!DeviceIoControl (dev, FSCTL_SET_SPARSE, NULL, 0, NULL, 0, &tmp, NULL))
				{
					handleWin32Error (hwndDlg);
					nStatus = ERR_DONT_REPORT; 
					goto error;
				}
			}

			// Preallocate the file
			if (!SetFilePointerEx (dev, volumeSize, NULL, FILE_BEGIN)
				|| !SetEndOfFile (dev)
				|| SetFilePointer (dev, 0, NULL, FILE_BEGIN) != 0)
			{
				handleWin32Error (hwndDlg);
				nStatus = ERR_DONT_REPORT;
				goto error;
			}
		}
	}

	if (hiddenVol && !bDevice && bPreserveTimestamp)
	{
		/* Remember the container timestamp (used to reset file date and time of file-hosted
		containers to preserve plausible deniability of hidden volume)  */
		if (GetFileTime ((HANDLE) dev, &ftCreationTime, &ftLastAccessTime, &ftLastWriteTime) == 0)
		{
			bTimeStampValid = FALSE;
			MessageBoxW (hwndDlg, GetString ("GETFILETIME_FAILED_IMPLANT"), lpszTitle, MB_OK | MB_ICONEXCLAMATION);
		}
		else
			bTimeStampValid = TRUE;
	}

	KillTimer (hwndDlg, 0xff);

	/* Volume header */

	// Hidden volume setup
	if (hiddenVol)
	{
		// Check hidden volume size
		if (hiddenVolHostSize < MIN_HIDDEN_VOLUME_HOST_SIZE || hiddenVolHostSize > MAX_HIDDEN_VOLUME_HOST_SIZE)
		{		
			nStatus = ERR_VOL_SIZE_WRONG;
			goto error;
		}

		// Seek to hidden volume header location
		if (!SeekHiddenVolHeader ((HFILE) dev, hiddenVolHostSize, bDevice))
		{
			nStatus = ERR_VOL_SEEKING;
			goto error;
		}

	}

	// Write the volume header
	if (_lwrite ((HFILE) dev, header, HEADER_SIZE) == HFILE_ERROR)
	{
		handleWin32Error (hwndDlg);
		nStatus = ERR_DONT_REPORT;
		goto error;
	}

	/* Data area */

	startSector = HEADER_SIZE / SECTOR_SIZE;	// Data area of normal volume starts right after volume header

	if (hiddenVol)
	{
		// Calculate data area position of hidden volume
		unsigned __int64 startOffset = hiddenVolHostSize - size - HIDDEN_VOL_HEADER_OFFSET;
		cryptoInfo->hiddenVolumeOffset = startOffset;

		// Validate the offset
		if (startOffset % SECTOR_SIZE != 0)
		{
			nStatus = ERR_VOL_SIZE_WRONG; 
			goto error;
		}

		startSector = startOffset / SECTOR_SIZE;	
		quickFormat = TRUE;		// To entirely format a hidden volume would be redundant
	}

	// Format filesystem

	switch (fileSystem)
	{
	case FILESYS_NONE:
	case FILESYS_NTFS:
		nStatus = FormatNoFs (startSector, num_sectors, dev, cryptoInfo, quickFormat);
		break;
		
	case FILESYS_FAT:
		if (num_sectors > 0xFFFFffff)
		{
			nStatus = ERR_VOL_SIZE_WRONG; 
			goto error;
		}

		// Calculate the fats, root dir etc
		ft.num_sectors = (unsigned int) (num_sectors);
		ft.cluster_size = clusterSize;
		memcpy (ft.volume_name, "NO NAME    ", 11);
		GetFatParams (&ft); 
		*realClusterSize = ft.cluster_size * SECTOR_SIZE;

		nStatus = FormatFat (startSector, &ft, (void *) dev, cryptoInfo, quickFormat);
		break;
	}

	if (bDevice && nStatus == 0 
		&& driveLetter > 1)		// If a drive letter is assigned to the device, but not A: or B:
	{
		char rootPath[] = { driveLetter + 'A', ':', '\\', 0 };

		// The device has been successfully formatted so we should remove its original drive letter (inexperienced 
		// users often attempt to double click the original drive letter and due to the Windows format prompt
		// they sometimes format the volume, which disables encryption without them realizing it).
		DeleteVolumeMountPoint (rootPath);
	}

error:
	dwError = GetLastError();

	burn (header, sizeof (header));
	VirtualUnlock (header, sizeof (header));

	crypto_close (cryptoInfo);

	if (bTimeStampValid)
	{
		// Restore the container timestamp (to preserve plausible deniability of the hidden volume) 
		if (SetFileTime (dev, &ftCreationTime, &ftLastAccessTime, &ftLastWriteTime) == 0)
			MessageBoxW (hwndDlg, GetString ("SETFILETIME_FAILED_IMPLANT"), lpszTitle, MB_OK | MB_ICONEXCLAMATION);
	}

	if (!bDevice && !hiddenVol && nStatus != 0)
	{
		// Remove preallocated part before closing file handle if format failed
		if (SetFilePointer (dev, 0, NULL, FILE_BEGIN) == 0)
			SetEndOfFile (dev);
	}

	CloseHandle (dev);
	dev = INVALID_HANDLE_VALUE;

	if (dosDev[0])
		RemoveFakeDosName (volumePath, dosDev);

	if (nStatus != 0)
	{
		SetLastError(dwError);
		return nStatus;
	}

	if (fileSystem == FILESYS_NTFS)
	{
		// Quick-format volume as NTFS
		int driveNo = GetLastAvailableDrive ();
		MountOptions mountOptions;
		int retCode;

		ZeroMemory (&mountOptions, sizeof (mountOptions));

		if (driveNo == -1)
		{
			MessageBoxW (hwndDlg, GetString ("NO_FREE_DRIVES"), lpszTitle, ICON_HAND);
			MessageBoxW (hwndDlg, GetString ("FORMAT_NTFS_STOP"), lpszTitle, ICON_HAND);

			return ERR_NO_FREE_DRIVES;
		}

		mountOptions.ReadOnly = FALSE;
		mountOptions.Removable = FALSE;
		mountOptions.ProtectHiddenVolume = FALSE;
		mountOptions.PreserveTimestamp = bPreserveTimestamp;

		if (MountVolume (hwndDlg, driveNo, volumePath, password, FALSE, TRUE, &mountOptions, FALSE, TRUE) < 1)
		{
			MessageBoxW (hwndDlg, GetString ("CANT_MOUNT_VOLUME"), lpszTitle, ICON_HAND);
			MessageBoxW (hwndDlg, GetString ("FORMAT_NTFS_STOP"), lpszTitle, ICON_HAND);
			return ERR_VOL_MOUNT_FAILED;
		}

		if (!IsAdmin () && IsUacSupported ())
			retCode = UacFormatNtfs (hwndDlg, driveNo, clusterSize);
		else
			retCode = FormatNtfs (driveNo, clusterSize);

		if (retCode != TRUE)
		{
			if (!UnmountVolume (hwndDlg, driveNo, FALSE))
				MessageBoxW (hwndDlg, GetString ("CANT_DISMOUNT_VOLUME"), lpszTitle, ICON_HAND);

			Error ("FORMAT_NTFS_FAILED");
			return ERR_DONT_REPORT;
		}

		if (!UnmountVolume (hwndDlg, driveNo, FALSE))
			MessageBoxW (hwndDlg, GetString ("CANT_DISMOUNT_VOLUME"), lpszTitle, ICON_HAND);
	}

	return nStatus;
}

#endif

int FormatNoFs (unsigned __int64 startSector, __int64 num_sectors, void * dev, PCRYPTO_INFO cryptoInfo, BOOL quickFormat)
{
	int write_buf_cnt = 0;
	char sector[SECTOR_SIZE], *write_buf;
	unsigned __int64 nSecNo = startSector;
	int retVal;
	char temporaryKey[DISKKEY_SIZE];

#ifdef _WIN32
	LARGE_INTEGER startOffset;
	LARGE_INTEGER newOffset;

	// Seek to start sector
	startOffset.QuadPart = startSector * SECTOR_SIZE;
	if (!SetFilePointerEx ((HANDLE) dev, startOffset, &newOffset, FILE_BEGIN)
		|| newOffset.QuadPart != startOffset.QuadPart)
	{
		return ERR_VOL_SEEKING;
	}
#endif

	write_buf = (char *) TCalloc (WRITE_BUF_SIZE);
	memset (sector, 0, sizeof (sector));

	/* Fill the rest of the data area with random data */

	if(!quickFormat)
	{
		/* Generate a random temporary key set to be used for "dummy" encryption that will fill
		the free disk space (data area) with random data.  This is necessary for plausible
		deniability of hidden volumes (and also reduces the amount of predictable plaintext
		within the volume). */

		// Temporary master key
		if (!RandgetBytes (temporaryKey, EAGetKeySize (cryptoInfo->ea), FALSE))
			goto fail;
		// Secondary key (LRW mode)
		if (!RandgetBytes (cryptoInfo->iv, sizeof cryptoInfo->iv, FALSE))
			goto fail;

		retVal = EAInit (cryptoInfo->ea, temporaryKey, cryptoInfo->ks);
		if (retVal != 0)
		{
			burn (temporaryKey, sizeof(temporaryKey));
			return retVal;
		}
		if (!EAInitMode (cryptoInfo))
		{
			burn (temporaryKey, sizeof(temporaryKey));
			return ERR_MODE_INIT_FAILED;
		}

		while (num_sectors--)
		{
			/* Generate random plaintext. Note that reused plaintext blocks are not a concern
			here since LRW mode is designed to hide patterns. Furthermore, patterns in plaintext
			do occur commonly on media in the "real world", so it might actually be a fatal
			mistake to try to avoid them completely. */

#if RNG_POOL_SIZE > SECTOR_SIZE
#error RNG_POOL_SIZE > SECTOR_SIZE
#endif

#ifdef _WIN32
			if (!RandpeekBytes (sector, RNG_POOL_SIZE)
				|| !RandpeekBytes (sector + RNG_POOL_SIZE, SECTOR_SIZE - RNG_POOL_SIZE))
				goto fail;
#else
			if ((nSecNo & 0x3fff) == 0)
			{
				if (!RandgetBytes (sector, RNG_POOL_SIZE, FALSE)
					|| !RandgetBytes (sector + RNG_POOL_SIZE, SECTOR_SIZE - RNG_POOL_SIZE, FALSE))
					goto fail;
			}
#endif
			// Encrypt the random plaintext and write it to the disk
			if (WriteSector (dev, sector, write_buf, &write_buf_cnt, &nSecNo,
				cryptoInfo) == FALSE)
				goto fail;
		}
		if (write_buf_cnt != 0 && 
#ifdef _WIN32
			_lwrite ((HFILE)dev, write_buf, write_buf_cnt) == HFILE_ERROR)
#else
			fwrite (write_buf, 1, write_buf_cnt, (FILE *)dev) != (size_t)write_buf_cnt)
#endif
			goto fail;
	}
	else
		nSecNo = num_sectors;

	UpdateProgressBar (nSecNo);

	TCfree (write_buf);
	burn (temporaryKey, sizeof(temporaryKey));
	return 0;

fail:

	TCfree (write_buf);
	burn (temporaryKey, sizeof(temporaryKey));
	return ERR_OS_ERROR;
}

#ifdef _WIN32

volatile BOOLEAN FormatExResult;

BOOLEAN __stdcall FormatExCallback (int command, DWORD subCommand, PVOID parameter)
{
	if (command == FMIFS_DONE)
		FormatExResult = *(BOOLEAN *) parameter;
	return TRUE;
}

BOOL FormatNtfs (int driveNo, int clusterSize)
{
	WCHAR dir[8] = { driveNo + 'A', 0 };
	PFORMATEX FormatEx;
	HMODULE hModule = LoadLibrary ("fmifs.dll");
	int i;

	if (hModule == NULL)
		return FALSE;

	if (!(FormatEx = (void *) GetProcAddress (GetModuleHandle("fmifs.dll"), "FormatEx")))
	{
		FreeLibrary (hModule);
		return FALSE;
	}

	wcscat (dir, L":\\");

	FormatExResult = FALSE;

	// Windows sometimes fail to format a volume (hosted on a removable medium) as NTFS.
	// It often helps to retry several times.
	for (i = 0; i < 10 && FormatExResult != TRUE; i++)
	{
		FormatEx (dir, FMIFS_HARDDISK, L"NTFS", L"", TRUE, clusterSize * 512, FormatExCallback);
	}

	FreeLibrary (hModule);
	return FormatExResult;
}

#endif

BOOL
WriteSector (void *dev, char *sector,
	     char *write_buf, int *write_buf_cnt,
	     __int64 *nSecNo, PCRYPTO_INFO cryptoInfo)
{
	static __int32 updateTime = 0;

	EncryptSectors ((unsigned __int32 *) sector,
		(*nSecNo)++, 1, cryptoInfo);

	memcpy (write_buf + *write_buf_cnt, sector, SECTOR_SIZE);
	(*write_buf_cnt) += SECTOR_SIZE;

	if (*write_buf_cnt == WRITE_BUF_SIZE)
	{
		if (
#ifdef _WIN32
			_lwrite ((HFILE)dev, write_buf, WRITE_BUF_SIZE) == HFILE_ERROR)
#else
			fwrite (write_buf, 1, WRITE_BUF_SIZE, (FILE *)dev) != WRITE_BUF_SIZE)
#endif
			return FALSE;
		else
			*write_buf_cnt = 0;
	}
	
#ifdef _WIN32
	if (GetTickCount () - updateTime > 25)
	{
		if (UpdateProgressBar (*nSecNo))
			return FALSE;

		updateTime = GetTickCount ();
	}
#else
	UpdateProgressBar (*nSecNo);
#endif

	return TRUE;

}
