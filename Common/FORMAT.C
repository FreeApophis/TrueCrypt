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

#include <stdlib.h>
#include <string.h>

#include "Tcdefs.h"

#include "Common.h"
#include "Crypto.h"
#include "Fat.h"
#include "Format.h"
#include "Random.h"
#include "Volumes.h"

#include "Apidrvr.h"
#include "Dlgcode.h"
#include "Language.h"
#include "Progress.h"
#include "Resource.h"
#include "Format/FormatCom.h"
#include "Format/Tcformat.h"


uint64 GetVolumeDataAreaSize (BOOL hiddenVolume, uint64 volumeSize)
{
	uint64 reservedSize;

	if (hiddenVolume)
	{
		// Reserve free space at the end of the host filesystem
		if (volumeSize < TC_VOLUME_SMALL_SIZE_THRESHOLD)
			reservedSize = TC_HIDDEN_VOLUME_HOST_FS_RESERVED_END_AREA_SIZE;
		else
			reservedSize = TC_HIDDEN_VOLUME_HOST_FS_RESERVED_END_AREA_SIZE_HIGH; // Ensure size of a hidden volume larger than TC_VOLUME_SMALL_SIZE_THRESHOLD is a multiple of the maximum supported sector size
	}
	else
	{
		reservedSize = TC_TOTAL_VOLUME_HEADERS_SIZE;
	}

	if (volumeSize < reservedSize)
		return 0;

	return volumeSize - reservedSize;
}


int TCFormatVolume (volatile FORMAT_VOL_PARAMETERS *volParams)
{
	int nStatus;
	PCRYPTO_INFO cryptoInfo = NULL;
	HANDLE dev = INVALID_HANDLE_VALUE;
	DWORD dwError;
	char header[TC_VOLUME_HEADER_EFFECTIVE_SIZE];
	unsigned __int64 num_sectors, startSector;
	fatparams ft;
	FILETIME ftCreationTime;
	FILETIME ftLastWriteTime;
	FILETIME ftLastAccessTime;
	BOOL bTimeStampValid = FALSE;
	BOOL bInstantRetryOtherFilesys = FALSE;
	char dosDev[TC_MAX_PATH] = { 0 };
	char devName[MAX_PATH] = { 0 };
	int driveLetter = -1;
	WCHAR deviceName[MAX_PATH];
	uint64 dataOffset, dataAreaSize;
	LARGE_INTEGER offset;
	BOOL bFailedRequiredDASD = FALSE;


	/* WARNING: Note that if Windows fails to format the volume as NTFS and the volume size is
	less than TC_MAX_FAT_FS_SIZE, the user is asked within this function whether he wants to instantly
	retry FAT format instead (to avoid having to re-create the whole container again). If the user
	answers yes, some of the input parameters are modified, the code below 'begin_format' is re-executed 
	and some destructive operations that were performed during the first attempt must be (and are) skipped. 
	Therefore, whenever adding or modifying any potentially destructive operations below 'begin_format',
	determine whether they (or their portions) need to be skipped during such a second attempt; if so, 
	use the 'bInstantRetryOtherFilesys' flag to skip them. */

	if (volParams->hiddenVol)
	{
		dataOffset = volParams->hiddenVolHostSize - TC_VOLUME_HEADER_GROUP_SIZE - volParams->size;
	}
	else
	{
		if (volParams->size <= TC_TOTAL_VOLUME_HEADERS_SIZE)
			return ERR_VOL_SIZE_WRONG;

		dataOffset = TC_VOLUME_DATA_OFFSET;
	}

	dataAreaSize = GetVolumeDataAreaSize (volParams->hiddenVol, volParams->size);

	num_sectors = dataAreaSize / SECTOR_SIZE;

	if (volParams->bDevice)
	{
		strcpy ((char *)deviceName, volParams->volumePath);
		ToUNICODE ((char *)deviceName);

		driveLetter = GetDiskDeviceDriveLetter (deviceName);
	}

	VirtualLock (header, sizeof (header));

	nStatus = CreateVolumeHeaderInMemory (FALSE,
				     header,
				     volParams->ea,
					 FIRST_MODE_OF_OPERATION_ID,
				     volParams->password,
				     volParams->pkcs5,
					 NULL,
				     &cryptoInfo,
					 dataAreaSize,
					 volParams->hiddenVol ? dataAreaSize : 0,
					 dataOffset,
					 dataAreaSize,
					 0,
					 volParams->headerFlags,
					 FALSE);

	if (nStatus != 0)
	{
		burn (header, sizeof (header));
		VirtualUnlock (header, sizeof (header));
		return nStatus;
	}

begin_format:

	if (volParams->bDevice)
	{
		/* Device-hosted volume */

		DWORD dwResult;
		int nPass;

		if (FakeDosNameForDevice (volParams->volumePath, dosDev, devName, FALSE) != 0)
			return ERR_OS_ERROR;

		if (IsDeviceMounted (devName))
		{
			if ((dev = DismountDrive (devName, volParams->volumePath)) == INVALID_HANDLE_VALUE)
			{
				Error ("FORMAT_CANT_DISMOUNT_FILESYS");
				nStatus = ERR_DONT_REPORT; 
				goto error;
			}

			/* Gain "raw" access to the partition (it contains a live filesystem and the filesystem driver 
			would otherwise prevent us from writing to hidden sectors). */

			if (!DeviceIoControl (dev,
				FSCTL_ALLOW_EXTENDED_DASD_IO,
				NULL,
				0,   
				NULL,
				0,
				&dwResult,
				NULL))
			{
				bFailedRequiredDASD = TRUE;
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

				if (DefineDosDevice (DDD_RAW_TARGET_PATH, szDriveLetter, volParams->volumePath))
				{
					bResult = GetVolumeNameForVolumeMountPoint (rootPath, uniqVolName, MAX_PATH);

					DefineDosDevice (DDD_RAW_TARGET_PATH|DDD_REMOVE_DEFINITION|DDD_EXACT_MATCH_ON_REMOVE,
						szDriveLetter,
						volParams->volumePath);

					if (bResult 
						&& SetVolumeMountPoint (rootPath, uniqVolName))
					{
						// The drive letter can be removed now
						DeleteVolumeMountPoint (rootPath);
					}
				}
			}
		}

		// For extra safety, we will try to gain "raw" access to the partition. Note that this should actually be
		// redundant because if the filesystem was mounted, we already tried to obtain DASD above. If we failed,
		// bFailedRequiredDASD was set to TRUE and therefore we will perform pseudo "quick format" below. However, 
		// for extra safety, in case IsDeviceMounted() failed to detect a live filesystem, we will blindly
		// send FSCTL_ALLOW_EXTENDED_DASD_IO (possibly for a second time) without checking the result.

		DeviceIoControl (dev,
			FSCTL_ALLOW_EXTENDED_DASD_IO,
			NULL,
			0,   
			NULL,
			0,
			&dwResult,
			NULL);


		// If DASD is needed but we failed to obtain it, perform open - 'quick format' - close - open 
		// so that the filesystem driver does not prevent us from formatting hidden sectors.
		for (nPass = (bFailedRequiredDASD ? 0 : 1); nPass < 2; nPass++)
		{
			int retryCount;

			retryCount = 0;

			// Try exclusive access mode first
			// Note that when exclusive access is denied, it is worth retrying (usually succeeds after a few tries).
			while (dev == INVALID_HANDLE_VALUE && retryCount++ < EXCL_ACCESS_MAX_AUTO_RETRIES)
			{
				dev = CreateFile (devName, GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);

				if (retryCount > 1)
					Sleep (EXCL_ACCESS_AUTO_RETRY_DELAY);
			}

			if (dev == INVALID_HANDLE_VALUE)
			{
				// Exclusive access denied -- retry in shared mode
				dev = CreateFile (devName, GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
				if (dev != INVALID_HANDLE_VALUE)
				{
					if (IDNO == MessageBoxW (volParams->hwndDlg, GetString ("DEVICE_IN_USE_FORMAT"), lpszTitle, MB_YESNO|MB_ICONWARNING|MB_DEFBUTTON2))
					{
						nStatus = ERR_DONT_REPORT; 
						goto error;
					}
				}
				else
				{
					handleWin32Error (volParams->hwndDlg);
					Error ("CANT_ACCESS_VOL");
					nStatus = ERR_DONT_REPORT; 
					goto error;
				}
			}

			if (volParams->hiddenVol || bInstantRetryOtherFilesys)
				break;	// The following "quick format" operation would damage the outer volume

			if (nPass == 0)
			{
				char buf [2 * TC_MAX_VOLUME_SECTOR_SIZE];
				DWORD bw;

				// Perform pseudo "quick format" so that the filesystem driver does not prevent us from 
				// formatting hidden sectors
				memset (buf, 0, sizeof (buf));

				if (!WriteFile (dev, buf, sizeof (buf), &bw, NULL))
				{
					nStatus = ERR_OS_ERROR; 
					goto error;
				}

				FlushFileBuffers (dev);
				CloseHandle (dev);
				dev = INVALID_HANDLE_VALUE;
			}
		}

		if (DeviceIoControl (dev, FSCTL_IS_VOLUME_MOUNTED, NULL, 0, NULL, 0, &dwResult, NULL))
		{
			Error ("FORMAT_CANT_DISMOUNT_FILESYS");
			nStatus = ERR_DONT_REPORT; 
			goto error;
		}
	}
	else
	{
		/* File-hosted volume */

		// We could support FILE_ATTRIBUTE_HIDDEN as an option
		// (Now if the container has hidden or system file attribute, the OS will not allow
		// overwritting it; so the user will have to delete it manually).
		dev = CreateFile (volParams->volumePath, GENERIC_WRITE,
			(volParams->hiddenVol || bInstantRetryOtherFilesys) ? (FILE_SHARE_READ | FILE_SHARE_WRITE) : 0,
			NULL, (volParams->hiddenVol || bInstantRetryOtherFilesys) ? OPEN_EXISTING : CREATE_ALWAYS, 0, NULL);

		if (dev == INVALID_HANDLE_VALUE)
		{
			nStatus = ERR_OS_ERROR; 
			goto error;
		}

		if (!volParams->hiddenVol && !bInstantRetryOtherFilesys)
		{
			LARGE_INTEGER volumeSize;
			volumeSize.QuadPart = dataAreaSize + TC_VOLUME_HEADER_GROUP_SIZE;

			if (volParams->sparseFileSwitch && volParams->quickFormat)
			{
				// Create as sparse file container
				DWORD tmp;
				if (!DeviceIoControl (dev, FSCTL_SET_SPARSE, NULL, 0, NULL, 0, &tmp, NULL))
				{
					nStatus = ERR_OS_ERROR; 
					goto error;
				}
			}

			// Preallocate the file
			if (!SetFilePointerEx (dev, volumeSize, NULL, FILE_BEGIN)
				|| !SetEndOfFile (dev)
				|| SetFilePointer (dev, 0, NULL, FILE_BEGIN) != 0)
			{
				nStatus = ERR_OS_ERROR;
				goto error;
			}
		}
	}

	if (volParams->hiddenVol && !volParams->bDevice && bPreserveTimestamp)
	{
		/* Remember the container timestamp (used to reset file date and time of file-hosted
		containers to preserve plausible deniability of hidden volume)  */
		if (GetFileTime ((HANDLE) dev, &ftCreationTime, &ftLastAccessTime, &ftLastWriteTime) == 0)
		{
			bTimeStampValid = FALSE;
			MessageBoxW (volParams->hwndDlg, GetString ("GETFILETIME_FAILED_IMPLANT"), lpszTitle, MB_OK | MB_ICONEXCLAMATION);
		}
		else
			bTimeStampValid = TRUE;
	}

	KillTimer (volParams->hwndDlg, TIMER_ID_RANDVIEW);

	/* Volume header */

	// Hidden volume setup
	if (volParams->hiddenVol)
	{
		LARGE_INTEGER headerOffset;

		// Check hidden volume size
		if (volParams->hiddenVolHostSize < TC_MIN_HIDDEN_VOLUME_HOST_SIZE || volParams->hiddenVolHostSize > TC_MAX_HIDDEN_VOLUME_HOST_SIZE)
		{		
			nStatus = ERR_VOL_SIZE_WRONG;
			goto error;
		}

		// Seek to hidden volume header location
		
		headerOffset.QuadPart = TC_HIDDEN_VOLUME_HEADER_OFFSET;

		if (!SetFilePointerEx ((HANDLE) dev, headerOffset, NULL, FILE_BEGIN))
		{
			nStatus = ERR_OS_ERROR;
			goto error;
		}
	}
	else if (bInstantRetryOtherFilesys)
	{
		// The previous file system format failed and the user wants to try again with a different file system.
		// The volume header had been written successfully so we need to seek to the byte after the header.

		LARGE_INTEGER offset;
		offset.QuadPart = TC_VOLUME_DATA_OFFSET;
		if (!SetFilePointerEx ((HANDLE) dev, offset, NULL, FILE_BEGIN))
		{
			nStatus = ERR_OS_ERROR;
			goto error;
		}
	}

	if (!bInstantRetryOtherFilesys)
	{
		// Write the volume header
		if (_lwrite ((HFILE) dev, header, TC_VOLUME_HEADER_EFFECTIVE_SIZE) == HFILE_ERROR)
		{
			nStatus = ERR_OS_ERROR;
			goto error;
		}

		// To prevent fragmentation, write zeroes to reserved header sectors which are going to be filled with random data
		if (!volParams->hiddenVol)
		{
			byte buf[TC_VOLUME_HEADER_GROUP_SIZE - TC_VOLUME_HEADER_EFFECTIVE_SIZE];
			ZeroMemory (buf, sizeof (buf));
			if (_lwrite ((HFILE) dev, buf, sizeof (buf)) == HFILE_ERROR)
			{
				nStatus = ERR_OS_ERROR;
				goto error;
			}
		}
	}

	if (volParams->hiddenVol)
	{
		// Calculate data area position of hidden volume
		cryptoInfo->hiddenVolumeOffset = dataOffset;

		// Validate the offset
		if (dataOffset % SECTOR_SIZE != 0)
		{
			nStatus = ERR_VOL_SIZE_WRONG; 
			goto error;
		}

		volParams->quickFormat = TRUE;		// To entirely format a hidden volume would be redundant
	}

	/* Data area */
	startSector = dataOffset / SECTOR_SIZE;

	// Format filesystem

	switch (volParams->fileSystem)
	{
	case FILESYS_NONE:
	case FILESYS_NTFS:

		if (volParams->bDevice && !StartFormatWriteThread())
		{
			nStatus = ERR_OS_ERROR; 
			goto error;
		}

		nStatus = FormatNoFs (startSector, num_sectors, dev, cryptoInfo, volParams->quickFormat);

		if (volParams->bDevice)
			StopFormatWriteThread();

		break;
		
	case FILESYS_FAT:
		if (num_sectors > 0xFFFFffff)
		{
			nStatus = ERR_VOL_SIZE_WRONG; 
			goto error;
		}

		// Calculate the fats, root dir etc
		ft.num_sectors = (unsigned int) (num_sectors);
		ft.cluster_size = volParams->clusterSize;
		memcpy (ft.volume_name, "NO NAME    ", 11);
		GetFatParams (&ft); 
		*(volParams->realClusterSize) = ft.cluster_size * SECTOR_SIZE;

		if (volParams->bDevice && !StartFormatWriteThread())
		{
			nStatus = ERR_OS_ERROR; 
			goto error;
		}

		nStatus = FormatFat (startSector, &ft, (void *) dev, cryptoInfo, volParams->quickFormat);

		if (volParams->bDevice)
			StopFormatWriteThread();

		break;

	default:
		nStatus = ERR_PARAMETER_INCORRECT; 
		goto error;
	}

	if (nStatus != ERR_SUCCESS)
		goto error;

	// Write header backup
	offset.QuadPart = volParams->hiddenVol ? volParams->hiddenVolHostSize - TC_HIDDEN_VOLUME_HEADER_OFFSET : dataAreaSize + TC_VOLUME_HEADER_GROUP_SIZE;

	if (!SetFilePointerEx ((HANDLE) dev, offset, NULL, FILE_BEGIN))
	{
		nStatus = ERR_OS_ERROR;
		goto error;
	}

	nStatus = CreateVolumeHeaderInMemory (FALSE,
		header,
		volParams->ea,
		FIRST_MODE_OF_OPERATION_ID,
		volParams->password,
		volParams->pkcs5,
		cryptoInfo->master_keydata,
		&cryptoInfo,
		dataAreaSize,
		volParams->hiddenVol ? dataAreaSize : 0,
		dataOffset,
		dataAreaSize,
		0,
		volParams->headerFlags,
		FALSE);

	if (_lwrite ((HFILE) dev, header, TC_VOLUME_HEADER_EFFECTIVE_SIZE) == HFILE_ERROR)
	{
		nStatus = ERR_OS_ERROR;
		goto error;
	}

	// Fill reserved header sectors (including the backup header area) with random data
	if (!volParams->hiddenVol)
	{
		nStatus = WriteRandomDataToReservedHeaderAreas (dev, cryptoInfo, dataAreaSize, FALSE, FALSE);

		if (nStatus != ERR_SUCCESS)
			goto error;
	}

error:
	dwError = GetLastError();

	burn (header, sizeof (header));
	VirtualUnlock (header, sizeof (header));

	if (dev != INVALID_HANDLE_VALUE)
	{
		if (!volParams->bDevice && !volParams->hiddenVol && nStatus != 0)
		{
			// Remove preallocated part before closing file handle if format failed
			if (SetFilePointer (dev, 0, NULL, FILE_BEGIN) == 0)
				SetEndOfFile (dev);
		}

		FlushFileBuffers (dev);

		if (bTimeStampValid)
		{
			// Restore the container timestamp (to preserve plausible deniability of the hidden volume) 
			if (SetFileTime (dev, &ftCreationTime, &ftLastAccessTime, &ftLastWriteTime) == 0)
				MessageBoxW (volParams->hwndDlg, GetString ("SETFILETIME_FAILED_IMPLANT"), lpszTitle, MB_OK | MB_ICONEXCLAMATION);
		}

		CloseHandle (dev);
		dev = INVALID_HANDLE_VALUE;
	}

	if (nStatus != 0)
	{
		SetLastError(dwError);
		goto fv_end;
	}

	if (volParams->fileSystem == FILESYS_NTFS)
	{
		// Quick-format volume as NTFS
		int driveNo = GetLastAvailableDrive ();
		MountOptions mountOptions;
		int retCode;

		ZeroMemory (&mountOptions, sizeof (mountOptions));

		if (driveNo == -1)
		{
			MessageBoxW (volParams->hwndDlg, GetString ("NO_FREE_DRIVES"), lpszTitle, ICON_HAND);
			MessageBoxW (volParams->hwndDlg, GetString ("FORMAT_NTFS_STOP"), lpszTitle, ICON_HAND);

			nStatus = ERR_NO_FREE_DRIVES;
			goto fv_end;
		}

		mountOptions.ReadOnly = FALSE;
		mountOptions.Removable = FALSE;
		mountOptions.ProtectHiddenVolume = FALSE;
		mountOptions.PreserveTimestamp = bPreserveTimestamp;
		mountOptions.PartitionInInactiveSysEncScope = FALSE;
		mountOptions.UseBackupHeader = FALSE;

		if (MountVolume (volParams->hwndDlg, driveNo, volParams->volumePath, volParams->password, FALSE, TRUE, &mountOptions, FALSE, TRUE) < 1)
		{
			MessageBoxW (volParams->hwndDlg, GetString ("CANT_MOUNT_VOLUME"), lpszTitle, ICON_HAND);
			MessageBoxW (volParams->hwndDlg, GetString ("FORMAT_NTFS_STOP"), lpszTitle, ICON_HAND);
			nStatus = ERR_VOL_MOUNT_FAILED;
			goto fv_end;
		}

		if (!IsAdmin () && IsUacSupported ())
			retCode = UacFormatNtfs (volParams->hwndDlg, driveNo, volParams->clusterSize);
		else
			retCode = FormatNtfs (driveNo, volParams->clusterSize);

		if (retCode != TRUE)
		{
			if (!UnmountVolume (volParams->hwndDlg, driveNo, FALSE))
				MessageBoxW (volParams->hwndDlg, GetString ("CANT_DISMOUNT_VOLUME"), lpszTitle, ICON_HAND);

			if (dataAreaSize <= TC_MAX_FAT_FS_SIZE)
			{
				if (AskErrYesNo ("FORMAT_NTFS_FAILED_ASK_FAT") == IDYES)
				{
					// NTFS format failed and the user wants to try FAT format immediately
					volParams->fileSystem = FILESYS_FAT;
					bInstantRetryOtherFilesys = TRUE;
					volParams->quickFormat = TRUE;		// Volume has already been successfully TC-formatted
					volParams->clusterSize = 0;		// Default cluster size
					goto begin_format;
				}
			}
			else
				Error ("FORMAT_NTFS_FAILED");

			nStatus = ERR_DONT_REPORT;
			goto fv_end;
		}

		if (!UnmountVolume (volParams->hwndDlg, driveNo, FALSE))
			MessageBoxW (volParams->hwndDlg, GetString ("CANT_DISMOUNT_VOLUME"), lpszTitle, ICON_HAND);
	}

fv_end:

	if (dosDev[0])
		RemoveFakeDosName (volParams->volumePath, dosDev);

	crypto_close (cryptoInfo);

	return nStatus;
}


int FormatNoFs (unsigned __int64 startSector, __int64 num_sectors, void * dev, PCRYPTO_INFO cryptoInfo, BOOL quickFormat)
{
	int write_buf_cnt = 0;
	char sector[SECTOR_SIZE], write_buf[WRITE_BUF_SIZE];
	unsigned __int64 nSecNo = startSector;
	int retVal = 0;
	DWORD err;
	char temporaryKey[MASTER_KEYDATA_SIZE];
	char originalK2[MASTER_KEYDATA_SIZE];

	LARGE_INTEGER startOffset;
	LARGE_INTEGER newOffset;

	// Seek to start sector
	startOffset.QuadPart = startSector * SECTOR_SIZE;
	if (!SetFilePointerEx ((HANDLE) dev, startOffset, &newOffset, FILE_BEGIN)
		|| newOffset.QuadPart != startOffset.QuadPart)
	{
		return ERR_OS_ERROR;
	}

	VirtualLock (temporaryKey, sizeof (temporaryKey));
	VirtualLock (originalK2, sizeof (originalK2));

	memset (sector, 0, sizeof (sector));

	// Remember the original secondary key (XTS mode) before generating a temporary one
	memcpy (originalK2, cryptoInfo->k2, sizeof (cryptoInfo->k2));

	/* Fill the rest of the data area with random data */

	if(!quickFormat)
	{
		/* Generate a random temporary key set to be used for "dummy" encryption that will fill
		the free disk space (data area) with random data.  This is necessary for plausible
		deniability of hidden volumes. */

		// Temporary master key
		if (!RandgetBytes (temporaryKey, EAGetKeySize (cryptoInfo->ea), FALSE))
			goto fail;

		// Temporary secondary key (XTS mode)
		if (!RandgetBytes (cryptoInfo->k2, sizeof cryptoInfo->k2, FALSE))
			goto fail;

		retVal = EAInit (cryptoInfo->ea, temporaryKey, cryptoInfo->ks);
		if (retVal != ERR_SUCCESS)
			goto fail;

		if (!EAInitMode (cryptoInfo))
		{
			retVal = ERR_MODE_INIT_FAILED;
			goto fail;
		}

		while (num_sectors--)
		{
			/* Generate random plaintext. Note that reused plaintext blocks are not a concern here
			since XTS mode is designed to hide patterns. Furthermore, patterns in plaintext do 
			occur commonly on media in the "real world", so it might actually be a fatal mistake
			to try to avoid them completely. */

#if RNG_POOL_SIZE < SECTOR_SIZE
#error RNG_POOL_SIZE < SECTOR_SIZE
#endif

			if (!RandpeekBytes (sector, SECTOR_SIZE))
				goto fail;

			// Encrypt the random plaintext and write it to the disk
			if (WriteSector (dev, sector, write_buf, &write_buf_cnt, &nSecNo,
				cryptoInfo) == FALSE)
				goto fail;
		}

		if (!FlushFormatWriteBuffer (dev, write_buf, &write_buf_cnt, &nSecNo, cryptoInfo))
			goto fail;
	}
	else
		nSecNo = num_sectors;

	UpdateProgressBar (nSecNo);

	// Restore the original secondary key (XTS mode) in case NTFS format fails and the user wants to try FAT immediately
	memcpy (cryptoInfo->k2, originalK2, sizeof (cryptoInfo->k2));

	// Reinitialize the encryption algorithm and mode in case NTFS format fails and the user wants to try FAT immediately
	retVal = EAInit (cryptoInfo->ea, cryptoInfo->master_keydata, cryptoInfo->ks);
	if (retVal != ERR_SUCCESS)
		goto fail;
	if (!EAInitMode (cryptoInfo))
	{
		retVal = ERR_MODE_INIT_FAILED;
		goto fail;
	}

	burn (temporaryKey, sizeof(temporaryKey));
	burn (originalK2, sizeof(originalK2));
	VirtualUnlock (temporaryKey, sizeof (temporaryKey));
	VirtualUnlock (originalK2, sizeof (originalK2));
	return 0;

fail:
	err = GetLastError();

	burn (temporaryKey, sizeof(temporaryKey));
	burn (originalK2, sizeof(originalK2));
	VirtualUnlock (temporaryKey, sizeof (temporaryKey));
	VirtualUnlock (originalK2, sizeof (originalK2));

	SetLastError (err);
	return (retVal ? retVal : ERR_OS_ERROR);
}


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

	// Windows sometimes fails to format a volume (hosted on a removable medium) as NTFS.
	// It often helps to retry several times.
	for (i = 0; i < 10 && FormatExResult != TRUE; i++)
	{
		FormatEx (dir, FMIFS_HARDDISK, L"NTFS", L"", TRUE, clusterSize * SECTOR_SIZE, FormatExCallback);
	}

	FreeLibrary (hModule);
	return FormatExResult;
}


BOOL WriteSector (void *dev, char *sector,
	     char *write_buf, int *write_buf_cnt,
	     __int64 *nSecNo, PCRYPTO_INFO cryptoInfo)
{
	static __int32 updateTime = 0;

	(*nSecNo)++;

	memcpy (write_buf + *write_buf_cnt, sector, SECTOR_SIZE);
	(*write_buf_cnt) += SECTOR_SIZE;

	if (*write_buf_cnt == WRITE_BUF_SIZE && !FlushFormatWriteBuffer (dev, write_buf, write_buf_cnt, nSecNo, cryptoInfo))
		return FALSE;
	
	if (GetTickCount () - updateTime > 25)
	{
		if (UpdateProgressBar (*nSecNo))
			return FALSE;

		updateTime = GetTickCount ();
	}

	return TRUE;

}


static volatile BOOL WriteThreadRunning;
static volatile BOOL WriteThreadExitRequested;
static HANDLE WriteThreadHandle;

static byte *WriteThreadBuffer;
static HANDLE WriteBufferEmptyEvent;
static HANDLE WriteBufferFullEvent;

static volatile HANDLE WriteRequestHandle;
static volatile int WriteRequestSize; 
static volatile DWORD WriteRequestResult;


static void __cdecl FormatWriteThreadProc (void *arg)
{
	DWORD bytesWritten;

	SetThreadPriority (GetCurrentThread(), THREAD_PRIORITY_HIGHEST);

	while (!WriteThreadExitRequested)
	{
		if (WaitForSingleObject (WriteBufferFullEvent, INFINITE) == WAIT_FAILED)
		{
			handleWin32Error (NULL);
			break;
		}

		if (WriteThreadExitRequested)
			break;

		if (!WriteFile (WriteRequestHandle, WriteThreadBuffer, WriteRequestSize, &bytesWritten, NULL))
			WriteRequestResult = GetLastError();
		else		
			WriteRequestResult = ERROR_SUCCESS;

		if (!SetEvent (WriteBufferEmptyEvent))
		{
			handleWin32Error (NULL);
			break;
		}
	}

	WriteThreadRunning = FALSE;
	_endthread();
}


static BOOL StartFormatWriteThread ()
{
	DWORD sysErr;

	WriteBufferEmptyEvent = NULL;
	WriteBufferFullEvent = NULL;
	WriteThreadBuffer = NULL;

	WriteBufferEmptyEvent = CreateEvent (NULL, FALSE, TRUE, NULL);
	if (!WriteBufferEmptyEvent)
		goto err;

	WriteBufferFullEvent = CreateEvent (NULL, FALSE, FALSE, NULL);
	if (!WriteBufferFullEvent)
		goto err;

	WriteThreadBuffer = TCalloc (WRITE_BUF_SIZE);
	if (!WriteThreadBuffer)
	{
		SetLastError (ERROR_OUTOFMEMORY);
		goto err;
	}

	WriteThreadExitRequested = FALSE;
	WriteRequestResult = ERROR_SUCCESS;

	WriteThreadHandle = (HANDLE) _beginthread (FormatWriteThreadProc, 0, NULL);
	if ((uintptr_t) WriteThreadHandle == -1L)
		goto err;

	WriteThreadRunning = TRUE;
	return TRUE;

err:
	sysErr = GetLastError();

	if (WriteBufferEmptyEvent)
		CloseHandle (WriteBufferEmptyEvent);
	if (WriteBufferFullEvent)
		CloseHandle (WriteBufferFullEvent);
	if (WriteThreadBuffer)
		TCfree (WriteThreadBuffer);

	SetLastError (sysErr);
	return FALSE;
}


static void StopFormatWriteThread ()
{
	if (WriteThreadRunning)
	{
		WaitForSingleObject (WriteBufferEmptyEvent, INFINITE);

		WriteThreadExitRequested = TRUE;
		SetEvent (WriteBufferFullEvent);

		WaitForSingleObject (WriteThreadHandle, INFINITE);
	}

	CloseHandle (WriteBufferEmptyEvent);
	CloseHandle (WriteBufferFullEvent);
	TCfree (WriteThreadBuffer);
}


BOOL FlushFormatWriteBuffer (void *dev, char *write_buf, int *write_buf_cnt, __int64 *nSecNo, PCRYPTO_INFO cryptoInfo)
{
	UINT64_STRUCT unitNo;
	DWORD bytesWritten;

	if (*write_buf_cnt == 0)
		return TRUE;

	unitNo.Value = (*nSecNo - *write_buf_cnt / SECTOR_SIZE) * SECTOR_SIZE / ENCRYPTION_DATA_UNIT_SIZE;

	EncryptDataUnits (write_buf, &unitNo, *write_buf_cnt / ENCRYPTION_DATA_UNIT_SIZE, cryptoInfo);

	if (WriteThreadRunning)
	{
		if (WaitForSingleObject (WriteBufferEmptyEvent, INFINITE) == WAIT_FAILED)
			return FALSE;
		
		if (WriteRequestResult != ERROR_SUCCESS)
		{
			SetLastError (WriteRequestResult);
			return FALSE;
		}

		memcpy (WriteThreadBuffer, write_buf, *write_buf_cnt);
		WriteRequestHandle = dev;
		WriteRequestSize = *write_buf_cnt;

		if (!SetEvent (WriteBufferFullEvent))
			return FALSE;
	}
	else
	{
		if (!WriteFile ((HANDLE) dev, write_buf, *write_buf_cnt, &bytesWritten, NULL))
			return FALSE;
	}

	*write_buf_cnt = 0;
	return TRUE;
}
