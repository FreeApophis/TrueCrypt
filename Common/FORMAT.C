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
#include "progress.h"
#include "apidrvr.h"
#include "dlgcode.h"
#include "resource.h"


int
FormatVolume (char *lpszFilename,
	      BOOL bDevice,
		  char *volumePath,
	      unsigned __int64 size,
		  unsigned __int64 hiddenVolHostSize,
	      char *lpszPassword,
	      int cipher,
	      int pkcs5,
		  BOOL quickFormat,
		  int fileSystem,
		  int clusterSize,
		  char * summaryMsg,
	      HWND hwndDlg,
		  BOOL hiddenVol,
		  int *realClusterSize)
{
	int nStatus;
	PCRYPTO_INFO cryptoInfo;
	HANDLE dev = INVALID_HANDLE_VALUE;
	OPEN_TEST_STRUCT driver;
	DWORD dwError, dwThen, dwNow;
	diskio_f write;
	char header[SECTOR_SIZE];
	unsigned __int64 num_sectors, startSector;
	fatparams ft;
	FILETIME ftCreationTime;
	FILETIME ftLastWriteTime;
	FILETIME ftLastAccessTime;
	BOOL bTimeStampValid = FALSE;
	
	if (!hiddenVol)
		size -= HEADER_SIZE;	

	num_sectors = size / SECTOR_SIZE;
	VirtualLock (header, sizeof (header));

	/* Copies any header structures into header, but does not do any
	   disk io */
	nStatus = VolumeWriteHeader (header,
				     cipher,
				     lpszPassword,
				     pkcs5,
					 0,
					 0,
				     &cryptoInfo,
					 hiddenVol ? size : 0);

	if (nStatus != 0)
	{
		burn (header, sizeof (header));
		VirtualUnlock (header, sizeof (header));
		return nStatus;
	}

	write = (diskio_f) _lwrite;

	if (bDevice == TRUE)
	{
		dev = CreateFile (lpszFilename, GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
		if (dev == INVALID_HANDLE_VALUE)
		{
			// Try opening device in shared mode
			dev = CreateFile (lpszFilename, GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
			if (dev != INVALID_HANDLE_VALUE)
			{
				if (IDNO == MessageBox (hwndDlg, getstr (IDS_DEVICE_IN_USE_FORMAT), lpszTitle, MB_YESNO|MB_ICONWARNING|MB_DEFBUTTON2))
				{
					CloseHandle (dev);
					dev = INVALID_HANDLE_VALUE;
				}
			}
		}
	}
	else
	{
		// We could support FILE_ATTRIBUTE_HIDDEN as an option
		// (Now if the container has hidden or system file attribute, the OS will not allow
		// overwritting it; so the user will have to delete it manually).
		dev = CreateFile (lpszFilename, GENERIC_WRITE,
			hiddenVol ? (FILE_SHARE_READ | FILE_SHARE_WRITE) : 0,
			NULL, hiddenVol ? OPEN_EXISTING : CREATE_ALWAYS, 0, NULL);
	}

	if (dev == INVALID_HANDLE_VALUE)
	{
		nStatus = ERR_OS_ERROR; goto error;
	}

	if (hiddenVol && !bDevice)
	{
		/* Remember the container timestamp (used to reset file date and time of file-hosted
		containers to preserve plausible deniability of hidden volume)  */
		if (GetFileTime ((HANDLE) dev, &ftCreationTime, &ftLastAccessTime, &ftLastWriteTime) == 0)
		{
			bTimeStampValid = FALSE;
			MessageBox (hwndDlg, getstr (IDS_GETFILETIME_FAILED_IMPLANT), "TrueCrypt", MB_OK | MB_ICONEXCLAMATION);
		}
		else
			bTimeStampValid = TRUE;
	}

	KillTimer (hwndDlg, 0xff);

	InitProgressBar (num_sectors);
	dwThen = GetTickCount ();


	//// Volume header

	// Hidden volume setup
	if (hiddenVol)
	{
		// Check hidden volume size
		if (hiddenVolHostSize < MIN_HIDDEN_VOLUME_HOST_SIZE || hiddenVolHostSize > MAX_HIDDEN_VOLUME_HOST_SIZE)
		{		
			nStatus = ERR_VOL_SIZE_WRONG; goto error;
		}

		// Seek to hidden volume header location
		if (!SeekHiddenVolHeader ((HFILE) dev, hiddenVolHostSize, bDevice))
		{
			nStatus = ERR_VOL_SEEKING; goto error;
		}

	}

	// Write the volume header
	if ((*write) ((HFILE) dev, header, HEADER_SIZE) == HFILE_ERROR)
		return ERR_OS_ERROR;


	//// Data area

	startSector = 1;	// Data area of normal volume starts right after volume header

	if (hiddenVol)
	{
		// Calculate data area position of hidden volume
		unsigned __int64 startOffset = hiddenVolHostSize - size - HIDDEN_VOL_HEADER_OFFSET;

		// Validate the offset
		if (startOffset % SECTOR_SIZE != 0)
		{
			nStatus = ERR_VOL_SIZE_WRONG; goto error;
		}

		startSector = startOffset / SECTOR_SIZE;	
		quickFormat = TRUE;		// To entirely format a hidden volume would be redundant
	}

	// Format filesystem

	switch (fileSystem)
	{
	case FILESYS_NONE:
	case FILESYS_NTFS: // NTFS volume is just prepared for quick format performed by system
		nStatus = FormatNoFs (startSector, num_sectors, (HFILE) dev, cryptoInfo, 1000, write, quickFormat);
		break;

	case FILESYS_FAT:
		if (num_sectors > 0xFFFFffff)
		{
			nStatus = ERR_VOL_SIZE_WRONG; goto error;
		}

		// Calculate the fats, root dir etc
		ft.num_sectors = (unsigned int) (num_sectors);
		ft.cluster_size = clusterSize;
		memcpy (ft.volume_name, "           ", 11);
		GetFatParams (&ft); 
		*realClusterSize = ft.cluster_size * SECTOR_SIZE;

		nStatus = FormatFat (startSector, &ft, (HFILE) dev, cryptoInfo, 1000, write, quickFormat);
		break;
	}

error:

	dwNow = GetTickCount ();

	burn (header, sizeof (header));
	VirtualUnlock (header, sizeof (header));

	crypto_close (cryptoInfo);

	if (bTimeStampValid)
	{
		// Restore the container timestamp (to preserve plausible deniability of the hidden volume) 
		if (SetFileTime (dev, &ftCreationTime, &ftLastAccessTime, &ftLastWriteTime) == 0)
			MessageBox (hwndDlg, getstr (IDS_SETFILETIME_FAILED_IMPLANT), "TrueCrypt", MB_OK | MB_ICONEXCLAMATION);
	}

	CloseHandle (dev);

	dwError = GetLastError();

	if (nStatus!=0)
		SetLastError(dwError);
	else
	{
		switch (fileSystem)
		{
		case FILESYS_NONE:
			sprintf (summaryMsg, "Volume size:\t\t%I64d sectors (%I64d MB)\nFile system:\t\tNone"
				"\n\nFormatting took %lu seconds."
				, num_sectors, num_sectors*512/1024/1024
				, (dwNow - dwThen)/1000);
			break;

		case FILESYS_FAT:
			sprintf (summaryMsg, 
				"Volume size:\t\t%d sectors (%I64d MB)\nFile system:\t\tFAT%d\n"
				"FAT size:\t\t%d bytes\nCluster size:\t\t%d bytes\nClusters available:\t%d"
				"\n\nFormatting took %lu seconds."
				, ft.num_sectors, ((__int64) ft.num_sectors*512)/1024/1024, ft.size_fat
				, (int) (512*ft.fats*ft.fat_length),
				(int) (512*ft.cluster_size), ft.cluster_count,
				(dwNow - dwThen)/1000);
			break;

		case FILESYS_NTFS:
			{
				// NTFS format is performed by system so we first need to mount the volume
				int driveNo = GetLastAvailableDrive ();
				DWORD os_error;
				int err;

				if (driveNo == -1)
				{
					MessageBox (hwndDlg, "No free drive letter available. NTFS formatting cannot continue.", lpszTitle, ICON_HAND);
					return ERR_NO_FREE_DRIVES;
				}

				if (MountVolume (hwndDlg, driveNo, volumePath, lpszPassword, FALSE, TRUE, FALSE) < 1)
				{
					MessageBox (hwndDlg, "Cannot mount volume. NTFS formatting cannot continue.", lpszTitle, ICON_HAND);
					return ERR_VOL_MOUNT_FAILED;
				}

				// Quickformat volume as NTFS
				if (!FormatNtfs (driveNo, clusterSize))
				{
					MessageBox (hwndDlg, "NTFS formatting failed.\nTry using FAT file system instead.", lpszTitle, MB_ICONERROR);
				
					if (!UnmountVolume (hwndDlg, driveNo, FALSE))
						MessageBox (hwndDlg, "Volume dismount failed.", lpszTitle, MB_ICONERROR);

					return ERR_VOL_FORMAT_BAD;
				}

				if (!UnmountVolume (hwndDlg, driveNo, FALSE))
					MessageBox (hwndDlg, "Formatting succeeded but volume cannot be dismounted.", lpszTitle, MB_ICONEXCLAMATION);

				dwNow = GetTickCount ();

				sprintf (summaryMsg, "Volume size:\t\t%I64d sectors (%I64d MB)\nFile system:\t\tNTFS"
					"\n\nFormatting took %lu seconds."
					, num_sectors, num_sectors*512/1024/1024
					, (dwNow - dwThen)/1000);

				break;
			}
		}
	}

	return nStatus;
}


int FormatNoFs (unsigned __int64 startSector, __int64 num_sectors, HFILE dev, PCRYPTO_INFO cryptoInfo, int nFrequency, diskio_f write, BOOL quickFormat)
{
	int write_buf_cnt = 0;
	char sector[SECTOR_SIZE], *write_buf;
	int progress = 0;
	unsigned __int64 nSecNo = startSector;
	LARGE_INTEGER startOffset;
	LARGE_INTEGER newOffset;

	// Seek to start sector
	startOffset.QuadPart = startSector * SECTOR_SIZE;
	if (SetFilePointerEx ((HANDLE) dev, startOffset, &newOffset, FILE_BEGIN) == 0
		|| newOffset.QuadPart != newOffset.QuadPart)
	{
		return ERR_VOL_SEEKING;
	}

	write_buf = TCalloc (WRITE_BUF_SIZE);
	memset (sector, 0, sizeof (sector));

	// Write sectors
	if(!quickFormat)
	{
		/* Generate a random key and IV to be used for "dummy" encryption that will fill the
		   free disk space (data area) with random data. That will reduce the amount of
		   predictable plaintext within the volume and also increase the level of plausible
		   deniability of hidden volumes. */
		char key[DISKKEY_SIZE];
		RandgetBytes (key, DISKKEY_SIZE, FALSE); 
		RandgetBytes (cryptoInfo->iv, sizeof cryptoInfo->iv, FALSE); 
		EAInit (cryptoInfo->ea, key, cryptoInfo->ks);
		RandgetBytes (sector, 256, FALSE); 
		RandgetBytes (sector + 256, 256, FALSE); 

		while (num_sectors--)
		{
			if (WriteSector (dev, sector, write_buf, &write_buf_cnt, &nSecNo, &progress,
				cryptoInfo, nFrequency, write) == FALSE)
				goto fail;
		}
		if (write_buf_cnt != 0 && (*write) (dev, write_buf, write_buf_cnt) == HFILE_ERROR)
			goto fail;
	}
	else
		nSecNo = num_sectors;

	UpdateProgressBar (nSecNo);

	TCfree (write_buf);
	return 0;

fail:

	TCfree (write_buf);
	return ERR_OS_ERROR;
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

	if (hModule == NULL)
		return FALSE;

	if (!(FormatEx = (void *) GetProcAddress (GetModuleHandle("fmifs.dll"), "FormatEx")))
	{
		FreeLibrary (hModule);
		return FALSE;
	}

	wcscat (dir, L":\\");

	FormatExResult = FALSE;

	if (*(char *)dir > 'C' && *(char *)dir <= 'Z')
		FormatEx (dir, FMIFS_HARDDISK, L"NTFS", L"", TRUE, clusterSize * 512, FormatExCallback);

	FreeLibrary (hModule);
	return FormatExResult;
}

BOOL
WriteSector (HFILE dev, char *sector,
	     char *write_buf, int *write_buf_cnt,
	     __int64 *nSecNo, int *progress, PCRYPTO_INFO cryptoInfo,
	     int nFrequency, diskio_f write)
{

	EncryptSectors ((unsigned long *) sector,
		(*nSecNo)++, 1, cryptoInfo->ks, cryptoInfo->iv, cryptoInfo->ea);

	memcpy (write_buf + *write_buf_cnt, sector, SECTOR_SIZE);
	(*write_buf_cnt) += SECTOR_SIZE;


	if (*write_buf_cnt == WRITE_BUF_SIZE)
	{
		if ((*write) (dev, write_buf, WRITE_BUF_SIZE) == HFILE_ERROR)
			return FALSE;
		else
			*write_buf_cnt = 0;
	}

	if (++(*progress) == nFrequency)
	{
		if (UpdateProgressBar (*nSecNo) == TRUE)
			return FALSE;
		*progress = 0;
	}

	return TRUE;

}
