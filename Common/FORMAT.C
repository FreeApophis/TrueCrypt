/* The source code contained in this file has been derived from the source code
   of Encryption for the Masses 2.02a by Paul Le Roux. Modifications and
   additions to that source code contained in this file are Copyright (c) 2004
   TrueCrypt Team and Copyright (c) 2004 TrueCrypt Foundation. Unmodified
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


static int GetAvailableDrive ()
{
	DWORD dwUsedDrives = GetLogicalDrives();
	int i;

	for (i = 25; i > 2; i--)
	{
		if (!(dwUsedDrives & 1 << i))
			return i;
	}

	return -1;
}

static BOOL MountVolume (HWND hwndDlg, int driveNo, char *volumePath, char *szPassword)
{
	extern HANDLE hDriver;

	MOUNT_STRUCT driver;
	DWORD dwResult;
	BOOL bResult, bDevice;

	VirtualLock (&driver, sizeof (driver));

	driver.nDosDriveNo = driveNo;
	driver.bCache = 0;
	driver.time = 0;
	driver.nPasswordLen = strlen (szPassword);
	strcpy (driver.szPassword, szPassword);

	CreateFullVolumePath ((char *) driver.wszVolume, volumePath, &bDevice);
	ToUNICODE ((char *) driver.wszVolume);

	bResult = DeviceIoControl (hDriver, MOUNT, &driver,
		sizeof (driver), &driver, sizeof (driver), &dwResult, NULL);

	burn (&driver.szPassword, sizeof (driver.szPassword));

	VirtualUnlock (&driver, sizeof (driver));

	if (bResult == FALSE)
	{
		handleWin32Error (hwndDlg);
		return FALSE;
	}
	else
	{
		if (driver.nReturnCode == 0)
		{
			if (nCurrentOS == WIN_NT)
			{
				char *lpszPipeName = "\\\\.\\pipe\\truecryptservice";
				DWORD bytesRead;
				char inbuf[80];
				char outbuf[80];

				sprintf (outbuf, "mount %d", driver.nDosDriveNo);

				bResult = CallNamedPipe (lpszPipeName,
					outbuf, sizeof (outbuf),
					inbuf, sizeof (inbuf),
					&bytesRead, NMPWAIT_WAIT_FOREVER);

				if (bResult == FALSE)
				{
					handleWin32Error (hwndDlg);
				}
				else
				{
					DWORD os_err = 0;
					int err = 0;

					sscanf (inbuf, "%s %d %lu", outbuf, &err, &os_err);

					if (*inbuf == '-')
					{
						if (err == ERR_OS_ERROR)
						{
							SetLastError (os_err);
							handleWin32Error (hwndDlg);
						}
						else
						{
							handleError (hwndDlg, err);
						}

						bResult = FALSE;
					}
				}
				return bResult;
			}
		}
		else
		{
			handleError (hwndDlg, driver.nReturnCode);
			return FALSE;
		}
	}

	return TRUE;
}

int
FormatVolume (char *lpszFilename,
	      BOOL bDevice,
		  char *volumePath,
	      unsigned __int64 size,
	      char *lpszPassword,
	      int cipher,
	      int pkcs5,
		  BOOL quickFormat,
		  int fileSystem,
		  int clusterSize,
		  char * summaryMsg,
	      HWND hwndDlg)
{
	int nStatus;
	PCRYPTO_INFO cryptoInfo;
	void *dev = INVALID_HANDLE_VALUE;
	OPEN_TEST_STRUCT driver;
	DISKIO_STRUCT win9x_r0;
	DWORD dwError, dwThen, dwNow;
	diskio_f write;
	char header[SECTOR_SIZE];
	__int64 num_sectors;
	fatparams ft;
	
	size -= SECTOR_SIZE;	// less the first TC sector
	num_sectors = size / SECTOR_SIZE;

	if (fileSystem == FILESYS_FAT)
	{
		if (num_sectors > 0xFFFFffff)
			return ERR_VOL_SIZE_WRONG;

		ft.num_sectors = (unsigned int) (num_sectors);
		ft.cluster_size = clusterSize;
		memcpy (ft.volume_name, "           ", 11);
		/* Calculate the fats, root dir etc, and update ft */
		GetFatParams (&ft);
	}

	VirtualLock (header, sizeof (header));

	/* Copies any header structures into header, but does not do any
	   disk io */
	nStatus = VolumeWriteHeader (header,
				     cipher,
				     lpszPassword,
				     pkcs5,
					 0,
					 0,
				     &cryptoInfo);

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
	}
	else
	{
		/* We could support FILE_ATTRIBUTE_HIDDEN as an
		option! */
		dev = CreateFile (lpszFilename, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, 0, NULL);
	}

	if (dev == INVALID_HANDLE_VALUE)
	{
		return ERR_OS_ERROR;
	}

	KillTimer (hwndDlg, 0xff);

	InitProgressBar (num_sectors);
	dwThen = GetTickCount ();

	switch (fileSystem)
	{
	case FILESYS_NONE:
	case FILESYS_NTFS:
		nStatus = FormatNoFs (num_sectors, header, (HFILE) dev, cryptoInfo, 1000, write, bDevice==TRUE ? quickFormat:FALSE);
		break;

	case FILESYS_FAT:
		/* This does the disk io, both copying out the header, init the
		sectors, and writing the FAT tables etc */
		nStatus = FormatFat (&ft, header, (HFILE) dev, cryptoInfo, 1000, write, bDevice==TRUE ? quickFormat:FALSE);
		break;
	}

	dwNow = GetTickCount ();

	burn (header, sizeof (header));
	VirtualUnlock (header, sizeof (header));

	crypto_close (cryptoInfo);
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
				int driveNo = GetAvailableDrive ();
				DWORD os_error;
				int err;

				if (driveNo == -1)
				{
					MessageBox (hwndDlg, "No free drives available. NTFS formatting cannot continue.", lpszTitle, ICON_HAND);
					return ERR_NO_FREE_DRIVES;
				}

				if (!MountVolume (hwndDlg, driveNo, volumePath, lpszPassword))
				{
					MessageBox (hwndDlg, "Cannot mount volume. NTFS formatting cannot continue.", lpszTitle, ICON_HAND);
					return ERR_VOL_MOUNT_FAILED;
				}

				if (!FormatNtfs (driveNo, clusterSize))
				{
					MessageBox (hwndDlg, "NTFS formatting failed. Try using FAT filesystem.", lpszTitle, MB_ICONERROR);
					UnmountVolume (driveNo, &os_error, &err);
					return ERR_VOL_FORMAT_BAD;
				}

				UnmountVolume (driveNo, &os_error, &err);

				dwNow = GetTickCount ();

				sprintf (summaryMsg, "Volume size:\t\t%I64d sectors (%I64d MB)\nFile system:\t\tNTFS"
					"\n\nFormatting took %lu seconds."
					, num_sectors, num_sectors*512/1024/1024
					, (dwNow - dwThen)/1000);

				break;
			}
		}
	}

	NormalCursor ();

	return nStatus;
}


int FormatNoFs (__int64 num_sectors, char *header, HFILE dev, PCRYPTO_INFO cryptoInfo, int nFrequency, diskio_f write, BOOL quickFormat)
{
	int write_buf_cnt = 0;
	char sector[SECTOR_SIZE], *write_buf;
	int progress = 0;
	unsigned __int64 nSecNo = 1;

	if ((*write) (dev, header, SECTOR_SIZE) == HFILE_ERROR)
		return ERR_OS_ERROR;

	write_buf = TCalloc (WRITE_BUF_SIZE);

	memset (sector, 0, sizeof (sector));

	/* write data area */
	if(!quickFormat)
	{
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
	(*cryptoInfo->encrypt_sector) ((unsigned long *) sector,
	(*nSecNo)++, 1, cryptoInfo->ks, cryptoInfo->iv, cryptoInfo->cipher);
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



