/* Copyright (C) 2004 TrueCrypt Team, truecrypt.org
   This product uses components written by Paul Le Roux <pleroux@swprofessionals.com> */

#include "TCdefs.h"

#include "crypto.h"
#include "fat.h"
#include "format.h"
#include "volumes.h"
#include "progress.h"
#include "apidrvr.h"
#include "dlgcode.h"

int
FormatVolume (char *lpszFilename,
	      BOOL bDevice,
	      unsigned __int64 size,
	      char *lpszPassword,
	      int cipher,
	      int pkcs5,
	      fatparams * ft,
		  BOOL quickFormat,
	      HWND hwndDlg)
{
	int nStatus;
	PCRYPTO_INFO cryptoInfo;
	void *dev = INVALID_HANDLE_VALUE;
	OPEN_TEST_STRUCT driver;
	DISKIO_STRUCT win9x_r0;
	DWORD dwError;
	diskio_f write;

	if (nCurrentOS == WIN_NT || bDevice == FALSE)
	{
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
	}
	else
	{
		write = (diskio_f) win9x_io;

		if (OpenDevice (lpszFilename, &driver) == FALSE)
		{
			return ERR_OS_ERROR;
		}

		win9x_r0.devicenum = driver.device;
		win9x_r0.sectorstart = driver.secstart;
		win9x_r0.mode = 1;

		dev = &win9x_r0;
	}

	size -= SECTOR_SIZE;	// less the first TC sector

	ft->num_sectors = (int) (size / SECTOR_SIZE);
	memcpy (ft->volume_name, "           ", 11);

	{
		// Avoid random init delay before time counters start
		char tmp[1];
		RandgetBytes(&tmp, 1);
	}

	InitProgressBar (ft->num_sectors);

	/* Calculate the fats, root dir etc, and update ft */
	GetFatParams (ft);

	/* Copies any header structures into ft->header, but does not do any
	   disk io */
	nStatus = VolumeWriteHeader (ft->header,
				     cipher,
				     lpszPassword,
				     pkcs5,
					 0,
					 0,
				     &cryptoInfo);

	if (nStatus != 0)
		return nStatus;

	KillTimer (hwndDlg, 0xff);

	/* This does the disk io, both copying out the header, init the
	   sectors, and writing the FAT tables etc */
	nStatus = Format (ft, (HFILE) dev, cryptoInfo, 1000, write, bDevice==TRUE ? quickFormat:FALSE);

	dwError = GetLastError();

	crypto_close (cryptoInfo);

	if (dev != &win9x_r0)
		CloseHandle (dev);

	if (nStatus!=0)
		SetLastError(dwError);
	
	return nStatus;

}
