/* The source code contained in this file has been derived from the source code
   of Encryption for the Masses 2.02a by Paul Le Roux. Modifications and
   additions to that source code contained in this file are Copyright (c) 2004-2005
   TrueCrypt Foundation and Copyright (c) 2004 TrueCrypt Team. Unmodified
   parts are Copyright (c) 1998-99 Paul Le Roux. This is a TrueCrypt Foundation
   release. Please see the file license.txt for full license details. */

#include "TCdefs.h"
#include "progress.h"
#include "../format/resource.h"

extern HWND hCurPage;
extern HWND hProgressBar;
extern BOOL bThreadCancel;
extern int nPbar;

ULONG prevTime, startTime;
__int64 totalSectors;

void
InitProgressBar (__int64 totalSecs)
{
	HWND hProgressBar = GetDlgItem (hCurPage, nPbar);
	SendMessage (hProgressBar, PBM_SETRANGE32, 0, 10000);
	SendMessage (hProgressBar, PBM_SETSTEP, 1, 0);

	prevTime = startTime = GetTickCount ();
	totalSectors = totalSecs;
}

BOOL
UpdateProgressBar (__int64 nSecNo)
{
	char text[100];
	HWND hProgressBar = GetDlgItem (hCurPage, nPbar);
	int time = GetTickCount ();
	unsigned __int64 bytesDone = (nSecNo+1) * SECTOR_SIZE;

	int elapsed = (time - startTime) / 1000;

	if (bytesDone < (unsigned __int64) BYTES_PER_MB * 10000000)
		sprintf(text,"%I64d MB ", bytesDone / BYTES_PER_MB);
	else if (bytesDone < (unsigned __int64) BYTES_PER_GB * 10000000)
		sprintf(text,"%I64d GB ", bytesDone / BYTES_PER_GB);
	else if (bytesDone < (unsigned __int64) BYTES_PER_TB * 10000000)
		sprintf(text,"%I64d TB ", bytesDone / BYTES_PER_TB);
	else
		sprintf(text,"%I64d PB ", bytesDone / BYTES_PER_PB);

	SetWindowText (GetDlgItem (hCurPage, IDC_BYTESWRITTEN), text);

	if ((nSecNo+1) / 2 / 1024 / (1+elapsed) < 1024)
		sprintf(text,"%I64d MB/s ", (nSecNo+1) / 2 / 1024 / (1+elapsed));
	else
		sprintf(text,"%I64d GB/s ", (nSecNo+1) / 2 / 1024 / 1024 / (1+elapsed));

	SetWindowText (GetDlgItem (hCurPage, IDC_WRITESPEED), text);

	if (nSecNo < totalSectors)
	{
		int sec = (int)((totalSectors  - nSecNo) / ((nSecNo+1)/(elapsed+1)+1));

		if (sec >= 60 * 24 * 60)
			sprintf(text,"%d days ", sec / (60 * 24 * 60));
		else if (sec >= 120 * 60)
			sprintf(text,"%d hours ", sec / (60 * 60));
		else if (sec >= 120)
			sprintf(text,"%d minutes ", sec / 60);
		else if (sec >= 60)
			sprintf(text,"%d minute ", sec / 60);
		else
			sprintf(text,"%d s ", sec);

		SetWindowText (GetDlgItem (hCurPage, IDC_TIMEREMAIN), text);
	}

	prevTime = time;

	SendMessage (hProgressBar, PBM_SETPOS, (int) (10000.0 * nSecNo / totalSectors), 0);

	return bThreadCancel;
}
