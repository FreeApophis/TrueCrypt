/* The source code contained in this file has been derived from the source code
   of Encryption for the Masses 2.02a by Paul Le Roux. Modifications and
   additions to that source code contained in this file are Copyright (c) 2004
   TrueCrypt Team and Copyright (c) 2004 TrueCrypt Foundation. Unmodified
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

	int elapsed = (time - startTime) / 1000;

	if ((nSecNo+1) / 2 / 1024 < 1000000)
		wsprintf(text,"%d MB ", (nSecNo+1) / 2 / 1024);
	else
		wsprintf(text,"%d GB ", (nSecNo+1) / 2 / 1024 / 1024);

	SetWindowText (GetDlgItem (hCurPage, IDC_BYTESWRITTEN), text);

	if ((nSecNo+1) / 2 / 1024 / (1+elapsed) < 1024)
		wsprintf(text,"%d MB/s ", (nSecNo+1) / 2 / 1024 / (1+elapsed));
	else
		wsprintf(text,"%d GB/s ", (nSecNo+1) / 2 / 1024 / 1024 / (1+elapsed));

	SetWindowText (GetDlgItem (hCurPage, IDC_WRITESPEED), text);

	if (nSecNo < totalSectors)
	{
		int min = (int)((totalSectors  - nSecNo) / ((nSecNo+1)/(elapsed+1)+1) / 60);

		if (min < 60 * 24)
			wsprintf(text,"%d min ", min);
		else
			wsprintf(text,"%d days ", min / (60 * 24));

		SetWindowText (GetDlgItem (hCurPage, IDC_TIMEREMAIN), text);
	}

	prevTime = time;

	SendMessage (hProgressBar, PBM_SETPOS, (int) (10000.0 * nSecNo / totalSectors), 0);

	return bThreadCancel;
}
