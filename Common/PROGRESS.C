/* Copyright (C) 2004 TrueCrypt Foundation
   This product uses components written by Paul Le Roux <pleroux@swprofessionals.com> */

#include "TCdefs.h"
#include "progress.h"
#include "../format/resource.h"

extern HWND hCurPage;
extern HWND hProgressBar;
extern BOOL bThreadCancel;
extern int nPbar;

ULONG prevTime, startTime, totalSectors;

void
InitProgressBar (ULONG totalSecs)
{
	HWND hProgressBar = GetDlgItem (hCurPage, nPbar);
	SendMessage (hProgressBar, PBM_SETRANGE32, 0, 10000);
	SendMessage (hProgressBar, PBM_SETSTEP, 1, 0);

	prevTime = startTime = GetTickCount ();
	totalSectors = totalSecs;
}

BOOL
UpdateProgressBar (int nSecNo)
{
	char text[100];
	HWND hProgressBar = GetDlgItem (hCurPage, nPbar);
	int time = GetTickCount ();

	int elapsed = (time - startTime) / 1000;

	wsprintf(text,"%d MB ", (nSecNo+1) / 2 / 1024);
	SetWindowText (GetDlgItem (hCurPage, IDC_BYTESWRITTEN), text);

	wsprintf(text,"%d MB/s ", (nSecNo+1) / 2 / 1024 / (1+elapsed));
	SetWindowText (GetDlgItem (hCurPage, IDC_WRITESPEED), text);

	if (nSecNo < totalSectors)
	{
		wsprintf(text,"%d min ", (totalSectors  - nSecNo) / ((nSecNo+1)/(elapsed+1)+1) / 60);
		SetWindowText (GetDlgItem (hCurPage, IDC_TIMEREMAIN), text);
	}

	prevTime = time;

	SendMessage (hProgressBar, PBM_SETPOS, (int) (10000.0 * nSecNo / totalSectors), 0);

	return bThreadCancel;
}
