/*
 Legal Notice: Some portions of the source code contained in this file were
 derived from the source code of Encryption for the Masses 2.02a, which is
 Copyright (c) 1998-2000 Paul Le Roux and which is governed by the 'License
 Agreement for Encryption for the Masses'. Modifications and additions to
 the original source code (contained in this file) and all other portions of
 this file are Copyright (c) 2003-2008 TrueCrypt Foundation and are governed
 by the TrueCrypt License 2.5 the full text of which is contained in the
 file License.txt included in TrueCrypt binary and source code distribution
 packages. */

#include "Tcdefs.h"
#include "Language.h"
#include "Dlgcode.h"
#include "Progress.h"
#include "../Format/Tcformat.h"
#include "../Format/FormatCom.h"
#include "../Format/resource.h"

ULONG prevTime, startTime;
__int64 totalSectors;
__int64 resumedPointBytesDone;
BOOL bProgressBarReverse = FALSE;
BOOL bRWThroughput = FALSE;
BOOL bShowStatus = FALSE;
BOOL bPercentMode = FALSE;

static wchar_t *seconds, *minutes, *hours, *days;


// If bIOThroughput is TRUE, the speed reflects the amount of data read AND written per second (rather than
// the speed of the "transform cursor").
void InitProgressBar (__int64 totalSecs, __int64 bytesDone, BOOL bReverse, BOOL bIOThroughput, BOOL bDisplayStatus, BOOL bShowPercent)
{
	HWND hProgressBar = GetDlgItem (hCurPage, nPbar);
	SendMessage (hProgressBar, PBM_SETRANGE32, 0, 10000);
	SendMessage (hProgressBar, PBM_SETSTEP, 1, 0);

	bProgressBarReverse = bReverse;
	bRWThroughput = bIOThroughput;
	bShowStatus = bDisplayStatus;
	bPercentMode = bShowPercent;

	seconds = GetString ("SECONDS");
	minutes = GetString ("MINUTES");
	hours = GetString ("HOURS");
	days = GetString ("DAYS");

	prevTime = startTime = GetTickCount ();
	totalSectors = totalSecs;
	resumedPointBytesDone = bytesDone;
}


BOOL UpdateProgressBar (__int64 nSecNo)
{
	return UpdateProgressBarProc (nSecNo);
}


BOOL UpdateProgressBarProc (__int64 nSecNo)
{
	wchar_t text[100];
	wchar_t speed[100];
	HWND hProgressBar = GetDlgItem (hCurPage, nPbar);
	int time = GetTickCount ();
	int elapsed = (time - startTime) / 1000;

	unsigned __int64 bytesDone = (bProgressBarReverse ? ((totalSectors - nSecNo + 1) * SECTOR_SIZE) : ((nSecNo + 1) * SECTOR_SIZE));
	unsigned __int64 bytesPerSec = (bProgressBarReverse ? (resumedPointBytesDone - nSecNo * SECTOR_SIZE + 1) : (bytesDone - resumedPointBytesDone + 1)) / (elapsed + 1);

	if (bPercentMode)
	{
		double perc = (double) (100.0 * (bProgressBarReverse ? ((double) (totalSectors - nSecNo)) : ((double) nSecNo)) / (totalSectors == 0 ? 0.0001 : ((double) totalSectors)));

		if (perc > 99.999999999)
			wcscpy (text, GetString ("PROCESSED_PORTION_100_PERCENT"));
		else
			_snwprintf (text, sizeof text/2, GetString ("PROCESSED_PORTION_X_PERCENT"), perc);

		wcscat (speed, L" ");
	}
	else
	{
		GetSizeString (bytesDone, text);
		if (bytesDone < (unsigned __int64) BYTES_PER_MB * 1000000)
			swprintf(text, L"%I64d %s ", bytesDone / BYTES_PER_MB, GetString ("MB"));
		else if (bytesDone < (unsigned __int64) BYTES_PER_GB * 1000000)
			swprintf(text, L"%I64d %s ", bytesDone / BYTES_PER_GB, GetString ("GB"));
		else if (bytesDone < (unsigned __int64) BYTES_PER_TB * 1000000)
			swprintf(text, L"%I64d %s ", bytesDone / BYTES_PER_TB, GetString ("TB"));
		else
			swprintf(text, L"%I64d %s ", bytesDone / BYTES_PER_PB, GetString ("PB"));
	}

	SetWindowTextW (GetDlgItem (hCurPage, IDC_BYTESWRITTEN), text);

	if (!bShowStatus)
	{
		GetSpeedString (bRWThroughput ? bytesPerSec*2 : bytesPerSec, speed);
		wcscat (speed, L" ");
		SetWindowTextW (GetDlgItem (hCurPage, IDC_WRITESPEED), speed);
	}

	if (nSecNo < totalSectors)
	{
		__int32 sec = (__int32)((bProgressBarReverse ? nSecNo : (totalSectors - nSecNo)) / ((bytesPerSec == 0 ? 0.00001 : bytesPerSec) / SECTOR_SIZE));

		if (sec >= 60 * 60 * 24 * 2)
			swprintf (text, L"%d %s ", sec / (60 * 24 * 60), days);
		else if (sec >= 120 * 60)
			swprintf (text, L"%d %s ", sec / (60 * 60), hours);
		else if (sec >= 120)
			swprintf (text, L"%d %s ", sec / 60, minutes);
		else
			swprintf (text, L"%d %s ", sec, seconds);

		SetWindowTextW (GetDlgItem (hCurPage, IDC_TIMEREMAIN), text);
	}

	prevTime = time;

	SendMessage (hProgressBar, PBM_SETPOS, 
		(int) (10000.0 * (bProgressBarReverse ? (totalSectors - nSecNo) : nSecNo) / (totalSectors == 0 ? 1 : totalSectors)),
		0);

	return bThreadCancel;
}
