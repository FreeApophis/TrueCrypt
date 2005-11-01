/* Legal Notice: The source code contained in this file has been derived from
   the source code of Encryption for the Masses 2.02a, which is Copyright (c)
   1998-99 Paul Le Roux and which is covered by the 'License Agreement for
   Encryption for the Masses'. Modifications and additions to that source code
   contained in this file are Copyright (c) 2004-2005 TrueCrypt Foundation and
   Copyright (c) 2004 TrueCrypt Team, and are covered by TrueCrypt License 2.0
   the full text of which is contained in the file License.txt included in
   TrueCrypt binary and source code distribution archives.  */

#include "Tcdefs.h"
#include "Language.h"
#include "Dlgcode.h"
#include "Progress.h"
#include "../format/resource.h"

extern HWND hCurPage;
extern HWND hProgressBar;
extern BOOL bThreadCancel;
extern int nPbar;

ULONG prevTime, startTime;
__int64 totalSectors;

static wchar_t *minute, *minutes, *hours, *days;

void
InitProgressBar (__int64 totalSecs)
{
	HWND hProgressBar = GetDlgItem (hCurPage, nPbar);
	SendMessage (hProgressBar, PBM_SETRANGE32, 0, 10000);
	SendMessage (hProgressBar, PBM_SETSTEP, 1, 0);

	minutes = GetString ("MINUTES");
	hours = GetString ("HOURS");
	days = GetString ("DAYS");

	prevTime = startTime = GetTickCount ();
	totalSectors = totalSecs;
}

BOOL
UpdateProgressBar (__int64 nSecNo)
{
	wchar_t text[100];
	wchar_t speed[100];
	HWND hProgressBar = GetDlgItem (hCurPage, nPbar);
	int time = GetTickCount ();
	int elapsed = (time - startTime) / 1000;
	unsigned __int64 bytesDone = (nSecNo + 1) * SECTOR_SIZE;
	unsigned __int64 bytesPerSec = bytesDone / (1 + elapsed);

	GetSizeString (bytesDone, text);
	wcscat (text, L" ");
	SetWindowTextW (GetDlgItem (hCurPage, IDC_BYTESWRITTEN), text);

	GetSpeedString (bytesPerSec, speed);
	wcscat (speed, L" ");
	SetWindowTextW (GetDlgItem (hCurPage, IDC_WRITESPEED), speed);

	if (nSecNo < totalSectors)
	{
		int sec = (int)((totalSectors  - nSecNo) / ((nSecNo + 1)/(elapsed + 1) + 1));

		if (sec >= 60 * 60 * 24 * 2)
			swprintf (text, L"%d %s ", sec / (60 * 24 * 60), days);
		else if (sec >= 120 * 60)
			swprintf (text, L"%d %s ", sec / (60 * 60), hours);
		else if (sec >= 120)
			swprintf (text, L"%d %s ", sec / 60, minutes);
		else
			swprintf (text, L"%d s ", sec);

		SetWindowTextW (GetDlgItem (hCurPage, IDC_TIMEREMAIN), text);
	}

	prevTime = time;

	SendMessage (hProgressBar, PBM_SETPOS, (int) (10000.0 * nSecNo / totalSectors), 0);

	return bThreadCancel;
}
