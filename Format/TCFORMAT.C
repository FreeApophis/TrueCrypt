/* The source code contained in this file has been derived from the source code
   of Encryption for the Masses 2.02a by Paul Le Roux. Modifications and
   additions to that source code contained in this file are Copyright (c) 2004
   TrueCrypt Team and Copyright (c) 2004 TrueCrypt Foundation. Unmodified
   parts are Copyright (c) 1998-99 Paul Le Roux. This is a TrueCrypt Foundation
   release. Please see the file license.txt for full license details. */

#include "TCdefs.h"

#include <stdlib.h>
#include <limits.h>
#include <time.h>
#include <errno.h>
#include <io.h>
#include <sys/stat.h>

#include "crypto.h"
#include "apidrvr.h"
#include "dlgcode.h"
#include "combo.h"
#include "registry.h"
#include "../common/resource.h"
#include "random.h"
#include "fat.h"
#include "resource.h"
#include "TCFormat.h"
#include "uncroot.h"
#include "format.h"
#include "password.h"
#include "testcrypt.h"
#include "redtick.h"
#include "endian.h"

#include "cmdline.h"

#define WM_THREAD_ENDED		0x7ffe	/* WM_USER range message */
#define WM_FORMAT_FINISHED	0x7ffe+1	

#define RANDOM_SHOW_TIMER	30		// Refresh interval for Random pool display

enum wizard_pages
{
	FILE_PAGE,
	CIPHER_PAGE,
	SIZE_PAGE,
	PASSWORD_PAGE,
	FORMAT_PAGE
};

HWND hCurPage = NULL;		/* Handle to current wizard page */
int nCurPageNo = -1;		/* The current wizard page */
int nVolCipher = BLOWFISH;	/* Default cipher = Blowfish */
int pkcs5 = SHA1;			/* Which key derivation to use,
				   default=HMAC-SHA1 */
unsigned __int64 nFileSize = 0;		/* The volume size */
int nMultiplier = 1024*1024;		/* Was the size selection in KB or MB */
char szFileName[TC_MAX_PATH];	/* The file selected by the user */
char szDiskFile[TC_MAX_PATH];	/* Fully qualified name derived from szFileName */

BOOL bThreadCancel = FALSE;	/* If the user cancels the volume formatting;
				   this is set */
BOOL bThreadRunning = FALSE;	/* Is the thread running */

BOOL bDevice = FALSE;		/* Is this a partition volume ? */

BOOL showKeys = TRUE;
HWND hDiskKey = NULL;		/* Text box showing hex dump of disk key */
HWND hHeaderKey = NULL;		/* Text box showing hex dump of header key */

char szPassword[MAX_PASSWORD + 1];	/* Users password */
char szVerify[MAX_PASSWORD + 1];/* Tmp password buffer */

BOOL bHistory = FALSE;		/* Remember all the settings */

BOOL bHistoryCmdLine = FALSE; /* History control is always disabled */

int nPbar = 0;			/* Control ID of progress bar:- for format
				   code */

volatile BOOL quickFormat = FALSE;
volatile int fileSystem = 0;
volatile int clusterSize = 0;

void
localcleanup (void)
{
	Randfree ();

	/* Zero the password */
	burn (&szVerify[0], sizeof (szVerify));
	burn (&szPassword[0], sizeof (szPassword));

	/* Free the application title */
	if (lpszTitle != NULL)
		free (lpszTitle);

	UnregisterRedTick (hInst);

	/* Cleanup common code resources */
	cleanup ();

}

void
LoadSettings (HWND hwndDlg)
{
	bHistory = ReadRegistryInt ("SaveMountedVolumesHistory", FALSE);

	if (hwndDlg != NULL)
	{
		LoadCombo (GetDlgItem (hwndDlg, IDC_COMBO_BOX), "LastMountedVolume");
		return;
	}

	if (bHistoryCmdLine == TRUE)
		return;
}

void
SaveSettings (HWND hwndDlg)
{
	if (hwndDlg != NULL)
		DumpCombo (GetDlgItem (hwndDlg, IDC_COMBO_BOX), "LastMountedVolume", !bHistory);

	WriteRegistryInt ("SaveMountedVolumesHistory", bHistory);
}

void
EndMainDlg (HWND hwndDlg)
{

	if (nCurPageNo == FILE_PAGE)
	{
		if (IsWindow(GetDlgItem(hCurPage, IDC_NO_HISTORY)))
			bHistory = !IsButtonChecked (GetDlgItem (hCurPage, IDC_NO_HISTORY));

		MoveEditToCombo (GetDlgItem (hCurPage, IDC_COMBO_BOX));
		SaveSettings (hCurPage);
	}
	else 
	{
		SaveSettings (NULL);
	}

	EndDialog (hwndDlg, 0);
}


void
ComboSelChangeCipher (HWND hwndDlg)
{
	LPARAM nIndex = SendMessage (GetDlgItem (hwndDlg, IDC_COMBO_BOX), CB_GETCURSEL, 0, 0);

	if (nIndex == CB_ERR)
	{
		SetWindowText (GetDlgItem (hwndDlg, IDC_BOX_HELP), "");
	}
	else
	{
		UINT nID[4];

		nIndex = SendMessage (GetDlgItem (hwndDlg, IDC_COMBO_BOX), CB_GETITEMDATA, nIndex, 0);

		memset (nID, 0, sizeof (nID));

		switch (nIndex)
		{
		case DES56:
			nID[0] = IDS_DES_HELP0;
			nID[1] = IDS_DES_HELP1;
			SetWindowText (GetDlgItem (hwndDlg, IDC_BOX_HELP), getmultilinestr (nID));
			break;
		case BLOWFISH:
			nID[0] = IDS_BLOWFISH_HELP0;
			nID[1] = IDS_BLOWFISH_HELP1;
			SetWindowText (GetDlgItem (hwndDlg, IDC_BOX_HELP), getmultilinestr (nID));
			break;
		case AES:
			nID[0] = IDS_AES_HELP0;
			nID[1] = IDS_AES_HELP1;
			SetWindowText (GetDlgItem (hwndDlg, IDC_BOX_HELP), getmultilinestr (nID));
			break;
		case IDEA:
			nID[0] = IDS_IDEA_HELP0;
			nID[1] = IDS_IDEA_HELP1;
			SetWindowText (GetDlgItem (hwndDlg, IDC_BOX_HELP), getmultilinestr (nID));
			break;
		case CAST:
			nID[0] = IDS_CAST_HELP0;
			nID[1] = IDS_CAST_HELP1;
			SetWindowText (GetDlgItem (hwndDlg, IDC_BOX_HELP), getmultilinestr (nID));
			break;
		case TRIPLEDES:
			nID[0] = IDS_TRIPLEDES_HELP0;
			nID[1] = IDS_TRIPLEDES_HELP1;
			SetWindowText (GetDlgItem (hwndDlg, IDC_BOX_HELP), getmultilinestr (nID));
			break;
		case NONE:
			nID[0] = IDS_CIPHER_NONE_HELP0;
			nID[1] = 0;
			nID[2] = 0;
			nID[3] = 0;
			SetWindowText (GetDlgItem (hwndDlg, IDC_BOX_HELP), getmultilinestr (nID));
			break;
		}
	}

}

void
VerifySizeAndUpdate (HWND hwndDlg, BOOL bUpdate)
{
	BOOL bEnable = TRUE;
	char szTmp[16];
	__int64 lTmp;
	size_t i;

	GetWindowText (GetDlgItem (hwndDlg, IDC_SIZEBOX), szTmp, sizeof (szTmp));

	for (i = 0; i < strlen (szTmp); i++)
	{
		if (szTmp[i] >= '0' && szTmp[i] <= '9')
			continue;
		else
		{
			bEnable = FALSE;
			break;
		}
	}

	GetWindowText (GetDlgItem (hwndDlg, IDC_SIZEBOX), szTmp, sizeof (szTmp));
	lTmp = atoi64 (szTmp);
	if (IsButtonChecked (GetDlgItem (hwndDlg, IDC_KB)) == TRUE)
		i = BYTES_PER_KB;
	else
		i = BYTES_PER_MB;

	if (bEnable == TRUE)
	{
		if (lTmp * i < MIN_VOLUME_SIZE)
			bEnable = FALSE;
		if (lTmp * i > MAX_VOLUME_SIZE)
			bEnable = FALSE;
	}

	if (bUpdate == TRUE)
	{
		nFileSize = lTmp;
	}

	nMultiplier = i;

	EnableWindow (GetDlgItem (GetParent (hwndDlg), IDC_NEXT), bEnable);
}

/* Even though certain functions like getstr are not thread safe, they don't
   need to be, this is because the idea of have this app being multi-threaded
   is to allow a user to cancel the format process once it begins, not to do
   two things at once, so getstr will only ever have one thread running
   through it. */

void
formatThreadFunction (void *hwndDlg)
{
	int nStatus;
	char szDosDevice[TC_MAX_PATH];
	char szCFDevice[TC_MAX_PATH];
	char summaryMsg[512];
	DWORD dwWin32FormatError;
	int nDosLinkCreated = -1;

	ArrowWaitCursor ();

	if (bDevice == FALSE)
	{
		int x = _access (szDiskFile, 06);
		if (x == 0 || errno != ENOENT)
		{
			char szTmp[512];
			UINT nID;
			if (errno == EACCES)
				nID = IDS_READONLYPROMPT;
			else
				nID = IDS_OVERWRITEPROMPT;

			sprintf (szTmp, getstr (nID), szDiskFile);
			x = MessageBox (hwndDlg, szTmp, lpszTitle, YES_NO|MB_ICONWARNING|MB_DEFBUTTON2);

			if (x != IDYES)
				goto cancel;
		}

		if (_access (szDiskFile, 06) != 0)
		{
			if (errno == EACCES)
			{
				if (_chmod (szDiskFile, _S_IREAD | _S_IWRITE) != 0)
				{
					MessageBox (hwndDlg, getstr (IDS_ACCESSMODEFAIL), lpszTitle, ICON_HAND);
					goto cancel;
				}
			}
		}

		strcpy (szCFDevice, szDiskFile);
	}
	else
	{
		char szTmp[512];
		int x;

		sprintf (szTmp, getstr (IDS_OVERWRITEPROMPT_DEVICE), szFileName);
		x = MessageBox (hwndDlg, szTmp, lpszTitle, YES_NO|MB_ICONWARNING|MB_DEFBUTTON2);
		if (x != IDYES)
			goto cancel;

		if (nCurrentOS == WIN_NT)
		{
			nDosLinkCreated = FakeDosNameForDevice (szDiskFile, szDosDevice, szCFDevice, FALSE);
			if (nDosLinkCreated != 0)
			{
				handleWin32Error (hwndDlg);
				goto cancel;
			}
		}
		else
		{
			strcpy (szCFDevice, szDiskFile);
		}
	}

	nStatus = FormatVolume (szCFDevice,
				bDevice,
				szDiskFile,
				nFileSize * nMultiplier,
				szPassword,
				nVolCipher,
				pkcs5,
				quickFormat,
				fileSystem,
				clusterSize,
				summaryMsg,
				hwndDlg
				);

	if (nStatus == ERR_OUTOFMEMORY)
	{
		AbortProcess (IDS_OUTOFMEMORY);
	}

	dwWin32FormatError = GetLastError ();

	if (nDosLinkCreated == 0)
	{
		/* Only comes here when it's WIN_NT & disk partitions */
		int nStatus = RemoveFakeDosName (szDiskFile, szDosDevice);
		if (nStatus != 0)
			handleWin32Error (hwndDlg);
	}

	SetLastError (dwWin32FormatError);

	if (bThreadCancel == TRUE)
	{
		if (bDevice == FALSE)
			remove (szCFDevice);

		goto cancel;
	}

	if (nStatus != 0)
	{
		char szMsg[512];

		sprintf (szMsg, getstr (IDS_CREATE_FAILED), szDiskFile);

		MessageBox (hwndDlg, szMsg, lpszTitle, ICON_HAND);

		if (bDevice == FALSE)
			remove (szCFDevice);

		goto cancel;
	}
	else
	{
		NormalCursor ();

		/* Create the volstats dialog box */
		DialogBoxParam (hInst, MAKEINTRESOURCE (IDD_VOLSTATS_DLG), hwndDlg,
			    (DLGPROC) VolstatsDlgProc, (LPARAM) & summaryMsg[0]);

		SetTimer (hwndDlg, 0xff, RANDOM_SHOW_TIMER, NULL);
		PostMessage (hwndDlg, WM_FORMAT_FINISHED, 0, 0);
		bThreadRunning = FALSE;
		NormalCursor ();
		_endthread ();
	}

      cancel:

	SetTimer (hwndDlg, 0xff, RANDOM_SHOW_TIMER, NULL);

	PostMessage (hwndDlg, WM_THREAD_ENDED, 0, 0);
	bThreadRunning = FALSE;
	NormalCursor ();
	_endthread ();
}

void
OpenPageHelp (HWND hwndDlg, int nPage)
{
	int r = (int)ShellExecute (NULL, "open", szHelpFile, NULL, NULL, SW_SHOWNORMAL);
	if (nPage);		/* Remove warning */

	if (r == ERROR_FILE_NOT_FOUND)
		MessageBox (hwndDlg, getstr (IDS_HELP_ERROR), lpszTitle, MB_ICONERROR);

	if (r == SE_ERR_NOASSOC)
		MessageBox (hwndDlg, getstr (IDS_HELP_READER_ERROR), lpszTitle, MB_ICONERROR);
}

void
LoadPage (HWND hwndDlg, int nPageNo)
{
	RECT rW, rD;

	if (hCurPage != NULL)
	{
		DestroyWindow (hCurPage);
	}

	nCurPageNo = nPageNo;

	ShowWindow (GetDlgItem (hwndDlg, IDC_POS_BOX), SW_HIDE);
	EnableWindow (GetDlgItem (hwndDlg, IDC_POS_BOX), TRUE);
	GetWindowRect (GetDlgItem (hwndDlg, IDC_POS_BOX), &rW);

	switch (nPageNo)
	{
	case FILE_PAGE:

		hCurPage = CreateDialog (hInst, MAKEINTRESOURCE (IDD_FILE_PAGE_DLG), hwndDlg,
					 (DLGPROC) PageDialogProc);
		
		if (bHistoryCmdLine == TRUE)
			EnableWindow (GetDlgItem(hCurPage, IDC_NO_HISTORY),  FALSE);
		else
			EnableWindow (GetDlgItem(hCurPage, IDC_NO_HISTORY),  TRUE);
		break;

	case CIPHER_PAGE:
		hCurPage = CreateDialog (hInst, MAKEINTRESOURCE (IDD_CIPHER_PAGE_DLG), hwndDlg,
					 (DLGPROC) PageDialogProc);
		break;
	case SIZE_PAGE:
		hCurPage = CreateDialog (hInst, MAKEINTRESOURCE (IDD_SIZE_PAGE_DLG), hwndDlg,
					 (DLGPROC) PageDialogProc);
		break;
	case PASSWORD_PAGE:
		hCurPage = CreateDialog (hInst, MAKEINTRESOURCE (IDD_PASSWORD_PAGE_DLG), hwndDlg,
					 (DLGPROC) PageDialogProc);
		break;
	case FORMAT_PAGE:
		hCurPage = CreateDialog (hInst, MAKEINTRESOURCE (IDD_FORMAT_PAGE_DLG), hwndDlg,
					 (DLGPROC) PageDialogProc);
		break;
	}

	rD.left = 162;
	rD.top = 25;
	rD.right = 0;
	rD.bottom = 0;
	MapDialogRect (hwndDlg, &rD);

	if (hCurPage != NULL)
	{
		MoveWindow (hCurPage, rD.left, rD.top, rW.right - rW.left, rW.bottom - rW.top, TRUE);
		ShowWindow (hCurPage, SW_SHOWNORMAL);
	}
}

/* Except in response to the WM_INITDIALOG message, the dialog box procedure
   should return nonzero if it processes the message, and zero if it does
   not. - see DialogProc */
BOOL WINAPI
VolstatsDlgProc (HWND hwndDlg, UINT msg, WPARAM wParam, LPARAM lParam)
{
	WORD lw = LOWORD (wParam);

	switch (msg)
	{
	case WM_INITDIALOG:
		SetDefaultUserFont (hwndDlg);
		SetWindowText (GetDlgItem (hwndDlg, IDC_STATS_BOX), (char *) lParam);
		return 1;

	case WM_COMMAND:
		if (lw == IDOK)
		{
			EndDialog (hwndDlg, 0);
			return 1;
		}
		return 0;
	}

	return 0;
}

int
PrintFreeSpace (HWND hwndTextBox, char *lpszDrive, PLARGE_INTEGER lDiskFree)
{
	UINT nResourceString;
	int nMultiplier;
	char szTmp2[256];

	if (lDiskFree->QuadPart < BYTES_PER_KB)
		nMultiplier = 1;
	else if (lDiskFree->QuadPart < BYTES_PER_MB)
		nMultiplier = BYTES_PER_KB;
	else
		nMultiplier = BYTES_PER_MB;

	if (nMultiplier == 1)
		if (bDevice == TRUE)
			nResourceString = IDS_DEVICE_FREE_BYTES;
		else
			nResourceString = IDS_DISK_FREE_BYTES;
	else if (nMultiplier == 1024)
		if (bDevice == TRUE)
			nResourceString = IDS_DEVICE_FREE_KB;
		else
			nResourceString = IDS_DISK_FREE_KB;
	else if (bDevice == TRUE)
		nResourceString = IDS_DEVICE_FREE_MB;
	else
		nResourceString = IDS_DISK_FREE_MB;

	sprintf (szTmp2, getstr (nResourceString), lpszDrive, ((double) lDiskFree->QuadPart) / nMultiplier);
	SetWindowText (hwndTextBox, szTmp2);

	if (lDiskFree->QuadPart % (__int64) BYTES_PER_MB != 0)
		nMultiplier = BYTES_PER_KB;

	return nMultiplier == 1 ? nMultiplier : nMultiplier;
}

void
DisplaySizingErrorText (HWND hwndTextBox)
{
	char szTmp[256];

	if (nCurrentOS == WIN_NT)
	{
		if (translateWin32Error (szTmp, sizeof (szTmp)) == TRUE)
		{
			char szTmp2[256];
			sprintf (szTmp2, "%s\n%s", getstr (IDS_CANNOT_CALC_SPACE), szTmp);
			SetWindowText (hwndTextBox, szTmp2);
		}
		else
		{
			SetWindowText (hwndTextBox, "");
		}
	}
	else
	{
		SetWindowText (hwndTextBox, getstr (IDS_CANNOT_CALC_SPACE));
	}
}

void
EnableDisableFileNext (HWND hComboBox, HWND hMainButton)
{
	LPARAM nIndex = SendMessage (hComboBox, CB_GETCURSEL, 0, 0);
	if (nIndex == CB_ERR)
	{
		EnableWindow (hMainButton, FALSE);
		SetFocus (hComboBox);
	}
	else
	{
		EnableWindow (hMainButton, TRUE);
		SetFocus (hMainButton);
	}
}

BOOL
QueryFreeSpace (HWND hwndDlg, HWND hwndTextBox)
{
	if (bDevice == FALSE)
	{
		char szTmp[TC_MAX_PATH];
		ULARGE_INTEGER free;
		BOOL bResult;

		bResult = GetDiskFreeSpaceEx (MakeRootName (szTmp, szFileName), &free, 0, 0);

		if (bResult == FALSE)
		{
			DisplaySizingErrorText (hwndTextBox);
			return FALSE;
		}
		else
		{
			LARGE_INTEGER lDiskFree;
			lDiskFree.QuadPart = free.QuadPart;
			PrintFreeSpace (hwndTextBox, szTmp, &lDiskFree);
			return TRUE;
		}
	}
	else if (nCurrentOS == WIN_NT)
	{
		char szDosDevice[TC_MAX_PATH], szCFDevice[TC_MAX_PATH];
		int nDosLinkCreated;
		HANDLE dev;

		nDosLinkCreated = FakeDosNameForDevice (szDiskFile, szDosDevice,
							szCFDevice, FALSE);
		if (nDosLinkCreated != 0)
		{
			DisplaySizingErrorText (hwndTextBox);
			return FALSE;
		}

		dev = CreateFile (szCFDevice, GENERIC_READ, 0, NULL, OPEN_EXISTING, 0, NULL);

		if (dev == INVALID_HANDLE_VALUE)
		{
			int nStatus;

			DisplaySizingErrorText (hwndTextBox);
			nStatus = RemoveFakeDosName (szDiskFile, szDosDevice);
			if (nStatus != 0)
				handleWin32Error (hwndDlg);

			return FALSE;
		}
		else
		{
			DISK_GEOMETRY driveInfo;
			DWORD dwResult;
			int nStatus;
			BOOL bResult;

			nStatus = RemoveFakeDosName (szDiskFile, szDosDevice);
			if (nStatus != 0)
				handleWin32Error (hwndDlg);

			bResult = DeviceIoControl (dev, IOCTL_DISK_GET_DRIVE_GEOMETRY, NULL, 0,
			   &driveInfo, sizeof (driveInfo), &dwResult, NULL);

			if (driveInfo.MediaType == FixedMedia)
			{
				PARTITION_INFORMATION diskInfo;

				bResult = DeviceIoControl (dev, IOCTL_DISK_GET_PARTITION_INFO, NULL, 0,
							   &diskInfo, sizeof (diskInfo), &dwResult, NULL);

				if (bResult == TRUE)
				{
					nMultiplier = PrintFreeSpace (hwndTextBox, szDiskFile, &diskInfo.PartitionLength);
					nFileSize = diskInfo.PartitionLength.QuadPart / nMultiplier;

					if (nFileSize == 0)
					{
						SetWindowText (hwndTextBox, getstr (IDS_EXT_PARTITION));
						CloseHandle (dev);
						return FALSE;
					}

				}
				else
				{
					DisplaySizingErrorText (hwndTextBox);
					CloseHandle (dev);
					return FALSE;
				}

			}
			else if (bResult == TRUE)
			{
				LARGE_INTEGER lDiskFree;

				lDiskFree.QuadPart = driveInfo.Cylinders.QuadPart * driveInfo.BytesPerSector *
				    driveInfo.SectorsPerTrack * driveInfo.TracksPerCylinder;

				nMultiplier = PrintFreeSpace (hwndTextBox, szDiskFile, &lDiskFree);
				nFileSize = lDiskFree.QuadPart / nMultiplier;
			}
			else
			{
				DisplaySizingErrorText (hwndTextBox);
				CloseHandle (dev);
				return FALSE;
			}

			CloseHandle (dev);
			return TRUE;
		}
	}
	else
	{
		OPEN_TEST_STRUCT driver;
		BOOL bResult;

		bResult = OpenDevice (szDiskFile, &driver);

		if (bResult == TRUE)
		{
			LARGE_INTEGER lDiskFree;

			lDiskFree.QuadPart = (__int64) (driver.seclast - driver.secstart) * SECTOR_SIZE;
			nMultiplier = PrintFreeSpace (hwndTextBox, szDiskFile, &lDiskFree);
			nFileSize = lDiskFree.QuadPart / nMultiplier;
		}
		else
		{
			DisplaySizingErrorText (hwndTextBox);
			return FALSE;
		}

		return TRUE;
	}
}

void
AddComboPair (HWND hComboBox, char *lpszItem, int value)
{
	LPARAM nIndex;

	nIndex = SendMessage (hComboBox, CB_ADDSTRING, 0, (LPARAM) lpszItem);
	nIndex = SendMessage (hComboBox, CB_SETITEMDATA, nIndex, (LPARAM) value);
}

void
SelectCipher (HWND hComboBox, int *nCipher)
{
	LPARAM nCount = SendMessage (hComboBox, CB_GETCOUNT, 0, 0);
	LPARAM x, i;

	for (i = 0; i < nCount; i++)
	{
		x = SendMessage (hComboBox, CB_GETITEMDATA, i, 0);
		if (x == (LPARAM) * nCipher)
		{
			SendMessage (hComboBox, CB_SETCURSEL, i, 0);
			return;
		}
	}

	/* Something went wrong ; couldn't find the old cipher so we drop
	   back to a default */

	*nCipher = SendMessage (hComboBox, CB_GETITEMDATA, 0, 0);

	SendMessage (hComboBox, CB_SETCURSEL, 0, 0);

}

/* Except in response to the WM_INITDIALOG message, the dialog box procedure
   should return nonzero if it processes the message, and zero if it does
   not. - see DialogProc */
BOOL CALLBACK
PageDialogProc (HWND hwndDlg, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
	WORD lw = LOWORD (wParam);
	WORD hw = HIWORD (wParam);

	switch (uMsg)
	{
	case WM_INITDIALOG:

		SetDefaultUserFont (hwndDlg);

		switch (nCurPageNo)
		{
		case FILE_PAGE:
			{
				UINT nID[4] = { 0,0,0,0 };

				nID[0] = IDS_FILE_HELP0;
				nID[1] = IDS_FILE_HELP1;

				SendMessage (GetDlgItem (hwndDlg, IDC_COMBO_BOX), CB_RESETCONTENT, 0, 0);

				SendMessage (GetDlgItem (hwndDlg, IDC_COMBO_BOX), CB_LIMITTEXT, TC_MAX_PATH, 0);

				LoadSettings (hwndDlg);

				SendMessage (GetDlgItem (hwndDlg, IDC_NO_HISTORY), BM_SETCHECK, bHistory ? BST_UNCHECKED : BST_CHECKED, 0);

				SetWindowText (GetDlgItem (GetParent (hwndDlg), IDC_BOX_TITLE), getstr (IDS_FILE_TITLE));
				SetWindowText (GetDlgItem (hwndDlg, IDC_BOX_HELP), getmultilinestr (nID));

				SetFocus (GetDlgItem (hwndDlg, IDC_COMBO_BOX));

				SetWindowText (GetDlgItem (GetParent (hwndDlg), IDC_NEXT), getstr (IDS_NEXT));
				SetWindowText (GetDlgItem (GetParent (hwndDlg), IDC_PREV), getstr (IDS_PREV));
				EnableWindow (GetDlgItem (GetParent (hwndDlg), IDC_PREV), FALSE);

				AddComboItem (GetDlgItem (hwndDlg, IDC_COMBO_BOX), szFileName);

				EnableDisableFileNext (GetDlgItem (hwndDlg, IDC_COMBO_BOX),
				GetDlgItem (GetParent (hwndDlg), IDC_NEXT));

			}
			break;

		case CIPHER_PAGE:
			{
				int cipher;
				SendMessage (GetDlgItem (hwndDlg, IDC_COMBO_BOX), CB_RESETCONTENT, 0, 0);
				SetWindowText (GetDlgItem (GetParent (hwndDlg), IDC_BOX_TITLE), getstr (IDS_CIPHER_TITLE));

				for (cipher = 1; cipher <= LAST_CIPHER_ID; cipher++)
				{
					AddComboPair (GetDlgItem (hwndDlg, IDC_COMBO_BOX), get_cipher_name (cipher), cipher);
				}

				SelectCipher (GetDlgItem (hwndDlg, IDC_COMBO_BOX), &nVolCipher);
				ComboSelChangeCipher (hwndDlg);
				SetFocus (GetDlgItem (hwndDlg, IDC_COMBO_BOX));

				switch (pkcs5)
				{
				case SHA1:		CheckButton (GetDlgItem (hwndDlg, IDC_SHA1)); break;
				case RIPEMD160:	CheckButton (GetDlgItem (hwndDlg, IDC_RIPEMD160)); break;
				default:		pkcs5 = SHA1; CheckButton (GetDlgItem (hwndDlg, IDC_SHA1)); break;
				}

				EnableWindow (GetDlgItem (hwndDlg, IDC_SHA1), TRUE);
				EnableWindow (GetDlgItem (hwndDlg, IDC_RIPEMD160), TRUE);

				SetWindowText (GetDlgItem (GetParent (hwndDlg), IDC_NEXT), getstr (IDS_NEXT));
				SetWindowText (GetDlgItem (GetParent (hwndDlg), IDC_PREV), getstr (IDS_PREV));
				EnableWindow (GetDlgItem (GetParent (hwndDlg), IDC_PREV), TRUE);
				EnableWindow (GetDlgItem (GetParent (hwndDlg), IDC_NEXT), TRUE);
			}
			break;

		case SIZE_PAGE:
			{
				char szTmp[32];
				UINT nID[4] = { 0,0,0,0 };

				nID[0] = IDS_SIZE_HELP0;
				nID[1] = IDS_SIZE_HELP1;

				if (bDevice == TRUE)
				{
					nID[0] = IDS_SIZE_PARTITION_HELP;
					nID[1] = 0;
				}
				SendMessage (GetDlgItem (hwndDlg, IDC_SPACE_LEFT), WM_SETFONT, (WPARAM) hSmallBoldFont, (LPARAM) TRUE);
				SendMessage (GetDlgItem (hwndDlg, IDC_SIZEBOX), EM_LIMITTEXT, 10, 0);

				if(!QueryFreeSpace (hwndDlg, GetDlgItem (hwndDlg, IDC_SPACE_LEFT)))
				{
					nFileSize=0;
					SetWindowText (GetDlgItem (hwndDlg, IDC_SIZEBOX), "UNKNOWN");
					EnableWindow (GetDlgItem (hwndDlg, IDC_SIZEBOX), FALSE);
					EnableWindow (GetDlgItem (hwndDlg, IDC_KB), FALSE);
					EnableWindow (GetDlgItem (hwndDlg, IDC_MB), FALSE);

				}
				else if (bDevice == TRUE)
				{
					EnableWindow (GetDlgItem (hwndDlg, IDC_SIZEBOX), FALSE);
					EnableWindow (GetDlgItem (hwndDlg, IDC_KB), FALSE);
					EnableWindow (GetDlgItem (hwndDlg, IDC_MB), FALSE);
				}
				else
				{
					EnableWindow (GetDlgItem (hwndDlg, IDC_SIZEBOX), TRUE);
					EnableWindow (GetDlgItem (hwndDlg, IDC_KB), TRUE);
					EnableWindow (GetDlgItem (hwndDlg, IDC_MB), TRUE);
				}

				if (nMultiplier == 1024)
					SendMessage (GetDlgItem (hwndDlg, IDC_KB), BM_SETCHECK, BST_CHECKED, 0);
				else
					SendMessage (GetDlgItem (hwndDlg, IDC_MB), BM_SETCHECK, BST_CHECKED, 0);

				if (nFileSize != 0)
				{
					sprintf (szTmp, "%I64u", nFileSize);
					SetWindowText (GetDlgItem (hwndDlg, IDC_SIZEBOX), szTmp);
				}

				SetFocus (GetDlgItem (hwndDlg, IDC_SIZEBOX));

				SetWindowText (GetDlgItem (hwndDlg, IDC_BOX_HELP), getmultilinestr (nID));
				SetWindowText (GetDlgItem (GetParent (hwndDlg), IDC_BOX_TITLE), getstr (IDS_SIZE_TITLE));

				SetWindowText (GetDlgItem (GetParent (hwndDlg), IDC_NEXT), getstr (IDS_NEXT));
				SetWindowText (GetDlgItem (GetParent (hwndDlg), IDC_PREV), getstr (IDS_PREV));


				EnableWindow (GetDlgItem (GetParent (hwndDlg), IDC_PREV), TRUE);

				VerifySizeAndUpdate (hwndDlg, FALSE);
			}
			break;

		case PASSWORD_PAGE:
			{
				UINT nID[4];

				nID[0] = IDS_PASSWORD_HELP0;
				nID[1] = IDS_PASSWORD_HELP1;
				nID[2] = IDS_PASSWORD_HELP2;
				nID[3] = IDS_PASSWORD_HELP3;

				SendMessage (GetDlgItem (hwndDlg, IDC_PASSWORD), EM_LIMITTEXT, MAX_PASSWORD, 0);
				SendMessage (GetDlgItem (hwndDlg, IDC_VERIFY), EM_LIMITTEXT, MAX_PASSWORD, 0);

				SetWindowText (GetDlgItem (hwndDlg, IDC_PASSWORD), szPassword);
				SetWindowText (GetDlgItem (hwndDlg, IDC_VERIFY), szVerify);

				SetFocus (GetDlgItem (hwndDlg, IDC_PASSWORD));

				SetWindowText (GetDlgItem (hwndDlg, IDC_BOX_HELP), getmultilinestr (nID));
				SetWindowText (GetDlgItem (GetParent (hwndDlg), IDC_BOX_TITLE), getstr (IDS_PASSWORD_TITLE));

				SetWindowText (GetDlgItem (GetParent (hwndDlg), IDC_NEXT), getstr (IDS_NEXT));
				SetWindowText (GetDlgItem (GetParent (hwndDlg), IDC_PREV), getstr (IDS_PREV));

				EnableWindow (GetDlgItem (GetParent (hwndDlg), IDC_PREV), TRUE);

				VerifyPasswordAndUpdate (hwndDlg, GetDlgItem (GetParent (hwndDlg), IDC_NEXT),
					 GetDlgItem (hwndDlg, IDC_PASSWORD),
					   GetDlgItem (hwndDlg, IDC_VERIFY),
						      NULL, NULL);

			}
			break;

		case FORMAT_PAGE:
			{
				UINT nID[4];

				nID[0] = IDS_FORMAT_HELP0;
				nID[1] = IDS_FORMAT_HELP1;
				nID[2] = IDS_FORMAT_HELP2;
				nID[3] = 0;

				SetTimer (GetParent (hwndDlg), 0xff, RANDOM_SHOW_TIMER, NULL);

				hDiskKey = GetDlgItem (hwndDlg, IDC_DISK_KEY);
				hHeaderKey = GetDlgItem (hwndDlg, IDC_HEADER_KEY);

				SendMessage (GetDlgItem (hwndDlg, IDC_RANDOM_BYTES), WM_SETFONT, (WPARAM) hSmallFont, (LPARAM) TRUE);
				SendMessage (GetDlgItem (hwndDlg, IDC_DISK_KEY), WM_SETFONT, (WPARAM) hSmallFont, (LPARAM) TRUE);
				SendMessage (GetDlgItem (hwndDlg, IDC_HEADER_KEY), WM_SETFONT, (WPARAM) hSmallFont, (LPARAM) TRUE);

				SetWindowText (GetDlgItem (hwndDlg, IDC_BOX_HELP), getmultilinestr (nID));
				SetWindowText (GetDlgItem (GetParent (hwndDlg), IDC_BOX_TITLE), getstr (IDS_FORMAT_TITLE));

				EnableWindow (GetDlgItem (hwndDlg, IDC_QUICKFORMAT), bDevice);

				SendMessage (GetDlgItem (hwndDlg, IDC_SHOW_KEYS), BM_SETCHECK, showKeys ? BST_CHECKED : BST_UNCHECKED, 0);
				SetWindowText (GetDlgItem (hwndDlg, IDC_RANDOM_BYTES), showKeys ? "" : "****************************");
				SetWindowText (GetDlgItem (hwndDlg, IDC_HEADER_KEY), showKeys ? "" : "****************************");
				SetWindowText (GetDlgItem (hwndDlg, IDC_DISK_KEY), showKeys ? "" : "****************************");

				SendMessage (GetDlgItem (hwndDlg, IDC_CLUSTERSIZE), CB_RESETCONTENT, 0, 0);
				AddComboPair (GetDlgItem (hwndDlg, IDC_CLUSTERSIZE), "Default", 0);
				AddComboPair (GetDlgItem (hwndDlg, IDC_CLUSTERSIZE), "0.5 KB", 1);
				AddComboPair (GetDlgItem (hwndDlg, IDC_CLUSTERSIZE), "1 KB", 2);
				AddComboPair (GetDlgItem (hwndDlg, IDC_CLUSTERSIZE), "2 KB", 4);
				AddComboPair (GetDlgItem (hwndDlg, IDC_CLUSTERSIZE), "4 KB", 8);
				AddComboPair (GetDlgItem (hwndDlg, IDC_CLUSTERSIZE), "8 KB", 16);
				AddComboPair (GetDlgItem (hwndDlg, IDC_CLUSTERSIZE), "16 KB", 32);
				AddComboPair (GetDlgItem (hwndDlg, IDC_CLUSTERSIZE), "32 KB", 64);
				AddComboPair (GetDlgItem (hwndDlg, IDC_CLUSTERSIZE), "64 KB", 128);
				SendMessage (GetDlgItem (hwndDlg, IDC_CLUSTERSIZE), CB_SETCURSEL, 0, 0);

				SendMessage (GetDlgItem (hwndDlg, IDC_FILESYS), CB_RESETCONTENT, 0, 0);
				AddComboPair (GetDlgItem (hwndDlg, IDC_FILESYS), "None", FILESYS_NONE);

				if (nFileSize * nMultiplier / 512 < 0x7FFFffff)
					AddComboPair (GetDlgItem (hwndDlg, IDC_FILESYS), "FAT", FILESYS_FAT);

				if (nFileSize * nMultiplier / 512 > 5050)
				AddComboPair (GetDlgItem (hwndDlg, IDC_FILESYS), "NTFS", FILESYS_NTFS);

				SendMessage (GetDlgItem (hwndDlg, IDC_FILESYS), CB_SETCURSEL, 1, 0);

				EnableWindow (GetDlgItem (hwndDlg, IDC_FILESYS), TRUE);
				EnableWindow (GetDlgItem (hwndDlg, IDC_CLUSTERSIZE), TRUE);
				EnableWindow (GetDlgItem (hwndDlg, IDC_CANCEL_BAR), FALSE);

				SetWindowText (GetDlgItem (GetParent (hwndDlg), IDC_NEXT), getstr (IDS_FINISH));
				SetWindowText (GetDlgItem (GetParent (hwndDlg), IDC_PREV), getstr (IDS_PREV));

				EnableWindow (GetDlgItem (GetParent (hwndDlg), IDC_PREV), TRUE);
				EnableWindow (GetDlgItem (GetParent (hwndDlg), IDC_NEXT), TRUE);

				SetFocus (GetDlgItem (GetParent (hwndDlg), IDC_NEXT));
			}
			break;

		}
		return 0;

	case WM_HELP:
		OpenPageHelp (GetParent (hwndDlg), nCurPageNo);
		return 1;

	case WM_COMMAND:
		if (lw == IDC_CANCEL_BAR && nCurPageNo == FORMAT_PAGE)
		{
			if (MessageBox (hwndDlg, getstr (IDS_FORMAT_ABORT), lpszTitle, MB_YESNO | MB_ICONQUESTION | MB_DEFBUTTON2 ) == IDYES)
				bThreadCancel = TRUE;
			return 1;
		}

		if (lw == IDC_CIPHER_TEST && nCurPageNo == CIPHER_PAGE)
		{
			LPARAM nIndex;
			nIndex = SendMessage (GetDlgItem (hCurPage, IDC_COMBO_BOX), CB_GETCURSEL, 0, 0);
			nVolCipher = SendMessage (GetDlgItem (hCurPage, IDC_COMBO_BOX), CB_GETITEMDATA, nIndex, 0);

			DialogBoxParam (hInst, MAKEINTRESOURCE (IDD_CIPHER_TEST_DLG), 
				GetParent (hwndDlg), (DLGPROC) CipherTestDialogProc, (LPARAM)nVolCipher );
			return 1;
		}

		if (hw == CBN_EDITCHANGE && nCurPageNo == FILE_PAGE)
		{
			int j = GetWindowTextLength (GetDlgItem (hCurPage, IDC_COMBO_BOX));
			if (j > 0)
				EnableWindow (GetDlgItem (GetParent (hwndDlg), IDC_NEXT), TRUE);
			else
				EnableWindow (GetDlgItem (GetParent (hwndDlg), IDC_NEXT), FALSE);
			return 1;
		}
		
		if (hw == CBN_SELCHANGE && nCurPageNo == FILE_PAGE)
		{
			LPARAM nIndex;

			nIndex = MoveEditToCombo ((HWND) lParam);
			nIndex = UpdateComboOrder (GetDlgItem (hwndDlg, IDC_COMBO_BOX));

			if (nIndex != CB_ERR)
				EnableWindow (GetDlgItem (GetParent (hwndDlg), IDC_NEXT), TRUE);
			else
				EnableWindow (GetDlgItem (GetParent (hwndDlg), IDC_NEXT), FALSE);

			return 1;
		}
		
		if (hw == EN_CHANGE && nCurPageNo == SIZE_PAGE)
		{
			VerifySizeAndUpdate (hwndDlg, FALSE);
			return 1;
		}
		
		if (hw == EN_CHANGE && nCurPageNo == PASSWORD_PAGE)
		{
			VerifyPasswordAndUpdate (hwndDlg, GetDlgItem (GetParent (hwndDlg), IDC_NEXT),
					 GetDlgItem (hwndDlg, IDC_PASSWORD),
					   GetDlgItem (hwndDlg, IDC_VERIFY),
						 NULL, NULL);
			return 1;
		}
		
		if ((lw == IDC_KB || lw == IDC_MB) && nCurPageNo == SIZE_PAGE)
		{
			VerifySizeAndUpdate (hwndDlg, FALSE);
			return 1;
		}
		
		if (lw == IDC_BROWSE_FILES && nCurPageNo == FILE_PAGE)
		{
			if (BrowseFiles (hwndDlg, IDS_OPEN_TITLE, szFileName) == FALSE)
				return 1;

			AddComboItem (GetDlgItem (hwndDlg, IDC_COMBO_BOX), szFileName);

			EnableDisableFileNext (GetDlgItem (hwndDlg, IDC_COMBO_BOX),
				GetDlgItem (GetParent (hwndDlg), IDC_NEXT));

			return 1;
		}
		
		if (lw == IDC_BROWSE_DEVICES && nCurPageNo == FILE_PAGE)
		{
			int nResult = DialogBoxParam (hInst,
						      MAKEINTRESOURCE (IDD_RAWDEVICES_DLG), GetParent (hwndDlg),
						      (DLGPROC) RawDevicesDlgProc, (LPARAM) & szFileName[0]);
			if (nResult == IDOK)
			{
				AddComboItem (GetDlgItem (hwndDlg, IDC_COMBO_BOX), szFileName);

				EnableDisableFileNext (GetDlgItem (hwndDlg, IDC_COMBO_BOX),
				GetDlgItem (GetParent (hwndDlg), IDC_NEXT));

			}
			return 1;
		}
		
		if (hw == CBN_SELCHANGE && nCurPageNo == CIPHER_PAGE)
		{
			ComboSelChangeCipher (hwndDlg);
			return 1;
		}

		if (lw == IDC_QUICKFORMAT && IsButtonChecked (GetDlgItem (hCurPage, IDC_QUICKFORMAT)))
		{
			MessageBox (hwndDlg, getstr (IDS_WARN_QUICK_FORMAT), lpszTitle, MB_OK | MB_ICONEXCLAMATION);
			return 1;
		}


		if (lw == IDC_SHOW_KEYS)
		{
			showKeys = IsButtonChecked (GetDlgItem (hCurPage, IDC_SHOW_KEYS));

			SetWindowText (GetDlgItem (hCurPage, IDC_RANDOM_BYTES), showKeys ? "" : "****************************");
			SetWindowText (GetDlgItem (hCurPage, IDC_HEADER_KEY), showKeys ? "" : "****************************");
			SetWindowText (GetDlgItem (hCurPage, IDC_DISK_KEY), showKeys ? "" : "****************************");
			return 1;
		}
		return 0;
	}

	return 0;
}

/* Except in response to the WM_INITDIALOG message, the dialog box procedure
   should return nonzero if it processes the message, and zero if it does
   not. - see DialogProc */
BOOL CALLBACK
MainDialogProc (HWND hwndDlg, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
	WORD lw = LOWORD (wParam);

	if (lParam);		/* Remove unused parameter warning */

	switch (uMsg)
	{
	case WM_INITDIALOG:
		{
			/* Call the common dialog init code */
			InitDialog (hwndDlg);
			LoadSettings (hwndDlg);

			SendMessage (GetDlgItem (hwndDlg, IDC_BOX_TITLE), WM_SETFONT, (WPARAM) hTitleFont, (LPARAM) TRUE);
			SetWindowText (hwndDlg, lpszTitle);

			ExtractCommandLine (hwndDlg, (char *) lParam);

			LoadPage (hwndDlg, FILE_PAGE);
		}
		return 0;

	case WM_SYSCOMMAND:
		if (lw == IDC_ABOUT)
		{
			DialogBox (hInst, MAKEINTRESOURCE (IDD_ABOUT_DLG), hwndDlg, (DLGPROC) AboutDlgProc);
			return 1;
		}
		return 0;

	case WM_TIMER:
		{
			char tmp[21];
			char tmp2[43];
			int i;

			if (!showKeys) return 1;

			SendMessage (GetDlgItem (hwndDlg, IDC_RANDOM_BYTES), WM_SETFONT, (WPARAM) hSmallFont, (LPARAM) TRUE);

			RandpeekBytes (tmp, sizeof (tmp));

			tmp2[0] = 0;

			for (i = 0; i < sizeof (tmp); i++)
			{
				char tmp3[8];
				sprintf (tmp3, "%02X", (int) (unsigned char) tmp[i]);
				strcat (tmp2, tmp3);
			}

			tmp2[42] = 0;

            SetWindowText (GetDlgItem (hCurPage, IDC_RANDOM_BYTES), tmp2);

			return 1;
		}

	case WM_FORMAT_FINISHED:
		EnableWindow (GetDlgItem (hwndDlg, IDC_PREV), TRUE);
		EnableWindow (GetDlgItem (hwndDlg, IDHELP), TRUE);
		EnableWindow (GetDlgItem (hwndDlg, IDCANCEL), TRUE);
		EnableWindow (GetDlgItem (hCurPage, IDC_QUICKFORMAT), bDevice);
		EnableWindow (GetDlgItem (hCurPage, IDC_FILESYS), TRUE);
		EnableWindow (GetDlgItem (hCurPage, IDC_CLUSTERSIZE), TRUE);
		EnableWindow (GetDlgItem (hCurPage, IDC_CANCEL_BAR), FALSE);
		EnableWindow (GetDlgItem (hwndDlg, IDC_NEXT), TRUE);
		SendMessage (GetDlgItem (hCurPage, IDC_PROGRESS_BAR), PBM_SETPOS, 0, 0L);
		SetFocus (GetDlgItem (hwndDlg, IDC_NEXT));
		if (nCurPageNo == FORMAT_PAGE)
			KillTimer (hwndDlg, 0xff);

		LoadPage (hwndDlg, 0);
		break;

	case WM_THREAD_ENDED:
		EnableWindow (GetDlgItem (hwndDlg, IDC_PREV), TRUE);
		EnableWindow (GetDlgItem (hwndDlg, IDHELP), TRUE);
		EnableWindow (GetDlgItem (hwndDlg, IDCANCEL), TRUE);
		EnableWindow (GetDlgItem (hCurPage, IDC_QUICKFORMAT), bDevice);
		EnableWindow (GetDlgItem (hCurPage, IDC_FILESYS), TRUE);
		EnableWindow (GetDlgItem (hCurPage, IDC_CLUSTERSIZE), TRUE);
		EnableWindow (GetDlgItem (hCurPage, IDC_CANCEL_BAR), FALSE);
		EnableWindow (GetDlgItem (hwndDlg, IDC_NEXT), TRUE);
		SendMessage (GetDlgItem (hCurPage, IDC_PROGRESS_BAR), PBM_SETPOS, 0, 0L);
		SetFocus (GetDlgItem (hwndDlg, IDC_NEXT));
		return 1;

	case WM_HELP:
		OpenPageHelp (hwndDlg, nCurPageNo);
		return 1;

	case WM_COMMAND:
		if (lw == IDHELP)
		{
			OpenPageHelp (hwndDlg, nCurPageNo);
			return 1;
		}
		if (lw == IDCANCEL)
		{
			EndMainDlg (hwndDlg);
			return 1;
		}
		if (lw == IDC_NEXT)
		{
			if (nCurPageNo == FILE_PAGE)
			{
				GetWindowText (GetDlgItem (hCurPage, IDC_COMBO_BOX), szFileName, sizeof (szFileName));
				CreateFullVolumePath (szDiskFile, szFileName, &bDevice);
				MoveEditToCombo (GetDlgItem (hCurPage, IDC_COMBO_BOX));
				
				bHistory = !IsButtonChecked (GetDlgItem (hCurPage, IDC_NO_HISTORY));

				SaveSettings (hCurPage);
			}

			if (nCurPageNo == CIPHER_PAGE)
			{
				LPARAM nIndex;
				nIndex = SendMessage (GetDlgItem (hCurPage, IDC_COMBO_BOX), CB_GETCURSEL, 0, 0);
				nVolCipher = SendMessage (GetDlgItem (hCurPage, IDC_COMBO_BOX), CB_GETITEMDATA, nIndex, 0);

				if (IsButtonChecked (GetDlgItem (hCurPage, IDC_SHA1)))		pkcs5 = SHA1;
				if (IsButtonChecked (GetDlgItem (hCurPage, IDC_RIPEMD160)))	pkcs5 = RIPEMD160;

				RandSetHashFunction (pkcs5);
			}

			if (nCurPageNo == SIZE_PAGE)
				VerifySizeAndUpdate (hCurPage, TRUE);

			if (nCurPageNo == PASSWORD_PAGE)
				VerifyPasswordAndUpdate (hwndDlg, GetDlgItem (hwndDlg, IDC_NEXT),
					GetDlgItem (hCurPage, IDC_PASSWORD),
					  GetDlgItem (hCurPage, IDC_VERIFY),
					    szPassword, szVerify);

			// Format start
			if (nCurPageNo == FORMAT_PAGE)
			{
				if (bThreadRunning == TRUE)
					return 1;
				else
					bThreadRunning = TRUE;

				bThreadCancel = FALSE;

				EnableWindow (GetDlgItem (hwndDlg, IDC_PREV), FALSE);
				EnableWindow (GetDlgItem (hwndDlg, IDC_NEXT), FALSE);
				EnableWindow (GetDlgItem (hwndDlg, IDHELP), FALSE);
				EnableWindow (GetDlgItem (hwndDlg, IDCANCEL), FALSE);
				EnableWindow (GetDlgItem (hCurPage, IDC_QUICKFORMAT), FALSE);
				EnableWindow (GetDlgItem (hCurPage, IDC_CLUSTERSIZE), FALSE);
				EnableWindow (GetDlgItem (hCurPage, IDC_FILESYS), FALSE);
				EnableWindow (GetDlgItem (hCurPage, IDC_CANCEL_BAR), TRUE);
				SetFocus (GetDlgItem (hCurPage, IDC_CANCEL_BAR));

				quickFormat = IsButtonChecked (GetDlgItem (hCurPage, IDC_QUICKFORMAT));

				fileSystem = SendMessage (GetDlgItem (hCurPage, IDC_FILESYS), CB_GETITEMDATA
					,SendMessage (GetDlgItem (hCurPage, IDC_FILESYS), CB_GETCURSEL, 0, 0) , 0);

				clusterSize = SendMessage (GetDlgItem (hCurPage, IDC_CLUSTERSIZE), CB_GETITEMDATA
					,SendMessage (GetDlgItem (hCurPage, IDC_CLUSTERSIZE), CB_GETCURSEL, 0, 0) , 0);

				_beginthread (formatThreadFunction, 4096, hwndDlg);
				return 1;
			}

			if (nCurPageNo == SIZE_PAGE && nVolCipher == NONE)
				LoadPage (hwndDlg, nCurPageNo + 2);
			else
				LoadPage (hwndDlg, nCurPageNo + 1);

			return 1;
		}
		if (lw == IDC_PREV)
		{
			if (nCurPageNo == FILE_PAGE)
			{
				GetWindowText (GetDlgItem (hCurPage, IDC_COMBO_BOX), szFileName, sizeof (szFileName));
				CreateFullVolumePath (szDiskFile, szFileName, &bDevice);
				MoveEditToCombo (GetDlgItem (hCurPage, IDC_COMBO_BOX));
				SaveSettings (hCurPage);
			}

			if (nCurPageNo == CIPHER_PAGE)
			{
				LPARAM nIndex;
				nIndex = SendMessage (GetDlgItem (hCurPage, IDC_COMBO_BOX), CB_GETCURSEL, 0, 0);
				nVolCipher = SendMessage (GetDlgItem (hCurPage, IDC_COMBO_BOX), CB_GETITEMDATA, nIndex, 0);

				if (IsButtonChecked (GetDlgItem (hCurPage, IDC_SHA1)))		pkcs5 = SHA1;
				if (IsButtonChecked (GetDlgItem (hCurPage, IDC_RIPEMD160)))	pkcs5 = RIPEMD160;

				RandSetHashFunction (pkcs5);
			}

			if (nCurPageNo == SIZE_PAGE)
				VerifySizeAndUpdate (hCurPage, TRUE);

			if (nCurPageNo == PASSWORD_PAGE)
				VerifyPasswordAndUpdate (hwndDlg, GetDlgItem (hwndDlg, IDC_NEXT),
					GetDlgItem (hCurPage, IDC_PASSWORD),
					  GetDlgItem (hCurPage, IDC_VERIFY),
					    szPassword, szVerify);

			if (nCurPageNo == FORMAT_PAGE)
				KillTimer (hwndDlg, 0xff);

			if (nCurPageNo == FORMAT_PAGE && nVolCipher == NONE)
				LoadPage (hwndDlg, nCurPageNo - 2);
			else
				LoadPage (hwndDlg, nCurPageNo - 1);

			return 1;
		}
		return 0;

	case WM_CLOSE:
		{
			if (bThreadRunning && MessageBox (hwndDlg, getstr (IDS_FORMAT_ABORT), lpszTitle, MB_YESNO | MB_ICONQUESTION | MB_DEFBUTTON2 ) == IDYES)
			{
				bThreadCancel = TRUE;
				return 1;
			}
			return 0;
		}

	}

	return 0;
}

void
ExtractCommandLine (HWND hwndDlg, char *lpszCommandLine)
{
	char **lpszCommandLineArgs;	/* Array of command line arguments */
	int nNoCommandLineArgs;	/* The number of arguments in the array */

	/* Extract command line arguments */
	nNoCommandLineArgs = Win32CommandLine (lpszCommandLine, &lpszCommandLineArgs);
	if (nNoCommandLineArgs > 0)
	{
		int i;

		for (i = 0; i < nNoCommandLineArgs; i++)
		{
			argument args[]=
			{
				{"/history", "/h"},
				{"/help", "/?"}
			};

			argumentspec as;

			int nArgPos;
			int x;

			as.args = args;
			as.arg_cnt = sizeof(args)/ sizeof(args[0]);
			
			x = GetArgumentID (&as, lpszCommandLineArgs[i], &nArgPos);

			switch (x)
			{
			case 'h':
				{
					char szTmp[8];
					GetArgumentValue (lpszCommandLineArgs, nArgPos, &i, nNoCommandLineArgs,
						     szTmp, sizeof (szTmp));
					if (!_stricmp(szTmp,"y") || !_stricmp(szTmp,"yes"))
					{
						bHistory = TRUE;
						bHistoryCmdLine = TRUE;
					}

					if (!_stricmp(szTmp,"n") || !_stricmp(szTmp,"no"))
					{
						bHistory = FALSE;
						bHistoryCmdLine = TRUE;
					}
				}
				break;

			case '?':
			default:
				DialogBoxParam (hInst, MAKEINTRESOURCE (IDD_COMMANDHELP_DLG), hwndDlg, (DLGPROC)
						CommandHelpDlgProc, (LPARAM) &as);

				exit(0);
			}
		}
	}

	/* Free up the command line arguments */
	while (--nNoCommandLineArgs >= 0)
	{
		free (lpszCommandLineArgs[nNoCommandLineArgs]);
	}
}

int WINAPI
WINMAIN (HINSTANCE hInstance, HINSTANCE hPrevInstance,
	 char *lpszCommandLine, int nCmdShow)
{
	int status;

	if (hPrevInstance && lpszCommandLine && nCmdShow);	/* Remove unused
								   parameter warning */
	InitCommonControls ();

	nPbar = IDC_PROGRESS_BAR;

	if (Randinit ())
		AbortProcess (IDS_INIT_RAND);

	RegisterRedTick(hInstance);

	atexit (localcleanup);

	/* Allocate, dup, then store away the application title */
	lpszTitle = err_strdup (getstr (IDS_TITLE));

	InitApp (hInstance);

	status = DriverAttach ();
	if (status != 0)
	{
		if (status == ERR_OS_ERROR)
			handleWin32Error (NULL);
		else
			handleError (NULL, status);

		AbortProcess (IDS_NODRIVER);
	}


	/* Create the main dialog box */
	DialogBoxParam (hInstance, MAKEINTRESOURCE (IDD_MKFS_DLG), NULL, (DLGPROC) MainDialogProc, 
		(LPARAM)lpszCommandLine);

	return 0;
}
