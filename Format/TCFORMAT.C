/* The source code contained in this file has been derived from the source code
   of Encryption for the Masses 2.02a by Paul Le Roux. Modifications and
   additions to that source code contained in this file are Copyright (c) 2004-2005
   TrueCrypt Foundation and Copyright (c) 2004 TrueCrypt Team. Unmodified
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
#include "../common/common.h"
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
	INTRO_PAGE,
	HIDDEN_VOL_WIZARD_MODE_PAGE,
	FILE_PAGE,
	HIDDEN_VOL_HOST_PRE_CIPHER_PAGE,
	HIDDEN_VOL_PRE_CIPHER_PAGE,
	CIPHER_PAGE,
	SIZE_PAGE,
	HIDVOL_HOST_PASSWORD_PAGE,
	PASSWORD_PAGE,
	FORMAT_PAGE,
	FORMAT_FINISHED_PAGE
};

HWND hCurPage = NULL;		/* Handle to current wizard page */
int nCurPageNo = -1;		/* The current wizard page */
int nVolumeEA = 1;			/* Default encryption algorithm */
BOOL bHiddenVol = FALSE;	/* If true, we are (or will be) creating a hidden volume. */
BOOL bHiddenVolHost = FALSE;	/* If true, we are (or will be) creating the host volume (called "outer") for a hidden volume. */
BOOL bHiddenVolDirect = FALSE;	/* If true, the wizard omits creating a host volume in the course of the process of hidden volume creation. */
BOOL bHiddenVolFinished = FALSE;
int hiddenVolHostDriveNo = -1;	/* Drive letter for the volume intended to host a hidden volume. */
int realClusterSize;		/* Parameter used when determining the maximum possible size of a hidden volume. */
int pkcs5 = SHA1;			/* Which PRF to use in header key derivation, default = HMAC-SHA-1 */
unsigned __int64 nUIVolumeSize = 0;		/* The volume size. Important: This value is not in bytes. It has to be multiplied by nMultiplier. Do not use this value when actually creating the volume (it may chop off 512 bytes, if it is not a multiple of 1024 bytes). */
unsigned __int64 nVolumeSize = 0;		/* The volume size, in bytes. */
unsigned __int64 nHiddenVolHostSize = 0;	/* Size of the hidden volume host, in bytes */
__int64 nMaximumHiddenVolSize = 0;		/* Maximum possible size of the hidden volume, in bytes */
int nMultiplier = 1024*1024;		/* Size selection multiplier.  */
char szFileName[TC_MAX_PATH];	/* The file selected by the user */
char szDiskFile[TC_MAX_PATH];	/* Fully qualified name derived from szFileName */

BOOL bThreadCancel = FALSE;		/* TRUE if the user cancels the volume formatting */
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
	if (IsNonInstallMode ()) return;

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
ComboSelChangeEA (HWND hwndDlg)
{
	LPARAM nIndex = SendMessage (GetDlgItem (hwndDlg, IDC_COMBO_BOX), CB_GETCURSEL, 0, 0);

	if (nIndex == CB_ERR)
	{
		SetWindowText (GetDlgItem (hwndDlg, IDC_BOX_HELP), "");
	}
	else
	{
		char name[100];
		char auxLine[1024];
		char tmpStr[256];
		char cipherIDs[5];
		int i, cnt = 0;

		UINT nID[4];

		nIndex = SendMessage (GetDlgItem (hwndDlg, IDC_COMBO_BOX), CB_GETITEMDATA, nIndex, 0);
		EAGetName (name, nIndex);

		memset (nID, 0, sizeof (nID));

		if (strcmp (name, "Blowfish") == 0)
		{
			nID[0] = IDS_BLOWFISH_HELP0;
			nID[1] = IDS_BLOWFISH_HELP1;
			SetWindowText (GetDlgItem (hwndDlg, IDC_BOX_HELP), getmultilinestr (nID));
		}
		else if (strcmp (name, "AES") == 0)
		{
			nID[0] = IDS_AES_HELP0;
			nID[1] = IDS_AES_HELP1;
			SetWindowText (GetDlgItem (hwndDlg, IDC_BOX_HELP), getmultilinestr (nID));
		}
		else if (strcmp (name, "CAST5") == 0)
		{
			nID[0] = IDS_CAST_HELP0;
			nID[1] = IDS_CAST_HELP1;
			SetWindowText (GetDlgItem (hwndDlg, IDC_BOX_HELP), getmultilinestr (nID));
		}
		else if (strcmp (name, "Serpent") == 0)
		{
			nID[0] = IDS_SERPENT_HELP0;
			nID[1] = IDS_SERPENT_HELP1;
			SetWindowText (GetDlgItem (hwndDlg, IDC_BOX_HELP), getmultilinestr (nID));
		}
		else if (strcmp (name, "Triple DES") == 0)
		{
			nID[0] = IDS_TRIPLEDES_HELP0;
			nID[1] = IDS_TRIPLEDES_HELP1;
			SetWindowText (GetDlgItem (hwndDlg, IDC_BOX_HELP), getmultilinestr (nID));
		}
		else if (strcmp (name, "Twofish") == 0)
		{
			nID[0] = IDS_TWOFISH_HELP0;
			nID[1] = IDS_TWOFISH_HELP1;
			SetWindowText (GetDlgItem (hwndDlg, IDC_BOX_HELP), getmultilinestr (nID));
		}
		else if (EAGetCipherCount (nIndex) > 1)
		{
			// Cascade

			switch (EAGetMode(nIndex))
			{
			case INNER_CBC:
				sprintf(tmpStr, "sector");
				break;

			case OUTER_CBC:
				sprintf(tmpStr, "block");
				break;

			default:
				sprintf(tmpStr, "[?]");
				break;
			}

			cipherIDs[cnt++] = i = EAGetLastCipher(nIndex);
			while (i = EAGetPreviousCipher(nIndex, i))
			{
				cipherIDs[cnt] = i;
				cnt++; 
			}

			switch (cnt)	// Number of ciphers in the cascade
			{
			case 2:
				nID[0] = IDS_TWO_LAYER_CASCADE_HELP0;
				nID[1] = IDS_TWO_LAYER_CASCADE_HELP1;

				sprintf (auxLine, getmultilinestr (nID), 
					EAGetModeName(name, nIndex, FALSE),
					tmpStr,
					CipherGetName (cipherIDs[1]),
					CipherGetKeySize (cipherIDs[1])*8,
					CipherGetName (cipherIDs[0]),
					CipherGetKeySize (cipherIDs[0])*8);
				break;

			case 3:
				nID[0] = IDS_THREE_LAYER_CASCADE_HELP0;
				nID[1] = IDS_THREE_LAYER_CASCADE_HELP1;

				sprintf (auxLine, getmultilinestr (nID), 
					EAGetModeName(name, nIndex, FALSE),
					tmpStr,
					CipherGetName (cipherIDs[2]),
					CipherGetKeySize (cipherIDs[2])*8,
					CipherGetName (cipherIDs[1]),
					CipherGetKeySize (cipherIDs[1])*8,
					CipherGetName (cipherIDs[0]),
					CipherGetKeySize (cipherIDs[0])*8);
				break;

			default:
				nID[0] = IDS_CIPHER_NONE_HELP0;
				break;
			}


			SetWindowText (GetDlgItem (hwndDlg, IDC_BOX_HELP), auxLine);
		}
		else
		{
			// No info available for this encryption algorithm

			nID[0] = IDS_CIPHER_NONE_HELP0;		
			SetWindowText (GetDlgItem (hwndDlg, IDC_BOX_HELP), getmultilinestr (nID));
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

	if (IsButtonChecked (GetDlgItem (hwndDlg, IDC_KB)) == TRUE)
		nMultiplier = BYTES_PER_KB;
	else
		nMultiplier = BYTES_PER_MB;

	if (bDevice && !(bHiddenVol && !bHiddenVolHost))	// If raw device but not a hidden volume
	{
		lTmp = nVolumeSize;
		i = 1;
	}
	else
	{
		i = nMultiplier;
		lTmp = atoi64 (szTmp);
	}

	if (bEnable == TRUE)
	{
		if (lTmp * i < (bHiddenVolHost ? MIN_HIDDEN_VOLUME_HOST_SIZE : MIN_VOLUME_SIZE))
			bEnable = FALSE;

		if (!bHiddenVolHost && bHiddenVol)
		{
			if (lTmp * i > nMaximumHiddenVolSize)
				bEnable = FALSE;
		}
		else
		{
			if (lTmp * i > (bHiddenVolHost ? MAX_HIDDEN_VOLUME_HOST_SIZE : MAX_VOLUME_SIZE))
				bEnable = FALSE;
		}

		if (lTmp * i % SECTOR_SIZE != 0)
			bEnable = FALSE;
	}

	if (bUpdate == TRUE)
	{
		nUIVolumeSize = lTmp;

		if (!bDevice || (bHiddenVol && !bHiddenVolHost))	// Update only if it's not a raw device or if it's a hidden volume
			nVolumeSize = i * lTmp;
	}

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

	// Check administrator privileges
	if (!IsAdmin())
	{
		if (fileSystem == FILESYS_NTFS)
		{
			if (MessageBox (hwndDlg, getstr (IDS_ADMIN_PRIVILEGES_WARN_NTFS), lpszTitle, MB_OKCANCEL|MB_ICONWARNING|MB_DEFBUTTON2) == IDCANCEL)
				goto cancel;
		}
		if (bDevice)
		{
			if (MessageBox (hwndDlg, getstr (IDS_ADMIN_PRIVILEGES_WARN_DEVICES), lpszTitle, MB_OKCANCEL|MB_ICONWARNING|MB_DEFBUTTON2) == IDCANCEL)
				goto cancel;
		}
	}

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

			if (! ((bHiddenVol && !bHiddenVolHost) && nID == IDS_OVERWRITEPROMPT))	// Only ask ask for permission to overwrite an existing volume if we're not creating a hidden volume
			{
				sprintf (szTmp, getstr (nID), szDiskFile);
				x = MessageBox (hwndDlg, szTmp, lpszTitle, YES_NO|MB_ICONWARNING|MB_DEFBUTTON2);

				if (x != IDYES)
					goto cancel;
			}
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
		int x;
		char szTmp[512];
		int driveNo;
		WCHAR deviceName[MAX_PATH];

		strcpy ((char *)deviceName, szFileName);
		ToUNICODE ((char *)deviceName);

		driveNo = GetDiskDeviceDriveLetter (deviceName);

		if (!(bHiddenVol && !bHiddenVolHost))	// Do not ask for permission to overwrite an existing volume if we're creating a hidden volume within it
		{
			char drive[] = { driveNo == -1 ? 0 : '(', driveNo + 'A', ':', ')', ' ', 0 };
			char type[20];

			if (strstr (szFileName, "Partition"))
				strcpy (type, strstr (szFileName, "Partition0") == NULL ? "partition" : "device");
			else
				strcpy (type, "device");

			sprintf (szTmp, getstr (IDS_OVERWRITEPROMPT_DEVICE), type, szFileName, drive);

			x = MessageBox (hwndDlg, szTmp, lpszTitle, YES_NO|MB_ICONWARNING|MB_DEFBUTTON2);
			if (x != IDYES)
				goto cancel;
		}

		// Dismount drive if needed
		if (driveNo != -1)
		{
			CloseHandle (DismountDrive (driveNo));
		}

		// If we are encrypting whole device, dismount all partitions located on it first
		if (strstr (szFileName, "\\Partition0"))
		{
			int i, diskNo;
			if (sscanf (szFileName, "\\Device\\Harddisk%d\\", &diskNo) == 1)
			{	
				for (i = 1; i < 32; i++)
				{
					sprintf ((char *)deviceName, "\\Device\\Harddisk%d\\Partition%d", diskNo, i);
					ToUNICODE ((char *)deviceName);

					driveNo = GetDiskDeviceDriveLetter (deviceName);

					if (driveNo != -1)
					{
						if (quickFormat && i > 1)
						{ 
							// Quickformat prevents overwriting of existing filesystems and
							// an eventual remount could corrupt the volume
							MessageBox (hwndDlg, getstr (IDS_ERR_MOUNTED_FILESYSTEMS), lpszTitle, MB_ICONSTOP);
							goto cancel;
						}

						// Handle to dismounted volumes intentionally left open till program exit
						// to prevent remount during format
						DismountDrive (driveNo); 
					}
				}
			}
		}

		nDosLinkCreated = FakeDosNameForDevice (szDiskFile, szDosDevice, szCFDevice, FALSE);
		if (nDosLinkCreated != 0)
		{
			handleWin32Error (hwndDlg);
			goto cancel;
		}
	}

	ArrowWaitCursor ();

	nStatus = FormatVolume (szCFDevice,
				bDevice,
				szDiskFile,
				nVolumeSize,
				nHiddenVolHostSize,
				szPassword,
				nVolumeEA,
				pkcs5,
				quickFormat,
				fileSystem,
				clusterSize,
				summaryMsg,
				hwndDlg,
				bHiddenVol && !bHiddenVolHost,
				&realClusterSize);

	NormalCursor ();

	if (nStatus == ERR_OUTOFMEMORY)
	{
		AbortProcess (IDS_OUTOFMEMORY);
	}

	dwWin32FormatError = GetLastError ();

	if (bHiddenVolHost && !bThreadCancel)
	{
		/* Auto mount the newly created hidden volume host */
		switch (MountHiddenVolHost (hwndDlg, szDiskFile, &hiddenVolHostDriveNo, szPassword))
		{
		case ERR_NO_FREE_DRIVES:
			MessageBox (hwndDlg, "Error: No free drive letter for the outer volume!\nVolume creation cannot continue.", lpszTitle, ICON_HAND);
			break;
		case ERR_VOL_MOUNT_FAILED:
			MessageBox (hwndDlg, "Error: Cannot mount the outer volume!\nVolume creation cannot continue.", lpszTitle, ICON_HAND);
			break;
		}
	}

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

		if (!(bHiddenVolHost && hiddenVolHostDriveNo < 0))  // If the error was not that the hidden volume host could not be mounted (this error has already been reported to the user)
		{
			sprintf (szMsg, getstr (IDS_CREATE_FAILED), szDiskFile);
			MessageBox (hwndDlg, szMsg, lpszTitle, ICON_HAND);
		}

		if (bDevice == FALSE)
			remove (szCFDevice);

		goto cancel;
	}
	else
	{
		/* Volume successfully created */

		NormalCursor ();

		if (!bHiddenVolHost)
		{
			/* Create the volstats dialog box */
			DialogBoxParam (hInst, MAKEINTRESOURCE (IDD_VOLSTATS_DLG), hwndDlg,
				(DLGPROC) VolstatsDlgProc, (LPARAM) & summaryMsg[0]);

			if (bHiddenVol)
				bHiddenVolFinished = TRUE;
		}
		else
		{
			/* We've just created an outer volume (to host a hidden volume within) */

			MessageBeep (-1);
			bHiddenVolHost = FALSE; 
			bHiddenVolFinished = FALSE;
			nHiddenVolHostSize = nVolumeSize;

			// Clear the outer volume password
			memset(&szPassword[0], 0, sizeof (szPassword));
			memset(&szVerify[0], 0, sizeof (szVerify));
		}

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

	if (bHiddenVolHost && hiddenVolHostDriveNo < -1 && !bThreadCancel)	// If hidden volume host could not be mounted
		AbortProcessSilent ();

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
	case INTRO_PAGE:
		hCurPage = CreateDialog (hInst, MAKEINTRESOURCE (IDD_INTRO_PAGE_DLG), hwndDlg,
					 (DLGPROC) PageDialogProc);
		break;

	case HIDDEN_VOL_WIZARD_MODE_PAGE:
		hCurPage = CreateDialog (hInst, MAKEINTRESOURCE (IDD_HIDDEN_VOL_WIZARD_MODE_PAGE_DLG), hwndDlg,
					 (DLGPROC) PageDialogProc);
		break;

	case FILE_PAGE:

		hCurPage = CreateDialog (hInst, MAKEINTRESOURCE (IDD_FILE_PAGE_DLG), hwndDlg,
					 (DLGPROC) PageDialogProc);
		
		if (bHistoryCmdLine == TRUE)
			EnableWindow (GetDlgItem(hCurPage, IDC_NO_HISTORY),  FALSE);
		else
			EnableWindow (GetDlgItem(hCurPage, IDC_NO_HISTORY),  TRUE);
		break;

	case HIDDEN_VOL_HOST_PRE_CIPHER_PAGE:
		hCurPage = CreateDialog (hInst, MAKEINTRESOURCE (IDD_INFO_PAGE_DLG), hwndDlg,
					 (DLGPROC) PageDialogProc);
		break;
	case HIDDEN_VOL_PRE_CIPHER_PAGE:
		hCurPage = CreateDialog (hInst, MAKEINTRESOURCE (IDD_INFO_PAGE_DLG), hwndDlg,
					 (DLGPROC) PageDialogProc);
		break;
	case CIPHER_PAGE:
		hCurPage = CreateDialog (hInst, MAKEINTRESOURCE (IDD_CIPHER_PAGE_DLG), hwndDlg,
					 (DLGPROC) PageDialogProc);
		break;
	case SIZE_PAGE:
		hCurPage = CreateDialog (hInst, MAKEINTRESOURCE (IDD_SIZE_PAGE_DLG), hwndDlg,
					 (DLGPROC) PageDialogProc);
		break;
	case HIDVOL_HOST_PASSWORD_PAGE:
		hCurPage = CreateDialog (hInst, MAKEINTRESOURCE (IDD_HIDVOL_HOST_PASSWORD_PAGE_DLG), hwndDlg,
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
	case FORMAT_FINISHED_PAGE:
		hCurPage = CreateDialog (hInst, MAKEINTRESOURCE ((bHiddenVol && !bHiddenVolHost && !bHiddenVolFinished) ? IDD_HIDVOL_HOST_FILL_PAGE_DLG : IDD_INFO_PAGE_DLG), hwndDlg,
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
		switch (nPageNo)
		{
		case PASSWORD_PAGE:
			CheckCapsLock (hwndDlg, FALSE);
			break;
		}

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
	{
		if (bHiddenVol && !bHiddenVolHost)	// If it's a hidden volume
			nResourceString = IDS_MAX_HIDVOL_SIZE_BYTES;
		else if (bDevice == TRUE)
			nResourceString = IDS_DEVICE_FREE_BYTES;
		else
			nResourceString = IDS_DISK_FREE_BYTES;
	}
	else if (nMultiplier == BYTES_PER_KB)
	{
		if (bHiddenVol && !bHiddenVolHost)	// If it's a hidden volume
			nResourceString = IDS_MAX_HIDVOL_SIZE_KB;
		else if (bDevice == TRUE)
			nResourceString = IDS_DEVICE_FREE_KB;
		else
			nResourceString = IDS_DISK_FREE_KB;
	}
	else 
	{
		if (bHiddenVol && !bHiddenVolHost)	// If it's a hidden volume
			nResourceString = IDS_MAX_HIDVOL_SIZE_MB;
		else if (bDevice == TRUE)
			nResourceString = IDS_DEVICE_FREE_MB;
		else
			nResourceString = IDS_DISK_FREE_MB;
	}
 
	if (bHiddenVol && !bHiddenVolHost)	// If it's a hidden volume
	{
		sprintf (szTmp2, getstr (nResourceString), ((double) lDiskFree->QuadPart) / nMultiplier);
		SetWindowText (GetDlgItem (hwndTextBox, IDC_SIZEBOX), szTmp2);
	}
	else
		sprintf (szTmp2, getstr (nResourceString), lpszDrive, ((double) lDiskFree->QuadPart) / nMultiplier);

	SetWindowText (hwndTextBox, szTmp2);

	if (lDiskFree->QuadPart % (__int64) BYTES_PER_MB != 0)
		nMultiplier = BYTES_PER_KB;

	return nMultiplier;
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


// Note: GetFileVolSize is not to be used for devices (only for file-hosted volumes)
BOOL GetFileVolSize (HWND hwndDlg, unsigned __int64 *size)
{
	LARGE_INTEGER fileSize;
	HANDLE hFile;

	FILETIME ftLastAccessTime;
	BOOL bTimeStampValid = FALSE;

	hFile = CreateFile (szFileName, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);

	if (hFile == INVALID_HANDLE_VALUE)
	{
		MessageBox (hwndDlg, "Error: Cannot access the volume!\n\nMake sure that the selected volume exists, that it is\nnot being used by the system or an application, and\nthat it is not write-protected.", lpszTitle, ICON_HAND);
		return FALSE;
	}

	/* Remember the container timestamp (used to reset file date and time of file-hosted
	   containers to preserve plausible deniability of hidden volumes)  */
	if (GetFileTime (hFile, NULL, &ftLastAccessTime, NULL) == 0)
	{
		bTimeStampValid = FALSE;
		MessageBox (hwndDlg, getstr (IDS_GETFILETIME_FAILED_IMPLANT), "TrueCrypt", MB_OK | MB_ICONEXCLAMATION);
	}
	else
		bTimeStampValid = TRUE;


	if (GetFileSizeEx(hFile, &fileSize) == 0)
	{
		MessageBox (hwndDlg, "Error: Cannot get volume size!\n\nMake sure the selected volume is not being used\nby the system or an application.", lpszTitle, ICON_HAND);
		if (bTimeStampValid)
		{
			// Restore the container timestamp (to preserve plausible deniability). 
			if (SetFileTime (hFile, NULL, &ftLastAccessTime, NULL) == 0)
				MessageBox (hwndDlg, getstr (IDS_SETFILETIME_FAILED_PREP_IMPLANT), "TrueCrypt", MB_OK | MB_ICONEXCLAMATION);
		}
		CloseHandle (hFile);
		return FALSE;
	}

	if (bTimeStampValid)
	{
		// Restore the container timestamp (to preserve plausible deniability). 
		if (SetFileTime (hFile, NULL, &ftLastAccessTime, NULL) == 0)
			MessageBox (hwndDlg, getstr (IDS_SETFILETIME_FAILED_PREP_IMPLANT), "TrueCrypt", MB_OK | MB_ICONEXCLAMATION);
	}
	CloseHandle (hFile);
	*size = fileSize.QuadPart;
	return TRUE;
}


BOOL
QueryFreeSpace (HWND hwndDlg, HWND hwndTextBox, BOOL display)
{
	if (bHiddenVol && !bHiddenVolHost)	// If it's a hidden volume
	{
		LARGE_INTEGER lDiskFree;
		char szTmp[TC_MAX_PATH];

		lDiskFree.QuadPart = nMaximumHiddenVolSize;

		if (display)
			PrintFreeSpace (hwndTextBox, szTmp, &lDiskFree);

		return TRUE;
	}
	else if (bDevice == FALSE)
	{
		char szTmp[TC_MAX_PATH];
		ULARGE_INTEGER free;
		BOOL bResult;

		bResult = GetDiskFreeSpaceEx (MakeRootName (szTmp, szFileName), &free, 0, 0);

		if (bResult == FALSE)
		{
			if (display)
				DisplaySizingErrorText (hwndTextBox);

			return FALSE;
		}
		else
		{
			LARGE_INTEGER lDiskFree;
			lDiskFree.QuadPart = free.QuadPart;

			if (display)
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
			if (display)
				DisplaySizingErrorText (hwndTextBox);

			return FALSE;
		}

		dev = CreateFile (szCFDevice, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);

		if (dev == INVALID_HANDLE_VALUE)
		{
			int nStatus;

			if (display)
				DisplaySizingErrorText (hwndTextBox);

			nStatus = RemoveFakeDosName (szDiskFile, szDosDevice);
			if (nStatus != 0)
				handleWin32Error (hwndDlg);

			return FALSE;
		}
		else
		{
			DISK_GEOMETRY driveInfo;
			PARTITION_INFORMATION diskInfo;
			DWORD dwResult;
			int nStatus;
			BOOL bResult;

			nStatus = RemoveFakeDosName (szDiskFile, szDosDevice);
			if (nStatus != 0)
				handleWin32Error (hwndDlg);

			// Query partition size
			bResult = DeviceIoControl (dev, IOCTL_DISK_GET_PARTITION_INFO, NULL, 0,
				&diskInfo, sizeof (diskInfo), &dwResult, NULL);

			if (bResult == TRUE)
			{
				if (bResult == TRUE)
				{
					nVolumeSize = diskInfo.PartitionLength.QuadPart;

					if(display)
						nMultiplier = PrintFreeSpace (hwndTextBox, szDiskFile, &diskInfo.PartitionLength);

					nUIVolumeSize = diskInfo.PartitionLength.QuadPart / nMultiplier;

					if (nVolumeSize == 0)
					{
						if (display)
							SetWindowText (hwndTextBox, getstr (IDS_EXT_PARTITION));

						CloseHandle (dev);
						return FALSE;
					}
				}
			}
			else
			{
				LARGE_INTEGER lDiskFree;

				// Drive geometry info is used only when IOCTL_DISK_GET_PARTITION_INFO fails
				bResult = DeviceIoControl (dev, IOCTL_DISK_GET_DRIVE_GEOMETRY, NULL, 0,
					&driveInfo, sizeof (driveInfo), &dwResult, NULL);

				if (!bResult)
				{
					if (display)
						DisplaySizingErrorText (hwndTextBox);

					CloseHandle (dev);
					return FALSE;
				}

				lDiskFree.QuadPart = driveInfo.Cylinders.QuadPart * driveInfo.BytesPerSector *
				    driveInfo.SectorsPerTrack * driveInfo.TracksPerCylinder;

				nVolumeSize = lDiskFree.QuadPart;

				if (display)
					nMultiplier = PrintFreeSpace (hwndTextBox, szDiskFile, &lDiskFree);

				nUIVolumeSize = lDiskFree.QuadPart / nMultiplier;
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
			nVolumeSize = lDiskFree.QuadPart;

			if (display)
				nMultiplier = PrintFreeSpace (hwndTextBox, szDiskFile, &lDiskFree);

			nUIVolumeSize = lDiskFree.QuadPart / nMultiplier;
		}
		else
		{
			if (display)
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
SelectEA (HWND hComboBox, int *ea)
{
	LPARAM nCount = SendMessage (hComboBox, CB_GETCOUNT, 0, 0);
	LPARAM x, i;

	for (i = 0; i < nCount; i++)
	{
		x = SendMessage (hComboBox, CB_GETITEMDATA, i, 0);
		if (x == (LPARAM) * ea)
		{
			SendMessage (hComboBox, CB_SETCURSEL, i, 0);
			return;
		}
	}

	/* Something went wrong ; couldn't find the old ea so we drop
	   back to a default */

	*ea = SendMessage (hComboBox, CB_GETITEMDATA, 0, 0);

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
		case INTRO_PAGE:
			{
				UINT nID[4];

				nID[0] = IDS_INTRO_HELP0;
				nID[1] = IDS_INTRO_HELP1;
				nID[2] = IDS_INTRO_HELP2;
				nID[3] = IDS_INTRO_HELP3;

				SetWindowText (GetDlgItem (GetParent (hwndDlg), IDC_BOX_TITLE), getstr (IDS_INTRO_TITLE));

				CheckButton (GetDlgItem (hwndDlg, bHiddenVol ? IDC_HIDDEN_VOL : IDC_STD_VOL));

				SetWindowText (GetDlgItem (hwndDlg, IDC_BOX_HELP), getmultilinestr (nID));

				EnableWindow (GetDlgItem (hwndDlg, IDC_STD_VOL), TRUE);
				EnableWindow (GetDlgItem (hwndDlg, IDC_HIDDEN_VOL), TRUE);

				SetWindowText (GetDlgItem (GetParent (hwndDlg), IDC_NEXT), getstr (IDS_NEXT));
				SetWindowText (GetDlgItem (GetParent (hwndDlg), IDC_PREV), getstr (IDS_PREV));
				SetWindowText (GetDlgItem (GetParent (hwndDlg), IDCANCEL), getstr (IDS_CANCEL));
				EnableWindow (GetDlgItem (GetParent (hwndDlg), IDC_NEXT), TRUE);
				EnableWindow (GetDlgItem (GetParent (hwndDlg), IDC_PREV), FALSE);

			}
			break;

		case HIDDEN_VOL_WIZARD_MODE_PAGE:
			{
				UINT nID[4];

				nID[0] = IDS_HIDDEN_VOL_WIZARD_MODE_HELP0;
				nID[1] = IDS_HIDDEN_VOL_WIZARD_MODE_HELP1;
				nID[2] = IDS_HIDDEN_VOL_WIZARD_MODE_HELP2;
				nID[3] = IDS_HIDDEN_VOL_WIZARD_MODE_HELP3;

				SetWindowText (GetDlgItem (GetParent (hwndDlg), IDC_BOX_TITLE), getstr (IDS_HIDDEN_VOL_WIZARD_MODE_TITLE));

				CheckButton (GetDlgItem (hwndDlg, bHiddenVolDirect ? IDC_HIDVOL_WIZ_MODE_DIRECT : IDC_HIDVOL_WIZ_MODE_FULL));

				SetWindowText (GetDlgItem (hwndDlg, IDC_BOX_HELP), getmultilinestr (nID));

				EnableWindow (GetDlgItem (hwndDlg, IDC_HIDVOL_WIZ_MODE_DIRECT), TRUE);
				EnableWindow (GetDlgItem (hwndDlg, IDC_HIDVOL_WIZ_MODE_FULL), TRUE);

				SetWindowText (GetDlgItem (GetParent (hwndDlg), IDC_NEXT), getstr (IDS_NEXT));
				SetWindowText (GetDlgItem (GetParent (hwndDlg), IDC_PREV), getstr (IDS_PREV));
				SetWindowText (GetDlgItem (GetParent (hwndDlg), IDCANCEL), getstr (IDS_CANCEL));
				EnableWindow (GetDlgItem (GetParent (hwndDlg), IDC_NEXT), TRUE);
				EnableWindow (GetDlgItem (GetParent (hwndDlg), IDC_PREV), TRUE);

			}
			break;

		case FILE_PAGE:
			{
				UINT nID[4] = { 0,0,0,0 };

				if (bHiddenVolDirect && bHiddenVolHost)
				{
					nID[0] = IDS_FILE_HELP0_HIDDEN_HOST_VOL_DIRECT;
					nID[1] = 0;
				}
				else
				{
					nID[0] = bHiddenVolHost ? IDS_FILE_HELP0_HIDDEN_HOST_VOL : IDS_FILE_HELP0;
					nID[1] = bHiddenVolHost ? IDS_FILE_HELP1_HIDDEN_HOST_VOL : IDS_FILE_HELP1;
				}

				SendMessage (GetDlgItem (hwndDlg, IDC_COMBO_BOX), CB_RESETCONTENT, 0, 0);

				SendMessage (GetDlgItem (hwndDlg, IDC_COMBO_BOX), CB_LIMITTEXT, TC_MAX_PATH, 0);

				LoadSettings (hwndDlg);

				SendMessage (GetDlgItem (hwndDlg, IDC_NO_HISTORY), BM_SETCHECK, bHistory ? BST_UNCHECKED : BST_CHECKED, 0);

				SetWindowText (GetDlgItem (GetParent (hwndDlg), IDC_BOX_TITLE), getstr (IDS_FILE_TITLE));
				SetWindowText (GetDlgItem (hwndDlg, IDC_BOX_HELP), getmultilinestr (nID));

				SetFocus (GetDlgItem (hwndDlg, IDC_COMBO_BOX));

				SetWindowText (GetDlgItem (GetParent (hwndDlg), IDC_NEXT), getstr (IDS_NEXT));
				SetWindowText (GetDlgItem (GetParent (hwndDlg), IDC_PREV), getstr (IDS_PREV));
				EnableWindow (GetDlgItem (GetParent (hwndDlg), IDC_PREV), TRUE);

				AddComboItem (GetDlgItem (hwndDlg, IDC_COMBO_BOX), szFileName);

				EnableDisableFileNext (GetDlgItem (hwndDlg, IDC_COMBO_BOX),
				GetDlgItem (GetParent (hwndDlg), IDC_NEXT));

			}
			break;

		case HIDDEN_VOL_HOST_PRE_CIPHER_PAGE:
			{
				UINT nID[4];

				nID[0] = IDS_HIDVOL_HOST_PRE_CIPHER_HELP0;
				nID[1] = IDS_HIDVOL_HOST_PRE_CIPHER_HELP1;
				nID[2] = IDS_HIDVOL_HOST_PRE_CIPHER_HELP2;
				nID[3] = IDS_HIDVOL_HOST_PRE_CIPHER_HELP3;

				SetWindowText (GetDlgItem (GetParent (hwndDlg), IDC_BOX_TITLE), getstr (IDS_HIDVOL_HOST_PRE_CIPHER_TITLE));

				SetWindowText (GetDlgItem (hwndDlg, IDC_BOX_HELP), getmultilinestr (nID));

				SetWindowText (GetDlgItem (GetParent (hwndDlg), IDC_NEXT), getstr (IDS_NEXT));
				SetWindowText (GetDlgItem (GetParent (hwndDlg), IDC_PREV), getstr (IDS_PREV));
				EnableWindow (GetDlgItem (GetParent (hwndDlg), IDC_NEXT), TRUE);
				EnableWindow (GetDlgItem (GetParent (hwndDlg), IDC_PREV), TRUE);

			}
			break;

		case HIDDEN_VOL_PRE_CIPHER_PAGE:
			{
				UINT nID[4];

				nID[0] = IDS_HIDVOL_PRE_CIPHER_HELP0;
				nID[1] = 0;
				nID[2] = 0;
				nID[3] = 0;

				SetWindowText (GetDlgItem (GetParent (hwndDlg), IDC_BOX_TITLE), getstr (IDS_HIDVOL_PRE_CIPHER_TITLE));

				SetWindowText (GetDlgItem (hwndDlg, IDC_BOX_HELP), getmultilinestr (nID));

				SetWindowText (GetDlgItem (GetParent (hwndDlg), IDC_NEXT), getstr (IDS_NEXT));
				SetWindowText (GetDlgItem (GetParent (hwndDlg), IDC_PREV), getstr (IDS_PREV));
				EnableWindow (GetDlgItem (GetParent (hwndDlg), IDC_NEXT), TRUE);
				EnableWindow (GetDlgItem (GetParent (hwndDlg), IDC_PREV), FALSE);

			}
			break;

		case CIPHER_PAGE:
			{
				int ea;
				char buf[100];

				SendMessage (GetDlgItem (hwndDlg, IDC_COMBO_BOX), CB_RESETCONTENT, 0, 0);

				if (bHiddenVol)
					SetWindowText (GetDlgItem (GetParent (hwndDlg), IDC_BOX_TITLE), getstr (bHiddenVolHost ? IDS_CIPHER_HIDVOL_HOST_TITLE : IDS_CIPHER_HIDVOL_TITLE));
				else
					SetWindowText (GetDlgItem (GetParent (hwndDlg), IDC_BOX_TITLE), getstr (IDS_CIPHER_TITLE));

				for (ea = EAGetFirst (); ea != 0; ea = EAGetNext (ea))
				{
					AddComboPair (GetDlgItem (hwndDlg, IDC_COMBO_BOX), EAGetName (buf, ea), ea);
				}

				SelectEA (GetDlgItem (hwndDlg, IDC_COMBO_BOX), &nVolumeEA);
				ComboSelChangeEA (hwndDlg);
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

				if (bHiddenVolHost)
				{
					nID[0] = IDS_SIZE_HELP0_HIDDEN_HOST_VOL;
					nID[1] = IDS_SIZE_HELP1_HIDDEN_HOST_VOL;
				}
				else
				{
					nID[0] = bHiddenVol ? IDS_SIZE_HELP0_HIDDEN_VOL : IDS_SIZE_HELP0;
					nID[1] = bHiddenVol ? IDS_SIZE_HELP1_HIDDEN_VOL : IDS_SIZE_HELP1;
				}

				if (bDevice == TRUE && !(bHiddenVol && !bHiddenVolHost))	// If raw device but not a hidden volume
				{
					nID[0] = IDS_SIZE_PARTITION_HELP;
					nID[1] = bHiddenVolHost ? IDS_SIZE_PARTITION_HIDDEN_VOL_HELP : 0;
				}
				SendMessage (GetDlgItem (hwndDlg, IDC_SPACE_LEFT), WM_SETFONT, (WPARAM) hSmallBoldFont, (LPARAM) TRUE);
				SendMessage (GetDlgItem (hwndDlg, IDC_SIZEBOX), EM_LIMITTEXT, 10, 0);

				if(!QueryFreeSpace (hwndDlg, GetDlgItem (hwndDlg, IDC_SPACE_LEFT), TRUE))
				{
					nUIVolumeSize=0;
					nVolumeSize=0;
					SetWindowText (GetDlgItem (hwndDlg, IDC_SIZEBOX), "UNKNOWN");
					EnableWindow (GetDlgItem (hwndDlg, IDC_SIZEBOX), FALSE);
					EnableWindow (GetDlgItem (hwndDlg, IDC_KB), FALSE);
					EnableWindow (GetDlgItem (hwndDlg, IDC_MB), FALSE);

				}
				else if (bDevice == TRUE && !(bHiddenVol && !bHiddenVolHost))	// If raw device but not a hidden volume
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

				if (nMultiplier == BYTES_PER_KB)
					SendMessage (GetDlgItem (hwndDlg, IDC_KB), BM_SETCHECK, BST_CHECKED, 0);
				else
					SendMessage (GetDlgItem (hwndDlg, IDC_MB), BM_SETCHECK, BST_CHECKED, 0);

				if (nUIVolumeSize != 0)
				{
					sprintf (szTmp, "%I64u", nUIVolumeSize);
					SetWindowText (GetDlgItem (hwndDlg, IDC_SIZEBOX), szTmp);
				}

				SetFocus (GetDlgItem (hwndDlg, IDC_SIZEBOX));

				SetWindowText (GetDlgItem (hwndDlg, IDC_BOX_HELP), getmultilinestr (nID));

				if (bHiddenVol)
					SetWindowText (GetDlgItem (GetParent (hwndDlg), IDC_BOX_TITLE), getstr (bHiddenVolHost ? IDS_SIZE_HIDVOL_HOST_TITLE : IDS_SIZE_HIDVOL_TITLE));
				else
					SetWindowText (GetDlgItem (GetParent (hwndDlg), IDC_BOX_TITLE), getstr (IDS_SIZE_TITLE));


				SetWindowText (GetDlgItem (GetParent (hwndDlg), IDC_NEXT), getstr (IDS_NEXT));
				SetWindowText (GetDlgItem (GetParent (hwndDlg), IDC_PREV), getstr (IDS_PREV));


				EnableWindow (GetDlgItem (GetParent (hwndDlg), IDC_PREV), TRUE);

				VerifySizeAndUpdate (hwndDlg, FALSE);
			}
			break;

		case HIDVOL_HOST_PASSWORD_PAGE:
			{
				UINT nID[4];

				nID[0] = IDS_PASSWORD_HIDDENVOL_HOST_DIRECT_HELP0;
				nID[1] = IDS_PASSWORD_HIDDENVOL_HOST_DIRECT_HELP1;
				nID[2] = IDS_PASSWORD_HIDDENVOL_HOST_DIRECT_HELP2;
				nID[3] = 0;

				SendMessage (GetDlgItem (hwndDlg, IDC_PASSWORD_DIRECT), EM_LIMITTEXT, MAX_PASSWORD, 0);

				SetWindowText (GetDlgItem (hwndDlg, IDC_PASSWORD_DIRECT), szPassword);

				SetFocus (GetDlgItem (hwndDlg, IDC_PASSWORD_DIRECT));

				SetWindowText (GetDlgItem (hwndDlg, IDC_BOX_HELP), getmultilinestr (nID));

				SetWindowText (GetDlgItem (GetParent (hwndDlg), IDC_BOX_TITLE), getstr (IDS_PASSWORD_HIDVOL_HOST_TITLE));

				SetWindowText (GetDlgItem (GetParent (hwndDlg), IDC_NEXT), getstr (IDS_NEXT));
				SetWindowText (GetDlgItem (GetParent (hwndDlg), IDC_PREV), getstr (IDS_PREV));

				EnableWindow (GetDlgItem (GetParent (hwndDlg), IDC_PREV), TRUE);
				EnableWindow (GetDlgItem (GetParent (hwndDlg), IDC_NEXT), TRUE);
			}
			break;

		case PASSWORD_PAGE:
			{
				UINT nID[4];

				if (bHiddenVolHost)
				{
					nID[0] = IDS_PASSWORD_HIDDENVOL_HOST_HELP0;
					nID[1] = 0;
					nID[2] = 0;
					nID[3] = 0;
				}
				else if (bHiddenVol)
				{
					nID[0] = IDS_PASSWORD_HIDDENVOL_HELP0;
					nID[1] = IDS_PASSWORD_HELP1;
					nID[2] = IDS_PASSWORD_HELP2;
					nID[3] = IDS_PASSWORD_HELP3;
				}
				else
				{
					nID[0] = IDS_PASSWORD_HELP1;
					nID[1] = IDS_PASSWORD_HELP2;
					nID[2] = IDS_PASSWORD_HELP3;
					nID[3] = IDS_PASSWORD_HELP0;
				}

				SendMessage (GetDlgItem (hwndDlg, IDC_PASSWORD), EM_LIMITTEXT, MAX_PASSWORD, 0);
				SendMessage (GetDlgItem (hwndDlg, IDC_VERIFY), EM_LIMITTEXT, MAX_PASSWORD, 0);

				SetWindowText (GetDlgItem (hwndDlg, IDC_PASSWORD), szPassword);
				SetWindowText (GetDlgItem (hwndDlg, IDC_VERIFY), szVerify);

				SetFocus (GetDlgItem (hwndDlg, IDC_PASSWORD));

				SetWindowText (GetDlgItem (hwndDlg, IDC_BOX_HELP), getmultilinestr (nID));

				if (bHiddenVol)
					SetWindowText (GetDlgItem (GetParent (hwndDlg), IDC_BOX_TITLE), getstr (bHiddenVolHost ? IDS_PASSWORD_HIDVOL_HOST_TITLE : IDS_PASSWORD_HIDVOL_TITLE));
				else
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

				nID[0] = bHiddenVolHost ? IDS_FORMAT_HIDVOL_HOST_HELP0 : IDS_FORMAT_HELP0;
				nID[1] = bHiddenVolHost ? IDS_FORMAT_HIDVOL_HOST_HELP1 : IDS_FORMAT_HELP1;
				nID[2] = bHiddenVolHost ? IDS_FORMAT_HIDVOL_HOST_HELP2 : IDS_FORMAT_HELP2;
				nID[3] = 0;


				SetTimer (GetParent (hwndDlg), 0xff, RANDOM_SHOW_TIMER, NULL);

				hDiskKey = GetDlgItem (hwndDlg, IDC_DISK_KEY);
				hHeaderKey = GetDlgItem (hwndDlg, IDC_HEADER_KEY);

				SendMessage (GetDlgItem (hwndDlg, IDC_RANDOM_BYTES), WM_SETFONT, (WPARAM) hSmallFont, (LPARAM) TRUE);
				SendMessage (GetDlgItem (hwndDlg, IDC_DISK_KEY), WM_SETFONT, (WPARAM) hSmallFont, (LPARAM) TRUE);
				SendMessage (GetDlgItem (hwndDlg, IDC_HEADER_KEY), WM_SETFONT, (WPARAM) hSmallFont, (LPARAM) TRUE);

				SetWindowText (GetDlgItem (hwndDlg, IDC_BOX_HELP), getmultilinestr (nID));

				if (bHiddenVol)
					SetWindowText (GetDlgItem (GetParent (hwndDlg), IDC_BOX_TITLE), getstr (bHiddenVolHost ? IDS_FORMAT_HIDVOL_HOST_TITLE : IDS_FORMAT_HIDVOL_TITLE));
				else
					SetWindowText (GetDlgItem (GetParent (hwndDlg), IDC_BOX_TITLE), getstr (IDS_FORMAT_TITLE));

				EnableWindow (GetDlgItem (hwndDlg, IDC_QUICKFORMAT), bDevice && (!bHiddenVol));

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
				if (bHiddenVolHost)
				{
					// A volume within which a hidden volume is intended to be created can only be FAT (NTFS file system stores various info over the entire volume, which would get overwritten by the hidden volume).
					if (nVolumeSize <= MAX_FAT_VOLUME_SIZE)
						AddComboPair (GetDlgItem (hwndDlg, IDC_FILESYS), "FAT", FILESYS_FAT);
					else
						AddComboPair (GetDlgItem (hwndDlg, IDC_FILESYS), "None", FILESYS_NONE);

					SendMessage (GetDlgItem (hwndDlg, IDC_QUICKFORMAT), BM_SETCHECK, BST_UNCHECKED, 0);

					EnableWindow (GetDlgItem (hwndDlg, IDC_FILESYS), FALSE);
					SendMessage (GetDlgItem (hwndDlg, IDC_FILESYS), CB_SETCURSEL, 0, 0);
				}
				else
				{
					if (bHiddenVol)
						SendMessage (GetDlgItem (hwndDlg, IDC_QUICKFORMAT), BM_SETCHECK, BST_CHECKED, 0);

					AddComboPair (GetDlgItem (hwndDlg, IDC_FILESYS), "None", FILESYS_NONE);

					if (nVolumeSize <= MAX_FAT_VOLUME_SIZE)
						AddComboPair (GetDlgItem (hwndDlg, IDC_FILESYS), "FAT", FILESYS_FAT);

					if (nVolumeSize / 512 > 5050)
						AddComboPair (GetDlgItem (hwndDlg, IDC_FILESYS), "NTFS", FILESYS_NTFS);

					EnableWindow (GetDlgItem (hwndDlg, IDC_FILESYS), TRUE);

					/* IMPORTANT:
					   The default file system for ANY TrueCrypt volume must ALWAYS be FAT!
					   FAT is the only file system within which a hidden volume can be created. In future,
					   FAT file system will probably become obsolete and the fact that a TrueCrypt volume
					   contains FAT would probably arouse suspicion that it contains a hidden volume.
					   The only way to prevent this from happening is making FAT the default file system 
					   for ANY TrueCrypt volume. Then a user of a hidden volume, when asked why he used the
					   FAT file system, will be able to say "I left all the configurations which I did not
					   understand at their default settings."  */
					SendMessage (GetDlgItem (hwndDlg, IDC_FILESYS), CB_SETCURSEL, 1, 0);
				}

				EnableWindow (GetDlgItem (hwndDlg, IDC_CLUSTERSIZE), TRUE);
				EnableWindow (GetDlgItem (hwndDlg, IDC_CANCEL_BAR), FALSE);

				SetWindowText (GetDlgItem (GetParent (hwndDlg), IDC_NEXT), getstr (IDS_FINISH));
				SetWindowText (GetDlgItem (GetParent (hwndDlg), IDC_PREV), getstr (IDS_PREV));

				EnableWindow (GetDlgItem (GetParent (hwndDlg), IDC_PREV), TRUE);
				EnableWindow (GetDlgItem (GetParent (hwndDlg), IDC_NEXT), TRUE);

				SetFocus (GetDlgItem (GetParent (hwndDlg), IDC_NEXT));
			}
			break;

		case FORMAT_FINISHED_PAGE:
			{
				UINT nID[4];

				if (!bHiddenVolHost && bHiddenVol && !bHiddenVolFinished)
				{
					char msg[1028];
					char driveStr[2] = {hiddenVolHostDriveNo + 'A', 0};

					nID[0] = IDS_HIDVOL_HOST_FILLING_HELP0;
					nID[1] = IDS_HIDVOL_HOST_FILLING_HELP1;
					nID[2] = IDS_HIDVOL_HOST_FILLING_HELP2;
					nID[3] = IDS_HIDVOL_HOST_FILLING_HELP3;
					sprintf (msg, getmultilinestr (nID), driveStr);			
					SetWindowText (GetDlgItem (hwndDlg, IDC_BOX_HELP), msg);
					SetWindowText (GetDlgItem (GetParent (hwndDlg), IDC_BOX_TITLE), getstr (IDS_HIDVOL_HOST_FILLING_TITLE));
				}
				else 
				{
					nID[0] = bHiddenVol ? IDS_HIDVOL_FORMAT_FINISHED_HELP0 : IDS_FORMAT_FINISHED_HELP;
					nID[1] = bHiddenVol ? IDS_HIDVOL_FORMAT_FINISHED_HELP1 : 0;
					nID[2] = bHiddenVol ? IDS_HIDVOL_FORMAT_FINISHED_HELP2 : 0;
					nID[3] = bHiddenVol ? IDS_HIDVOL_FORMAT_FINISHED_HELP3 : 0;
					SetWindowText (GetDlgItem (hwndDlg, IDC_BOX_HELP), getmultilinestr (nID));
					SetWindowText (GetDlgItem (GetParent (hwndDlg), IDC_BOX_TITLE), getstr (bHiddenVol ? IDS_HIDVOL_FORMAT_FINISHED_TITLE : IDS_FORMAT_FINISHED_TITLE));
				}


				SetWindowText (GetDlgItem (GetParent (hwndDlg), IDC_NEXT), getstr (IDS_NEXT));
				SetWindowText (GetDlgItem (GetParent (hwndDlg), IDC_PREV), getstr (IDS_PREV));
				EnableWindow (GetDlgItem (GetParent (hwndDlg), IDC_NEXT), TRUE);
				EnableWindow (GetDlgItem (GetParent (hwndDlg), IDC_PREV), (!bHiddenVol || bHiddenVolFinished) ? TRUE : FALSE);

				if (!bHiddenVol || bHiddenVolFinished)
					SetWindowText (GetDlgItem (GetParent (hwndDlg), IDCANCEL), getstr (IDS_EXIT));
			}
			break;

		}
		return 0;

	case WM_HELP:
		OpenPageHelp (GetParent (hwndDlg), nCurPageNo);
		return 1;

	case WM_COMMAND:
		if (lw == IDC_OPEN_OUTER_VOLUME && nCurPageNo == FORMAT_FINISHED_PAGE)
		{
			OpenVolumeExplorerWindow (hiddenVolHostDriveNo);
		}

		if (lw == IDC_HIDDEN_VOL_HELP && nCurPageNo == INTRO_PAGE)
		{
			MessageBox (hwndDlg, 
"It may happen that you are forced by somebody to reveal the password to an\n\
encrypted volume. There are many situations where you cannot refuse to reveal the\n\
password (for example, when the adversary uses violence). Using a so-called hidden\n\
volume allows you to solve such situations in a diplomatic manner without revealing\n\
the password to your volume.\n\
\n\
The principle is that a TrueCrypt volume is created within another TrueCrypt volume\n\
(within the free space on the volume). Even when the outer volume is mounted, it is\n\
impossible to tell whether there is a hidden volume within it or not, because free\n\
space on any TrueCrypt volume is always filled with random data when the volume is\n\
created (if Quick Format is disabled) and no part of the hidden volume can be\n\
distinguished from random data. The password for the hidden volume must be different\n\
from the password for the outer volume. To the outer volume (before creating the\n\
hidden volume within it) you should copy some sensitive-looking files that you do\n\
NOT really want to hide. These files will be there for anyone who would force you to\n\
hand over the password. You will reveal only the password for the outer volume, not\n\
for the hidden one. Files that are really sensitive will be stored on the hidden\n\
volume.\n\
\n\
For more information, please refer to TrueCrypt User's Guide."
				, lpszTitle, MB_OK);
		}
		if (lw == IDC_CANCEL_BAR && nCurPageNo == FORMAT_PAGE)
		{
			if (MessageBox (hwndDlg, getstr (IDS_FORMAT_ABORT), lpszTitle, MB_YESNO | MB_ICONQUESTION | MB_DEFBUTTON2 ) == IDYES)
				bThreadCancel = TRUE;
			return 1;
		}

		if (lw == IDC_CIPHER_TEST && nCurPageNo == CIPHER_PAGE)
		{
			LPARAM nIndex;
			int i = 0, c;

			nIndex = SendMessage (GetDlgItem (hCurPage, IDC_COMBO_BOX), CB_GETCURSEL, 0, 0);
			nVolumeEA = SendMessage (GetDlgItem (hCurPage, IDC_COMBO_BOX), CB_GETITEMDATA, nIndex, 0);

			for (c = EAGetLastCipher (nVolumeEA); c != 0; c = EAGetPreviousCipher (nVolumeEA, c))
			{
				DialogBoxParam (hInst, MAKEINTRESOURCE (IDD_CIPHER_TEST_DLG), 
					GetParent (hwndDlg), (DLGPROC) CipherTestDialogProc, (LPARAM) c);
			}
			return 1;
		}

		if (lw == IDC_WIZ_BENCHMARK && nCurPageNo == CIPHER_PAGE)
		{
			int nResult = DialogBoxParam (hInst,
				MAKEINTRESOURCE (IDD_BENCHMARK_DLG), hwndDlg,
				(DLGPROC) BenchmarkDlgProc, (LPARAM) NULL);

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
		
		if (hw == EN_CHANGE && nCurPageNo == HIDVOL_HOST_PASSWORD_PAGE)
		{
			GetWindowText (GetDlgItem (hCurPage, IDC_PASSWORD_DIRECT), szPassword, sizeof (szPassword));
			return 1;
		}

		if ((lw == IDC_KB || lw == IDC_MB) && nCurPageNo == SIZE_PAGE)
		{
			VerifySizeAndUpdate (hwndDlg, FALSE);
			return 1;
		}
		
		if (lw == IDC_HIDDEN_VOL && nCurPageNo == INTRO_PAGE)
		{
			bHiddenVol = TRUE;
			bHiddenVolHost = TRUE;
			return 1;
		}

		if (lw == IDC_STD_VOL && nCurPageNo == INTRO_PAGE)
		{
			bHiddenVol = FALSE;
			bHiddenVolHost = FALSE;
			bHiddenVolDirect = FALSE;
			return 1;
		}

		if (lw == IDC_HIDVOL_WIZ_MODE_DIRECT && nCurPageNo == HIDDEN_VOL_WIZARD_MODE_PAGE)
		{
			bHiddenVolDirect = TRUE;
			return 1;
		}

		if (lw == IDC_HIDVOL_WIZ_MODE_FULL && nCurPageNo == HIDDEN_VOL_WIZARD_MODE_PAGE)
		{
			bHiddenVolDirect = FALSE;
			return 1;
		}

		if (lw == IDC_BROWSE_FILES && nCurPageNo == FILE_PAGE)
		{
			if (BrowseFiles (hwndDlg, IDS_OPEN_TITLE, szFileName, bHistory) == FALSE)
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

			// Check administrator privileges
			if (!strstr (szFileName, "Floppy") && !IsAdmin())
				MessageBox (hwndDlg, getstr (IDS_ADMIN_PRIVILEGES_WARN_DEVICES), lpszTitle, MB_OK|MB_ICONWARNING);

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
			ComboSelChangeEA (hwndDlg);
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
		
		if (lw == IDC_NO_HISTORY)
		{
			bHistory = !IsButtonChecked (GetDlgItem (hCurPage, IDC_NO_HISTORY));
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

			LoadPage (hwndDlg, INTRO_PAGE);
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
		EnableWindow (GetDlgItem (hCurPage, IDC_QUICKFORMAT), bDevice && (!bHiddenVol));
		EnableWindow (GetDlgItem (hCurPage, IDC_FILESYS), TRUE);
		EnableWindow (GetDlgItem (hCurPage, IDC_CLUSTERSIZE), TRUE);
		EnableWindow (GetDlgItem (hCurPage, IDC_CANCEL_BAR), FALSE);
		EnableWindow (GetDlgItem (hwndDlg, IDC_NEXT), TRUE);
		SendMessage (GetDlgItem (hCurPage, IDC_PROGRESS_BAR), PBM_SETPOS, 0, 0L);
		SetFocus (GetDlgItem (hwndDlg, IDC_NEXT));
		if (nCurPageNo == FORMAT_PAGE)
			KillTimer (hwndDlg, 0xff);

		LoadPage (hwndDlg, FORMAT_FINISHED_PAGE);

		break;

	case WM_THREAD_ENDED:
		if (!bHiddenVolHost)
		{
			EnableWindow (GetDlgItem (hCurPage, IDC_QUICKFORMAT), bDevice && (!bHiddenVol));
			EnableWindow (GetDlgItem (hCurPage, IDC_FILESYS), TRUE);
		}
		EnableWindow (GetDlgItem (hCurPage, IDC_CLUSTERSIZE), TRUE);
		EnableWindow (GetDlgItem (hwndDlg, IDC_PREV), TRUE);
		EnableWindow (GetDlgItem (hwndDlg, IDHELP), TRUE);
		EnableWindow (GetDlgItem (hwndDlg, IDCANCEL), TRUE);
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
			if (hiddenVolHostDriveNo > -1)
				UnmountVolume (hwndDlg, hiddenVolHostDriveNo, FALSE);

			EndMainDlg (hwndDlg);

			return 1;
		}
		if (lw == IDC_NEXT)
		{
			if (nCurPageNo == INTRO_PAGE)
			{
				if (IsButtonChecked (GetDlgItem (hCurPage, IDC_HIDDEN_VOL)) == TRUE)
				{
					if (!IsAdmin()
						&& IDNO == MessageBox (hwndDlg, getstr (IDS_ADMIN_PRIVILEGES_WARN_HIDVOL),
							lpszTitle, MB_ICONWARNING|MB_YESNO|MB_DEFBUTTON2))
					{
						nCurPageNo--;
					}
					else
					{
						bHiddenVol = TRUE;
						bHiddenVolHost = TRUE;
					}
				}
				else
				{
					bHiddenVol = FALSE;
					bHiddenVolHost = FALSE;
					bHiddenVolDirect = FALSE;
					nCurPageNo++;		// Skip the hidden volume creation wizard mode selection
				}
			}

			else if (nCurPageNo == HIDDEN_VOL_WIZARD_MODE_PAGE)
			{
				if (IsButtonChecked (GetDlgItem (hCurPage, IDC_HIDVOL_WIZ_MODE_DIRECT)) == TRUE)
					bHiddenVolDirect = TRUE;
				else
					bHiddenVolDirect = FALSE;
			}

			else if (nCurPageNo == FILE_PAGE)
			{
				GetWindowText (GetDlgItem (hCurPage, IDC_COMBO_BOX), szFileName, sizeof (szFileName));
				CreateFullVolumePath (szDiskFile, szFileName, &bDevice);
				MoveEditToCombo (GetDlgItem (hCurPage, IDC_COMBO_BOX));

				bHistory = !IsButtonChecked (GetDlgItem (hCurPage, IDC_NO_HISTORY));

				SaveSettings (hCurPage);

				if (bHiddenVolDirect && bHiddenVolHost)
				{

					nCurPageNo = HIDVOL_HOST_PASSWORD_PAGE - 1;

					if (bDevice)
					{
						if(!QueryFreeSpace (hwndDlg, GetDlgItem (hwndDlg, IDC_SPACE_LEFT), FALSE))
						{
							MessageBox (hwndDlg, "Error: Cannot get volume size!\n\nMake sure the selected volume exists and is not being\nused by the system or an application.", lpszTitle, ICON_HAND);
							nCurPageNo = FILE_PAGE - 1; 
						}
						else
							nHiddenVolHostSize = nVolumeSize;
					}
					else
					{
						if (!GetFileVolSize (hwndDlg, &nHiddenVolHostSize))
						{
							nCurPageNo = FILE_PAGE - 1;
						}
					}
				}
				else
				{
					if (!bHiddenVol)
						nCurPageNo = HIDDEN_VOL_PRE_CIPHER_PAGE;		// Skip the extra info on hidden volume 
					else if (!bHiddenVolHost)
						nCurPageNo = HIDDEN_VOL_HOST_PRE_CIPHER_PAGE;	// Skip the info on the outer volume
				}
			}

			else if (nCurPageNo == HIDDEN_VOL_HOST_PRE_CIPHER_PAGE)
			{
				if (bHiddenVolHost)
					nCurPageNo = HIDDEN_VOL_PRE_CIPHER_PAGE;		// Skip the info on the hiddem volume
			}

			else if (nCurPageNo == CIPHER_PAGE)
			{
				LPARAM nIndex;
				nIndex = SendMessage (GetDlgItem (hCurPage, IDC_COMBO_BOX), CB_GETCURSEL, 0, 0);
				nVolumeEA = SendMessage (GetDlgItem (hCurPage, IDC_COMBO_BOX), CB_GETITEMDATA, nIndex, 0);

				if (IsButtonChecked (GetDlgItem (hCurPage, IDC_SHA1)))		pkcs5 = SHA1;
				if (IsButtonChecked (GetDlgItem (hCurPage, IDC_RIPEMD160)))	pkcs5 = RIPEMD160;

				RandSetHashFunction (pkcs5);
			}

			else if (nCurPageNo == SIZE_PAGE)
			{
				VerifySizeAndUpdate (hCurPage, TRUE);

				if (!(bHiddenVolDirect && bHiddenVolHost))
					nCurPageNo++;
			}

			else if (nCurPageNo == PASSWORD_PAGE)
			{
				VerifyPasswordAndUpdate (hwndDlg, GetDlgItem (hwndDlg, IDC_NEXT),
					GetDlgItem (hCurPage, IDC_PASSWORD),
					  GetDlgItem (hCurPage, IDC_VERIFY),
					    szPassword, szVerify);

				// Check password length
				if (!bHiddenVolHost && !CheckPasswordLength (hwndDlg, GetDlgItem (hCurPage, IDC_PASSWORD)))
						nCurPageNo--;
			}

			else if (nCurPageNo == HIDVOL_HOST_PASSWORD_PAGE)
			{
				int retCode;
				GetWindowText (GetDlgItem (hCurPage, IDC_PASSWORD_DIRECT), szPassword, sizeof (szPassword));

				/* Mount the volume which is to host the new hidden volume */

				if (hiddenVolHostDriveNo < 0)		// If the hidden volume host is not mounted yet
					retCode = MountHiddenVolHost (hwndDlg, szDiskFile, &hiddenVolHostDriveNo, szPassword);
				else
					retCode = 0;					// Mounted

				switch (retCode)
				{
				case ERR_NO_FREE_DRIVES:
					MessageBox (hwndDlg, "Error: No free drive letter for the outer volume!", lpszTitle, ICON_HAND);
					nCurPageNo--;
					break;
				case ERR_VOL_MOUNT_FAILED:
					NormalCursor ();
					nCurPageNo--;
					break;
				case 0:

					/* Hidden volume host successfully mounted */

					ArrowWaitCursor ();

					// Verify that the outer volume contains a suitable file system and retrieve cluster size
					switch (AnalyzeHiddenVolumeHost (hwndDlg, &hiddenVolHostDriveNo, &realClusterSize))
					{
					case -1:
						hiddenVolHostDriveNo = -1;
						AbortProcessSilent ();
						break;

					case 0:
						NormalCursor ();
						nCurPageNo--;
						break;

					case 1:

						// Determine the maximum possible size of the hidden volume
						if (DetermineMaxHiddenVolSize (hwndDlg) < 1)
						{
							// Non-fatal error while determining maximum possible size of the hidden volume
							nCurPageNo--;
							NormalCursor();
						}
						else
						{
							// Maximum possible size of the hidden volume successfully determined

							nCurPageNo = HIDDEN_VOL_PRE_CIPHER_PAGE - 1;

							bHiddenVolHost = FALSE; 
							bHiddenVolFinished = FALSE;

							// Clear the outer volume password
							memset(&szPassword[0], 0, sizeof (szPassword));
							memset(&szVerify[0], 0, sizeof (szVerify));

							EnableWindow (GetDlgItem (GetParent (hwndDlg), IDC_NEXT), TRUE);
							NormalCursor ();

							nCurPageNo = HIDDEN_VOL_PRE_CIPHER_PAGE - 1; 
						}
						break;
					}
				}
			}
            
			// Format start
			else if (nCurPageNo == FORMAT_PAGE)
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

				if (bHiddenVolHost)
				{
					hiddenVolHostDriveNo = -1;
					nMaximumHiddenVolSize = 0;
					quickFormat = FALSE;
				}
				else if (bHiddenVol)
					quickFormat = TRUE;
				else
					quickFormat = IsButtonChecked (GetDlgItem (hCurPage, IDC_QUICKFORMAT));

				if (bHiddenVolHost)
					fileSystem = FILESYS_FAT;
				else
				{
					fileSystem = SendMessage (GetDlgItem (hCurPage, IDC_FILESYS), CB_GETITEMDATA
						,SendMessage (GetDlgItem (hCurPage, IDC_FILESYS), CB_GETCURSEL, 0, 0) , 0);
				}
				clusterSize = SendMessage (GetDlgItem (hCurPage, IDC_CLUSTERSIZE), CB_GETITEMDATA
					,SendMessage (GetDlgItem (hCurPage, IDC_CLUSTERSIZE), CB_GETCURSEL, 0, 0) , 0);

				// Increase cluster size if it's too small for this volume size
				if (fileSystem == FILESYS_FAT && clusterSize > 0)
				{
					BOOL fixed = FALSE;
					while (clusterSize < 128 
						&& nVolumeSize / clusterSize > 17179869184I64)
					{
						clusterSize *= 2;
						fixed = TRUE;
					}
					if (fixed)
						MessageBox (hwndDlg, "The selected cluster size is too small for this volume size.\nA greater cluster size will be used instead.", lpszTitle, MB_ICONWARNING);
				}
				
				_beginthread (formatThreadFunction, 4096, hwndDlg);
				return 1;
			}

			// Wizard loop restart
			else if (nCurPageNo == FORMAT_FINISHED_PAGE)
			{

				if (!bHiddenVol || bHiddenVolFinished)
				{

					SetWindowText (GetDlgItem (GetParent (hwndDlg), IDCANCEL), getstr (IDS_CANCEL));
					bHiddenVolFinished = FALSE;
					memset(&szPassword[0], 0, sizeof (szPassword));
					memset(&szVerify[0], 0, sizeof (szVerify));
					nCurPageNo = INTRO_PAGE;
					LoadPage (hwndDlg, INTRO_PAGE);
					return 1;
				}
				else
				{
					ArrowWaitCursor ();

					// Verify that the outer volume contains a suitable file system
					switch (AnalyzeHiddenVolumeHost (hwndDlg, &hiddenVolHostDriveNo, &realClusterSize))
					{
					case -1:
						hiddenVolHostDriveNo = -1;
						AbortProcessSilent ();
						break;

					case 0:
						NormalCursor ();
						nCurPageNo--;
						break;

					case 1:

						/* Determine the maximum possible size of the hidden volume */

						if (DetermineMaxHiddenVolSize (hwndDlg) < 1)
						{
							NormalCursor ();
							goto ovf_end;
						}

						nCurPageNo = HIDDEN_VOL_PRE_CIPHER_PAGE - 1;

						EnableWindow (GetDlgItem (GetParent (hwndDlg), IDC_NEXT), TRUE);
						NormalCursor ();
						break;
					}
				}
			}

			if (nCurPageNo == SIZE_PAGE && nVolumeEA == NONE)
				LoadPage (hwndDlg, nCurPageNo + 2);
			else
				LoadPage (hwndDlg, nCurPageNo + 1);
ovf_end:
			return 1;
		}
		if (lw == IDC_PREV)
		{
			if (nCurPageNo == HIDDEN_VOL_WIZARD_MODE_PAGE)
			{
				if (IsButtonChecked (GetDlgItem (hCurPage, IDC_HIDVOL_WIZ_MODE_DIRECT)) == TRUE)
					bHiddenVolDirect = TRUE;
				else
					bHiddenVolDirect = FALSE;
			}

			else if (nCurPageNo == FILE_PAGE)
			{
				GetWindowText (GetDlgItem (hCurPage, IDC_COMBO_BOX), szFileName, sizeof (szFileName));
				CreateFullVolumePath (szDiskFile, szFileName, &bDevice);
				MoveEditToCombo (GetDlgItem (hCurPage, IDC_COMBO_BOX));
				SaveSettings (hCurPage);

				if (!bHiddenVol)
					nCurPageNo--;		// Skip the hidden volume creation wizard mode selection

			}

			else if (nCurPageNo == CIPHER_PAGE)
			{
				LPARAM nIndex;
				nIndex = SendMessage (GetDlgItem (hCurPage, IDC_COMBO_BOX), CB_GETCURSEL, 0, 0);
				nVolumeEA = SendMessage (GetDlgItem (hCurPage, IDC_COMBO_BOX), CB_GETITEMDATA, nIndex, 0);

				if (IsButtonChecked (GetDlgItem (hCurPage, IDC_SHA1)))		pkcs5 = SHA1;
				if (IsButtonChecked (GetDlgItem (hCurPage, IDC_RIPEMD160)))	pkcs5 = RIPEMD160;

				RandSetHashFunction (pkcs5);

				if (!bHiddenVol)
					nCurPageNo = HIDDEN_VOL_HOST_PRE_CIPHER_PAGE;	// Skip the extra info on hidden volume 
				else if (bHiddenVolHost)
					nCurPageNo = HIDDEN_VOL_PRE_CIPHER_PAGE;		// Skip the info on the hidden volume
			}

			else if (nCurPageNo == SIZE_PAGE)
				VerifySizeAndUpdate (hCurPage, TRUE);

			else if (nCurPageNo == PASSWORD_PAGE)
			{
				VerifyPasswordAndUpdate (hwndDlg, GetDlgItem (hwndDlg, IDC_NEXT),
					GetDlgItem (hCurPage, IDC_PASSWORD),
					  GetDlgItem (hCurPage, IDC_VERIFY),
					    szPassword, szVerify);

				nCurPageNo--;		// Skip the hidden volume host password page
			}

			else if (nCurPageNo == HIDVOL_HOST_PASSWORD_PAGE)
			{
				GetWindowText (GetDlgItem (hCurPage, IDC_PASSWORD_DIRECT), szPassword, sizeof (szPassword));
				nCurPageNo = FILE_PAGE + 1;
			}


			else if (nCurPageNo == FORMAT_PAGE)
			{
				KillTimer (hwndDlg, 0xff);
			}

			if (nCurPageNo == FORMAT_PAGE && nVolumeEA == NONE)
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


int DetermineMaxHiddenVolSize (HWND hwndDlg)
{
	__int64 nbrFreeClusters = 0;
	__int64 nbrReserveBytes;

	ArrowWaitCursor ();

	// Get the map of the clusters that are free and in use on the outer volume.
	// The map will be scanned to determine the size of the uninterrupted block of free
	// space (provided there is any) whose end is aligned with the end of the volume.
	// The value will then be used to determine the maximum possible size of the hidden volume.

	switch (ScanVolClusterBitmap (hwndDlg,
		&hiddenVolHostDriveNo,
		nHiddenVolHostSize / realClusterSize,
		&nbrFreeClusters))
	{
	case -1:
		hiddenVolHostDriveNo = -1;
		AbortProcessSilent ();
		break;
	case 0:
		return 0;
		break;
	}

	if (nbrFreeClusters * realClusterSize < MIN_VOLUME_SIZE + HIDDEN_VOL_HEADER_OFFSET)
	{
		MessageBox (hwndDlg, getstr (IDS_NO_SPACE_FOR_HIDDEN_VOL), lpszTitle, ICON_HAND);
		AbortProcessSilent ();
	}

	// Add a reserve (in case the user mounts the outer volume and creates new files
	// on it by accident or OS writes some new data behind his or her back, such as
	// System Restore etc.)
	nbrReserveBytes = nHiddenVolHostSize / 200;
	if (nbrReserveBytes > BYTES_PER_MB * 10)
		nbrReserveBytes = BYTES_PER_MB * 10;

	// Compute the final value

	nMaximumHiddenVolSize = nbrFreeClusters * realClusterSize - HIDDEN_VOL_HEADER_OFFSET - nbrReserveBytes;
	nMaximumHiddenVolSize &= ~0x1ffI64;		// Must be a multiple of the sector size

	if (nMaximumHiddenVolSize < MIN_VOLUME_SIZE)
	{
		MessageBox (hwndDlg, getstr (IDS_NO_SPACE_FOR_HIDDEN_VOL), lpszTitle, ICON_HAND);
		AbortProcessSilent ();
	}
	else if (nMaximumHiddenVolSize > MAX_HIDDEN_VOLUME_SIZE)
		nMaximumHiddenVolSize = MAX_HIDDEN_VOLUME_SIZE;


	// Prepare the hidden volume size parameters
	if (nMaximumHiddenVolSize < BYTES_PER_MB)
		nMultiplier = BYTES_PER_KB;
	else
		nMultiplier = BYTES_PER_MB;

	nUIVolumeSize = nMaximumHiddenVolSize / nMultiplier;	// Set the initial value for the hidden volume size input field to the max
	nVolumeSize = nUIVolumeSize * nMultiplier;				// Chop off possible remainder

	return 1;
}


// Tests whether the file system of the given volume is suitable to host a hidden volume and
// retrieves the cluster size.
int AnalyzeHiddenVolumeHost (HWND hwndDlg, int *driveNo, int *realClusterSize)
{
	HANDLE hDevice;
	DWORD bytesReturned;
	int result;
	char lpFileName[7] = {'\\','\\','.','\\',*driveNo + 'A',':',0};
	BYTE readBuffer[SECTOR_SIZE*2];
	LARGE_INTEGER offset, offsetNew;

	hDevice = CreateFile (lpFileName, GENERIC_READ, FILE_SHARE_READ|FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);

	if (hDevice == INVALID_HANDLE_VALUE)
	{
		MessageBox (hwndDlg, "Error: Cannot access the outer volume!\nVolume creation cannot continue.", lpszTitle, ICON_HAND);
		goto efsf_error;
	}

	offset.QuadPart = 0;

	if (SetFilePointerEx (hDevice, offset, &offsetNew, FILE_BEGIN) == 0)
	{
		handleWin32Error (hwndDlg);
		MessageBox (hwndDlg, "Cannot seek position within the outer volume!\nVolume creation cannot continue.", lpszTitle, ICON_HAND);
		goto efs_error;
	}

	result = ReadFile(hDevice, &readBuffer, (DWORD) SECTOR_SIZE, &bytesReturned, NULL);

	if (result == 0)
	{
		handleWin32Error (hwndDlg);
		MessageBox (hwndDlg, "Cannot read volume!\nVolume creation cannot continue.", lpszTitle, ICON_HAND);
		goto efs_error;
	}

	CloseHandle (hDevice);

	if ((readBuffer[0x36] == 'F' && readBuffer[0x37] == 'A' && readBuffer[0x38] == 'T')
	|| (readBuffer[0x52] == 'F' && readBuffer[0x53] == 'A' && readBuffer[0x54] == 'T'))
	{
		// FAT file system detected

		// Retrieve the cluster size
		*realClusterSize = ((int) readBuffer[0xb] + ((int) readBuffer[0xc] << 8)) * (int) readBuffer[0xd];	
		return 1;
	}
	else
	{
		if (bHiddenVolDirect)
		{
			UnmountVolume (hwndDlg, *driveNo, FALSE);
			*driveNo = -1;
		}

		MessageBox (hwndDlg, "A hidden volume can only be created within a FAT volume.\n\nFor more information, please refer to the documentation.", lpszTitle, ICON_HAND);
		return 0;
	}

efs_error:
	CloseHandle (hDevice);

efsf_error:
	CloseVolumeExplorerWindows (hwndDlg, *driveNo);

	if (UnmountVolume (hwndDlg, *driveNo, FALSE))
		*driveNo = -1;

	return -1;
}


// Mounts a volume within which the user intends to create a hidden volume
int MountHiddenVolHost (HWND hwndDlg, char *volumePath, int *driveNo, char *lpszPassword)
{
	MountOptions mountOptions;

	*driveNo = GetLastAvailableDrive ();

	if (*driveNo == -1)
	{
		*driveNo = -2;
		return ERR_NO_FREE_DRIVES;
	}

	mountOptions.ReadOnly = bHiddenVolDirect;
	mountOptions.Removable = ReadRegistryInt ("MountVolumesRemovable", FALSE);

	if (MountVolume (hwndDlg, *driveNo, volumePath, lpszPassword, FALSE, TRUE, &mountOptions, FALSE) < 1)
	{
		*driveNo = -3;
		return ERR_VOL_MOUNT_FAILED;
	}
	return 0;
}


/* Gets the map of the clusters that are free and in use on a volume that is to host
   a hidden volume. The map is scanned to determine the size of the uninterrupted
   block of free space (provided there is any) whose end is aligned with the end
   of the volume. The value will then be used to determine the maximum possible size
   of the hidden volume. */
int ScanVolClusterBitmap (HWND hwndDlg, int *driveNo, __int64 nbrClusters, __int64 *nbrFreeClusters)
{
	PVOLUME_BITMAP_BUFFER lpOutBuffer;
	STARTING_LCN_INPUT_BUFFER lpInBuffer;

	HANDLE hDevice;
	DWORD lBytesReturned;
	int retVal;
	BYTE rmnd;
	char lpFileName[7] = {'\\','\\','.','\\', *driveNo + 'A', ':', 0};
	int i;

	DWORD bufLen;
	__int64 bitmapCnt;

	hDevice = CreateFile (lpFileName, GENERIC_READ, FILE_SHARE_READ|FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);

	if (hDevice == INVALID_HANDLE_VALUE)
	{
		MessageBox (hwndDlg, "Error: Cannot access the outer volume!\nVolume creation cannot continue.", lpszTitle, ICON_HAND);
		goto vcmf_error;
	}

	CloseVolumeExplorerWindows (hwndDlg, *driveNo);
	
	i = 5;	// Auto-retry locking i times because on some systems the first lock attempt always fails for some reason. 
	while (!DeviceIoControl(hDevice, FSCTL_LOCK_VOLUME, NULL, 0, NULL, 0, &lBytesReturned, NULL))
	{
		if (i <= 0)
		{
			retVal = MessageBox (hwndDlg, "Error: Cannot lock the outer volume!\n\nVolume cannot be locked if it contains files or folders\nbeing used by an application or the system.\n\nPlease close any application that might be using files\nor directories on the volume and click Retry.\n\nWARNING: If you decide to ignore this, you must ensure\nthat after you click Ignore, no more data will be written\nto the volume until it is dismounted. Failure to do so may\nadversely affect plausible deniability of the hidden volume!", lpszTitle, MB_ABORTRETRYIGNORE | MB_DEFBUTTON2);
			if (retVal == IDABORT)
			{
				CloseHandle (hDevice);
				return 0;
			}
			else if (retVal == IDIGNORE) break;
		}
		else
		{
			i--;
			Sleep (UNMOUNT_AUTO_RETRY_DELAY);
		}
	}

 	bufLen = (DWORD) (nbrClusters / 8 + 2 * sizeof(LARGE_INTEGER));
	bufLen += 100000 + bufLen/10;	// Add reserve

	lpOutBuffer = malloc(bufLen);

	if (lpOutBuffer == NULL)
	{
		MessageBox (hwndDlg, "Error: Cannot allocate memory for cluster bitmap!\nVolume creation cannot continue.", lpszTitle, ICON_HAND);
		goto vcmf_error;
	}

	lpInBuffer.StartingLcn.QuadPart = 0;

	if ( !DeviceIoControl (hDevice,
		FSCTL_GET_VOLUME_BITMAP,
		&lpInBuffer,
		sizeof(lpInBuffer),
		lpOutBuffer,
		bufLen,  
		&lBytesReturned,
		NULL))
	{
		handleWin32Error (hwndDlg);
		MessageBox (hwndDlg, "Error: Cannot get volume cluster bitmap!\nVolume creation cannot continue.", lpszTitle, ICON_HAND);

		goto vcm_error;
	}

	rmnd = (BYTE) (lpOutBuffer->BitmapSize.QuadPart % 8);

	if ((rmnd != 0) 
	&& ((lpOutBuffer->Buffer[lpOutBuffer->BitmapSize.QuadPart / 8] & ((1 << rmnd)-1) ) != 0))
	{
		*nbrFreeClusters = 0;
	}
	else
	{
		*nbrFreeClusters = lpOutBuffer->BitmapSize.QuadPart;
		bitmapCnt = lpOutBuffer->BitmapSize.QuadPart / 8;

		// Scan the bitmap from the end
		while (--bitmapCnt >= 0)
		{
			if (lpOutBuffer->Buffer[bitmapCnt] != 0)
			{
				// There might be up to 7 extra free clusters in this byte of the bitmap. 
				// These are ignored because there is always a cluster reserve added anyway.
				*nbrFreeClusters = lpOutBuffer->BitmapSize.QuadPart - ((bitmapCnt + 1) * 8);	
				break;
			}
		}
	}

	CloseHandle (hDevice);
	free(lpOutBuffer);
	while (!UnmountVolume (hwndDlg, *driveNo, FALSE))
	{
		if (MessageBox (hwndDlg, "Error: Cannot dismount the outer volume!\n\nVolume cannot be dismounted if it contains files or folders\nbeing used by a program or the system.\n\nPlease close any program that might be using files\nor directories on the volume and click Retry.", lpszTitle, MB_RETRYCANCEL) != IDRETRY)
			return 0;
	}

	*driveNo = -1;
	return 1;

vcm_error:
	CloseHandle (hDevice);
	free(lpOutBuffer);

vcmf_error:
	CloseVolumeExplorerWindows (hwndDlg, *driveNo);

	if (UnmountVolume (hwndDlg, *driveNo, FALSE))
		*driveNo = -1;

	return -1;
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

	if (!AutoTestAlgorithms())
		AbortProcess (IDS_AUTOTEST_FAILED_WIZARD);


	/* Create the main dialog box */
	DialogBoxParam (hInstance, MAKEINTRESOURCE (IDD_MKFS_DLG), NULL, (DLGPROC) MainDialogProc, 
		(LPARAM)lpszCommandLine);

	return 0;
}
