/* Copyright (C) 2004 TrueCrypt Foundation
   This product uses components written by Paul Le Roux <pleroux@swprofessionals.com> */

#include "TCdefs.h"

#include "crypto.h"
#include "apidrvr.h"
#include "dlgcode.h"
#include "combo.h"
#include "registry.h"
#include "../common/resource.h"

#include "resource.h"
#include "cmdline.h"
#include "Mount.h"

#include "dismount.h"

#include "Password.h"
#include <time.h>

BOOL bExplore = FALSE;				/* Display explorer window after mount */
BOOL bBeep = FALSE;					/* Donot beep after mount */
char szFileName[TC_MAX_PATH];		/* Volume to mount */
char szDriveLetter[3];				/* Drive Letter to mount */
BOOL bCacheInDriver = FALSE;		/* Cache any passwords we see */
BOOL bHistory = FALSE;				/* Don't save history */
BOOL bHistoryCmdLine = FALSE;		/* History control is always disabled */
BOOL bCloseDismountedWindows=TRUE;	/* Close all open explorer windows of dismounted volume */
BOOL bWipeCacheOnExit = FALSE;		/* Wipe password from chace on exit */

BOOL bWipe = FALSE;					/* Wipe driver passwords */
BOOL bAuto = FALSE;					/* Do everything without user input */

BOOL bQuiet = FALSE;				/* No dialogs/messages */
char commandLinePassword[MAX_PASSWORD + 1] = {0};	/* Password passed from command line */

#define VMOUNTED 1
#define VFREE	0

int nCurrentShowType = 0;			/* current display mode, mount, unmount etc */
int nSelectedDriveIndex = 0;		/* Item number of selected drive */

void
localcleanup (void)
{
	/* Free the application title */
	if (lpszTitle != NULL)
		free (lpszTitle);

	/* Cleanup common code resources */
	cleanup ();
}

void
RefreshMainDlg (HWND hwndDlg)
{
	int drive = (char) (HIWORD (GetSelectedLong (GetDlgItem (hwndDlg, IDC_DRIVELIST))));

	MoveEditToCombo (GetDlgItem (hwndDlg, IDC_VOLUME));
	LoadDriveLetters (GetDlgItem (hwndDlg, IDC_DRIVELIST), drive);
	EnableDisableButtons (hwndDlg);
}

void
EndMainDlg (HWND hwndDlg)
{
	MoveEditToCombo (GetDlgItem (hwndDlg, IDC_VOLUME));
	if (!bQuiet) SaveSettings (hwndDlg);

	if (bWipeCacheOnExit)
	{
		DWORD dwResult;
		DeviceIoControl (hDriver, WIPE_CACHE, NULL, 0, NULL, 0, &dwResult, NULL);
	}

	EndDialog (hwndDlg, 0);
}

void
EnableDisableButtons (HWND hwndDlg)
{
	HWND hOKButton = GetDlgItem (hwndDlg, IDOK);
	HWND hChangeButton = GetDlgItem (hwndDlg, IDC_CHANGE_PASSWORD);
	HWND hVolume = GetDlgItem (hwndDlg, IDC_VOLUME);
	BOOL bEnable = TRUE;
	WORD x;

	x = LOWORD (GetSelectedLong (GetDlgItem (hwndDlg, IDC_DRIVELIST)));

	if (GetWindowTextLength (GetDlgItem (hwndDlg, IDC_VOLUME)) > 0)
	{
		EnableWindow (hOKButton, TRUE);
		EnableMenuItem (GetMenu (hwndDlg), ID_MOUNT_VOLUME, MF_ENABLED);

		EnableWindow (hChangeButton, TRUE);
		EnableMenuItem (GetMenu (hwndDlg), IDC_CHANGE_PASSWORD, MF_ENABLED);
	}
	else
	{
		EnableWindow (hOKButton, FALSE);
		EnableMenuItem (GetMenu (hwndDlg), ID_MOUNT_VOLUME, MF_GRAYED);

		EnableWindow (hChangeButton, FALSE);
		EnableMenuItem (GetMenu (hwndDlg), IDC_CHANGE_PASSWORD, MF_GRAYED);
	}

	if (x == VFREE)
	{
		SetWindowText (hOKButton, getstr (IDS_MOUNT_BUTTON));

		EnableMenuItem (GetMenu (hwndDlg), ID_UNMOUNT_VOLUME, MF_GRAYED);
	}

	if (x == VMOUNTED)
	{
		SetWindowText (hOKButton, getstr (IDS_UNMOUNT_BUTTON));
		EnableWindow (hOKButton, TRUE);

		EnableMenuItem (GetMenu (hwndDlg), ID_MOUNT_VOLUME, MF_GRAYED);
		EnableMenuItem (GetMenu (hwndDlg), ID_UNMOUNT_VOLUME, MF_ENABLED);

		EnableWindow (GetDlgItem (hwndDlg, IDC_VOLUME_PROPERTIES), TRUE);
		EnableMenuItem (GetMenu (hwndDlg), IDC_VOLUME_PROPERTIES, MF_ENABLED);
	}
	else
	{
		EnableWindow (GetDlgItem (hwndDlg, IDC_VOLUME_PROPERTIES), FALSE);
		EnableMenuItem (GetMenu (hwndDlg), IDC_VOLUME_PROPERTIES, MF_GRAYED);
	}

	EnableWindow (GetDlgItem (hwndDlg, IDC_WIPE_CACHE), !IsPasswordCacheEmpty());
	EnableMenuItem (GetMenu (hwndDlg), IDC_WIPE_CACHE, IsPasswordCacheEmpty() ? MF_GRAYED:MF_ENABLED);
	EnableMenuItem (GetMenu (hwndDlg), IDC_CLEAR_HISTORY, IsComboEmpty (GetDlgItem (hwndDlg, IDC_VOLUME)) ? MF_GRAYED:MF_ENABLED);
}

void
OpenPageHelp (HWND hwndDlg)
{
	int r = (int)ShellExecute (NULL, "open", szHelpFile, NULL, NULL, SW_SHOWNORMAL);

	if (r == ERROR_FILE_NOT_FOUND)
		MessageBox (hwndDlg, getstr (IDS_HELP_ERROR), lpszTitle, MB_ICONERROR);

	if (r == SE_ERR_NOASSOC)
		MessageBox (hwndDlg, getstr (IDS_HELP_READER_ERROR), lpszTitle, MB_ICONERROR);
}

void
LoadSettings (HWND hwndDlg)
{

	// Options
	bCacheInDriver =			ReadRegistryInt ("CachePasswordsInDriver", FALSE);
	bExplore =					ReadRegistryInt ("OpenExplorerWindowAfterMount", FALSE);
	bCloseDismountedWindows =	ReadRegistryInt ("CloseExplorerWindowsOnDismount", TRUE);
	bHistory =					ReadRegistryInt ("SaveMountedVolumesHistory", FALSE);
	bWipeCacheOnExit =			ReadRegistryInt ("WipePasswordCacheOnExit", FALSE);

	// Drive Letter
	ReadRegistryString ("LastSelectedDrive", "", szDriveLetter, sizeof (szDriveLetter));

	// History
	if (bHistoryCmdLine != TRUE)
		LoadCombo (GetDlgItem (hwndDlg, IDC_VOLUME), "LastMountedVolume");
}

void
SaveSettings (HWND hwndDlg)
{
	char szTmp[32] = {0};
	LPARAM lLetter;

	// Options
	WriteRegistryInt ("CachePasswordsInDriver",			bCacheInDriver);
	WriteRegistryInt ("OpenExplorerWindowAfterMount",	bExplore);
	WriteRegistryInt ("CloseExplorerWindowsOnDismount", bCloseDismountedWindows);
	WriteRegistryInt ("SaveMountedVolumesHistory",		!IsButtonChecked (GetDlgItem (hwndDlg, IDC_NO_HISTORY)));
	WriteRegistryInt ("WipePasswordCacheOnExit",		bWipeCacheOnExit);

	// Drive Letter
	lLetter = GetSelectedLong (GetDlgItem (hwndDlg, IDC_DRIVELIST));
	if (LOWORD (lLetter) != 0xffff)
		sprintf (szTmp, "%c:", (char) HIWORD (lLetter));
	WriteRegistryString ("LastSelectedDrive", szTmp);

	// History
	DumpCombo (GetDlgItem (hwndDlg, IDC_VOLUME), "LastMountedVolume", IsButtonChecked (GetDlgItem (hwndDlg, IDC_NO_HISTORY)));
}

BOOL
SelectItem (HWND hTree, char nLetter)
{
	int i;
	LVITEM item;
	
	for (i = 0; i < ListView_GetItemCount(hTree); i++)
	{
		memset(&item, 0, sizeof(LVITEM));
		item.mask = LVIF_PARAM;
		item.iItem = i;

		if (ListView_GetItem (hTree, &item) == FALSE)
			return FALSE;
		else
		{
			if (HIWORD (item.lParam) == nLetter)
			{
				memset(&item, 0, sizeof(LVITEM));
				item.state = LVIS_FOCUSED|LVIS_SELECTED;
				item.stateMask = LVIS_FOCUSED|LVIS_SELECTED;
				item.mask = LVIF_STATE;
				item.iItem = i;
				SendMessage(hTree, LVM_SETITEMSTATE, i, (LPARAM) &item);
				return TRUE;
			}
		}

	}

	return TRUE;
}


// Fills drive list
// drive>0 = update only the corresponding drive subitems
void
LoadDriveLetters (HWND hTree, int drive)
{
	char *szDriveLetters[]=
	{"A:", "B:", "C:", "D:",
	 "E:", "F:", "G:", "H:", "I:", "J:", "K:",
	 "L:", "M:", "N:", "O:", "P:", "Q:", "R:",
	 "S:", "T:", "U:", "V:", "W:", "X:", "Y:",
	 "Z:"};

	DWORD dwResult;
	BOOL bResult;	
	DWORD dwUsedDrives;
	MOUNT_LIST_STRUCT driver;

	LVITEM listItem;
	int item = 0;
	char i;

	bResult = DeviceIoControl (hDriver, MOUNT_LIST, &driver,
		sizeof (driver), &driver, sizeof (driver), &dwResult,
		NULL);

	if (bResult == FALSE)
	{
		handleWin32Error (hTree);
		driver.ulMountedDrives = 0;
	}

	dwUsedDrives = GetLogicalDrives();
	if (dwUsedDrives == 0 && bQuiet == FALSE)
			MessageBox (hTree, getstr (IDS_DRIVELETTERS), lpszTitle, ICON_HAND);

	if(drive == 0)
		ListView_DeleteAllItems(hTree);

	for (i = 2; i < 26; i++)
	{
		int curDrive = 0;

		if(drive > 0)
		{
			LVITEM tmp;
			memset(&tmp, 0, sizeof(LVITEM));
			tmp.mask = LVIF_PARAM;
			tmp.iItem = item;
			if (ListView_GetItem (hTree, &tmp) != FALSE)
				curDrive = HIWORD(tmp.lParam);
		}

		if ( driver.ulMountedDrives & (1 << i) )
		{
			char szTmp[256];

			memset(&listItem, 0, sizeof(listItem));

			listItem.mask = LVIF_TEXT | LVIF_IMAGE | LVIF_PARAM;
			listItem.iImage = 1;
			listItem.iItem = item++;  

			if(drive > 0 && drive != curDrive)
				continue;

			if (nCurrentOS == WIN_NT)
				ToSBCS ((void *) driver.wszVolume[i]);

			if (memcmp (driver.wszVolume[i], "\\Device", 7) == 0)
				sprintf (szTmp, "%s", ((char *) driver.wszVolume[i]));
			else
			{
				if (nCurrentOS == WIN_NT)
					sprintf (szTmp, "%s", ((char *) driver.wszVolume[i]) + 4);
				else
					sprintf (szTmp, "%s", (char *) driver.wszVolume[i]);
			}

			listItem.pszText = szDriveLetters[i];
			listItem.lParam = MAKELONG (VMOUNTED, i + 'A');
			
			if(drive == 0) 
				ListView_InsertItem (hTree, &listItem);
			else
				ListView_SetItem (hTree, &listItem);

			listItem.mask=LVIF_TEXT;   
			listItem.pszText = szTmp;

			listItem.iSubItem = 1;
			ListView_SetItem(hTree, &listItem);

			if(driver.diskLength[i] > 1024I64*1024*1024)
				sprintf (szTmp,"%.1f GB",(double)(driver.diskLength[i]/1024.0/1024/1024));
			else if(driver.diskLength[i] > 1024I64*1024)
				sprintf (szTmp, "%I64d MB", driver.diskLength[i]/1024/1024);
			else if(driver.diskLength[i] > 0)
				sprintf (szTmp, "%I64d KB", driver.diskLength[i]/1024);
			else
				szTmp[0] = 0;

			listItem.iSubItem = 2;
			ListView_SetItem(hTree, &listItem);

			sprintf (szTmp, "%s", get_cipher_name (driver.cipher[i]));
			listItem.iSubItem = 3;
			ListView_SetItem(hTree, &listItem);

		}
		else
		{
			if (!(dwUsedDrives & 1 << i))
			{
				if(drive > 0 && drive != HIWORD (GetSelectedLong (hTree)))
				{
					item++;
					continue;
				}

				memset(&listItem,0,sizeof(listItem));

				listItem.mask = LVIF_TEXT | LVIF_IMAGE | LVIF_PARAM;
				listItem.iImage = 0;
				listItem.iItem = item++;  
				listItem.pszText = szDriveLetters[i];
				listItem.lParam = MAKELONG (VFREE, i + 'A');

				if(drive == 0) 
					ListView_InsertItem (hTree, &listItem);
				else
					ListView_SetItem (hTree, &listItem);

				listItem.mask=LVIF_TEXT;   
				listItem.pszText = "";
				listItem.iSubItem = 1;
				ListView_SetItem(hTree, &listItem);
				listItem.iSubItem = 2;
				ListView_SetItem(hTree, &listItem);
				listItem.iSubItem = 3;
				ListView_SetItem(hTree, &listItem);

			}
		}
	}
}


/* Except in response to the WM_INITDIALOG message, the dialog box procedure
   should return nonzero if it processes the message, and zero if it does
   not. - see DialogProc */
BOOL WINAPI
PasswordChangeDlgProc (HWND hwndDlg, UINT msg, WPARAM wParam, LPARAM lParam)
{

	WORD lw = LOWORD (wParam);
	WORD hw = HIWORD (wParam);

	if (lParam);		/* remove warning */
	if (hw);			/* remove warning */

	switch (msg)
	{
	case WM_INITDIALOG:
		{
			UINT nID[4];

			nID[0] = IDS_PASSWORD_HELP0;
			nID[1] = IDS_PASSWORD_HELP1;
			nID[2] = IDS_PASSWORD_HELP2;
			nID[3] = IDS_PASSWORD_HELP3;

			SetDefaultUserFont (hwndDlg);

			SendMessage (GetDlgItem (hwndDlg, IDC_OLD_PASSWORD), EM_LIMITTEXT, MAX_PASSWORD, 0);
			SendMessage (GetDlgItem (hwndDlg, IDC_PASSWORD), EM_LIMITTEXT, MAX_PASSWORD, 0);
			SendMessage (GetDlgItem (hwndDlg, IDC_VERIFY), EM_LIMITTEXT, MAX_PASSWORD, 0);
			SetWindowText (GetDlgItem (hwndDlg, IDC_BOX_HELP), getmultilinestr (nID));
			EnableWindow (GetDlgItem (hwndDlg, IDOK), FALSE);

			return 1;
		}

	case WM_COMMAND:
		if (lw == IDCANCEL)
		{
			// Attempt to wipe passwords stored in the input field buffers
			char tmp[MAX_PASSWORD+1];
			memset (tmp, 'X', MAX_PASSWORD);
			tmp[MAX_PASSWORD] = 0;

			SetWindowText (GetDlgItem (hwndDlg, IDC_PASSWORD), tmp);	
			SetWindowText (GetDlgItem (hwndDlg, IDC_OLD_PASSWORD), tmp);	
			SetWindowText (GetDlgItem (hwndDlg, IDC_VERIFY), tmp);	

			EndDialog (hwndDlg, IDCANCEL);
			return 1;
		}
		if (hw == EN_CHANGE)
		{
			VerifyPasswordAndUpdate (hwndDlg, GetDlgItem (hwndDlg, IDOK), GetDlgItem (hwndDlg, IDC_PASSWORD),
						 GetDlgItem (hwndDlg, IDC_VERIFY), NULL, NULL);
			return 1;
		}
		if (lw == IDOK)
		{
			HWND hParent = GetParent (hwndDlg);
			char szOldPassword[MAX_PASSWORD + 1];
			char szPassword[MAX_PASSWORD + 1];
			int nStatus;

			GetWindowText (GetDlgItem (hParent, IDC_VOLUME), szFileName, sizeof (szFileName));

			GetWindowText (GetDlgItem (hwndDlg, IDC_OLD_PASSWORD), szOldPassword, sizeof (szOldPassword));

			GetWindowText (GetDlgItem (hwndDlg, IDC_PASSWORD), szPassword, sizeof (szPassword));

			nStatus = ChangePwd (szFileName, szOldPassword, szPassword);

			burn (szOldPassword, sizeof (szOldPassword));
			burn (szPassword, sizeof (szPassword));

			if (nStatus != 0)
				handleError (hwndDlg, nStatus);
			else
			{
				// Attempt to wipe passwords stored in the input field buffers
				char tmp[MAX_PASSWORD+1];
				memset (tmp, 'X', MAX_PASSWORD);
				tmp[MAX_PASSWORD] = 0;
				SetWindowText (GetDlgItem (hwndDlg, IDC_PASSWORD), tmp);	
				SetWindowText (GetDlgItem (hwndDlg, IDC_OLD_PASSWORD), tmp);	
				SetWindowText (GetDlgItem (hwndDlg, IDC_VERIFY), tmp);	

				EndDialog (hwndDlg, IDOK);
			}

			return 1;
		}
		return 0;
	}

	return 0;
}

/* Except in response to the WM_INITDIALOG message, the dialog box procedure
   should return nonzero if it processes the message, and zero if it does
   not. - see DialogProc */
BOOL WINAPI
PasswordDlgProc (HWND hwndDlg, UINT msg, WPARAM wParam, LPARAM lParam)
{
	WORD lw = LOWORD (wParam);
	static char* szXPwd;	

	switch (msg)
	{
	case WM_INITDIALOG:
		{
			szXPwd = (char*) lParam;
			SetDefaultUserFont (hwndDlg);
			SendMessage (GetDlgItem (hwndDlg, IDC_PASSWORD), EM_LIMITTEXT, MAX_PASSWORD, 0);
			SendMessage (GetDlgItem (hwndDlg, IDC_CACHE), BM_SETCHECK, bCacheInDriver ? BST_CHECKED:BST_UNCHECKED, 0);
			return 1;
		}

	case WM_COMMAND:

		if (lw == IDCANCEL || lw == IDOK)
		{
			char tmp[MAX_PASSWORD+1];
			
			if (lw == IDOK)
			{
				GetWindowText (GetDlgItem (hwndDlg, IDC_PASSWORD), szXPwd, MAX_PASSWORD + 1);
				bCacheInDriver = IsButtonChecked (GetDlgItem (hwndDlg, IDC_CACHE));	 
			}

			// Attempt to wipe password stored in the input field buffer
			memset (tmp, 'X', MAX_PASSWORD);
			tmp[MAX_PASSWORD] = 0;
			SetWindowText (GetDlgItem (hwndDlg, IDC_PASSWORD), tmp);	
			SetWindowText (GetDlgItem (hwndDlg, IDC_PASSWORD), 0);	

			EndDialog (hwndDlg, lw);
			return 1;
		}
		return 0;
	}

	return 0;
}

BOOL WINAPI
PreferencesDlgProc (HWND hwndDlg, UINT msg, WPARAM wParam, LPARAM lParam)
{
	WORD lw = LOWORD (wParam);

	switch (msg)
	{
	case WM_INITDIALOG:
		{
			SetDefaultUserFont (hwndDlg);
		
			SendMessage (GetDlgItem (hwndDlg, IDC_PREF_OPEN_EXPLORER), BM_SETCHECK, 
						bExplore ? BST_CHECKED:BST_UNCHECKED, 0);

			SendMessage (GetDlgItem (hwndDlg, IDC_PREF_CLOSE_DISMOUNTED_WINDOWS), BM_SETCHECK, 
						bCloseDismountedWindows ? BST_CHECKED:BST_UNCHECKED, 0);
			
			SendMessage (GetDlgItem (hwndDlg, IDC_PREF_WIPE_CACHE_ON_EXIT), BM_SETCHECK, 
						bWipeCacheOnExit ? BST_CHECKED:BST_UNCHECKED, 0);

			SendMessage (GetDlgItem (hwndDlg, IDC_PREF_CACHE_PASSWORDS), BM_SETCHECK, 
						bCacheInDriver ? BST_CHECKED:BST_UNCHECKED, 0);
			
			
			return 1;
		}

	case WM_COMMAND:

		if (lw == IDCANCEL)
		{
			EndDialog (hwndDlg, lw);
			return 1;
		}

		if (lw == IDOK)
		{
			bExplore = IsButtonChecked (GetDlgItem (hwndDlg, IDC_PREF_OPEN_EXPLORER));	 
			bCloseDismountedWindows = IsButtonChecked (GetDlgItem (hwndDlg, IDC_PREF_CLOSE_DISMOUNTED_WINDOWS));	 
			bWipeCacheOnExit = IsButtonChecked (GetDlgItem (hwndDlg, IDC_PREF_WIPE_CACHE_ON_EXIT));	 
			bCacheInDriver = IsButtonChecked (GetDlgItem (hwndDlg, IDC_PREF_CACHE_PASSWORDS));	 

			EndDialog (hwndDlg, lw);
			return 1;
		}
		return 0;
	}

	return 0;
}

BOOL WINAPI
VolumePropertiesDlgProc (HWND hwndDlg, UINT msg, WPARAM wParam, LPARAM lParam)
{
	WORD lw = LOWORD (wParam);

	switch (msg)
	{
	case WM_INITDIALOG:
		{
			VOLUME_PROPERTIES_STRUCT prop;
			DWORD dwResult;
			BOOL bResult;	

			LVCOLUMN lvCol;
			LVITEM listItem;
			HWND list = GetDlgItem (hwndDlg, IDC_VOLUME_PROPERTIES_LIST);
			char szTmp[128];

			SetDefaultUserFont (hwndDlg);

			SendMessage (list,LVM_SETEXTENDEDLISTVIEWSTYLE,0,
				LVS_EX_FULLROWSELECT
				|LVS_EX_HEADERDRAGDROP 
				//|LVS_EX_GRIDLINES 
				//|LVS_EX_TWOCLICKACTIVATE 
				); 

			memset (&lvCol,0,sizeof(lvCol));               
			lvCol.mask = LVCF_TEXT|LVCF_WIDTH|LVCF_SUBITEM|LVCF_FMT;  
			lvCol.pszText = "Value";                           
			lvCol.cx = 220;
			lvCol.fmt = LVCFMT_LEFT ;
			SendMessage (list,LVM_INSERTCOLUMN,0,(LPARAM)&lvCol);

			lvCol.pszText = "Property";  
			lvCol.cx = 100;           
			lvCol.fmt = LVCFMT_LEFT;
			SendMessage (list,LVM_INSERTCOLUMN,0,(LPARAM)&lvCol);
	
	
			memset (&prop, 0, sizeof(prop));
			prop.driveNo = HIWORD (GetSelectedLong (GetDlgItem (GetParent(hwndDlg), IDC_DRIVELIST))) - 'A';

			bResult = DeviceIoControl (hDriver, VOLUME_PROPERTIES, &prop,
				sizeof (prop), &prop, sizeof (prop), &dwResult,
				NULL);
	
			memset (&listItem, 0, sizeof(listItem));

			listItem.mask = LVIF_TEXT;
			listItem.iItem = -1;

			listItem.pszText = "Volume Location";
			listItem.iItem++; 
			listItem.iSubItem = 0;
			ListView_InsertItem(list, &listItem);
			listItem.iSubItem++;
			listItem.pszText = (LPSTR)prop.wszVolume;
			if (nCurrentOS == WIN_NT)
			{
				ToSBCS (prop.wszVolume);
				if (prop.wszVolume[0] == '?\\')
				listItem.pszText = (LPSTR)prop.wszVolume + 4;
			}
			ListView_SetItem(list, &listItem);

			listItem.pszText = "Volume Size";
			listItem.iItem++;  
			listItem.iSubItem = 0;
			ListView_InsertItem(list, &listItem);
			listItem.iSubItem++;
			sprintf (szTmp, "%I64d bytes", prop.diskLength);
			listItem.pszText = szTmp;
			ListView_SetItem (list, &listItem);

			listItem.pszText = "Cipher";
			listItem.iItem++; 
			listItem.iSubItem = 0;
			ListView_InsertItem(list, &listItem);
			listItem.iSubItem++;
			listItem.pszText = get_cipher_name (prop.cipher);
			ListView_SetItem (list, &listItem);

			listItem.pszText = "Key Size";
			listItem.iItem++;  
			listItem.iSubItem = 0;
			ListView_InsertItem(list, &listItem);
			listItem.iSubItem++;
			sprintf (szTmp, "%d bits", get_key_size (prop.cipher)*8);
			listItem.pszText = szTmp;
			ListView_SetItem (list, &listItem);

			listItem.pszText = "PKCS5 PRF";
			listItem.iItem++; 
			listItem.iSubItem = 0;
			ListView_InsertItem(list, &listItem);
			listItem.iSubItem++;
			listItem.pszText = get_hash_name (prop.pkcs5);
			ListView_SetItem (list, &listItem);

			listItem.pszText = "PKCS5 Iterations";
			listItem.iItem++;  
			listItem.iSubItem = 0;
			ListView_InsertItem(list, &listItem);
			listItem.iSubItem++;
			sprintf (szTmp, "%d", prop.pkcs5Iterations);
			listItem.pszText = szTmp;
			ListView_SetItem (list, &listItem);
			
			{
				FILETIME ft, curFt;
				SYSTEMTIME st;
				char date[128];
				memset (date, 0, sizeof (date));

				listItem.pszText = "Volume Created";
				listItem.iItem++;  
				listItem.iSubItem = 0;
				ListView_InsertItem (list, &listItem);

				listItem.iSubItem++;
				*(unsigned __int64 *)(&ft) = prop.volumeCreationTime;
				FileTimeToSystemTime (&ft, &st);
				GetDateFormat (LOCALE_USER_DEFAULT, 0, &st, 0, (LPSTR) szTmp, sizeof (szTmp));
				sprintf (date, "%s ", szTmp);
				GetTimeFormat (LOCALE_USER_DEFAULT, 0, &st, 0, (LPSTR) szTmp, sizeof (szTmp));
				strcat (date, szTmp);
				listItem.pszText = date;
				ListView_SetItem (list, &listItem);

				listItem.pszText = "Password Changed";
				listItem.iItem++;  
				listItem.iSubItem = 0;
				ListView_InsertItem (list, &listItem);

				listItem.iSubItem++;
				*(unsigned __int64 *)(&ft) = prop.headerCreationTime;
				FileTimeToSystemTime (&ft, &st);
				GetDateFormat (LOCALE_USER_DEFAULT, 0, &st, 0, (LPSTR) szTmp, sizeof (szTmp));
				sprintf (date, "%s ", szTmp);
				GetTimeFormat (LOCALE_USER_DEFAULT, 0, &st, 0, (LPSTR) szTmp, sizeof (szTmp));
				strcat (date, szTmp);

				GetLocalTime (&st);
				SystemTimeToFileTime (&st, &curFt);
				sprintf (date + strlen (date), " (%I64d days ago)"
					, (*(__int64 *)&curFt - *(__int64 *)&ft)/1000000000000 );
				listItem.pszText = date;
				ListView_SetItem (list, &listItem);
			}

			return 1;
		}

	case WM_COMMAND:

		if (lw == IDCANCEL)
		{
			EndDialog (hwndDlg, lw);
			return 1;
		}

		if (lw == IDOK)
		{
			EndDialog (hwndDlg, lw);
			return 1;
		}
		return 0;
	}

	return 0;
}

void
BuildTree (HWND hTree)
{
	HIMAGELIST hList;
	HBITMAP hBitmap, hBitmapMask;
	LVCOLUMN lvCol;
	SendMessage(hTree,LVM_SETEXTENDEDLISTVIEWSTYLE,0,
		LVS_EX_FULLROWSELECT
		|LVS_EX_HEADERDRAGDROP 
		//|LVS_EX_GRIDLINES 
		//|LVS_EX_TWOCLICKACTIVATE 
		); 

	memset(&lvCol,0,sizeof(lvCol)); 

	lvCol.mask = LVCF_TEXT|LVCF_WIDTH|LVCF_SUBITEM|LVCF_FMT;  
	lvCol.pszText="Drive";                           
	lvCol.cx=40;
	lvCol.fmt = LVCFMT_COL_HAS_IMAGES|LVCFMT_LEFT ;
	SendMessage (hTree,LVM_INSERTCOLUMN,0,(LPARAM)&lvCol);

	lvCol.pszText="Volume";  
	lvCol.cx=290;           
	lvCol.fmt = LVCFMT_LEFT;
	SendMessage (hTree,LVM_INSERTCOLUMN,1,(LPARAM)&lvCol);

	lvCol.pszText="Size";  
	lvCol.cx=80;
	lvCol.fmt = LVCFMT_RIGHT;
	SendMessage (hTree,LVM_INSERTCOLUMN,2,(LPARAM)&lvCol);

	lvCol.pszText="Cipher";  
	lvCol.cx=110;
	lvCol.fmt = LVCFMT_LEFT;
	SendMessage (hTree,LVM_INSERTCOLUMN,3,(LPARAM)&lvCol);

	hBitmap = LoadBitmap (hInst, MAKEINTRESOURCE (IDB_DRIVEICON));
	if (hBitmap == NULL)
		return;
	hBitmapMask = LoadBitmap (hInst, MAKEINTRESOURCE (IDB_DRIVEICON_MASK));

	hList = ImageList_Create (16, 12, ILC_COLOR8|ILC_MASK, 2, 2);
	if (ImageList_Add (hList, hBitmap, hBitmapMask) == -1)
	{
		DeleteObject (hBitmap);
		return;
	}
	else
		DeleteObject (hBitmap);

	ListView_SetImageList (hTree, hList, LVSIL_NORMAL); 
	ListView_SetImageList (hTree, hList, LVSIL_SMALL);

	LoadDriveLetters (hTree, 0);
}

LPARAM
GetSelectedLong (HWND hTree)
{
	int hItem = ListView_GetSelectionMark (hTree);
	LVITEM item;

	if (nSelectedDriveIndex != 0)
		hItem = nSelectedDriveIndex;

	memset(&item, 0, sizeof(LVITEM));
	item.mask = LVIF_PARAM;
	item.iItem = hItem;

	if (ListView_GetItem (hTree, &item) == FALSE)
		return MAKELONG (0xffff, 0xffff);
	else
		return item.lParam;
}

LPARAM
GetItemLong (HWND hTree, int itemNo)
{
	LVITEM item;

	memset(&item, 0, sizeof(LVITEM));
	item.mask = LVIF_PARAM;
	item.iItem = itemNo;

	if (ListView_GetItem (hTree, &item) == FALSE)
		return MAKELONG (0xffff, 0xffff);
	else
		return item.lParam;
}

static BOOL MountVolume (HWND hwndDlg, int driveNo, char *volumePath, char *szPassword, int quiet)
{
	MOUNT_STRUCT driver;
	DWORD dwResult;
	BOOL bResult, bDevice;

	if (IsMountedVolume (volumePath))
	{
		if (!quiet)
			MessageBox(0, getstr (IDS_ALREADY_MOUNTED), lpszTitle, MB_ICONASTERISK);
		return FALSE;
	}

	driver.nDosDriveNo = driveNo;
	driver.bCache = bCacheInDriver;
	driver.time = time (NULL);
	driver.nPasswordLen = strlen (szPassword);
	strcpy (driver.szPassword, szPassword);

	CreateFullVolumePath ((char *) driver.wszVolume, volumePath, &bDevice);

	if (nCurrentOS == WIN_NT)
		ToUNICODE ((char *) driver.wszVolume);

	bResult = DeviceIoControl (hDriver, MOUNT, &driver,
		sizeof (driver), &driver, sizeof (driver), &dwResult, NULL);

	burn (&driver.szPassword, sizeof (driver.szPassword));

	if (bResult == FALSE)
	{
		if (!quiet)
			handleWin32Error (hwndDlg);
		return bResult;
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

					if (*inbuf == '-' && !quiet)
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

						bResult = 0;
					}

				}

				if (bResult == FALSE && !quiet)
				{					
					MessageBox (hwndDlg, getstr (IDS_SYMLINK), lpszTitle, ICON_HAND);
					return FALSE;
				}

			}
			else 
			{
				EjectStop ((char)toupper(szFileName[0]), TRUE);
			}
		}
		else
		{
			if (!quiet)	handleError (hwndDlg, driver.nReturnCode);

			return FALSE;
		}
	}

	return TRUE;
}

static BOOL IsPasswordCacheEmpty (void)
{
	DWORD dw;
	return !DeviceIoControl (hDriver, CACHE_STATUS, 0, 0, 0, 0, &dw, 0);
}

static BOOL IsMountedVolume (char *volname)
{
	MOUNT_LIST_STRUCT mlist;
	DWORD dwResult;
	int i;
	char volume[TC_MAX_PATH*2+16];

	strcpy (volume, volname);
	if (nCurrentOS == WIN_NT) 
	{
		if (strstr (volname, "\\Device\\") != volname)
			sprintf(volume, "\\??\\%s", volname);
		ToUNICODE (volume);
	}

	memset (&mlist, 0, sizeof (mlist));
	DeviceIoControl (hDriver, MOUNT_LIST, &mlist,
		sizeof (mlist), &mlist, sizeof (mlist), &dwResult,
		NULL);

	for (i=0 ; i<26; i++)
		if (nCurrentOS != WIN_NT && 0 == strcmp ((char *)mlist.wszVolume[i], volume) 
			|| nCurrentOS == WIN_NT && 0 == wcscmp (mlist.wszVolume[i], (WCHAR *)volume))
			return TRUE;

	return FALSE;
}

static int AskUserPassword (HWND hwndDlg, char *password)
{
	int result = DialogBoxParam (hInst, 
		MAKEINTRESOURCE (IDD_PASSWORD_DLG), hwndDlg,
		(DLGPROC) PasswordDlgProc, (LPARAM) password);

	if (result != IDOK)
		*password = 0;

	return result == IDOK;
}

// GUI actions

static void Mount (HWND hwndDlg)
{
	char szPassword[MAX_PASSWORD + 1];
	int mounted = 0;
	int nDosDriveNo = HIWORD (GetSelectedLong (GetDlgItem (hwndDlg, IDC_DRIVELIST))) - 'A';

	burn (szPassword, sizeof (szPassword));
	GetWindowText (GetDlgItem (hwndDlg, IDC_VOLUME), szFileName,
		sizeof (szFileName));

	if (strlen(szFileName) == 0)
		return;

	if (IsMountedVolume (szFileName))
	{
		MessageBox(0, getstr (IDS_ALREADY_MOUNTED), lpszTitle, MB_ICONASTERISK);
		return;
	}

	// First try cached passwords and if they fail ask user for a new one
	ArrowWaitCursor ();
	mounted = MountVolume (hwndDlg, nDosDriveNo, szFileName, "", TRUE);
	NormalCursor ();
	
	while (!mounted)
	{
		if (!AskUserPassword (hwndDlg, szPassword))
			return;

		ArrowWaitCursor ();
		mounted = MountVolume (hwndDlg, nDosDriveNo, szFileName, szPassword, FALSE);
		NormalCursor ();
	}

	if (mounted)
	{
		if (bBeep == TRUE)
			MessageBeep (MB_OK);

		RefreshMainDlg(hwndDlg);

		if (bExplore == TRUE)
		{	
			ArrowWaitCursor();
			OpenVolumeExplorerWindow (nDosDriveNo);
			NormalCursor();
		}
	}

	burn (szPassword, sizeof (szPassword));
	return;
}

void OpenVolumeExplorerWindow (int driveNo)
{
	char dosName[5];
	SHFILEINFO fInfo;

	sprintf (dosName, "%c:\\", (char) driveNo + 'A');

	// Force explorer to discover the drive
	SHGetFileInfo (dosName, 0, &fInfo, sizeof (fInfo), 0);

	ShellExecute (NULL, "open", dosName, NULL, NULL, SW_SHOWNORMAL);
}

static BOOL CALLBACK CloseVolumeExplorerWindowsEnum( HWND hwnd, LPARAM driveNo)
{
	char get[128], driveStr[10];
	HWND h;

	GetClassName (hwnd, get, sizeof get);

	if (strcmp (get, "CabinetWClass") == 0)
	{
		sprintf (driveStr, "%c:\\", driveNo + 'A');

		// Title bar
		GetWindowText (hwnd, get, sizeof get);
		if (strstr (get, driveStr) == get)
		{
			PostMessage (hwnd, WM_CLOSE, 0, 0);
			return TRUE;
		}

		// URL edit box
		h = FindWindowEx (hwnd, 0, "WorkerW", 0);
		if (!h) return TRUE;
		h = FindWindowEx (h, 0, "ReBarWindow32", 0);
		if (!h) return TRUE;
		h = FindWindowEx (h, 0, "ComboBoxEx32", 0);
		if (h)
		{
			SendMessage (h, WM_GETTEXT, sizeof get, (LPARAM) get);
			if (strstr (get, driveStr) == get)
				PostMessage (hwnd, WM_CLOSE, 0, 0);
		}
	}
	return TRUE;
}

void CloseVolumeExplorerWindows (HWND hwnd, int driveNo)
{
	EnumWindows (CloseVolumeExplorerWindowsEnum, (LPARAM) driveNo);
}

static void Dismount (HWND hwndDlg, int nDosDriveNo)
{
	char *lpszPipeName = "\\\\.\\pipe\\truecryptservice";
	DWORD bytesRead;
	BOOL bResult;
	char inbuf[80];
	char outbuf[80];

	if (nDosDriveNo == 0)
		nDosDriveNo = (char) (HIWORD (GetSelectedLong (GetDlgItem (hwndDlg, IDC_DRIVELIST))) - 'A');

	if (nCurrentOS == WIN_NT)
	{

		if (bCloseDismountedWindows)
			CloseVolumeExplorerWindows (hwndDlg, nDosDriveNo);

		/* Unmount the volume using the TrueCryptService,
		this is done to allow non-administrators
		to unmount volumes */

		sprintf (outbuf, "unmount %d", nDosDriveNo);

		ArrowWaitCursor ();

		bResult = CallNamedPipe (lpszPipeName,
			outbuf, sizeof (outbuf),
			inbuf, sizeof (inbuf),
			&bytesRead, NMPWAIT_WAIT_FOREVER);

		NormalCursor ();

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
				//if (err == ERR_OS_ERROR)
				//{
				//	SetLastError (os_err);

				//	handleWin32Error (hwndDlg);
				//}
				//else
				//{
				//	handleError (hwndDlg, err);
				//}
				MessageBox(0, getstr (IDS_UNMOUNT_FAILED), lpszTitle, MB_ICONEXCLAMATION);
			} 
			else
			{
				//if (bBeep == TRUE)
				//	MessageBeep (MB_OK);

				RefreshMainDlg(hwndDlg);
			}
		}

	}
	else
	{
		int err = 0;

		bResult = CloseSlot (nDosDriveNo, 0, &err);

		if (bResult == FALSE)
		{
			handleWin32Error (hwndDlg);
		}
		else
		{
			if (err != 0)
			{
				//handleError (hwndDlg, err);
				MessageBox(0, getstr (IDS_UNMOUNT_FAILED), lpszTitle, MB_ICONEXCLAMATION);
			}
			else
			{
				//if (bBeep == TRUE)
				//	MessageBeep (MB_OK);

				RefreshMainDlg(hwndDlg);
			}
		}
	}

	return;
}



static void DismountAll (HWND hwndDlg)
{
	char *lpszPipeName = "\\\\.\\pipe\\truecryptservice";
	DWORD bytesRead;
	BOOL bResult;
	int nDosDriveNo;
	char inbuf[80];
	char outbuf[80];

	nDosDriveNo = (char) (HIWORD (GetSelectedLong (GetDlgItem (hwndDlg, IDC_DRIVELIST))) -
		'A');

	ArrowWaitCursor();

	if (nCurrentOS == WIN_NT)
	{
		if (bCloseDismountedWindows)
		{
			MOUNT_LIST_STRUCT driver;
			DWORD dwResult;

			if (DeviceIoControl (hDriver, MOUNT_LIST, &driver, sizeof (driver), &driver, sizeof (driver), &dwResult, NULL))
			{
				int i;
				for (i = 0; i < 26; i++)
					if ((driver.ulMountedDrives & 1 << i))
						CloseVolumeExplorerWindows (hwndDlg, i); 

			}
		}

		/* Unmount the volume using the TrueCryptService,
		this is done to allow non-administrators
		to unmount volumes */

		strcpy (outbuf, "unmountall");

		ArrowWaitCursor ();

		bResult = CallNamedPipe (lpszPipeName,
			outbuf, sizeof (outbuf),
			inbuf, sizeof (inbuf),
			&bytesRead, NMPWAIT_WAIT_FOREVER);

		NormalCursor ();

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
				//if (err == ERR_OS_ERROR)
				//{
				//	SetLastError (os_err);

				//	handleWin32Error (hwndDlg);
				//}
				//else
				//{
				//	handleError (hwndDlg, err);
				//}

				RefreshMainDlg(hwndDlg);
				MessageBox(0, getstr (IDS_UNMOUNT_FAILED), lpszTitle, MB_ICONEXCLAMATION);
			}
			else
			{
				if (bBeep == TRUE)
					MessageBeep (MB_OK);
			}
		}
	}
	else
	{
		DWORD os_error;
		int i, err;

		for (i=0; i<26; i++)
			CloseSlot (i, 0, &err);
	}

	RefreshMainDlg (hwndDlg);
	NormalCursor();
}

static void MountAllPartitions (HWND hwndDlg)
{
	HWND driveList = GetDlgItem (hwndDlg, IDC_DRIVELIST);
	int i, n, selDrive = ListView_GetSelectionMark (driveList);
	char szPassword[MAX_PASSWORD + 1];

	// User is always asked for password as we can't tell 
	// for sure if it is needed or not
	burn (szPassword, sizeof (szPassword));
	if (!AskUserPassword (hwndDlg, szPassword))
		return;

	ArrowWaitCursor();
	
	for (i = 0; i < 64; i++)
	{
		BOOL drivePresent = FALSE;

		for (n = 1; n <= 32; n++)
		{
			char szFileName[TC_MAX_PATH];
			OPEN_TEST_STRUCT driver;

			sprintf (szFileName, "\\Device\\Harddisk%d\\Partition%d", i, n);
			if (OpenDevice (szFileName, &driver) == TRUE && !IsMountedVolume (szFileName))
			{	
				int nDosDriveNo;

				while (LOWORD (GetItemLong (driveList, selDrive)) != 0xffff)
				{
					if(LOWORD (GetItemLong (driveList, selDrive)) != VFREE)
					{
						selDrive++;
						continue;
					}
					nDosDriveNo = HIWORD(GetItemLong (driveList, selDrive)) - 'A';
					break;
				}

				if (LOWORD (GetItemLong (driveList, selDrive)) == 0xffff)
					goto ret;

				// First try user password then cached passwords
				if (MountVolume (hwndDlg, nDosDriveNo, szFileName, szPassword, TRUE)
					|| MountVolume (hwndDlg, nDosDriveNo, szFileName, "", TRUE))
				{
					LoadDriveLetters (driveList, (HIWORD (GetItemLong (GetDlgItem (hwndDlg, IDC_DRIVELIST), selDrive))));
					selDrive++;

					if (bExplore == TRUE)
					{	
						ArrowWaitCursor();
						OpenVolumeExplorerWindow (nDosDriveNo);
						NormalCursor();
					}
				}
			}
		}
	}

ret:
	burn (szPassword, sizeof (szPassword));
	EnableDisableButtons (hwndDlg);
	NormalCursor();
}

static void ChangePassword (HWND hwndDlg)
{
	int result;
	
	GetWindowText (GetDlgItem (hwndDlg, IDC_VOLUME), szFileName, sizeof (szFileName));
	if (IsMountedVolume (szFileName))
	{
		MessageBox (hwndDlg, getstr (IDS_MOUNTED_NOPWCHANGE), lpszTitle, MB_ICONEXCLAMATION);
		return;
	}

	result = DialogBox (hInst, MAKEINTRESOURCE (IDD_PASSWORDCHANGE_DLG), hwndDlg,
		(DLGPROC) PasswordChangeDlgProc);

	if (result == IDOK)
	{
		HWND tmp = GetDlgItem (hwndDlg, IDC_PASSWORD);
		MessageBox (hwndDlg, getstr (IDS_PASSWORD_CHANGED), lpszTitle, MB_ICONASTERISK);
		SetFocus (tmp);
	}
}

static void SelectContainer (HWND hwndDlg)
{
	if (BrowseFiles (hwndDlg, IDS_OPEN_TITLE, szFileName) == FALSE)
		return;

	AddComboItem (GetDlgItem (hwndDlg, IDC_VOLUME), szFileName);
	EnableDisableButtons (hwndDlg);
	SetFocus (GetDlgItem (hwndDlg, IDC_PASSWORD));
}

static void SelectPartition (HWND hwndDlg)
{
	int nResult = DialogBoxParam (hInst, MAKEINTRESOURCE (IDD_RAWDEVICES_DLG), hwndDlg,
		(DLGPROC) RawDevicesDlgProc, (LPARAM) & szFileName[0]);
	if (nResult == IDOK)
	{
		AddComboItem (GetDlgItem (hwndDlg, IDC_VOLUME), szFileName);
		EnableDisableButtons (hwndDlg);
		SetFocus (GetDlgItem (hwndDlg, IDC_PASSWORD));
	}
}

static void WipeCache (HWND hwndDlg)
{
	DWORD dwResult;
	BOOL bResult;

	bResult = DeviceIoControl (hDriver, WIPE_CACHE, NULL, 0, NULL, 0, &dwResult, NULL);

	if (bResult == FALSE)
		handleWin32Error (hwndDlg);
	else
	{
		EnableDisableButtons (hwndDlg);

		if (bQuiet == FALSE)
			MessageBox (hwndDlg, getstr (IDS_WIPE_CACHE), lpszTitle, MB_ICONINFORMATION);
	}
}


/* Except in response to the WM_INITDIALOG message, the dialog box procedure
   should return nonzero if it processes the message, and zero if it does
   not. - see DialogProc */
BOOL CALLBACK
MainDialogProc (HWND hwndDlg, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
	WORD lw = LOWORD (wParam);
	WORD hw = HIWORD (wParam);
	if (lParam);		/* remove warning */

	switch (uMsg)
	{

	case WM_INITDIALOG:
		{
			ExtractCommandLine (hwndDlg, (char *) lParam);

			if (!bQuiet) LoadSettings (hwndDlg);

			/* Call the common dialog init code */
			InitDialog (hwndDlg);
			SetDefaultUserFont (hwndDlg);

			SendMessage (GetDlgItem (hwndDlg, IDC_VOLUME), CB_LIMITTEXT, TC_MAX_PATH, 0);

			SendMessage (GetDlgItem (hwndDlg, IDC_NO_DRIVES_STATIC), WM_SETFONT, (WPARAM) hBoldFont, (LPARAM) TRUE);
			SetWindowText (hwndDlg, lpszTitle);

			BuildTree (GetDlgItem (hwndDlg, IDC_DRIVELIST));


			if (*szDriveLetter != 0)
			{
				SelectItem (GetDlgItem (hwndDlg, IDC_DRIVELIST), *szDriveLetter);

				if(nSelectedDriveIndex > SendMessage (GetDlgItem (hwndDlg, IDC_DRIVELIST), LVM_GETITEMCOUNT, 0, 0)/2) 
					SendMessage(GetDlgItem (hwndDlg, IDC_DRIVELIST), LVM_SCROLL, 0, 1000);
			}

			SendMessage (GetDlgItem (hwndDlg, IDC_NO_HISTORY), BM_SETCHECK, bHistory ? BST_UNCHECKED : BST_CHECKED, 0);

			EnableDisableButtons (hwndDlg);

			if (bWipe == TRUE)
			{
				WipeCache (hwndDlg);
				if (bQuiet) ExitProcess (0);
			}

			// Automount
			if (bAuto == TRUE && IsWindowEnabled (GetDlgItem (hwndDlg, IDOK)))
			{
				if (!IsMountedVolume (szFileName))
				{
					BOOL mounted;

					// Cached password
					mounted = MountVolume (hwndDlg, szDriveLetter[0] - 'A', szFileName, "", TRUE);

					if (!mounted && commandLinePassword[0] != 0)
					{
						// Command line password
						mounted = MountVolume (hwndDlg, szDriveLetter[0] - 'A', szFileName, commandLinePassword, TRUE);
						burn (commandLinePassword, sizeof (commandLinePassword));
					}

					// Ask user for password
					while (!mounted)
					{
						char szPassword[MAX_PASSWORD + 1];

						if (!AskUserPassword (hwndDlg, szPassword))
							break;

						ArrowWaitCursor ();
						mounted = MountVolume (hwndDlg, szDriveLetter[0] - 'A', szFileName, szPassword, FALSE);
						burn (szPassword, sizeof (szPassword));
						NormalCursor ();
					}

					if (mounted)
					{
						if (bBeep == TRUE) MessageBeep (MB_OK);
						if (bExplore == TRUE) OpenVolumeExplorerWindow (szDriveLetter[0] - 'A');
						if (bQuiet) ExitProcess (0);
					}
					else if (bQuiet) ExitProcess (1);
					
					RefreshMainDlg(hwndDlg);
				}
				else if (bQuiet) ExitProcess (0);
			}

			SetFocus (GetDlgItem (hwndDlg, IDC_DRIVELIST));
		}
		return 0;

	case WM_SYSCOMMAND:
		if (lw == IDC_ABOUT)
		{
			DialogBox (hInst, MAKEINTRESOURCE (IDD_ABOUT_DLG), hwndDlg, (DLGPROC) AboutDlgProc);
			return 1;
		}
		return 0;

	case WM_HELP:
		OpenPageHelp (hwndDlg);
		return 1;

	case WM_NOTIFY:
		// Single click in drive list
		if (((LPNMHDR) lParam)->code == LVN_ITEMCHANGED && (((LPNMLISTVIEW) lParam)->uNewState & LVIS_FOCUSED ))
		{
			nSelectedDriveIndex = ((LPNMLISTVIEW) lParam)->iItem;
			EnableDisableButtons (hwndDlg);

			return 1;
		}

		// Double click in drive list
		if (((LPNMHDR) lParam)->code == LVN_ITEMACTIVATE)
		{
			int state = GetItemLong(GetDlgItem (hwndDlg, IDC_DRIVELIST), ((LPNMITEMACTIVATE)lParam)->iItem );
			nSelectedDriveIndex = ((LPNMITEMACTIVATE)lParam)->iItem;
			if (LOWORD(state) == VMOUNTED)
			{
				// Open explorer window for mounted volume
				ArrowWaitCursor ();
				OpenVolumeExplorerWindow (HIWORD(state) - 'A');
				NormalCursor ();
			}
			else if (LOWORD (GetSelectedLong (GetDlgItem (hwndDlg, IDC_DRIVELIST))) == VFREE)
			{
				Mount (hwndDlg);
			}
		}
		return 0;

	case WM_ERASEBKGND:
		return 0;

	case WM_COMMAND:

		if (lw == IDCANCEL)
		{
			EndMainDlg (hwndDlg);
			return 1;
		}

		if (lw == IDHELP || lw == IDM_HELP)
		{
			OpenPageHelp (hwndDlg);
			return 1;
		}

		if (lw == IDM_ABOUT || lw == IDB_LOGO)
		{
			DialogBox (hInst, MAKEINTRESOURCE (IDD_ABOUT_DLG), hwndDlg, (DLGPROC) AboutDlgProc);
			return 1;
		}

		if ((lw == IDOK || lw == ID_MOUNT_VOLUME) 
			&& LOWORD (GetSelectedLong (GetDlgItem (hwndDlg, IDC_DRIVELIST))) == VFREE)
		{

			Mount (hwndDlg);
			return 1;
		}

		if ((lw == IDOK || lw == ID_MOUNT_VOLUME || lw == IDC_MOUNTALL) 
			&& LOWORD (GetSelectedLong (GetDlgItem (hwndDlg, IDC_DRIVELIST))) == 0xffff)
		{
			MessageBox (hwndDlg, "No drive selected.","TrueCrypt", MB_ICONEXCLAMATION);
			return 1;
		}

		if (lw == IDOK && LOWORD (GetSelectedLong (GetDlgItem (hwndDlg, IDC_DRIVELIST))) == VMOUNTED
			|| lw == ID_UNMOUNT_VOLUME)
		{
			Dismount (hwndDlg, 0);
			return 1;
		}

		if (lw == IDUNMOUNTALL)
		{
			DismountAll (hwndDlg);
			return 1;
		}

		if (lw == IDC_MOUNTALL)
		{
			MountAllPartitions (hwndDlg);
			return 1;
		}
		
		if (lw == IDC_BROWSE_FILES)
		{
			SelectContainer (hwndDlg);
			return 1;
		}

		if (lw == IDC_BROWSE_DEVICES)
		{
			SelectPartition (hwndDlg);
			return 1;
		}

		if (lw == IDC_CHANGE_PASSWORD)
		{
			ChangePassword (hwndDlg);
			return 1;
		}

		if (lw == IDC_WIPE_CACHE)
		{
			WipeCache (hwndDlg);
			return 1;
		}

		if (lw == IDC_CLEAR_HISTORY)
		{
			ClearCombo (GetDlgItem (hwndDlg, IDC_VOLUME));
			DumpCombo (GetDlgItem (hwndDlg, IDC_VOLUME), "LastMountedVolume", TRUE);
			EnableDisableButtons (hwndDlg);
			return 1;
		}

		if (lw == IDC_CREATE_VOLUME)
		{
			char t[TC_MAX_PATH];
			char *tmp;

			GetModuleFileName (NULL, t, sizeof (t));
			tmp = strrchr (t, '\\');
			if (tmp)
			{
				strcpy (++tmp, "TrueCrypt Format.exe");
				ShellExecute (NULL, "open", t, NULL, NULL, SW_SHOWNORMAL);
			}
			return 1;
		}

		if (lw == ID_WEBSITE)
		{
			ShellExecute (NULL, "open", "http://www.google.com/search?q=truecrypt", NULL, NULL, SW_SHOWNORMAL);
			return 1;
		}
		
		if (lw == ID_PREFERENCES)
		{
			DialogBoxParam (hInst, 
				MAKEINTRESOURCE (IDD_PREFERENCES_DLG), hwndDlg,
				(DLGPROC) PreferencesDlgProc, (LPARAM) 0);
			return 1;
		}

		if (lw == IDC_VOLUME_PROPERTIES)
		{
			DialogBoxParam (hInst, 
				MAKEINTRESOURCE (IDD_VOLUME_PROPERTIES), hwndDlg,
				(DLGPROC) VolumePropertiesDlgProc, (LPARAM) 0);
			return 1;
		}

		if (lw == IDC_VOLUME && hw == CBN_EDITCHANGE)
		{
			PostMessage (hwndDlg, WM_USER, 0, 0);
			return 1;
		}

		if (lw == IDC_VOLUME && hw == CBN_SELCHANGE)
		{
			UpdateComboOrder (GetDlgItem (hwndDlg, IDC_VOLUME));
			MoveEditToCombo ((HWND) lParam);
			PostMessage (hwndDlg, WM_USER, 0, 0);
			return 1;
		}

		return 0;

	case WM_USER:
		EnableDisableButtons (hwndDlg);
		return 1;

	case WM_CLOSE:
		EndMainDlg (hwndDlg);
		return 1;
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
				{"/volume", "/v"},
				{"/letter", "/l"},
				{"/explore", "/e"},
				{"/beep", "/b"},
				{"/password", "/p"},
				{"/auto", "/a"},
				{"/cache", "/c"},
				{"/history", "/h"},
				{"/wipecache", "/w"},
				{"/quiet", "/q"},
				{"/help", "/?"},
				{"/dismount", "/d"}
			};

			argumentspec as;

			int nArgPos;
			int x;

			as.args = args;
			as.arg_cnt = sizeof(args)/ sizeof(args[0]);
			
			x = GetArgumentID (&as, lpszCommandLineArgs[i], &nArgPos);

			switch (x)
			{
			case 'd':

				if (HAS_ARGUMENT == GetArgumentValue (lpszCommandLineArgs, nArgPos, &i, nNoCommandLineArgs,
				     szDriveLetter, sizeof (szDriveLetter)))
					Dismount (hwndDlg, (char)toupper(szDriveLetter[0]) - 'A');
				else 
					DismountAll (hwndDlg);

				ExitProcess (0);
				break;

			case 'v':
				if (HAS_ARGUMENT == GetArgumentValue (lpszCommandLineArgs, nArgPos, &i,
								      nNoCommandLineArgs, szFileName, sizeof (szFileName)))
				{
					// Relative path must be converted to absolute
					if (szFileName[0] != '\\' && strchr (szFileName, ':') == 0)
					{
						char path[MAX_PATH*2];
						GetCurrentDirectory (MAX_PATH, path);
						strcat (path, "\\");
						strcat (path, szFileName);
						strncpy (szFileName, path, MAX_PATH-1);
					}
					AddComboItem (GetDlgItem (hwndDlg, IDC_VOLUME), szFileName);
				}
				break;

			case 'l':
				GetArgumentValue (lpszCommandLineArgs, nArgPos, &i, nNoCommandLineArgs,
				     szDriveLetter, sizeof (szDriveLetter));
				*szDriveLetter = (char) toupper (*szDriveLetter);
				break;

			case 'e':
				bExplore = TRUE;
				break;

			case 'b':
				bBeep = TRUE;
				break;

			case 'p':
				GetArgumentValue (lpszCommandLineArgs, nArgPos, &i, nNoCommandLineArgs,
						     commandLinePassword, sizeof (commandLinePassword));
				break;

			case 'a':
				bAuto = TRUE;
				break;

			case 'c':
				{
					char szTmp[8];
					GetArgumentValue (lpszCommandLineArgs, nArgPos, &i, nNoCommandLineArgs,
						     szTmp, sizeof (szTmp));
					if (!_stricmp(szTmp,"y") || !_stricmp(szTmp,"yes"))
						bCacheInDriver = TRUE;
					if (!_stricmp(szTmp,"n") || !_stricmp(szTmp,"no"))
						bCacheInDriver = FALSE;
				}
				break;

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

			case 'w':
				bWipe = TRUE;
				break;

			case 'q':
				bQuiet = TRUE;
				break;

			case '?':
				DialogBoxParam (hInst, MAKEINTRESOURCE (IDD_COMMANDHELP_DLG), hwndDlg, (DLGPROC)
						CommandHelpDlgProc, (LPARAM) &as);
				exit(0);
				break;

				// no option = file name
			default:
				{
					strncpy (szFileName, lpszCommandLineArgs[0], MAX_PATH-1);
					if (szFileName[0] != '\\' && strchr (szFileName, ':') == 0)
					{
						char path[MAX_PATH*2];
						GetCurrentDirectory (MAX_PATH, path);
						strcat (path, "\\");
						strcat (path, szFileName);
						strncpy (szFileName, path, MAX_PATH-1);
					}
					AddComboItem (GetDlgItem (hwndDlg, IDC_VOLUME), szFileName);
				}
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
WINMAIN (HINSTANCE hInstance, HINSTANCE hPrevInstance, char *lpszCommandLine,
	 int nCmdShow)
{
	int status;

	if (nCmdShow && hPrevInstance);	/* Remove unused parameter warning */

	atexit (localcleanup);

	/* Allocate, dup, then store away the application title */
	lpszTitle = err_strdup (getstr (IDS_TITLE));

	/* Call InitApp to initialize the common code */
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
	DialogBoxParam (hInstance, MAKEINTRESOURCE (IDD_MOUNT_DLG), NULL, (DLGPROC) MainDialogProc,
			(LPARAM) lpszCommandLine);

	/* Terminate */
	return 0;
}
