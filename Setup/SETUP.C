/* The source code contained in this file has been derived from the source code
   of Encryption for the Masses 2.02a by Paul Le Roux. Modifications and
   additions to that source code contained in this file are Copyright (c) 2004
   TrueCrypt Foundation and Copyright (c) 2004 TrueCrypt Team. Unmodified
   parts are Copyright (c) 1998-99 Paul Le Roux. This is a TrueCrypt Foundation
   release. Please see the file license.txt for full license details. */

#include "TCdefs.h"
#include <SrRestorePtApi.h>

#define MAX_PASSWORD 

#include "apidrvr.h"
#include "dlgcode.h"
#include "../common/resource.h"

#include "resource.h"

#include "dir.h"
#include "setup.h"

#include <sys\types.h>
#include <sys\stat.h>

#pragma warning( disable : 4201 )
#pragma warning( disable : 4115 )

#include <shlobj.h>

#pragma warning( default : 4201 )
#pragma warning( default : 4115 )

char dlg_file_name[TC_MAX_PATH];
BOOL bUninstall = FALSE;
BOOL bDone = FALSE;

HMODULE SystemRestoreDll = 0;

BOOL
StatDeleteFile (char *lpszFile)
{
	struct __stat64 st;

	if (_stat64 (lpszFile, &st) == 0)
		return DeleteFile (lpszFile);
	else
		return TRUE;
}

BOOL
StatRemoveDirectory (char *lpszDir)
{
	struct __stat64 st;

	if (_stat64 (lpszDir, &st) == 0)
		return RemoveDirectory (lpszDir);
	else
		return TRUE;
}

HRESULT
CreateLink (char *lpszPathObj, char *lpszArguments,
	    char *lpszPathLink)
{
	HRESULT hres;
	IShellLink *psl;

	/* Get a pointer to the IShellLink interface.  */
	hres = CoCreateInstance (&CLSID_ShellLink, NULL,
			       CLSCTX_INPROC_SERVER, &IID_IShellLink, &psl);
	if (SUCCEEDED (hres))
	{
		IPersistFile *ppf;

		/* Set the path to the shortcut target, and add the
		   description.  */
		psl->lpVtbl->SetPath (psl, lpszPathObj);
		psl->lpVtbl->SetArguments (psl, lpszArguments);

		/* Query IShellLink for the IPersistFile interface for saving
		   the shortcut in persistent storage.  */
		hres = psl->lpVtbl->QueryInterface (psl, &IID_IPersistFile,
						    &ppf);

		if (SUCCEEDED (hres))
		{
			WORD wsz[TC_MAX_PATH];

			/* Ensure that the string is ANSI.  */
			MultiByteToWideChar (CP_ACP, 0, lpszPathLink, -1,
					     wsz, TC_MAX_PATH);

			/* Save the link by calling IPersistFile::Save.  */
			hres = ppf->lpVtbl->Save (ppf, wsz, TRUE);
			ppf->lpVtbl->Release (ppf);
		}
		psl->lpVtbl->Release (psl);
	}
	return hres;
}

void
GetProgramPath (HWND hwndDlg, char *path)
{
	ITEMIDLIST *i;
	HRESULT res;

	if (nCurrentOS == WIN_NT && IsDlgButtonChecked (hwndDlg, IDC_ALL_USERS))
        res = SHGetSpecialFolderLocation (hwndDlg, CSIDL_COMMON_PROGRAMS, &i);
	else
        res = SHGetSpecialFolderLocation (hwndDlg, CSIDL_PROGRAMS, &i);

	SHGetPathFromIDList (i, path);
}


void
StatusMessage (HWND hwndDlg, char *head, char *txt)
{
	char szTmp[TC_MAX_PATH];
	sprintf (szTmp, head, txt);
	SendMessage (GetDlgItem (hwndDlg, IDC_FILES), LB_ADDSTRING, 0, (LPARAM) szTmp);
		
	SendDlgItemMessage (hwndDlg, IDC_FILES, LB_SETTOPINDEX, 
		SendDlgItemMessage (hwndDlg, IDC_FILES, LB_GETCOUNT, 0, 0) - 1, 0);
}

void
RegMessage (HWND hwndDlg, char *txt)
{
	StatusMessage (hwndDlg, "Adding registry entry %s", txt);
}

void
CopyMessage (HWND hwndDlg, char *txt)
{
	StatusMessage (hwndDlg, "Copying %s", txt);
}

void
RemoveMessage (HWND hwndDlg, char *txt)
{
	StatusMessage (hwndDlg, "Removing %s", txt);
}

void
ServiceMessage (HWND hwndDlg, char *txt)
{
	StatusMessage (hwndDlg, "Service %s", txt);
}

void
IconMessage (HWND hwndDlg, char *txt)
{
	StatusMessage (hwndDlg, "Adding icon %s", txt);
}

int CALLBACK
BrowseCallbackProc(HWND hwnd,UINT uMsg,LPARAM lp, LPARAM pData) 
{
	switch(uMsg) {
	case BFFM_INITIALIZED: 
	{
	  /* WParam is TRUE since we are passing a path.
	   It would be FALSE if we were passing a pidl. */
	   SendMessage(hwnd,BFFM_SETSELECTION,TRUE,(LPARAM)pData);
	   break;
	}

	case BFFM_SELCHANGED: 
	{
		char szDir[TC_MAX_PATH];

	   /* Set the status window to the currently selected path. */
	   if (SHGetPathFromIDList((LPITEMIDLIST) lp ,szDir)) 
	   {
		  SendMessage(hwnd,BFFM_SETSTATUSTEXT,0,(LPARAM)szDir);
	   }
	   break;
	}

	default:
	   break;
	}

	return 0;
}

BOOL
BrowseFiles2 (HWND hwndDlg, char* lpszTitle, char* lpszFileName)
{
	BROWSEINFO bi;
	LPITEMIDLIST pidl;
	LPMALLOC pMalloc;
	BOOL bOK  = FALSE;

	if (SUCCEEDED(SHGetMalloc(&pMalloc))) 
	{
		ZeroMemory(&bi,sizeof(bi));
		bi.hwndOwner = hwndDlg;
		bi.pszDisplayName = 0;
		bi.lpszTitle = lpszTitle;
		bi.pidlRoot = 0;
		bi.ulFlags = BIF_RETURNONLYFSDIRS | BIF_STATUSTEXT /*| BIF_EDITBOX*/;
		bi.lpfn = BrowseCallbackProc;
		bi.lParam = (LPARAM)lpszFileName;

		pidl = SHBrowseForFolder(&bi);
		if (pidl!=NULL) 
		{
			if (SHGetPathFromIDList(pidl,lpszFileName)==TRUE) 
			{
				bOK = TRUE;
			}

			pMalloc->lpVtbl->Free(pMalloc,pidl);
			pMalloc->lpVtbl->Release(pMalloc);
		}
	}

	return bOK;
}


void
LoadLicense (HWND hwndDlg)
{
	FILE *fp;

	fp = fopen ("Setup Files\\license.txt", "rb");

	if (fp == NULL)
		return;
	else
	{
		long x;

		fseek (fp, 0, SEEK_END);
		x = ftell (fp);
		rewind (fp);

		if (x > 0)
		{
			char *tmp = malloc (x + 1);
			long z;

			if (tmp == NULL)
				goto exit;
			z = (long) fread (tmp, 1, x, fp);
			if (z != x)
			{
				free (tmp);
				goto exit;
			}
			else
			{
				int i;
				tmp[x] = 0;

				//// Remove single CRLFs
				//for (i = 0; i < x - 3; i++)
				//{
				//	if (tmp[i] == 0xd && tmp[i+2] == 0xd)
				//		i += 4;

				//	if (tmp[i] == 0xd && tmp[i+2] != 0xd)
				//	{
				//		tmp[i] = tmp[i+1] = ' ';
				//	}
				//}

				SendMessage (GetDlgItem (hwndDlg, IDC_LICENSE), WM_SETFONT, (WPARAM) hFixedFont, (LPARAM) 0);
				SetWindowText (GetDlgItem (hwndDlg, IDC_LICENSE), tmp);

				free (tmp);
			}
		}
	}

      exit:
	fclose (fp);
}

BOOL
DoFilesInstall (HWND hwndDlg, char *szDestDir, BOOL bUninstallSupport)
{


	char *szFiles[]=
	{
		"ATrueCrypt.exe", "ATrueCrypt Format.exe",
		"Alicense.txt", "ATrueCrypt User Guide.pdf",
		"WTrueCrypt Setup.exe", "Dtruecrypt.sys"
	};

	char szTmp[TC_MAX_PATH];
	BOOL bOK = TRUE;
	int i;

	if (bUninstall == TRUE)
		bUninstallSupport = FALSE;

	for (i = 0; i < sizeof (szFiles) / sizeof (szFiles[0]); i++)
	{
		BOOL bResult, bSlash;
		char szDir[TC_MAX_PATH];
		int x;

		if (bUninstallSupport == FALSE && strstr (szFiles[i], "TrueCrypt Setup") != 0)
			continue;

		if (*szFiles[i] == 'A')
			strcpy (szDir, szDestDir);
		else if (*szFiles[i] == 'S')
			GetSystemDirectory (szDir, sizeof (szDir));
		else if (*szFiles[i] == 'I')
		{
			GetSystemDirectory (szDir, sizeof (szDir));

			x = strlen (szDestDir);
			if (szDestDir[x - 1] == '\\')
				bSlash = TRUE;
			else
				bSlash = FALSE;

			if (bSlash == FALSE)
				strcat (szDir, "\\");

			strcat (szDir, "IOSUBSYS");
		}
		else if (*szFiles[i] == 'D')
		{
			GetSystemDirectory (szDir, sizeof (szDir));

			x = strlen (szDestDir);
			if (szDestDir[x - 1] == '\\')
				bSlash = TRUE;
			else
				bSlash = FALSE;

			if (bSlash == FALSE)
				strcat (szDir, "\\");

			strcat (szDir, "Drivers");
		}
		else if (*szFiles[i] == 'W')
			GetWindowsDirectory (szDir, sizeof (szDir));

		x = strlen (szDestDir);
		if (szDestDir[x - 1] == '\\')
			bSlash = TRUE;
		else
			bSlash = FALSE;

		if (bSlash == FALSE)
			strcat (szDir, "\\");

		if ((*szFiles[i] == 'D' || *szFiles[i] == 'S') && nCurrentOS != WIN_NT)
			continue;

		if (*szFiles[i] == 'I' && nCurrentOS == WIN_NT)
			continue;

		sprintf (szTmp, "%s%s", szDir, szFiles[i] + 1);

		if (bUninstall == FALSE)
			CopyMessage (hwndDlg, szTmp);
		else
			RemoveMessage (hwndDlg, szTmp);

		if (bUninstall == FALSE)
		{
			bResult = CopyFile (szFiles[i] + 1, szTmp, FALSE);
			if (!bResult)
			{
				char s[256];
				sprintf (s, "Setup Files\\%s", szFiles[i] + 1);
				bResult = CopyFile (s, szTmp, FALSE);
			}
		}
		else
		{
			bResult = StatDeleteFile (szTmp);
		}

		if (bResult == FALSE)
		{
			LPVOID lpMsgBuf;
			DWORD dwError = GetLastError ();
			char szTmp2[700];

			FormatMessage (
					      FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM,
					      NULL,
					      dwError,
				 MAKELANGID (LANG_NEUTRAL, SUBLANG_DEFAULT),	/* Default language */
					      (char *) &lpMsgBuf,
					      0,
					      NULL
				);


			if (bUninstall == FALSE)
				sprintf (szTmp2, "Installation of '%s' has failed.\n%s\nDo you want to continue installing?",
					 szTmp, lpMsgBuf);
			else
				sprintf (szTmp2, "Uninstallation of '%s' has failed.\n%s\nDo you want to continue uninstalling?",
					 szTmp, lpMsgBuf);

			LocalFree (lpMsgBuf);

			if (MessageBox (hwndDlg, szTmp2, lpszTitle, MB_YESNO | MB_ICONHAND) != IDYES)
				return FALSE;
		}

	}

	return bOK;
}

BOOL
DoRegInstall (HWND hwndDlg, char *szDestDir, BOOL bInstallType, BOOL bUninstallSupport)
{
	char szDir[TC_MAX_PATH], *key;
	HKEY hkey = 0;
	BOOL bSlash, bOK = FALSE;
	DWORD dw;
	int x;

	strcpy (szDir, szDestDir);
	x = strlen (szDestDir);
	if (szDestDir[x - 1] == '\\')
		bSlash = TRUE;
	else
		bSlash = FALSE;

	if (bSlash == FALSE)
		strcat (szDir, "\\");

	if (nCurrentOS == WIN_NT)
	{
		/* 9/9/99 FIX This code should no longer be needed as we use
		   the "services" api to install the driver now, rather than
		   setting the registry by hand */

		/* Install device driver */
		key = "SYSTEM\\CurrentControlSet\\Services\\truecrypt";
		RegMessage (hwndDlg, key);
		if (RegCreateKeyEx (HKEY_LOCAL_MACHINE,
				    key,
				    0, NULL, REG_OPTION_NON_VOLATILE, KEY_WRITE, NULL, &hkey, &dw) != ERROR_SUCCESS)
			goto error;

		dw = 1;
		if (RegSetValueEx (hkey, "Type", 0, REG_DWORD, (BYTE *) & dw, 4) != ERROR_SUCCESS)
			goto error;

		dw = 1;
		if (RegSetValueEx (hkey, "Start", 0, REG_DWORD, (BYTE *) & dw, 4) != ERROR_SUCCESS)
			goto error;

		dw = 1;
		if (RegSetValueEx (hkey, "ErrorControl", 0, REG_DWORD, (BYTE *) & dw, 4) != ERROR_SUCCESS)
			goto error;

		if (RegSetValueEx (hkey, "Group", 0, REG_SZ, (BYTE *) "Primary disk", 13) != ERROR_SUCCESS)
			goto error;

		RegCloseKey (hkey);
		hkey = 0;
	}

	if (bInstallType == TRUE)
	{
		char szTmp[TC_MAX_PATH];

		key = "SOFTWARE\\Classes\\TrueCryptVolume";
		RegMessage (hwndDlg, key);
		if (RegCreateKeyEx (HKEY_LOCAL_MACHINE,
				    key,
				    0, NULL, REG_OPTION_NON_VOLATILE, KEY_WRITE, NULL, &hkey, &dw) != ERROR_SUCCESS)
			goto error;

		sprintf (szTmp, "TrueCrypt Volume", szDir);
		if (RegSetValueEx (hkey, "", 0, REG_SZ, (BYTE *) szTmp, strlen (szTmp) + 1) != ERROR_SUCCESS)
			goto error;

		RegCloseKey (hkey);
		hkey = 0;

		key = "SOFTWARE\\Classes\\TrueCryptVolume\\DefaultIcon";
		RegMessage (hwndDlg, key);
		if (RegCreateKeyEx (HKEY_LOCAL_MACHINE,
				    key,
				    0, NULL, REG_OPTION_NON_VOLATILE, KEY_WRITE, NULL, &hkey, &dw) != ERROR_SUCCESS)
			goto error;

		sprintf (szTmp, "%sTrueCrypt.exe,1", szDir);
		if (RegSetValueEx (hkey, "", 0, REG_SZ, (BYTE *) szTmp, strlen (szTmp) + 1) != ERROR_SUCCESS)
			goto error;

		RegCloseKey (hkey);
		hkey = 0;

		key = "SOFTWARE\\Classes\\TrueCryptVolume\\Shell\\open\\command";
		RegMessage (hwndDlg, key);
		if (RegCreateKeyEx (HKEY_LOCAL_MACHINE,
				    key,
				    0, NULL, REG_OPTION_NON_VOLATILE, KEY_WRITE, NULL, &hkey, &dw) != ERROR_SUCCESS)
			goto error;

		sprintf (szTmp, "\"%sTrueCrypt.exe\" /v \"%%1\"", szDir );
		if (RegSetValueEx (hkey, "", 0, REG_SZ, (BYTE *) szTmp, strlen (szTmp) + 1) != ERROR_SUCCESS)
			goto error;

		RegCloseKey (hkey);
		hkey = 0;

		key = "SOFTWARE\\Classes\\.tc";
		RegMessage (hwndDlg, key);
		if (RegCreateKeyEx (HKEY_LOCAL_MACHINE,
				    key,
				    0, NULL, REG_OPTION_NON_VOLATILE, KEY_WRITE, NULL, &hkey, &dw) != ERROR_SUCCESS)
			goto error;

		strcpy (szTmp, "TrueCryptVolume");
		if (RegSetValueEx (hkey, "", 0, REG_SZ, (BYTE *) szTmp, strlen (szTmp) + 1) != ERROR_SUCCESS)
			goto error;
	}


	if (bUninstallSupport == TRUE)
	{
		char szTmp[TC_MAX_PATH];

		key = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\TrueCrypt";
		RegMessage (hwndDlg, key);
		if (RegCreateKeyEx (HKEY_LOCAL_MACHINE,
				    key,
				    0, NULL, REG_OPTION_NON_VOLATILE, KEY_WRITE, NULL, &hkey, &dw) != ERROR_SUCCESS)
			goto error;

		GetWindowsDirectory (szDir, sizeof (szDir));

		x = strlen (szDir);
		if (szDir[x - 1] == '\\')
			bSlash = TRUE;
		else
			bSlash = FALSE;

		if (bSlash == FALSE)
			strcat (szDir, "\\");

		sprintf (szTmp, "%sTrueCrypt Setup.exe /u", szDir);
		if (RegSetValueEx (hkey, "UninstallString", 0, REG_SZ, (BYTE *) szTmp, strlen (szTmp) + 1) != ERROR_SUCCESS)
			goto error;

		strcpy (szTmp, "TrueCrypt");
		if (RegSetValueEx (hkey, "DisplayName", 0, REG_SZ, (BYTE *) szTmp, strlen (szTmp) + 1) != ERROR_SUCCESS)
			goto error;
	}

	bOK = TRUE;

      error:
	if (hkey != 0)
		RegCloseKey (hkey);

	if (bOK == FALSE)
	{
		handleWin32Error (hwndDlg);
		MessageBox (hwndDlg, "The installation of the registry entries has failed", lpszTitle, MB_ICONHAND);
	}

	return bOK;
}

BOOL
DoRegUninstall (HWND hwndDlg)
{
	BOOL bOK = FALSE;

	StatusMessage (hwndDlg, "%s", "Removing registry entries");

	RegDeleteKey (HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\TrueCrypt");
	RegDeleteKey (HKEY_LOCAL_MACHINE, "SOFTWARE\\Classes\\TrueCryptVolume\\Shell\\open\\command");
	RegDeleteKey (HKEY_LOCAL_MACHINE, "SOFTWARE\\Classes\\TrueCryptVolume\\Shell\\open");
	RegDeleteKey (HKEY_LOCAL_MACHINE, "SOFTWARE\\Classes\\TrueCryptVolume\\Shell");
	RegDeleteKey (HKEY_LOCAL_MACHINE, "SOFTWARE\\Classes\\TrueCryptVolume\\DefaultIcon");
	RegDeleteKey (HKEY_LOCAL_MACHINE, "SOFTWARE\\Classes\\TrueCryptVolume");
	RegDeleteKey (HKEY_CURRENT_USER, "SOFTWARE\\TrueCrypt");
	if (RegDeleteKey (HKEY_LOCAL_MACHINE, "SOFTWARE\\Classes\\.tc") != ERROR_SUCCESS)
		goto error;

	bOK = TRUE;

      error:

	if (bOK == FALSE && GetLastError ()!= ERROR_NO_TOKEN && GetLastError ()!= ERROR_FILE_NOT_FOUND
	    && GetLastError ()!= ERROR_PATH_NOT_FOUND)
	{
		handleWin32Error (hwndDlg);
		MessageBox (hwndDlg, "The uninstallation of the registry entries has failed", lpszTitle, MB_ICONHAND);
	}
	else
		bOK = TRUE;

	return bOK;

}

BOOL
DoServiceUninstall (HWND hwndDlg, char *lpszService)
{
	SC_HANDLE hManager, hService = NULL;
	BOOL bOK = FALSE, bRet;
	SERVICE_STATUS status;
	char szTmp[128];
	int x;

	if (nCurrentOS != WIN_NT)
		return TRUE;
	else
		memset (&status, 0, sizeof (status));	/* Keep VC6 quiet */

	hManager = OpenSCManager (NULL, NULL, SC_MANAGER_ALL_ACCESS);
	if (hManager == NULL)
		goto error;

	hService = OpenService (hManager, lpszService, SERVICE_ALL_ACCESS);
	if (hService == NULL)
		goto error;

	sprintf (szTmp, "stopping %s", lpszService);
	ServiceMessage (hwndDlg, szTmp);

#define WAIT_PERIOD 3

	for (x = 0; x < WAIT_PERIOD; x++)
	{
		bRet = QueryServiceStatus (hService, &status);
		if (bRet != TRUE)
			goto error;

		if (status.dwCurrentState != SERVICE_START_PENDING &&
		    status.dwCurrentState != SERVICE_STOP_PENDING &&
		    status.dwCurrentState != SERVICE_CONTINUE_PENDING)
			break;

		Sleep (1000);
	}

	if (status.dwCurrentState != SERVICE_STOPPED)
	{
		bRet = ControlService (hService, SERVICE_CONTROL_STOP, &status);
		if (bRet == FALSE)
			goto try_delete;

		for (x = 0; x < WAIT_PERIOD; x++)
		{
			bRet = QueryServiceStatus (hService, &status);
			if (bRet != TRUE)
				goto error;

			if (status.dwCurrentState != SERVICE_START_PENDING &&
			    status.dwCurrentState != SERVICE_STOP_PENDING &&
			  status.dwCurrentState != SERVICE_CONTINUE_PENDING)
				break;

			Sleep (1000);
		}

		if (status.dwCurrentState != SERVICE_STOPPED && status.dwCurrentState != SERVICE_STOP_PENDING)
			goto error;
	}

      try_delete:
	sprintf (szTmp, "deleting %s", lpszService);
	ServiceMessage (hwndDlg, szTmp);

	if (hService != NULL)
		CloseServiceHandle (hService);

	if (hManager != NULL)
		CloseServiceHandle (hManager);

	hManager = OpenSCManager (NULL, NULL, SC_MANAGER_ALL_ACCESS);
	if (hManager == NULL)
		goto error;

	hService = OpenService (hManager, lpszService, SERVICE_ALL_ACCESS);
	if (hService == NULL)
		goto error;

	bRet = DeleteService (hService);
	if (bRet == FALSE)
		goto error;

	bOK = TRUE;

      error:
	if (bOK == FALSE && GetLastError ()!= ERROR_SERVICE_DOES_NOT_EXIST)
	{
		handleWin32Error (hwndDlg);
		MessageBox (hwndDlg, "The uninstallation of the device driver has failed", lpszTitle, MB_ICONHAND);
	}
	else
		bOK = TRUE;

	if (hService != NULL)
		CloseServiceHandle (hService);

	if (hManager != NULL)
		CloseServiceHandle (hManager);

	return bOK;
}

BOOL
DoDriverUnload (HWND hwndDlg)
{
	BOOL bOK = TRUE;
	int status;

	status = DriverAttach ();
	if (status != 0)
	{
		if (status == ERR_OS_ERROR && GetLastError ()!= ERROR_FILE_NOT_FOUND)
		{
			handleWin32Error (hwndDlg);
			AbortProcess (IDS_NODRIVER);
		}

		if (status != ERR_OS_ERROR)
		{
			handleError (NULL, status);
			AbortProcess (IDS_NODRIVER);
		}
	}

	if (hDriver != INVALID_HANDLE_VALUE)
	{
		MOUNT_LIST_STRUCT driver;
		DWORD dwResult;
		BOOL bResult;

		bResult = DeviceIoControl (hDriver, MOUNT_LIST, &driver, sizeof (driver), &driver,
			sizeof (driver), &dwResult, NULL);

		if (bResult == TRUE)
		{
			if (driver.ulMountedDrives != 0)
			{
				bOK = FALSE;
				MessageBox (hwndDlg, "Volumes are still mounted! All volumes must be dismounted before installation can continue.", lpszTitle, MB_ICONHAND);
			}
		}
		else
		{
			bOK = FALSE;
			handleWin32Error (hwndDlg);
		}

		CloseHandle (hDriver);
		hDriver = INVALID_HANDLE_VALUE;

	}

	return bOK;
}


BOOL
DoDriverInstall (HWND hwndDlg)
{
	SC_HANDLE hManager, hService = NULL;
	BOOL bOK = FALSE, bRet, bSlash;
	char szDir[TC_MAX_PATH];
	int x;

	if (nCurrentOS != WIN_NT)
		return TRUE;

	hManager = OpenSCManager (NULL, NULL, SC_MANAGER_ALL_ACCESS);
	if (hManager == NULL)
		goto error;

	GetSystemDirectory (szDir, sizeof (szDir));

	x = strlen (szDir);
	if (szDir[x - 1] == '\\')
		bSlash = TRUE;
	else
		bSlash = FALSE;

	if (bSlash == FALSE)
		strcat (szDir, "\\");

	strcat (szDir, "Drivers\\truecrypt.sys");

	ServiceMessage (hwndDlg, "installing TrueCrypt driver service");

	hService = CreateService (hManager, "truecrypt", "truecrypt",
				  SERVICE_ALL_ACCESS, SERVICE_KERNEL_DRIVER, SERVICE_AUTO_START, SERVICE_ERROR_NORMAL,
				  szDir, NULL, NULL, NULL, NULL, NULL
		);
	if (hService == NULL)
		goto error;
	else
		CloseServiceHandle (hService);

	hService = OpenService (hManager, "truecrypt", SERVICE_ALL_ACCESS);
	if (hService == NULL)
		goto error;

	ServiceMessage (hwndDlg, "starting TrueCrypt driver service");

	bRet = StartService (hService, 0, NULL);
	if (bRet == FALSE)
		goto error;

	bOK = TRUE;

      error:
	if (bOK == FALSE && GetLastError ()!= ERROR_SERVICE_ALREADY_RUNNING)
	{
		handleWin32Error (hwndDlg);
		MessageBox (hwndDlg, "The installation of the device driver has failed", lpszTitle, MB_ICONHAND);
	}
	else
		bOK = TRUE;

	if (hService != NULL)
		CloseServiceHandle (hService);

	if (hManager != NULL)
		CloseServiceHandle (hManager);

	return bOK;
}

BOOL
DoShortcutsUninstall (HWND hwndDlg, char *szDestDir)
{
	char szLinkDir[TC_MAX_PATH], szDir[TC_MAX_PATH];
	char szTmp[TC_MAX_PATH], szTmp2[TC_MAX_PATH];
	BOOL bSlash, bOK = FALSE;
	HRESULT hOle;
	int x;
	BOOL allUsers = FALSE;

	hOle = OleInitialize (NULL);

	// User start menu
    SHGetSpecialFolderPath (hwndDlg, szLinkDir, CSIDL_PROGRAMS, 0);
	x = strlen (szLinkDir);
	if (szLinkDir[x - 1] == '\\')
		bSlash = TRUE;
	else
		bSlash = FALSE;

	if (bSlash == FALSE)
		strcat (szLinkDir, "\\");

	strcat (szLinkDir, "TrueCrypt");

	// Global start menu
	if (nCurrentOS == WIN_NT)
	{
		struct _stat st;
		char path[TC_MAX_PATH];

		SHGetSpecialFolderPath (hwndDlg, path, CSIDL_COMMON_PROGRAMS, 0);
		strcat (path, "\\TrueCrypt");

		if (_stat (path, &st) == 0)
		{
			strcpy (szLinkDir, path);
			allUsers = TRUE;
		}
	}

	// Start menu entries
	sprintf (szTmp2, "%s%s", szLinkDir, "\\TrueCrypt.lnk");
	RemoveMessage (hwndDlg, szTmp2);
	if (StatDeleteFile (szTmp2) == FALSE)
		goto error;

	sprintf (szTmp2, "%s%s", szLinkDir, "\\TrueCrypt User's Guide.lnk");
	RemoveMessage (hwndDlg, szTmp2);
	if (StatDeleteFile (szTmp2) == FALSE)
		goto error;

	GetWindowsDirectory (szDir, sizeof (szDir));
	sprintf (szTmp2, "%s%s", szLinkDir, "\\Uninstall TrueCrypt.lnk");
	RemoveMessage (hwndDlg, szTmp2);
	if (StatDeleteFile (szTmp2) == FALSE)
		goto error;

	// Start menu group
	RemoveMessage ((HWND) hwndDlg, szLinkDir);
	if (StatRemoveDirectory (szLinkDir) == FALSE)
	{
		handleWin32Error ((HWND) hwndDlg);
		goto error;
	}

	// Desktop icon

	if (allUsers)
		SHGetSpecialFolderPath (hwndDlg, szLinkDir, CSIDL_COMMON_DESKTOPDIRECTORY, 0);
	else
		SHGetSpecialFolderPath (hwndDlg, szLinkDir, CSIDL_DESKTOPDIRECTORY, 0);

	sprintf (szTmp2, "%s%s", szLinkDir, "\\TrueCrypt.lnk");

	RemoveMessage (hwndDlg, szTmp2);
	if (StatDeleteFile (szTmp2) == FALSE)
		goto error;

	bOK = TRUE;

error:
	OleUninitialize ();

	return bOK;
}

BOOL
DoShortcutsInstall (HWND hwndDlg, char *szDestDir, BOOL bProgGroup, BOOL bDesktopIcon)
{
	char szLinkDir[TC_MAX_PATH], szDir[TC_MAX_PATH];
	char szTmp[TC_MAX_PATH], szTmp2[TC_MAX_PATH];
	BOOL bSlash, bOK = FALSE;
	HRESULT hOle;
	int x;

	if (bProgGroup == FALSE && bDesktopIcon == FALSE)
		return TRUE;

	hOle = OleInitialize (NULL);

	GetProgramPath (hwndDlg, szLinkDir);

	x = strlen (szLinkDir);
	if (szLinkDir[x - 1] == '\\')
		bSlash = TRUE;
	else
		bSlash = FALSE;

	if (bSlash == FALSE)
		strcat (szLinkDir, "\\");

	strcat (szLinkDir, "TrueCrypt");

	strcpy (szDir, szDestDir);
	x = strlen (szDestDir);
	if (szDestDir[x - 1] == '\\')
		bSlash = TRUE;
	else
		bSlash = FALSE;

	if (bSlash == FALSE)
		strcat (szDir, "\\");

	if (bProgGroup)
	{
		if (mkfulldir (szLinkDir, TRUE) != 0)
		{
			char szTmp[TC_MAX_PATH];
			int x;

			//sprintf (szTmp, "The program folder '%s' does not exist. Do you want to create this folder?", szLinkDir);
			//x = MessageBox (hwndDlg, szTmp, lpszTitle, MB_ICONQUESTION | MB_YESNO);
			//if (x == IDNO)
			//{
			//	goto error;
			//}

			if (mkfulldir (szLinkDir, FALSE) != 0)
			{
				handleWin32Error (hwndDlg);
				sprintf (szTmp, "The folder '%s' could not be created", szLinkDir);
				MessageBox (hwndDlg, szTmp, lpszTitle, MB_ICONHAND);
				goto error;
			}
		}

		sprintf (szTmp, "%s%s", szDir, "TrueCrypt.exe");
		sprintf (szTmp2, "%s%s", szLinkDir, "\\TrueCrypt.lnk");

		IconMessage (hwndDlg, szTmp2);
		if (CreateLink (szTmp, "", szTmp2) != S_OK)
			goto error;


		sprintf (szTmp, "%s%s", szDir, "TrueCrypt User Guide.pdf");
		sprintf (szTmp2, "%s%s", szLinkDir, "\\TrueCrypt User's Guide.lnk");

		IconMessage (hwndDlg, szTmp2);
		if (CreateLink (szTmp, "", szTmp2) != S_OK)
			goto error;

		GetWindowsDirectory (szDir, sizeof (szDir));
		x = strlen (szDir);
		if (szDir[x - 1] == '\\')
			bSlash = TRUE;
		else
			bSlash = FALSE;

		if (bSlash == FALSE)
			strcat (szDir, "\\");

		sprintf (szTmp, "%s%s", szDir, "TrueCrypt Setup.exe");
		sprintf (szTmp2, "%s%s", szLinkDir, "\\Uninstall TrueCrypt.lnk");

		IconMessage (hwndDlg, szTmp2);
		if (CreateLink (szTmp, "/u", szTmp2) != S_OK)
			goto error;

	}

	if (bDesktopIcon)
	{
		strcpy (szDir, szDestDir);
		x = strlen (szDestDir);
		if (szDestDir[x - 1] == '\\')
			bSlash = TRUE;
		else
			bSlash = FALSE;

		if (bSlash == FALSE)
			strcat (szDir, "\\");

		if (nCurrentOS == WIN_NT && IsDlgButtonChecked (hwndDlg, IDC_ALL_USERS))
			SHGetSpecialFolderPath (hwndDlg, szLinkDir, CSIDL_COMMON_DESKTOPDIRECTORY, 0);
		else
			SHGetSpecialFolderPath (hwndDlg, szLinkDir, CSIDL_DESKTOPDIRECTORY, 0);

		sprintf (szTmp, "%s%s", szDir, "TrueCrypt.exe");
		sprintf (szTmp2, "%s%s", szLinkDir, "\\TrueCrypt.lnk");

		IconMessage (hwndDlg, szTmp2);

		if (CreateLink (szTmp, "", szTmp2) != S_OK)
			goto error;
	}

	bOK = TRUE;

error:
	OleUninitialize ();

	return bOK;
}


void
RebootPrompt (HWND hwndDlg, BOOL bOK)
{
	if (bOK == TRUE)
	{
		SetWindowText (GetDlgItem ((HWND) hwndDlg, IDOK), "E&xit");

		EnableWindow (GetDlgItem ((HWND) hwndDlg, IDCANCEL), FALSE);

		bDone = TRUE;

		if (nCurrentOS == WIN_NT)
		{
			if (bUninstall == FALSE)
				MessageBox ((HWND) hwndDlg, "TrueCrypt has been successfuly installed.", lpszTitle, MB_ICONINFORMATION);
			else
				MessageBox ((HWND) hwndDlg, "TrueCrypt has been successfuly uninstalled.", lpszTitle, MB_ICONINFORMATION);
		}
		else
		{
			int x;

			if (bUninstall == FALSE)
				x = MessageBox ((HWND) hwndDlg, "TrueCrypt has been successfuly installed.\nTo use TrueCrypt your system must be restarted.", lpszTitle, MB_ICONINFORMATION);
			else
				x = MessageBox ((HWND) hwndDlg, "TrueCrypt has been successfuly uninstalled.\nYour system must be restarted.", lpszTitle, MB_ICONINFORMATION);
		}
	}
	else
	{
		if (bUninstall == FALSE)
			MessageBox ((HWND) hwndDlg, "The installation has failed!", lpszTitle, MB_ICONHAND);
		else
			MessageBox ((HWND) hwndDlg, "The uninstall has failed!", lpszTitle, MB_ICONHAND);
	}
}

static void SetSystemRestorePoint (void *hwndDlg, BOOL finalize)
{
	static RESTOREPOINTINFO RestPtInfo;
	static STATEMGRSTATUS SMgrStatus;
	static BOOL failed = FALSE;
	static BOOL (__stdcall *_SRSetRestorePoint)(PRESTOREPOINTINFO, PSTATEMGRSTATUS);
	
	if (!SystemRestoreDll) return;

	_SRSetRestorePoint = (BOOL (__stdcall *)(PRESTOREPOINTINFO, PSTATEMGRSTATUS))GetProcAddress (SystemRestoreDll,"SRSetRestorePointA");
	if (_SRSetRestorePoint == 0)
	{
		FreeLibrary (SystemRestoreDll);
		SystemRestoreDll = 0;
		return;
	}

	if (!finalize)
	{
		StatusMessage (hwndDlg, "%s", "Creating system restore point");

		// Initialize the RESTOREPOINTINFO structure
		RestPtInfo.dwEventType = BEGIN_SYSTEM_CHANGE;

		// Notify the system that changes are about to be made.
		// An application is to be installed.
		RestPtInfo.dwRestorePtType = APPLICATION_INSTALL;

		// Set RestPtInfo.llSequenceNumber.
		RestPtInfo.llSequenceNumber = 0;

		// String to be displayed by System Restore for this restore point. 
		strcpy(RestPtInfo.szDescription, "TrueCrypt installation");

		// Notify the system that changes are to be made and that
		// the beginning of the restore point should be marked. 
		if(!_SRSetRestorePoint(&RestPtInfo, &SMgrStatus)) 
		{
			StatusMessage (hwndDlg, "%s", "Failed to create System Restore point!");
			failed = TRUE;
		}

		return;
	}

	if (failed)	return;

	StatusMessage (hwndDlg, "%s", "Closing system restore point");

	// The application performs some installation operations here.

	// Re-initialize the RESTOREPOINTINFO structure to notify the 
	// system that the operation is finished.
	RestPtInfo.dwEventType = END_SYSTEM_CHANGE;

	// End the system change by returning the sequence number 
	// received from the first call to SRSetRestorePoint.
	RestPtInfo.llSequenceNumber = SMgrStatus.llSequenceNumber;

	// Notify the system that the operation is done and that this
	// is the end of the restore point.
	if(!_SRSetRestorePoint(&RestPtInfo, &SMgrStatus)) 
	{
		StatusMessage (hwndDlg, "%s", "Closing system restore point failed!");
	}
	else
		StatusMessage (hwndDlg, "%s", "System restore point created");

}

void
DoUninstall (void *hwndDlg)
{
	BOOL bOK = TRUE;

	EnableWindow (GetDlgItem ((HWND) hwndDlg, IDOK), FALSE);

	WaitCursor ();

	SendMessage (GetDlgItem ((HWND) hwndDlg, IDC_FILES), LB_RESETCONTENT, 0, 0);

	if (DoDriverUnload (hwndDlg) == FALSE)
	{
		bOK = FALSE;
	}
	else if (DoServiceUninstall (hwndDlg, "TrueCryptService") == FALSE)
	{
		bOK = FALSE;
	}
	else if (DoServiceUninstall (hwndDlg, "truecrypt") == FALSE)
	{
		bOK = FALSE;
	}
	else if (DoFilesInstall ((HWND) hwndDlg, dlg_file_name, FALSE) == FALSE)
	{
		bOK = FALSE;
	}
	else if (DoRegUninstall ((HWND) hwndDlg) == FALSE)
	{
		bOK = FALSE;
	}
	else if (DoShortcutsUninstall (hwndDlg, dlg_file_name) == FALSE)
	{
		bOK = FALSE;
	}
	else
	{
		RemoveMessage ((HWND) hwndDlg, dlg_file_name);
		if (StatRemoveDirectory (dlg_file_name) == FALSE)
		{
			handleWin32Error ((HWND) hwndDlg);
			bOK = FALSE;
		}
	}

	NormalCursor ();

	EnableWindow (GetDlgItem ((HWND) hwndDlg, IDOK), TRUE);

	RebootPrompt (hwndDlg, bOK);

}

void
DoInstall (void *hwndDlg)
{
	BOOL bOK = TRUE;

	EnableWindow (GetDlgItem ((HWND) hwndDlg, IDOK), FALSE);

	WaitCursor ();

	SendMessage (GetDlgItem ((HWND) hwndDlg, IDC_FILES), LB_RESETCONTENT, 0, 0);

	if (DoDriverUnload (hwndDlg) == FALSE)
	{
		NormalCursor ();
		EnableWindow (GetDlgItem ((HWND) hwndDlg, IDOK), TRUE);
		return;
	}
	
	if (IsButtonChecked (GetDlgItem ((HWND) hwndDlg, IDC_SYSTEM_RESTORE)))
	{
		SetSystemRestorePoint (hwndDlg, FALSE);
	}

	if (DoServiceUninstall (hwndDlg, "TrueCryptService") == FALSE)
	{
		bOK = FALSE;
	}
	else if (DoServiceUninstall (hwndDlg, "truecrypt") == FALSE)
	{
		bOK = FALSE;
	}
	else if (DoFilesInstall ((HWND) hwndDlg, dlg_file_name, IsButtonChecked (GetDlgItem ((HWND) hwndDlg, IDC_UNINSTALL))) == FALSE)
	{
		bOK = FALSE;
	}
	else if (DoRegInstall ((HWND) hwndDlg, dlg_file_name,
		IsButtonChecked (GetDlgItem ((HWND) hwndDlg, IDC_FILE_TYPE)),
			       IsButtonChecked (GetDlgItem ((HWND) hwndDlg, IDC_UNINSTALL))) == FALSE)
	{
		bOK = FALSE;
	}
	else if (DoDriverInstall (hwndDlg) == FALSE)
	{
		bOK = FALSE;
	}
	else if (DoShortcutsInstall (hwndDlg, dlg_file_name,
				     IsButtonChecked (GetDlgItem ((HWND) hwndDlg, IDC_PROG_GROUP)),
					 IsButtonChecked (GetDlgItem ((HWND) hwndDlg, IDC_DESKTOP_ICON))) == FALSE)
	{
		bOK = FALSE;
	}

	if (IsButtonChecked (GetDlgItem ((HWND) hwndDlg, IDC_SYSTEM_RESTORE)))
		SetSystemRestorePoint (hwndDlg, TRUE);

	if (bOK)
		StatusMessage (hwndDlg, "%s", "Installation completed.");

	NormalCursor ();

	EnableWindow (GetDlgItem ((HWND) hwndDlg, IDOK), TRUE);

	RebootPrompt (hwndDlg, bOK);
}


BOOL WINAPI
InstallDlgProc (HWND hwndDlg, UINT msg, WPARAM wParam, LPARAM lParam)
{
	WORD lw = LOWORD (wParam);
	if (lParam);		/* remove warning */

	switch (msg)
	{
	case WM_INITDIALOG:
		SetDefaultUserFont (hwndDlg);
		InitDialog (hwndDlg);

		{
			char path[MAX_PATH+20];
			ITEMIDLIST *i;
			SHGetSpecialFolderLocation (hwndDlg, CSIDL_PROGRAM_FILES, &i);
			SHGetPathFromIDList (i, path);
			strcat (path, "\\TrueCrypt");
			SetWindowText (GetDlgItem (hwndDlg, IDC_DESTINATION), path);
		}

		if (bUninstall == FALSE)
		{
			SendMessage (GetDlgItem (hwndDlg, IDC_FILES), LB_ADDSTRING, 0, (LPARAM) "By clicking 'Install', you accept the license agreement.");

			LoadLicense (hwndDlg);
		}

		SendMessage (GetDlgItem (hwndDlg, IDC_ALL_USERS), BM_SETCHECK, BST_CHECKED, 0);
		if (nCurrentOS != WIN_NT)
			EnableWindow (GetDlgItem ((HWND) hwndDlg, IDC_ALL_USERS), FALSE);

		SendMessage (GetDlgItem (hwndDlg, IDC_FILE_TYPE), BM_SETCHECK, BST_CHECKED, 0);
		SendMessage (GetDlgItem (hwndDlg, IDC_UNINSTALL), BM_SETCHECK, BST_CHECKED, 0);
		SendMessage (GetDlgItem (hwndDlg, IDC_PROG_GROUP), BM_SETCHECK, BST_CHECKED, 0);
		SendMessage (GetDlgItem (hwndDlg, IDC_DESKTOP_ICON), BM_SETCHECK, BST_CHECKED, 0);

		// System Restore
		SystemRestoreDll = LoadLibrary("srclient.dll");

		if (SystemRestoreDll != 0)
			SendMessage (GetDlgItem (hwndDlg, IDC_SYSTEM_RESTORE), BM_SETCHECK, BST_CHECKED, 0);
		else
			EnableWindow (GetDlgItem ((HWND) hwndDlg, IDC_SYSTEM_RESTORE), FALSE);

		SetWindowText (hwndDlg, lpszTitle);
		return 1;

	case WM_SYSCOMMAND:
		if (lw == IDC_ABOUT)
		{
			DialogBox (hInst, MAKEINTRESOURCE (IDD_ABOUT_DLG), hwndDlg, (DLGPROC) AboutDlgProc);
			return 1;
		}
		return 0;

	case WM_COMMAND:
		if (lw == IDOK)
		{
			char szDirname[TC_MAX_PATH];

			if (bDone == TRUE)
			{
				EndDialog (hwndDlg, IDOK);
				return 1;
			}

			GetWindowText (GetDlgItem (hwndDlg, IDC_DESTINATION), szDirname, sizeof (szDirname));

			if (bUninstall == FALSE)
			{
				if (mkfulldir (szDirname, TRUE) != 0)
				{
					char szTmp[TC_MAX_PATH];
					int x;

					//sprintf (szTmp, "The directory '%s' does not exist. Do you want to create this directory?", szDirname);
					//x = MessageBox (hwndDlg, szTmp, lpszTitle, MB_ICONQUESTION | MB_YESNO);
					//if (x == IDNO)
					//{
					//	SetFocus (GetDlgItem (hwndDlg, IDC_DESTINATION));
					//	return 1;
					//}

					if (mkfulldir (szDirname, FALSE) != 0)
					{
						handleWin32Error (hwndDlg);
						sprintf (szTmp, "The directory '%s' could not be created", szDirname);
						MessageBox (hwndDlg, szTmp, lpszTitle, MB_ICONHAND);
						return 1;
					}

				}
			}

			strcpy (dlg_file_name, szDirname);

			if (bUninstall == FALSE)
				_beginthread (DoInstall, 16384, (void *) hwndDlg);
			else
				_beginthread (DoUninstall, 16384, (void *) hwndDlg);

			return 1;
		}

		if (lw == IDCANCEL)
		{
			EndDialog (hwndDlg, IDCANCEL);
			return 1;
		}

		if (lw == IDC_BROWSE)
		{
			char szDirname[TC_MAX_PATH];

			GetWindowText (GetDlgItem (hwndDlg, IDC_DESTINATION), szDirname, sizeof (szDirname));

			if (BrowseFiles2 (hwndDlg, "Please select a folder", szDirname) == TRUE)
				SetWindowText (GetDlgItem (hwndDlg, IDC_DESTINATION), szDirname);
			
			return 1;
		}

		if (lw == IDC_DESTINATION && HIWORD (wParam) == EN_CHANGE && bDone == FALSE)
		{
			if (GetWindowTextLength (GetDlgItem (hwndDlg, IDC_DESTINATION)) <= 0)
				EnableWindow (GetDlgItem (hwndDlg, IDOK), FALSE);
			else
				EnableWindow (GetDlgItem (hwndDlg, IDOK), TRUE);
			return 1;
		}

		return 0;

	case WM_CLOSE:
		EndDialog (hwndDlg, IDCANCEL);
		return 1;
	}

	return 0;
}


int WINAPI
WINMAIN (HINSTANCE hInstance, HINSTANCE hPrevInstance, char *lpszCommandLine,
	 int nCmdShow)
{
	if (nCmdShow && hPrevInstance);	/* Remove unused parameter warning */

	lpszTitle = "TrueCrypt Setup";

	/* Call InitApp to initialize the common code */
	InitApp (hInstance);

	if (CurrentOSMajor < 5)
	{
		MessageBox (NULL, "TrueCrypt requires at least Windows 2000 to run.", lpszTitle, MB_ICONSTOP);
		return 0;
	}

	if (nCurrentOS == WIN_NT && IsAdmin ()!= TRUE)
		if (MessageBox (NULL, "To successfully install/uninstall TrueCrypt you must have Administrator rights, "
				"do you still want to continue?", lpszTitle, MB_YESNO | MB_ICONQUESTION) != IDYES)
			return 0;

	if (lpszCommandLine[0] == '/' && (lpszCommandLine[1] == 'u' || lpszCommandLine[1] == 'U'))
	{
		bUninstall = TRUE;
	}

	if (bUninstall == FALSE)
	{
		if (CurrentOSMajor == 5 && CurrentOSMinor == 0)
			MessageBox (NULL, "If you are upgrading from a previous version of TrueCrypt\nyou should first uninstall TrueCrypt and reboot system.", lpszTitle, MB_ICONINFORMATION);

		/* Create the main dialog box */
		DialogBox (hInstance, MAKEINTRESOURCE (IDD_INSTALL), NULL, (DLGPROC) InstallDlgProc);
	}
	else
	{
		/* Create the main dialog box */
		DialogBox (hInstance, MAKEINTRESOURCE (IDD_UNINSTALL), NULL, (DLGPROC) InstallDlgProc);
	}

	/* Terminate */
	return 0;
}
