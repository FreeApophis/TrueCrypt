/*
 Legal Notice: The source code contained in this file has been derived from
 the source code of Encryption for the Masses 2.02a, which is Copyright (c)
 Paul Le Roux and which is covered by the 'License Agreement for Encryption
 for the Masses'. Modifications and additions to that source code contained
 in this file are Copyright (c) TrueCrypt Foundation and are covered by the
 TrueCrypt License 2.2 the full text of which is contained in the file
 License.txt included in TrueCrypt binary and source code distribution
 packages. */

#include "Tcdefs.h"
#include <SrRestorePtApi.h>
#include <sys/types.h>
#include <sys/stat.h>

#include "Apidrvr.h"
#include "Combo.h"
#include "ComSetup.h"
#include "Dlgcode.h"
#include "Language.h"
#include "Registry.h"
#include "Resource.h"

#include "Dir.h"
#include "Setup.h"

#include "../Common/Resource.h"
#include "../Mount/Mount.h"

#pragma warning( disable : 4201 )
#pragma warning( disable : 4115 )

#include <shlobj.h>

#pragma warning( default : 4201 )
#pragma warning( default : 4115 )

char dlg_file_name[TC_MAX_PATH];
char SetupFilesDir[TC_MAX_PATH];
char UninstallBatch[MAX_PATH];

BOOL bUninstall = FALSE;
BOOL bDone = FALSE;
BOOL Rollback = FALSE;
BOOL bUpgrade = FALSE;
BOOL bFirstTimeInstall = FALSE;
char *UninstallPath;

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

	if (IsDlgButtonChecked (hwndDlg, IDC_ALL_USERS))
        res = SHGetSpecialFolderLocation (hwndDlg, CSIDL_COMMON_PROGRAMS, &i);
	else
        res = SHGetSpecialFolderLocation (hwndDlg, CSIDL_PROGRAMS, &i);

	SHGetPathFromIDList (i, path);
}

void
StatusMessage (HWND hwndDlg , char *stringId)
{
	if (Rollback)
		return;

	SendMessageW (GetDlgItem (hwndDlg, IDC_FILES), LB_ADDSTRING, 0, (LPARAM) GetString (stringId));

	SendDlgItemMessage (hwndDlg, IDC_FILES, LB_SETTOPINDEX, 
		SendDlgItemMessage (hwndDlg, IDC_FILES, LB_GETCOUNT, 0, 0) - 1, 0);
}

void
StatusMessageParam (HWND hwndDlg, char *stringId, char *param)
{
	wchar_t szTmp[1024];

	if (Rollback)
		return;

	wsprintfW (szTmp, L"%s %hs", GetString (stringId), param);
	SendMessageW (GetDlgItem (hwndDlg, IDC_FILES), LB_ADDSTRING, 0, (LPARAM) szTmp);
		
	SendDlgItemMessage (hwndDlg, IDC_FILES, LB_SETTOPINDEX, 
		SendDlgItemMessage (hwndDlg, IDC_FILES, LB_GETCOUNT, 0, 0) - 1, 0);
}

void
RegMessage (HWND hwndDlg, char *txt)
{
	StatusMessageParam (hwndDlg, "ADDING_REG", txt);
}

void
CopyMessage (HWND hwndDlg, char *txt)
{
	StatusMessageParam (hwndDlg, "INSTALLING", txt);
}

void
RemoveMessage (HWND hwndDlg, char *txt)
{
	if (!Rollback)
		StatusMessageParam (hwndDlg, "REMOVING", txt);
}

void
IconMessage (HWND hwndDlg, char *txt)
{
	StatusMessageParam (hwndDlg, "ADDING_ICON", txt);
}


BOOL
DoFilesInstall (HWND hwndDlg, char *szDestDir)
{
	char *szFiles[]=
	{
		"ATrueCrypt.exe",
		"ATrueCrypt Format.exe",
		"ATrueCrypt User Guide.pdf",
		"ATrueCrypt Setup.exe",
		"Atruecrypt.sys",
		"Atruecrypt-x64.sys",
		"ALicense.txt",
		"Dtruecrypt.sys"
	};

	char szTmp[TC_MAX_PATH];
	BOOL bOK = TRUE;
	int i, x;

	x = strlen (szDestDir);
	if (x < 1)
		return FALSE;

	if (szDestDir[x - 1] != '\\')
		strcat (szDestDir, "\\");

	for (i = 0; i < sizeof (szFiles) / sizeof (szFiles[0]); i++)
	{
		BOOL bResult;
		char szDir[TC_MAX_PATH];

		if (bUninstall && strstr (szFiles[i], "TrueCrypt Setup") != 0)
			continue;

		if (*szFiles[i] == 'A')
			strcpy (szDir, szDestDir);
		else if (*szFiles[i] == 'D')
		{
			GetSystemDirectory (szDir, sizeof (szDir));

			x = strlen (szDir);
			if (szDir[x - 1] != '\\')
				strcat (szDir, "\\");

			strcat (szDir, "Drivers\\");
		}
		else if (*szFiles[i] == 'W')
			GetWindowsDirectory (szDir, sizeof (szDir));

		if (*szFiles[i] == 'I')
			continue;

		sprintf (szTmp, "%s%s", szDir, szFiles[i] + 1);

		if (bUninstall == FALSE)
			CopyMessage (hwndDlg, szTmp);
		else
			RemoveMessage (hwndDlg, szTmp);

		if (bUninstall == FALSE)
		{
			SetCurrentDirectory (SetupFilesDir);

			bResult = TCCopyFile (szFiles[i] + 1, szTmp);
			if (!bResult)
			{
				char s[256];

				sprintf (s, "Setup Files\\%s", 
					(strcmp (szFiles[i], "Dtruecrypt.sys") == 0 && Is64BitOs ()) ? 
					"truecrypt-x64.sys" : szFiles[i] + 1);

				bResult = TCCopyFile (s, szTmp);
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
			wchar_t szTmp2[700];

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
				wsprintfW (szTmp2, GetString ("INSTALL_OF_FAILED"), szTmp, lpMsgBuf);
			else
				wsprintfW (szTmp2, GetString ("UNINSTALL_OF_FAILED"), szTmp, lpMsgBuf);

			LocalFree (lpMsgBuf);

			if (!Silent && MessageBoxW (hwndDlg, szTmp2, lpszTitle, MB_YESNO | MB_ICONHAND) != IDYES)
				return FALSE;
		}
	}

	// Language pack
	if (bUninstall == FALSE)
	{
		WIN32_FIND_DATA f;
		HANDLE h;
		
		SetCurrentDirectory (SetupFilesDir);
		h = FindFirstFile ("Language.*.xml", &f);

		if (h != INVALID_HANDLE_VALUE)
		{
			char d[MAX_PATH*2];
			sprintf (d, "%s%s", szDestDir, f.cFileName);
			CopyMessage (hwndDlg, d);
			TCCopyFile (f.cFileName, d);
			FindClose (h);
		}

		SetCurrentDirectory (SetupFilesDir);
		SetCurrentDirectory ("Setup files");
		h = FindFirstFile ("TrueCrypt User Guide.*.pdf", &f);
		if (h != INVALID_HANDLE_VALUE)
		{
			char d[MAX_PATH*2];
			sprintf (d, "%s%s", szDestDir, f.cFileName);
			CopyMessage (hwndDlg, d);
			TCCopyFile (f.cFileName, d);
			FindClose (h);
		}
		SetCurrentDirectory (SetupFilesDir);
	}

	return bOK;
}

BOOL
DoRegInstall (HWND hwndDlg, char *szDestDir, BOOL bInstallType)
{
	char szDir[TC_MAX_PATH], *key;
	char szTmp[TC_MAX_PATH];
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

	if (bInstallType)
	{

		key = "Software\\Classes\\TrueCryptVolume";
		RegMessage (hwndDlg, key);
		if (RegCreateKeyEx (HKEY_LOCAL_MACHINE,
				    key,
				    0, NULL, REG_OPTION_NON_VOLATILE, KEY_WRITE, NULL, &hkey, &dw) != ERROR_SUCCESS)
			goto error;

		strcpy (szTmp, "TrueCrypt Volume");
		if (RegSetValueEx (hkey, "", 0, REG_SZ, (BYTE *) szTmp, strlen (szTmp) + 1) != ERROR_SUCCESS)
			goto error;

		RegCloseKey (hkey);
		hkey = 0;

		key = "Software\\Classes\\TrueCryptVolume\\DefaultIcon";
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

		key = "Software\\Classes\\TrueCryptVolume\\Shell\\open\\command";
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

		key = "Software\\Classes\\.tc";
		RegMessage (hwndDlg, key);
		if (RegCreateKeyEx (HKEY_LOCAL_MACHINE,
				    key,
				    0, NULL, REG_OPTION_NON_VOLATILE, KEY_WRITE, NULL, &hkey, &dw) != ERROR_SUCCESS)
			goto error;

		strcpy (szTmp, "TrueCryptVolume");
		if (RegSetValueEx (hkey, "", 0, REG_SZ, (BYTE *) szTmp, strlen (szTmp) + 1) != ERROR_SUCCESS)
			goto error;
		
		RegCloseKey (hkey);
		hkey = 0;
	}

	key = "Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\TrueCrypt";
	RegMessage (hwndDlg, key);
	if (RegCreateKeyEx (HKEY_LOCAL_MACHINE,
		key,
		0, NULL, REG_OPTION_NON_VOLATILE, KEY_WRITE, NULL, &hkey, &dw) != ERROR_SUCCESS)
		goto error;

	sprintf (szTmp, "\"%sTrueCrypt Setup.exe\" /u %s", szDir, szDestDir);
	if (RegSetValueEx (hkey, "UninstallString", 0, REG_SZ, (BYTE *) szTmp, strlen (szTmp) + 1) != ERROR_SUCCESS)
		goto error;

	sprintf (szTmp, "\"%sTrueCrypt Setup.exe\"", szDir);
	if (RegSetValueEx (hkey, "DisplayIcon", 0, REG_SZ, (BYTE *) szTmp, strlen (szTmp) + 1) != ERROR_SUCCESS)
		goto error;

	strcpy (szTmp, "TrueCrypt");
	if (RegSetValueEx (hkey, "DisplayName", 0, REG_SZ, (BYTE *) szTmp, strlen (szTmp) + 1) != ERROR_SUCCESS)
		goto error;

	strcpy (szTmp, "TrueCrypt Foundation");
	if (RegSetValueEx (hkey, "Publisher", 0, REG_SZ, (BYTE *) szTmp, strlen (szTmp) + 1) != ERROR_SUCCESS)
		goto error;

	strcpy (szTmp, "http://www.truecrypt.org/");
	if (RegSetValueEx (hkey, "URLInfoAbout", 0, REG_SZ, (BYTE *) szTmp, strlen (szTmp) + 1) != ERROR_SUCCESS)
		goto error;
		
	bOK = TRUE;

error:
	if (hkey != 0)
		RegCloseKey (hkey);

	if (bOK == FALSE)
	{
		handleWin32Error (hwndDlg);
		Error ("REG_INSTALL_FAILED");
	}
	
	// Register COM servers for UAC
	if (nCurrentOS == WIN_VISTA_OR_LATER)
	{
		if (!RegisterComServers (szDir))
		{
			Error ("COM_REG_FAILED");
			return FALSE;
		}
	}

	return bOK;
}

BOOL
DoApplicationDataUninstall (HWND hwndDlg)
{
	char path[MAX_PATH];
	char path2[MAX_PATH];
	BOOL bOK = TRUE;

	StatusMessage (hwndDlg, "REMOVING_APPDATA");

	SHGetFolderPath (NULL, CSIDL_APPDATA, NULL, 0, path);
	strcat (path, "\\TrueCrypt\\");

	// Delete favorite volumes file
	sprintf (path2, "%s%s", path, FILE_FAVORITE_VOLUMES);
	RemoveMessage (hwndDlg, path2);
	StatDeleteFile (path2);

	// Delete keyfile defaults
	sprintf (path2, "%s%s", path, FILE_DEFAULT_KEYFILES);
	RemoveMessage (hwndDlg, path2);
	StatDeleteFile (path2);

	// Delete history file
	sprintf (path2, "%s%s", path, FILE_HISTORY);
	RemoveMessage (hwndDlg, path2);
	StatDeleteFile (path2);
	
	// Delete configuration file
	sprintf (path2, "%s%s", path, FILE_CONFIGURATION);
	RemoveMessage (hwndDlg, path2);
	StatDeleteFile (path2);

	SHGetFolderPath (NULL, CSIDL_APPDATA, NULL, 0, path);
	strcat (path, "\\TrueCrypt");
	RemoveMessage (hwndDlg, path);
	if (!StatRemoveDirectory (path))
	{
		handleWin32Error (hwndDlg);
		bOK = FALSE;
	}

	return bOK;
}

BOOL
DoRegUninstall (HWND hwndDlg, BOOL bRemoveDeprecated)
{
	BOOL bOK = FALSE;
	char regk [64];

	// Unregister COM servers
	if (!bRemoveDeprecated && nCurrentOS == WIN_VISTA_OR_LATER)
	{
		if (!UnregisterComServers (dlg_file_name))
			StatusMessage (hwndDlg, "COM_DEREG_FAILED");
	}

	if (!bRemoveDeprecated)
		StatusMessage (hwndDlg, "REMOVING_REG");

	RegDeleteKey (HKEY_LOCAL_MACHINE, "Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\TrueCrypt");
	RegDeleteKey (HKEY_LOCAL_MACHINE, "Software\\Classes\\TrueCryptVolume\\Shell\\open\\command");
	RegDeleteKey (HKEY_LOCAL_MACHINE, "Software\\Classes\\TrueCryptVolume\\Shell\\open");
	RegDeleteKey (HKEY_LOCAL_MACHINE, "Software\\Classes\\TrueCryptVolume\\Shell");
	RegDeleteKey (HKEY_LOCAL_MACHINE, "Software\\Classes\\TrueCryptVolume\\DefaultIcon");
	RegDeleteKey (HKEY_LOCAL_MACHINE, "Software\\Classes\\TrueCryptVolume");
	RegDeleteKey (HKEY_CURRENT_USER, "Software\\TrueCrypt");

	if (!bRemoveDeprecated)
	{
		// Split the string in order to prevent some antivirus packages from falsely reporting  
		// TrueCrypt.exe to contain a possible Trojan horse because of this string (heuristic scan).
		sprintf (regk, "%s%s", "Software\\Microsoft\\Windows\\Curren", "tVersion\\Run");
		DeleteRegistryValue (regk, "TrueCrypt");

		RegDeleteKey (HKEY_LOCAL_MACHINE, "Software\\Classes\\.tc");
	}

	bOK = TRUE;

	if (bOK == FALSE && GetLastError ()!= ERROR_NO_TOKEN && GetLastError ()!= ERROR_FILE_NOT_FOUND
	    && GetLastError ()!= ERROR_PATH_NOT_FOUND)
	{
		handleWin32Error (hwndDlg);
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
	BOOL firstTry = TRUE;
	int x;

	memset (&status, 0, sizeof (status));	/* Keep VC6 quiet */

retry:

	hManager = OpenSCManager (NULL, NULL, SC_MANAGER_ALL_ACCESS);
	if (hManager == NULL)
		goto error;

	hService = OpenService (hManager, lpszService, SERVICE_ALL_ACCESS);
	if (hService == NULL)
		goto error;

	if (strcmp ("truecrypt", lpszService) == 0)
		StatusMessage (hwndDlg, "STOPPING_DRIVER");
	else
		StatusMessageParam (hwndDlg, "STOPPING", lpszService);

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

	if (strcmp ("truecrypt", lpszService) == 0)
		StatusMessage (hwndDlg, "REMOVING_DRIVER");
	else
		StatusMessageParam (hwndDlg, "REMOVING", lpszService);

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
	{
		if (firstTry && GetLastError () == ERROR_SERVICE_MARKED_FOR_DELETE)
		{
			// Second try for an eventual no-install driver instance
			CloseServiceHandle (hService);
			CloseServiceHandle (hManager);

			Sleep(1000);
			firstTry = FALSE;
			goto retry;
		}

		goto error;
	}

	bOK = TRUE;

error:

	if (bOK == FALSE && GetLastError ()!= ERROR_SERVICE_DOES_NOT_EXIST)
	{
		handleWin32Error (hwndDlg);
		MessageBoxW (hwndDlg, GetString ("DRIVER_UINSTALL_FAILED"), lpszTitle, MB_ICONHAND);
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
		if (status == ERR_OS_ERROR && GetLastError () != ERROR_FILE_NOT_FOUND)
		{
			handleWin32Error (hwndDlg);
			AbortProcess ("NODRIVER");
		}

		if (status != ERR_OS_ERROR)
		{
			handleError (NULL, status);
			AbortProcess ("NODRIVER");
		}
	}

	if (hDriver != INVALID_HANDLE_VALUE)
	{
		MOUNT_LIST_STRUCT driver;
		LONG driverVersion = VERSION_NUM;
		int refCount;
		DWORD dwResult;
		BOOL bResult;


		// Try to determine if it's upgrade (and not reinstall, downgrade, or first-time install).
		bUpgrade = (DeviceIoControl (hDriver, DRIVER_VERSION, &driverVersion, 4, &driverVersion, 4, &dwResult, NULL) 
					&& driverVersion < VERSION_NUM);


		bResult = DeviceIoControl (hDriver, MOUNT_LIST, &driver, sizeof (driver), &driver,
			sizeof (driver), &dwResult, NULL);

		if (bResult)
		{
			if (driver.ulMountedDrives != 0)
			{
				bOK = FALSE;
				MessageBoxW (hwndDlg, GetString ("DISMOUNT_ALL_FIRST"), lpszTitle, MB_ICONHAND);
			}
		}
		else
		{
			bOK = FALSE;
			handleWin32Error (hwndDlg);
		}
		
		// Try to close all open TC windows
		if (bOK)
		{
			BOOL TCWindowClosed = FALSE;

			EnumWindows (CloseTCWindowsEnum, (LPARAM) &TCWindowClosed);

			if (TCWindowClosed) 
				Sleep (2000);
		}

		// Test for any applications attached to driver
		bResult = DeviceIoControl (hDriver, DEVICE_REFCOUNT, &refCount, sizeof (refCount), &refCount,
			sizeof (refCount), &dwResult, NULL);

		if (bOK && bResult && refCount > 1)
		{
			MessageBoxW (hwndDlg, GetString ("CLOSE_TC_FIRST"), lpszTitle, MB_ICONSTOP);
			bOK = FALSE;
		}

		CloseHandle (hDriver);
		hDriver = INVALID_HANDLE_VALUE;
	}
	else
	{
		bFirstTimeInstall = TRUE;
	}

	return bOK;
}


BOOL
DoDriverInstall (HWND hwndDlg)
{
	SC_HANDLE hManager, hService = NULL;
	BOOL bOK = FALSE, bRet;

	hManager = OpenSCManager (NULL, NULL, SC_MANAGER_ALL_ACCESS);
	if (hManager == NULL)
		goto error;

	StatusMessage (hwndDlg, "INSTALLING_DRIVER");

	hService = CreateService (hManager, "truecrypt", "truecrypt",
		SERVICE_ALL_ACCESS, SERVICE_KERNEL_DRIVER, SERVICE_SYSTEM_START, SERVICE_ERROR_NORMAL,
		!Is64BitOs () ? "System32\\drivers\\truecrypt.sys" : "SysWOW64\\drivers\\truecrypt.sys",
		NULL, NULL, NULL, NULL, NULL);

	if (hService == NULL)
		goto error;
	else
		CloseServiceHandle (hService);

	hService = OpenService (hManager, "truecrypt", SERVICE_ALL_ACCESS);
	if (hService == NULL)
		goto error;

	StatusMessage (hwndDlg, "STARTING_DRIVER");

	bRet = StartService (hService, 0, NULL);
	if (bRet == FALSE)
		goto error;

	bOK = TRUE;

error:
	if (bOK == FALSE && GetLastError () != ERROR_SERVICE_ALREADY_RUNNING)
	{
		handleWin32Error (hwndDlg);
		MessageBoxW (hwndDlg, GetString ("DRIVER_INSTALL_FAILED"), lpszTitle, MB_ICONHAND);
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
	char szLinkDir[TC_MAX_PATH];
	char szTmp2[TC_MAX_PATH];
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

	sprintf (szTmp2, "%s%s", szLinkDir, "\\TrueCrypt Website.url");
	RemoveMessage (hwndDlg, szTmp2);
	if (StatDeleteFile (szTmp2) == FALSE)
		goto error;

	sprintf (szTmp2, "%s%s", szLinkDir, "\\Uninstall TrueCrypt.lnk");
	RemoveMessage (hwndDlg, szTmp2);
	if (StatDeleteFile (szTmp2) == FALSE)
		goto error;
	
	sprintf (szTmp2, "%s%s", szLinkDir, "\\TrueCrypt User's Guide.lnk");
	DeleteFile (szTmp2);

	// Start menu group
	RemoveMessage ((HWND) hwndDlg, szLinkDir);
	if (StatRemoveDirectory (szLinkDir) == FALSE)
		handleWin32Error ((HWND) hwndDlg);

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
	char szTmp[TC_MAX_PATH], szTmp2[TC_MAX_PATH], szTmp3[TC_MAX_PATH];
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
		FILE *f;

		if (mkfulldir (szLinkDir, TRUE) != 0)
		{
			wchar_t szTmp[TC_MAX_PATH];

			if (mkfulldir (szLinkDir, FALSE) != 0)
			{
				handleWin32Error (hwndDlg);
				wsprintfW (szTmp, GetString ("CANT_CREATE_FOLDER"), szLinkDir);
				MessageBoxW (hwndDlg, szTmp, lpszTitle, MB_ICONHAND);
				goto error;
			}
		}

		sprintf (szTmp, "%s%s", szDir, "TrueCrypt.exe");
		sprintf (szTmp2, "%s%s", szLinkDir, "\\TrueCrypt.lnk");

		IconMessage (hwndDlg, szTmp2);
		if (CreateLink (szTmp, "", szTmp2) != S_OK)
			goto error;

		sprintf (szTmp2, "%s%s", szLinkDir, "\\TrueCrypt Website.url");
		IconMessage (hwndDlg, szTmp2);
		f = fopen (szTmp2, "w");
		if (f)
		{
			fprintf (f, "[InternetShortcut]\nURL=%s&dest=index\n", TC_APPLINK);
			fclose (f);
		}
		else
			goto error;

		sprintf (szTmp, "%s%s", szDir, "TrueCrypt Setup.exe");
		sprintf (szTmp2, "%s%s", szLinkDir, "\\Uninstall TrueCrypt.lnk");
		sprintf (szTmp3, "/u %s", szDestDir);

		IconMessage (hwndDlg, szTmp2);
		if (CreateLink (szTmp, szTmp3, szTmp2) != S_OK)
			goto error;

		sprintf (szTmp2, "%s%s", szLinkDir, "\\TrueCrypt User's Guide.lnk");
		DeleteFile (szTmp2);
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

		if (IsDlgButtonChecked (hwndDlg, IDC_ALL_USERS))
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
OutcomePrompt (HWND hwndDlg, BOOL bOK)
{
	if (bOK)
	{
		EnableWindow (GetDlgItem ((HWND) hwndDlg, IDCANCEL), FALSE);

		bDone = TRUE;

		if (bUninstall == FALSE)
			Info ("INSTALL_OK");
		else
		{
			wchar_t str[4096];

			swprintf (str, GetString ("UNINSTALL_OK"), dlg_file_name);
			MessageBoxW (hwndDlg, str, lpszTitle, MB_ICONASTERISK);
		}
	}
	else
	{
		if (bUninstall == FALSE)
			Error ("INSTALL_FAILED");
		else
			Error ("UNINSTALL_FAILED");
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
		StatusMessage (hwndDlg, "CREATING_SYS_RESTORE");

		RestPtInfo.dwEventType = BEGIN_SYSTEM_CHANGE;
		RestPtInfo.dwRestorePtType = APPLICATION_INSTALL;
		RestPtInfo.llSequenceNumber = 0;
		strcpy (RestPtInfo.szDescription, "TrueCrypt installation");

		if(!_SRSetRestorePoint (&RestPtInfo, &SMgrStatus)) 
		{
			StatusMessage (hwndDlg, "FAILED_SYS_RESTORE");
			failed = TRUE;
		}
	}
	else if (!failed)
	{
		RestPtInfo.dwEventType = END_SYSTEM_CHANGE;
		RestPtInfo.llSequenceNumber = SMgrStatus.llSequenceNumber;
		RestPtInfo.dwRestorePtType = CANCELLED_OPERATION;

		if(!_SRSetRestorePoint(&RestPtInfo, &SMgrStatus)) 
		{
			StatusMessage (hwndDlg, "FAILED_SYS_RESTORE");
		}
		else
			StatusMessage (hwndDlg, "SYS_RESTORE_CREATED");
	}
}

void
DoUninstall (void *hwndDlg)
{
	BOOL bOK = TRUE;

	if (!Rollback)
		EnableWindow (GetDlgItem ((HWND) hwndDlg, IDC_UNINSTALL), FALSE);

	WaitCursor ();

	if (!Rollback)
		SendMessage (GetDlgItem ((HWND) hwndDlg, IDC_FILES), LB_RESETCONTENT, 0, 0);

	if (DoDriverUnload (hwndDlg) == FALSE)
	{
		bOK = FALSE;
	}
	else if (DoServiceUninstall (hwndDlg, "truecrypt") == FALSE)
	{
		bOK = FALSE;
	}
	else if (DoRegUninstall ((HWND) hwndDlg, FALSE) == FALSE)
	{
		bOK = FALSE;
	}
	else if (DoFilesInstall ((HWND) hwndDlg, dlg_file_name) == FALSE)
	{
		bOK = FALSE;
	}
	else if (DoShortcutsUninstall (hwndDlg, dlg_file_name) == FALSE)
	{
		bOK = FALSE;
	}
	else if (!DoApplicationDataUninstall (hwndDlg))
	{
		bOK = FALSE;
	}
	else
	{
		char temp[MAX_PATH];
		FILE *f;

		// Deprecated service
		DoServiceUninstall (hwndDlg, "TrueCryptService");

		GetTempPath (sizeof (temp), temp);
		_snprintf (UninstallBatch, sizeof (UninstallBatch), "%s\\TrueCrypt-Uninstall.bat", temp);

		// Create uninstall batch
		f = fopen (UninstallBatch, "w");
		if (!f)
			bOK = FALSE;
		else
		{
			fprintf (f, ":loop\n"
				"del \"%s\\%s\"\n"
				"if exist \"%s\\%s\" goto loop\n"
				"rmdir \"%s\"\n"
				"del \"%s\"",
				dlg_file_name, "TrueCrypt Setup.exe",
				dlg_file_name, "TrueCrypt Setup.exe",
				dlg_file_name,
				UninstallBatch
				);
			fclose (f);
		}
	}

	NormalCursor ();

	if (Rollback)
		return;

	if (bOK)
		PostMessage (hwndDlg, WM_APP + 2, 0, 0);
		
	EnableWindow (GetDlgItem ((HWND) hwndDlg, IDC_UNINSTALL), TRUE);
	OutcomePrompt (hwndDlg, bOK);
}

void
DoInstall (void *hwndDlg)
{
	BOOL bOK = TRUE;
	char path[MAX_PATH];

	EnableWindow (GetDlgItem ((HWND) hwndDlg, IDC_INSTALL), FALSE);
	SendMessage (GetDlgItem ((HWND) hwndDlg, IDC_FILES), LB_RESETCONTENT, 0, 0);

	if (DoDriverUnload (hwndDlg) == FALSE)
	{
		NormalCursor ();
		EnableWindow (GetDlgItem ((HWND) hwndDlg, IDC_INSTALL), TRUE);
		return;
	}
	
	if (IsButtonChecked (GetDlgItem ((HWND) hwndDlg, IDC_SYSTEM_RESTORE)))
		SetSystemRestorePoint (hwndDlg, FALSE);

	// Remove deprecated
	DoServiceUninstall (hwndDlg, "TrueCryptService");
	
	DoRegUninstall ((HWND) hwndDlg, TRUE);

	GetWindowsDirectory (path, sizeof (path));
	strcat_s (path, sizeof (path), "\\TrueCrypt Setup.exe");
	DeleteFile (path);

	if (DoServiceUninstall (hwndDlg, "truecrypt") == FALSE)
	{
		bOK = FALSE;
	}
	else if (DoFilesInstall ((HWND) hwndDlg, dlg_file_name) == FALSE)
	{
		bOK = FALSE;
	}
	else if (DoRegInstall ((HWND) hwndDlg, dlg_file_name,
		IsButtonChecked (GetDlgItem ((HWND) hwndDlg, IDC_FILE_TYPE))) == FALSE)
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
	{
		UninstallBatch[0] = 0;
		StatusMessage (hwndDlg, "INSTALL_COMPLETED");
		EnableWindow (GetDlgItem ((HWND) hwndDlg, IDC_INSTALL), TRUE);
	}
	else
	{
		bUninstall = TRUE;
		Rollback = TRUE;
		Silent = TRUE;

		DoUninstall (hwndDlg);

		bUninstall = FALSE;
		Rollback = FALSE;
		Silent = FALSE;

		StatusMessage (hwndDlg, "ROLLBACK");
	}

	PostMessage (hwndDlg,  WM_APP + 1, 0, 0);
	OutcomePrompt (hwndDlg, bOK);

	if (bOK && !bUninstall)
	{
		if (bUpgrade && (AskYesNo ("AFTER_UPGRADE_RELEASE_NOTES") == IDYES))
		{
			Applink ("releasenotes", TRUE, "");
		}
		else if (bFirstTimeInstall && AskYesNo ("AFTER_INSTALL_TUTORIAL") == IDYES)
		{
			Applink ("beginnerstutorial", TRUE, "");
		}
	}
}


BOOL WINAPI
InstallDlgProc (HWND hwndDlg, UINT msg, WPARAM wParam, LPARAM lParam)
{
	WORD lw = LOWORD (wParam);
	if (lParam);		/* remove warning */

	switch (msg)
	{
	case WM_INITDIALOG:
		MainDlg = hwndDlg;
		InitDialog (hwndDlg);
		LocalizeDialog (hwndDlg, NULL);

		if (UninstallPath == NULL)
		{
			char path[MAX_PATH+20];
			ITEMIDLIST *i;
			SHGetSpecialFolderLocation (hwndDlg, CSIDL_PROGRAM_FILES, &i);
			SHGetPathFromIDList (i, path);
			strcat (path, "\\TrueCrypt");
			SetWindowText (GetDlgItem (hwndDlg, IDC_DESTINATION), path);
		}
		else
			SetWindowText (GetDlgItem (hwndDlg, IDC_DESTINATION), UninstallPath);

		if (bUninstall == FALSE)
		{
			char *licenseText;

			licenseText = GetLegalNotices ();
			if (licenseText != NULL)
			{
				SetWindowText (GetDlgItem (hwndDlg, IDC_LICENSE), licenseText);
				free (licenseText);
			}
		}

		SendMessage (GetDlgItem (hwndDlg, IDC_ALL_USERS), BM_SETCHECK, BST_CHECKED, 0);
		SendMessage (GetDlgItem (hwndDlg, IDC_FILE_TYPE), BM_SETCHECK, BST_CHECKED, 0);
		SendMessage (GetDlgItem (hwndDlg, IDC_PROG_GROUP), BM_SETCHECK, BST_CHECKED, 0);
		SendMessage (GetDlgItem (hwndDlg, IDC_DESKTOP_ICON), BM_SETCHECK, BST_CHECKED, 0);

		// System Restore
		SystemRestoreDll = LoadLibrary ("srclient.dll");

		if (SystemRestoreDll != 0)
			SendMessage (GetDlgItem (hwndDlg, IDC_SYSTEM_RESTORE), BM_SETCHECK, BST_CHECKED, 0);
		else
			EnableWindow (GetDlgItem ((HWND) hwndDlg, IDC_SYSTEM_RESTORE), FALSE);

		SetWindowTextW (hwndDlg, lpszTitle);

		return 1;

	case WM_SYSCOMMAND:
		if (lw == IDC_ABOUT)
		{
			DialogBoxW (hInst, MAKEINTRESOURCEW (IDD_ABOUT_DLG), hwndDlg, (DLGPROC) AboutDlgProc);
			return 1;
		}
		return 0;

	case WM_COMMAND:
		if (lw == IDC_INSTALL || lw == IDC_UNINSTALL)
		{
			char szDirname[TC_MAX_PATH];

			if (bDone)
			{
				EndDialog (hwndDlg, IDC_INSTALL);
				return 1;
			}

			GetWindowText (GetDlgItem (hwndDlg, IDC_DESTINATION), szDirname, sizeof (szDirname));

			if (bUninstall == FALSE)
			{
				if (mkfulldir (szDirname, TRUE) != 0)
				{
					wchar_t szTmp[TC_MAX_PATH];

					if (mkfulldir (szDirname, FALSE) != 0)
					{
						handleWin32Error (hwndDlg);
						wsprintfW (szTmp, GetString ("CANT_CREATE_FOLDER"), szDirname);
						MessageBoxW (hwndDlg, szTmp, lpszTitle, MB_ICONHAND);
						return 1;
					}
				}
			}

			strcpy (dlg_file_name, szDirname);

			WaitCursor ();

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

			if (BrowseDirectories (hwndDlg, "SELECT_INSTALL_DIR", szDirname))
				SetWindowText (GetDlgItem (hwndDlg, IDC_DESTINATION), szDirname);
			
			return 1;
		}

		if (lw == IDC_DESTINATION && HIWORD (wParam) == EN_CHANGE && bDone == FALSE)
		{
			if (GetWindowTextLength (GetDlgItem (hwndDlg, IDC_DESTINATION)) <= 0)
				EnableWindow (GetDlgItem (hwndDlg, IDC_INSTALL), FALSE);
			else
				EnableWindow (GetDlgItem (hwndDlg, IDC_INSTALL), TRUE);
			return 1;
		}

		return 0;

	case WM_APP + 1:
		SetWindowTextW (GetDlgItem ((HWND) hwndDlg, IDC_INSTALL), GetString ("EXIT"));
		NormalCursor ();
		break;

	case WM_APP + 2:
		SetWindowTextW (GetDlgItem ((HWND) hwndDlg, IDC_UNINSTALL), GetString ("FINALIZE"));
		NormalCursor ();
		break;

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

	lpszTitle = L"TrueCrypt Setup";

	/* Call InitApp to initialize the common code */
	InitApp (hInstance, NULL);

	if (IsAdmin () != TRUE)
		if (MessageBoxW (NULL, GetString ("SETUP_ADMIN"), lpszTitle, MB_YESNO | MB_ICONQUESTION) != IDYES)
			exit (1);

	/* Setup directory */
	{
		char *s;
		GetModuleFileName (NULL, SetupFilesDir, sizeof (SetupFilesDir));
		s = strrchr (SetupFilesDir, '\\');
		if (s)
			s[1] = 0;
	}

	if (lpszCommandLine[0] == '/' && lpszCommandLine[1] == 'u')
	{
		bUninstall = TRUE;
		if (lpszCommandLine[2] == ' ')
			UninstallPath = &lpszCommandLine[3];
	}

	// Force uninstall or stop setup when files are missing
	if (!bUninstall)
	{
		WIN32_FIND_DATA fd;
		HANDLE fh;

		SetCurrentDirectory (SetupFilesDir);

		fh = FindFirstFile ("Setup Files", &fd);
		if (fh == INVALID_HANDLE_VALUE)
		{
			fh = FindFirstFile ("TrueCrypt.exe", &fd);
			if (fh == INVALID_HANDLE_VALUE)
			{
				Error ("SETUP_INCOMPLETE");
				exit (1);
			}
			else
			{
				FindClose (fh);
				bUninstall = TRUE;
				UninstallPath = SetupFilesDir;
			}
		}
		else
			FindClose (fh);
	}

	if (bUninstall == FALSE)
	{
		/* Create the main dialog box */
		DialogBoxW (hInstance, MAKEINTRESOURCEW (IDD_INSTALL), NULL, (DLGPROC) InstallDlgProc);
	}
	else
	{
		/* Create the main dialog box */
		DialogBoxW (hInstance, MAKEINTRESOURCEW (IDD_UNINSTALL), NULL, (DLGPROC) InstallDlgProc);
		
		if (UninstallBatch[0])
		{
			STARTUPINFO si;
			PROCESS_INFORMATION pi;

			ZeroMemory (&si, sizeof (si));
			si.cb = sizeof (si);
			si.dwFlags = STARTF_USESHOWWINDOW;
			si.wShowWindow = SW_HIDE;

			if (!CreateProcess (UninstallBatch, NULL, NULL, NULL, FALSE, IDLE_PRIORITY_CLASS, NULL, NULL, &si, &pi))
				DeleteFile (UninstallBatch);
		}
	}

	/* Terminate */
	cleanup ();

	return 0;
}
