/*
 Legal Notice: Some portions of the source code contained in this file were
 derived from the source code of Encryption for the Masses 2.02a, which is
 Copyright (c) 1998-2000 Paul Le Roux and which is governed by the 'License
 Agreement for Encryption for the Masses'. Modifications and additions to
 the original source code (contained in this file) and all other portions of
 this file are Copyright (c) 2003-2008 TrueCrypt Foundation and are governed
 by the TrueCrypt License 2.4 the full text of which is contained in the
 file License.txt included in TrueCrypt binary and source code distribution
 packages. */

#include "Tcdefs.h"
#include <SrRestorePtApi.h>
#include <sys/types.h>
#include <sys/stat.h>

#include "Apidrvr.h"
#include "BootEncryption.h"
#include "Combo.h"
#include "ComSetup.h"
#include "Dlgcode.h"
#include "Language.h"
#include "Registry.h"
#include "Resource.h"

#include "Dir.h"
#include "Setup.h"
#include "SelfExtract.h"
#include "Wizard.h"

#include "../Common/Resource.h"
#include "../Mount/Mount.h"

using namespace TrueCrypt;

#pragma warning( disable : 4201 )
#pragma warning( disable : 4115 )

#include <shlobj.h>

#pragma warning( default : 4201 )
#pragma warning( default : 4115 )

char InstallationPath[TC_MAX_PATH];
char SetupFilesDir[TC_MAX_PATH];
char UninstallBatch[MAX_PATH];

BOOL bUninstall = FALSE;
BOOL bMakePackage = FALSE;
BOOL bDone = FALSE;
BOOL Rollback = FALSE;
BOOL bUpgrade = FALSE;
BOOL SystemEncryptionUpgrade = FALSE;
BOOL bRepairMode = FALSE;
BOOL bChangeMode = FALSE;
BOOL bDevm = FALSE;
BOOL bFirstTimeInstall = FALSE;
BOOL bUninstallInProgress = FALSE;

BOOL bSystemRestore = TRUE;
BOOL bForAllUsers = TRUE;
BOOL bRegisterFileExt = TRUE;
BOOL bAddToStartMenu = TRUE;
BOOL bDesktopIcon = TRUE;

HMODULE volatile SystemRestoreDll = 0;

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
	hres = CoCreateInstance (CLSID_ShellLink, NULL,
			       CLSCTX_INPROC_SERVER, IID_IShellLink, (LPVOID *) &psl);
	if (SUCCEEDED (hres))
	{
		IPersistFile *ppf;

		/* Set the path to the shortcut target, and add the
		   description.  */
		psl->SetPath (lpszPathObj);
		psl->SetArguments (lpszArguments);

		/* Query IShellLink for the IPersistFile interface for saving
		   the shortcut in persistent storage.  */
		hres = psl->QueryInterface (IID_IPersistFile,
						    (void **) &ppf);

		if (SUCCEEDED (hres))
		{
			wchar_t wsz[TC_MAX_PATH];

			/* Ensure that the string is ANSI.  */
			MultiByteToWideChar (CP_ACP, 0, lpszPathLink, -1,
					     wsz, TC_MAX_PATH);

			/* Save the link by calling IPersistFile::Save.  */
			hres = ppf->Save (wsz, TRUE);
			ppf->Release ();
		}
		psl->Release ();
	}
	return hres;
}

void
GetProgramPath (HWND hwndDlg, char *path)
{
	ITEMIDLIST *i;
	HRESULT res;

	if (bForAllUsers)
        res = SHGetSpecialFolderLocation (hwndDlg, CSIDL_COMMON_PROGRAMS, &i);
	else
        res = SHGetSpecialFolderLocation (hwndDlg, CSIDL_PROGRAMS, &i);

	SHGetPathFromIDList (i, path);
}

void 
StatusMessage (HWND hwndDlg, char *stringId)
{
	if (Rollback)
		return;

	SendMessageW (GetDlgItem (hwndDlg, IDC_LOG_WINDOW), LB_ADDSTRING, 0, (LPARAM) GetString (stringId));

	SendDlgItemMessage (hwndDlg, IDC_LOG_WINDOW, LB_SETTOPINDEX, 
		SendDlgItemMessage (hwndDlg, IDC_LOG_WINDOW, LB_GETCOUNT, 0, 0) - 1, 0);
}

void 
StatusMessageParam (HWND hwndDlg, char *stringId, char *param)
{
	wchar_t szTmp[1024];

	if (Rollback)
		return;

	wsprintfW (szTmp, L"%s %hs", GetString (stringId), param);
	SendMessageW (GetDlgItem (hwndDlg, IDC_LOG_WINDOW), LB_ADDSTRING, 0, (LPARAM) szTmp);
		
	SendDlgItemMessage (hwndDlg, IDC_LOG_WINDOW, LB_SETTOPINDEX, 
		SendDlgItemMessage (hwndDlg, IDC_LOG_WINDOW, LB_GETCOUNT, 0, 0) - 1, 0);
}

void
ClearLogWindow (HWND hwndDlg)
{
	SendMessage (GetDlgItem (hwndDlg, IDC_LOG_WINDOW), LB_RESETCONTENT, 0, 0);
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


BOOL DoFilesInstall (HWND hwndDlg, char *szDestDir)
{
	/* WARNING: Note that, despite its name, this function is used during UNinstallation as well. */

	char szTmp[TC_MAX_PATH];
	BOOL bOK = TRUE;
	int i, x, fileNo;
	char curFileName [TC_MAX_PATH] = {0};

	if (!bUninstall && !bDevm)
	{
		// Self-extract all files to memory

		GetModuleFileName (NULL, szTmp, sizeof (szTmp));

		if (!SelfExtractInMemory (szTmp))
			return FALSE;
	}

	x = strlen (szDestDir);
	if (x < 2)
		return FALSE;

	if (szDestDir[x - 1] != '\\')
		strcat (szDestDir, "\\");

	for (i = 0; i < sizeof (szFiles) / sizeof (szFiles[0]); i++)
	{
		BOOL bResult;
		char szDir[TC_MAX_PATH];

		if (strstr (szFiles[i], "TrueCrypt Setup") != 0)
		{
			if (bUninstall)
				continue;	// Prevent 'access denied' error

			if (bRepairMode)
				continue;	// Destination = target
		}

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

			if (strstr (szFiles[i], "TrueCrypt Setup") != 0)
			{
				// Copy ourselves (the distribution package) to the destination location as 'TrueCrypt Setup.exe'

				char mp[MAX_PATH];

				GetModuleFileName (NULL, mp, sizeof (mp));
				bResult = TCCopyFile (mp, szTmp);
			}
			else
			{
				strncpy (curFileName, szFiles[i] + 1, strlen (szFiles[i]) - 1);
				curFileName [strlen (szFiles[i]) - 1] = 0;

				if (Is64BitOs ()
					&& strcmp (szFiles[i], "Dtruecrypt.sys") == 0)
				{
					strncpy (curFileName, FILENAME_64BIT_DRIVER, sizeof (FILENAME_64BIT_DRIVER));
				}

				if (!bDevm)
				{
					bResult = FALSE;

					// Find the correct decompressed file in memory
					for (fileNo = 0; fileNo < NBR_COMPRESSED_FILES; fileNo++)
					{
						// Write the file (stored in memory) directly to the destination location 
						// (there will be no temporary files).
						if (memcmp (
							curFileName, 
							Decompressed_Files[fileNo].fileName, 
							min (strlen (curFileName), (size_t) Decompressed_Files[fileNo].fileNameLength)) == 0)
						{
							bResult = SaveBufferToFile (
								(char *) Decompressed_Files[fileNo].fileContent,
								szTmp,
								Decompressed_Files[fileNo].fileLength, 
								FALSE);

							break;
						}
					}
				}
				else
				{
					bResult = TCCopyFile (curFileName, szTmp);
				}
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

	/* IMPORTANT: IF YOU CHANGE THIS IN ANY WAY, REVISE AND UPDATE SetInstallationPath() ACCORDINGLY! */ 
	sprintf (szTmp, "\"%sTrueCrypt Setup.exe\" /u", szDir);
	if (RegSetValueEx (hkey, "UninstallString", 0, REG_SZ, (BYTE *) szTmp, strlen (szTmp) + 1) != ERROR_SUCCESS)
		goto error;

	sprintf (szTmp, "\"%sTrueCrypt Setup.exe\" /c", szDir);
	if (RegSetValueEx (hkey, "ModifyPath", 0, REG_SZ, (BYTE *) szTmp, strlen (szTmp) + 1) != ERROR_SUCCESS)
		goto error;

	sprintf (szTmp, "\"%sTrueCrypt Setup.exe\"", szDir);
	if (RegSetValueEx (hkey, "DisplayIcon", 0, REG_SZ, (BYTE *) szTmp, strlen (szTmp) + 1) != ERROR_SUCCESS)
		goto error;

	strcpy (szTmp, VERSION_STRING);
	if (RegSetValueEx (hkey, "DisplayVersion", 0, REG_SZ, (BYTE *) szTmp, strlen (szTmp) + 1) != ERROR_SUCCESS)
		goto error;
		
	strcpy (szTmp, "TrueCrypt");
	if (RegSetValueEx (hkey, "DisplayName", 0, REG_SZ, (BYTE *) szTmp, strlen (szTmp) + 1) != ERROR_SUCCESS)
		goto error;

	strcpy (szTmp, "TrueCrypt Foundation");
	if (RegSetValueEx (hkey, "Publisher", 0, REG_SZ, (BYTE *) szTmp, strlen (szTmp) + 1) != ERROR_SUCCESS)
		goto error;

	sprintf (szTmp, "%s&dest=index\n", TC_APPLINK);
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

	// Delete system encryption configuration file
	sprintf (path2, "%s%s", path, FILE_SYSTEM_ENCRYPTION_CFG);
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
		if (!UnregisterComServers (InstallationPath))
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
		int volumesMounted;

		// Try to determine if it's upgrade (and not reinstall, downgrade, or first-time install).
		bResult = DeviceIoControl (hDriver, TC_IOCTL_GET_DRIVER_VERSION, NULL, 0, &driverVersion, sizeof (driverVersion), &dwResult, NULL);

		if (!bResult)
			bResult = DeviceIoControl (hDriver, TC_IOCTL_LEGACY_GET_DRIVER_VERSION, NULL, 0, &driverVersion, sizeof (driverVersion), &dwResult, NULL);

		bUpgrade = bResult && driverVersion < VERSION_NUM;

		// Test for encrypted boot drive
		try
		{
			BootEncryption bootEnc (hwndDlg);
			if (bootEnc.GetDriverServiceStartType() == SERVICE_BOOT_START)
			{
				if (!bUpgrade || driverVersion < 0x500)
				{
					Error ("SETUP_FAILED_BOOT_DRIVE_ENCRYPTED");
					return FALSE;
				}

				SystemEncryptionUpgrade = TRUE;
			}
		}
		catch (...)	{ }

		if (!SystemEncryptionUpgrade)
		{
			// Check mounted volumes
			bResult = DeviceIoControl (hDriver, TC_IOCTL_IS_ANY_VOLUME_MOUNTED, NULL, 0, &volumesMounted, sizeof (volumesMounted), &dwResult, NULL);

			if (!bResult)
			{
				bResult = DeviceIoControl (hDriver, TC_IOCTL_LEGACY_GET_MOUNTED_VOLUMES, NULL, 0, &driver, sizeof (driver), &dwResult, NULL);
				if (bResult)
					volumesMounted = driver.ulMountedDrives;
			}

			if (bResult)
			{
				if (volumesMounted != 0)
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
		bResult = DeviceIoControl (hDriver, TC_IOCTL_GET_DEVICE_REFCOUNT, &refCount, sizeof (refCount), &refCount,
			sizeof (refCount), &dwResult, NULL);

		if (bOK && bResult && refCount > 1)
		{
			MessageBoxW (hwndDlg, GetString ("CLOSE_TC_FIRST"), lpszTitle, MB_ICONSTOP);
			bOK = FALSE;
		}

		if (!bOK || !SystemEncryptionUpgrade)
		{
			CloseHandle (hDriver);
			hDriver = INVALID_HANDLE_VALUE;
		}
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
	if (SystemEncryptionUpgrade)
		return TRUE;

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


BOOL UpgradeBootLoader (HWND hwndDlg)
{
	if (!SystemEncryptionUpgrade)
		return TRUE;

	try
	{
		BootEncryption bootEnc (hwndDlg);
		if (bootEnc.GetInstalledBootLoaderVersion() < VERSION_NUM)
		{
			bootEnc.InstallBootLoader ();
			Info ("BOOT_LOADER_UPGRADE_OK");
		}
		return TRUE;
	}
	catch (Exception &e)
	{
		e.Show (hwndDlg);
	}
	catch (...) { }

	Error ("BOOT_LOADER_UPGRADE_FAILED");
	return FALSE;
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
			if (mkfulldir (szLinkDir, FALSE) != 0)
			{
				wchar_t szTmp[TC_MAX_PATH];

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
		strcpy (szTmp3, "/u");

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

		if (bForAllUsers)
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
		{
			if (bDevm)
				PostMessage (MainDlg, WM_CLOSE, 0, 0);
			else if (!SystemEncryptionUpgrade)
				Info ("INSTALL_OK");
		}
		else
		{
			wchar_t str[4096];

			swprintf (str, GetString ("UNINSTALL_OK"), InstallationPath);
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

static void SetSystemRestorePoint (HWND hwndDlg, BOOL finalize)
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
		strcpy (RestPtInfo.szDescription, bUninstall ? "TrueCrypt uninstallation" : "TrueCrypt installation");

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

		if(!_SRSetRestorePoint(&RestPtInfo, &SMgrStatus)) 
		{
			StatusMessage (hwndDlg, "FAILED_SYS_RESTORE");
		}
		else
			StatusMessage (hwndDlg, "SYS_RESTORE_CREATED");
	}
}

void
DoUninstall (void *arg)
{
	HWND hwndDlg = (HWND) arg;
	BOOL bOK = TRUE;
	BOOL bTempSkipSysRestore = FALSE;

	if (!Rollback)
		EnableWindow (GetDlgItem ((HWND) hwndDlg, IDC_UNINSTALL), FALSE);

	WaitCursor ();

	if (!Rollback)
	{
		ClearLogWindow (hwndDlg);
	}

	if (DoDriverUnload (hwndDlg) == FALSE)
	{
		bOK = FALSE;
		bTempSkipSysRestore = TRUE;		// Volumes are possibly mounted; defer System Restore point creation for this uninstall attempt.
	}
	else
	{
		if (!Rollback && bSystemRestore && !bTempSkipSysRestore)
			SetSystemRestorePoint (hwndDlg, FALSE);

		if (DoServiceUninstall (hwndDlg, "truecrypt") == FALSE)
		{
			bOK = FALSE;
		}
		else if (DoRegUninstall ((HWND) hwndDlg, FALSE) == FALSE)
		{
			bOK = FALSE;
		}
		else if (DoFilesInstall ((HWND) hwndDlg, InstallationPath) == FALSE)
		{
			bOK = FALSE;
		}
		else if (DoShortcutsUninstall (hwndDlg, InstallationPath) == FALSE)
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
					"del \"%s%s\"\n"
					"if exist \"%s%s\" goto loop\n"
					"rmdir \"%s\"\n"
					"del \"%s\"",
					InstallationPath, "TrueCrypt Setup.exe",
					InstallationPath, "TrueCrypt Setup.exe",
					InstallationPath,
					UninstallBatch
					);
				fclose (f);
			}
		}
	}

	NormalCursor ();

	if (Rollback)
		return;

	if (bSystemRestore && !bTempSkipSysRestore)
		SetSystemRestorePoint (hwndDlg, TRUE);

	if (bOK)
		PostMessage (hwndDlg, TC_APPMSG_UNINSTALL_SUCCESS, 0, 0);
	else
		bUninstallInProgress = FALSE;

	EnableWindow (GetDlgItem ((HWND) hwndDlg, IDC_UNINSTALL), TRUE);
	OutcomePrompt (hwndDlg, bOK);
}

void
DoInstall (void *arg)
{
	HWND hwndDlg = (HWND) arg;
	BOOL bOK = TRUE;
	char path[MAX_PATH];

	// Refresh the main GUI (wizard thread)
	InvalidateRect (GetDlgItem (MainDlg, IDD_INSTL_DLG), NULL, TRUE);

	ClearLogWindow(hwndDlg);

	if (mkfulldir (InstallationPath, TRUE) != 0)
	{
		if (mkfulldir (InstallationPath, FALSE) != 0)
		{
			wchar_t szTmp[TC_MAX_PATH];

			handleWin32Error (hwndDlg);
			wsprintfW (szTmp, GetString ("CANT_CREATE_FOLDER"), InstallationPath);
			MessageBoxW (hwndDlg, szTmp, lpszTitle, MB_ICONHAND);
			Error ("INSTALL_FAILED");
			PostMessage (MainDlg, TC_APPMSG_INSTALL_FAILURE, 0, 0);
			return;
		}
	}

	UpdateProgressBarProc(2);

	if (DoDriverUnload (hwndDlg) == FALSE)
	{
		NormalCursor ();
		PostMessage (MainDlg, TC_APPMSG_INSTALL_FAILURE, 0, 0);
		return;
	}

	UpdateProgressBarProc(12);
	
	if (bSystemRestore)
		SetSystemRestorePoint (hwndDlg, FALSE);

	UpdateProgressBarProc(50);

	// Remove deprecated
	DoServiceUninstall (hwndDlg, "TrueCryptService");
	
	UpdateProgressBarProc(55);

	if (!SystemEncryptionUpgrade)
		DoRegUninstall ((HWND) hwndDlg, TRUE);

	UpdateProgressBarProc(62);

	GetWindowsDirectory (path, sizeof (path));
	strcat_s (path, sizeof (path), "\\TrueCrypt Setup.exe");
	DeleteFile (path);

	if (UpdateProgressBarProc(63) && !SystemEncryptionUpgrade && DoServiceUninstall (hwndDlg, "truecrypt") == FALSE)
	{
		bOK = FALSE;
	}
	else if (UpdateProgressBarProc(72) && DoFilesInstall ((HWND) hwndDlg, InstallationPath) == FALSE)
	{
		bOK = FALSE;
	}
	else if (UpdateProgressBarProc(80) && !SystemEncryptionUpgrade && DoRegInstall ((HWND) hwndDlg, InstallationPath, bRegisterFileExt ) == FALSE)
	{
		bOK = FALSE;
	}
	else if (UpdateProgressBarProc(85) && !SystemEncryptionUpgrade && DoDriverInstall (hwndDlg) == FALSE)
	{
		bOK = FALSE;
	}
	else if (SystemEncryptionUpgrade && UpgradeBootLoader (hwndDlg) == FALSE)
	{
		bOK = FALSE;
	}
	else if (UpdateProgressBarProc(93) && DoShortcutsInstall (hwndDlg, InstallationPath, bAddToStartMenu, bDesktopIcon) == FALSE)
	{
		bOK = FALSE;
	}

	if (bOK)
		UpdateProgressBarProc(97);

	if (bSystemRestore)
		SetSystemRestorePoint (hwndDlg, TRUE);

	if (bOK)
	{
		UpdateProgressBarProc(100);
		UninstallBatch[0] = 0;
		StatusMessage (hwndDlg, "INSTALL_COMPLETED");
		PostMessage (MainDlg, TC_APPMSG_INSTALL_SUCCESS, 0, 0);
	}
	else
	{
		UpdateProgressBarProc(0);
		bUninstall = TRUE;
		Rollback = TRUE;
		Silent = TRUE;

		if (!SystemEncryptionUpgrade)
			DoUninstall (hwndDlg);

		bUninstall = FALSE;
		Rollback = FALSE;
		Silent = FALSE;

		StatusMessage (hwndDlg, "ROLLBACK");
	}

	OutcomePrompt (hwndDlg, bOK);

	if (!bOK)
	{
		PostMessage (MainDlg, TC_APPMSG_INSTALL_FAILURE, 0, 0);
	}
	else if (!bUninstall && !bDevm)
	{
		if (SystemEncryptionUpgrade)
		{
			if (AskYesNo ("UPGRADE_OK_REBOOT_REQUIRED") == IDYES)
			{
				BootEncryption bootEnc (hwndDlg);
				bootEnc.RestartComputer();
			}
		}
		else
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
}


void SetInstallationPath (HWND hwndDlg)
{
	HKEY hkey;
	BOOL bInstallPathDetermined = FALSE;
	char path[MAX_PATH+20];
	ITEMIDLIST *itemList;

	memset (InstallationPath, 0, sizeof (InstallationPath));

	// Determine if TrueCrypt is already installed and try to determine its "Program Files" location
	if (RegOpenKeyEx (HKEY_LOCAL_MACHINE, "Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\TrueCrypt", 0, KEY_READ, &hkey) == ERROR_SUCCESS)
	{
		/* Default 'UninstallString' registry strings written by past versions of TrueCrypt:
		------------------------------------------------------------------------------------
		1.0		C:\WINDOWS\TrueCrypt Setup.exe /u			[optional]
		1.0a	C:\WINDOWS\TrueCrypt Setup.exe /u			[optional]
		2.0		C:\WINDOWS\TrueCrypt Setup.exe /u			[optional]
		2.1		C:\WINDOWS\TrueCrypt Setup.exe /u			[optional]
		2.1a	C:\WINDOWS\TrueCrypt Setup.exe /u			[optional]
		3.0		C:\WINDOWS\TrueCrypt Setup.exe /u			[optional]
		3.0a	C:\WINDOWS\TrueCrypt Setup.exe /u			[optional]
		3.1		The UninstallString was NEVER written (fortunately, 3.1a replaced 3.1 after 2 weeks)
		3.1a	C:\WINDOWS\TrueCrypt Setup.exe /u
		4.0		C:\WINDOWS\TrueCrypt Setup.exe /u C:\Program Files\TrueCrypt
		4.1		C:\WINDOWS\TrueCrypt Setup.exe /u C:\Program Files\TrueCrypt
		4.2		C:\WINDOWS\TrueCrypt Setup.exe /u C:\Program Files\TrueCrypt
		4.2a	C:\WINDOWS\TrueCrypt Setup.exe /u C:\Program Files\TrueCrypt
		4.3		"C:\Program Files\TrueCrypt\TrueCrypt Setup.exe" /u C:\Program Files\TrueCrypt\
		4.3a	"C:\Program Files\TrueCrypt\TrueCrypt Setup.exe" /u C:\Program Files\TrueCrypt\
		5.0		"C:\Program Files\TrueCrypt\TrueCrypt Setup.exe" /u

		Note: In versions 1.0-3.0a the user was able to choose whether to install the uninstaller.
			  The default was to install it. If it wasn't installed, there was no UninstallString.
		*/

		char rv[MAX_PATH*4];
		DWORD size = sizeof (rv);
		if (RegQueryValueEx (hkey, "UninstallString", 0, 0, (LPBYTE) &rv, &size) == ERROR_SUCCESS)
		{
			size_t len = 0;

			// Cut and paste the location (path) where TrueCrypt is installed to InstallationPath
			if (rv[0] == '"')
			{
				// 4.3 or later

				len = strrchr (rv, '/') - rv - 2;
				strncpy (InstallationPath, rv + 1, len);
				InstallationPath [len] = 0;
				bInstallPathDetermined = TRUE;

				if (InstallationPath [strlen (InstallationPath) - 1] != '\\')
				{
					len = strrchr (InstallationPath, '\\') - InstallationPath;
					InstallationPath [len] = 0;
				}
			}
			else
			{
				// 1.0-4.2a (except 3.1)

				len = strrchr (rv, '/') - rv;
				if (rv[len+2] == ' ')
				{
					// 4.0-4.2a

					strncpy (InstallationPath, rv + len + 3, strlen (rv) - len - 3);
					InstallationPath [strlen (rv) - len - 3] = 0;
					bInstallPathDetermined = TRUE;
				}
				else
				{
					// 1.0-3.1a (except 3.1)

					// We know that TrueCrypt is installed but don't know where. It's not safe to continue installing
					// over the old version.

					Error ("UNINSTALL_OLD_VERSION_FIRST");

					len = strrchr (rv, '/') - rv - 1;
					strncpy (InstallationPath, rv, len);	// Path and filename of the uninstaller
					InstallationPath [len] = 0;
					bInstallPathDetermined = FALSE;

					ShellExecute (NULL, "open", InstallationPath, "/u", NULL, SW_SHOWNORMAL);
					RegCloseKey (hkey);
					cleanup ();
					exit (1);
				}
			}

		}
		RegCloseKey (hkey);
	}

	if (bInstallPathDetermined)
	{
		char mp[MAX_PATH];

		// Determine whether we were launched from the folder where TrueCrypt is installed
		GetModuleFileName (NULL, mp, sizeof (mp));
		if (strncmp (InstallationPath, mp, min (strlen(InstallationPath), strlen(mp))) == 0)
		{
			// We were launched from the folder where TrueCrypt is installed

			if (!IsNonInstallMode() && !bDevm)
				bChangeMode = TRUE;
		}
	}
	else
	{
		/* TrueCypt is not installed or it wasn't possible to determine where it is installed. */

		// Default "Program Files" path. 
		SHGetSpecialFolderLocation (hwndDlg, CSIDL_PROGRAM_FILES, &itemList);
		SHGetPathFromIDList (itemList, path);
		strcat (path, "\\TrueCrypt\\");
		strcpy (InstallationPath, path);
	}

	// Make sure the path ends with a backslash
	if (InstallationPath [strlen (InstallationPath) - 1] != '\\')
	{
		strcat (InstallationPath, "\\");
	}
}


// Handler for uninstall only (install is handled by the wizard)
BOOL CALLBACK
UninstallDlgProc (HWND hwndDlg, UINT msg, WPARAM wParam, LPARAM lParam)
{
	WORD lw = LOWORD (wParam);

	switch (msg)
	{
	case WM_INITDIALOG:
		MainDlg = hwndDlg;
		InitDialog (hwndDlg);
		LocalizeDialog (hwndDlg, NULL);

		SetWindowTextW (hwndDlg, lpszTitle);

		// System Restore
		SetCheckBox (hwndDlg, IDC_SYSTEM_RESTORE, bSystemRestore);
		if (SystemRestoreDll == 0)
		{
			SetCheckBox (hwndDlg, IDC_SYSTEM_RESTORE, FALSE);
			EnableWindow (GetDlgItem (hwndDlg, IDC_SYSTEM_RESTORE), FALSE);
		}

		SetFocus (GetDlgItem (hwndDlg, IDC_UNINSTALL));

		return 1;

	case WM_SYSCOMMAND:
		if (lw == IDC_ABOUT)
		{
			DialogBoxW (hInst, MAKEINTRESOURCEW (IDD_ABOUT_DLG), hwndDlg, (DLGPROC) AboutDlgProc);
			return 1;
		}
		return 0;

	case WM_COMMAND:
		if (lw == IDC_UNINSTALL)
		{
			if (bDone)
			{
				bUninstallInProgress = FALSE;
				PostMessage (hwndDlg, WM_CLOSE, 0, 0);
				return 1;
			}

			bUninstallInProgress = TRUE;

			WaitCursor ();

			if (bUninstall)
				_beginthread (DoUninstall, 16384, (void *) hwndDlg);

			return 1;
		}

		if (lw == IDC_SYSTEM_RESTORE)
		{
			bSystemRestore = IsButtonChecked (GetDlgItem (hwndDlg, IDC_SYSTEM_RESTORE));
			return 1;
		}

		if (lw == IDCANCEL)
		{
			PostMessage (hwndDlg, WM_CLOSE, 0, 0);
			return 1;
		}

		return 0;

	case TC_APPMSG_UNINSTALL_SUCCESS:
		SetWindowTextW (GetDlgItem ((HWND) hwndDlg, IDC_UNINSTALL), GetString ("FINALIZE"));
		NormalCursor ();
		return 1;

	case WM_CLOSE:
		if (bUninstallInProgress)
		{
			NormalCursor();
			if (AskNoYes("CONFIRM_EXIT_UNIVERSAL") == IDNO)
			{
				return 1;
			}
			WaitCursor ();
		}
		EndDialog (hwndDlg, IDCANCEL);
		return 1;
	}

	return 0;
}


int WINAPI
WINMAIN (HINSTANCE hInstance, HINSTANCE hPrevInstance, char *lpszCommandLine,
	 int nCmdShow)
{
	SelfExtractStartupInit();

	lpszTitle = L"TrueCrypt Setup";

	/* Call InitApp to initialize the common code */
	InitApp (hInstance, NULL);

	if (IsAdmin () != TRUE)
		if (MessageBoxW (NULL, GetString ("SETUP_ADMIN"), lpszTitle, MB_YESNO | MB_ICONQUESTION) != IDYES)
		{
			cleanup ();
			exit (1);
		}

	/* Setup directory */
	{
		char *s;
		GetModuleFileName (NULL, SetupFilesDir, sizeof (SetupFilesDir));
		s = strrchr (SetupFilesDir, '\\');
		if (s)
			s[1] = 0;
	}

	/* Parse command line arguments */

	if (lpszCommandLine[0] == '/')
	{
		if (lpszCommandLine[1] == 'u')
		{
			// Uninstall:	/u

			bUninstall = TRUE;
		}
		else if (lpszCommandLine[1] == 'c')
		{
			// Change:	/c

			bChangeMode = TRUE;
		}
		else if (lpszCommandLine[1] == 'p')
		{
			// Create self-extracting package:	/p

			bMakePackage = TRUE;
		}
		else if (lpszCommandLine[1] == 'd')
		{
			// Dev mode:	/d
			bDevm = TRUE;
		}
	}
 
	if (bMakePackage)
	{
		/* Create self-extracting package */

		MakeSelfExtractingPackage (NULL, SetupFilesDir);
	}
	else
	{
		SetInstallationPath (NULL);

		if (!bUninstall)
		{
			if (IsSelfExtractingPackage())
			{
				if (!VerifyPackageIntegrity())
				{
					// Package corrupted 
					cleanup ();
					exit (1);
				}
				bDevm = FALSE;
			}
			else if (!bDevm)
			{
				MessageBox (NULL, "Error: This installer file does not contain any compressed files.\n\nTo create a self-extracting installer package (with embedded compressed files), run 'TrueCrypt Setup.exe /p'.", "TrueCrypt", MB_ICONERROR | MB_SETFOREGROUND | MB_TOPMOST);
				cleanup ();
				exit (1);
			}

			if (bChangeMode)
			{
				/* TrueCrypt is already installed on this system and we were launched from the Program Files folder */

				char *tmpStr[] = {0, "SELECT_AN_ACTION", "REPAIR_REINSTALL", "UNINSTALL", "EXIT", 0};

				// Ask the user to select either Repair or Unistallation
				switch (AskMultiChoice ((void **) tmpStr))
				{
				case 1:
					bRepairMode = TRUE;
					break;
				case 2:
					bUninstall = TRUE;
					break;
				default:
					cleanup ();
					exit (1);
				}
			}
		}

		// System Restore
		SystemRestoreDll = LoadLibrary ("srclient.dll");

		if (!bUninstall)
		{
			/* Create the main dialog for install */

			DialogBoxParamW (hInstance, MAKEINTRESOURCEW (IDD_INSTL_DLG), NULL, (DLGPROC) MainDialogProc, 
				(LPARAM)lpszCommandLine);
		}
		else
		{
			/* Create the main dialog for uninstall  */

			DialogBoxW (hInstance, MAKEINTRESOURCEW (IDD_UNINSTALL), NULL, (DLGPROC) UninstallDlgProc);

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
	}

	/* Terminate */
	cleanup ();

	return 0;
}
