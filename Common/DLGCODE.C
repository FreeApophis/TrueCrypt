/* Copyright (C) 2004 TrueCrypt Foundation
   This product uses components written by Paul Le Roux <pleroux@swprofessionals.com> */

#include "TCdefs.h"

#include <stdlib.h>

#include "resource.h"
#include "crypto.h"
#include "apidrvr.h"
#include "dlgcode.h"

char szHelpFile[TC_MAX_PATH];
HFONT hSmallFont = NULL;
HFONT hBoldFont = NULL;
HFONT hSmallBoldFont = NULL;
HFONT hTitleFont = NULL;
HFONT hFixedFont = NULL;

HFONT hUserFont = NULL;
HFONT hUserUnderlineFont = NULL;
HFONT hUserBoldFont = NULL;

char *lpszTitle = NULL;
int nCurrentOS = 0;
int CurrentOSMajor = 0;
int CurrentOSMinor = 0;

/* Handle to the device driver */
HANDLE hDriver = INVALID_HANDLE_VALUE;
HINSTANCE hInst = NULL;
HANDLE hMutex = NULL;
HCURSOR hCursor = NULL;

ATOM hDlgClass, hSplashClass;

/* Windows dialog class */
#define WINDOWS_DIALOG_CLASS "#32770"

/* Custom class names */
#define TC_DLG_CLASS "CustomDlg"
#define TC_SPLASH_CLASS "SplashDlg"

void
cleanup ()
{
	/* Cleanup the GDI fonts */
	if (hFixedFont != NULL)
		DeleteObject (hFixedFont);
	if (hSmallFont != NULL)
		DeleteObject (hSmallFont);
	if (hBoldFont != NULL)
		DeleteObject (hBoldFont);
	if (hSmallBoldFont != NULL)
		DeleteObject (hSmallBoldFont);
	if (hTitleFont != NULL)
		DeleteObject (hTitleFont);
	if (hUserFont != NULL)
		DeleteObject (hUserFont);
	if (hUserUnderlineFont != NULL)
		DeleteObject (hUserUnderlineFont);
	if (hUserBoldFont != NULL)
		DeleteObject (hUserBoldFont);
	/* Cleanup our dialog class */
	if (hDlgClass)
		UnregisterClass (TC_DLG_CLASS, hInst);
	if (hSplashClass)
		UnregisterClass (TC_SPLASH_CLASS, hInst);
	/* Close the device driver handle */
	if (hDriver != INVALID_HANDLE_VALUE)
	{
		CloseHandle (hDriver);
	}

	if (hMutex != NULL)
	{
		CloseHandle (hMutex);
	}
}

void
LowerCaseCopy (char *lpszDest, char *lpszSource)
{
	int i = strlen (lpszSource);

	lpszDest[i] = 0;
	while (--i >= 0)
	{
		lpszDest[i] = (char) tolower (lpszSource[i]);
	}

}

void
UpperCaseCopy (char *lpszDest, char *lpszSource)
{
	int i = strlen (lpszSource);

	lpszDest[i] = 0;
	while (--i >= 0)
	{
		lpszDest[i] = (char) toupper (lpszSource[i]);
	}
}

void
CreateFullVolumePath (char *lpszDiskFile, char *lpszFileName, BOOL * bDevice)
{
	if (strcmp (lpszFileName, "Floppy (A:)") == 0)
		strcpy (lpszFileName, "\\Device\\Floppy0");
	else if (strcmp (lpszFileName, "Floppy (B:)") == 0)
		strcpy (lpszFileName, "\\Device\\Floppy1");

	UpperCaseCopy (lpszDiskFile, lpszFileName);

	*bDevice = FALSE;

	if (memcmp (lpszDiskFile, "\\DEVICE", sizeof (char) * 7) == 0)
	{
		*bDevice = TRUE;
	}

	strcpy (lpszDiskFile, lpszFileName);

#if _DEBUG
	OutputDebugString ("CreateFullVolumePath: ");
	OutputDebugString (lpszDiskFile);
	OutputDebugString ("\n");
#endif

}

int
FakeDosNameForDevice (char *lpszDiskFile, char *lpszDosDevice, char *lpszCFDevice, BOOL bNameOnly)
{
	BOOL bDosLinkCreated = TRUE;
	sprintf (lpszDosDevice, "truecrypt%lu", GetCurrentProcessId ());

	if (bNameOnly == FALSE)
		bDosLinkCreated = DefineDosDevice (DDD_RAW_TARGET_PATH, lpszDosDevice, lpszDiskFile);

	if (bDosLinkCreated == FALSE)
	{
		return ERR_OS_ERROR;
	}
	else
		sprintf (lpszCFDevice, "\\\\.\\%s", lpszDosDevice);

	return 0;
}

int
RemoveFakeDosName (char *lpszDiskFile, char *lpszDosDevice)
{
	BOOL bDosLinkRemoved = DefineDosDevice (DDD_RAW_TARGET_PATH | DDD_EXACT_MATCH_ON_REMOVE |
			DDD_REMOVE_DEFINITION, lpszDosDevice, lpszDiskFile);
	if (bDosLinkRemoved == FALSE)
	{
		return ERR_OS_ERROR;
	}

	return 0;
}

char *
getstr (UINT nID)
{
	static char szMsg[256];
	if (LoadString (hInst, nID, szMsg, sizeof (szMsg)) == 0)
		return "";
	else
		return szMsg;
}

char *
getmultilinestr (UINT nID[4])
{
	static char szMsg[1024];
	if (nID[0])
		strcpy (szMsg, getstr (nID[0]));
	if (nID[1])
		strcat (szMsg, getstr (nID[1]));
	if (nID[2])
		strcat (szMsg, getstr (nID[2]));
	if (nID[3])
		strcat (szMsg, getstr (nID[3]));
	return szMsg;

}

void
AbortProcess (UINT nID)
{
	MessageBeep (MB_ICONEXCLAMATION);
	MessageBox (NULL, getstr (nID), lpszTitle, ICON_HAND);
	exit (1);
}

void *
err_malloc (size_t size)
{
	void *z = (void *) TCalloc (size);
	if (z)
		return z;
	AbortProcess (IDS_OUTOFMEMORY);
	return 0;
}

char *
err_strdup (char *lpszText)
{
	int j = (strlen (lpszText) + 1) * sizeof (char);
	char *z = (char *) err_malloc (j);
	memmove (z, lpszText, j);
	return z;
}

void
handleWin32Error (HWND hwndDlg)
{
	LPVOID lpMsgBuf;
	DWORD dwError = GetLastError ();

	FormatMessage (
		FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM,
			      NULL,
			      dwError,
			      MAKELANGID (LANG_NEUTRAL, SUBLANG_DEFAULT),	/* Default language */
			      (char *) &lpMsgBuf,
			      0,
			      NULL
	    );

	MessageBox (hwndDlg, lpMsgBuf, lpszTitle, ICON_HAND);
	LocalFree (lpMsgBuf);
}

BOOL
translateWin32Error (char *lpszMsgBuf, int nSizeOfBuf)
{
	DWORD dwError = GetLastError ();

	if (FormatMessage (FORMAT_MESSAGE_FROM_SYSTEM, NULL, dwError,
			   MAKELANGID (LANG_NEUTRAL, SUBLANG_DEFAULT),	/* Default language */
			   lpszMsgBuf, nSizeOfBuf, NULL))
		return TRUE;
	else
		return FALSE;
}

/* Except in response to the WM_INITDIALOG message, the dialog box procedure
   should return nonzero if it processes the message, and zero if it does
   not. - see DialogProc */
BOOL WINAPI
AboutDlgProc (HWND hwndDlg, UINT msg, WPARAM wParam, LPARAM lParam)
{
	WORD lw = LOWORD (wParam);
	if (lParam);		/* remove warning */

	switch (msg)
	{

	case WM_INITDIALOG:
		{
			char szTmp[32];

			SetDefaultUserFont (hwndDlg);
			SendMessage (GetDlgItem (hwndDlg, ID_WEBSITE), WM_SETFONT, (WPARAM) hUserUnderlineFont, 0);
			SendMessage (GetDlgItem (hwndDlg, IDT_ABOUT_VERSION), WM_SETFONT, (WPARAM) hUserBoldFont, 0);

			sprintf (szTmp, "TrueCrypt %s", VERSION_STRING);
			SetDlgItemText (hwndDlg, IDT_ABOUT_VERSION, szTmp);
			return 1;
		}

	case WM_COMMAND:
		if (lw == IDOK || lw == IDCANCEL)
		{
			EndDialog (hwndDlg, 0);
			return 1;
		}

		if (lw == ID_WEBSITE)
		{
			ArrowWaitCursor ();
			ShellExecute (NULL, "open", "http://www.google.com/search?q=truecrypt", NULL, NULL, SW_SHOWNORMAL);
			Sleep (200);
			NormalCursor ();
			return 1;
		}
		return 0;

	case WM_CLOSE:
		EndDialog (hwndDlg, 0);
		return 1;
	}

	return 0;
}

/* Except in response to the WM_INITDIALOG message, the dialog box procedure
   should return nonzero if it processes the message, and zero if it does
   not. - see DialogProc */
BOOL WINAPI
WarningDlgProc (HWND hwndDlg, UINT msg, WPARAM wParam, LPARAM lParam)
{
	WORD lw = LOWORD (wParam);
	if (lParam);		/* remove warning */

	switch (msg)
	{
	case WM_INITDIALOG:
		SetDefaultUserFont (hwndDlg);
		SetWindowText (GetDlgItem (hwndDlg, IDC_WARNING_TEXT), (char*) lParam);
		return 1;
	case WM_COMMAND:
		if (lw == IDOK || lw == IDCANCEL)
		{
			BOOL x = IsButtonChecked (GetDlgItem (hwndDlg, IDC_NEVER_SHOW));
			if (x == TRUE)
				EndDialog (hwndDlg, IDOK);
			else
				EndDialog (hwndDlg, IDCANCEL);
			return 1;
		}
		return 0;
	case WM_CLOSE:
		EndDialog (hwndDlg, 0);
		return 1;
	}

	return 0;
}

BOOL
IsButtonChecked (HWND hButton)
{
	if (SendMessage (hButton, BM_GETCHECK, 0, 0) == BST_CHECKED)
		return TRUE;
	else
		return FALSE;
}

void
CheckButton (HWND hButton)
{
	SendMessage (hButton, BM_SETCHECK, BST_CHECKED, 0);
}


/*****************************************************************************
  ToSBCS: converts a unicode string to Single Byte Character String (SBCS).
  ***************************************************************************/

void
ToSBCS (LPWSTR lpszText)
{
	int j = wcslen (lpszText);
	if (j == 0)
	{
		strcpy ((char *) lpszText, "");
		return;
	}
	else
	{
		char *lpszNewText = (char *) err_malloc (j + 1);
		j = WideCharToMultiByte (CP_ACP, 0L, lpszText, -1, lpszNewText, j + 1, NULL, NULL);
		if (j > 0)
			strcpy ((char *) lpszText, lpszNewText);
		else
			strcpy ((char *) lpszText, "");
		free (lpszNewText);
	}
}

/*****************************************************************************
  ToUNICODE: converts a SBCS string to a UNICODE string.
  ***************************************************************************/

void
ToUNICODE (char *lpszText)
{
	int j = strlen (lpszText);
	if (j == 0)
	{
		wcscpy ((LPWSTR) lpszText, (LPWSTR) WIDE (""));
		return;
	}
	else
	{
		LPWSTR lpszNewText = (LPWSTR) err_malloc ((j + 1) * 2);
		j = MultiByteToWideChar (CP_ACP, 0L, lpszText, -1, lpszNewText, j + 1);
		if (j > 0)
			wcscpy ((LPWSTR) lpszText, lpszNewText);
		else
			wcscpy ((LPWSTR) lpszText, (LPWSTR) "");
		free (lpszNewText);
	}
}

/* InitDialog - initialize the applications main dialog, this function should
   be called only once in the dialogs WM_INITDIALOG message handler */
void
InitDialog (HWND hwndDlg)
{
	HDC hDC;
	int nHeight;
	LOGFONT lf;
	HMENU hMenu;

	hDC = GetDC (hwndDlg);

	nHeight = -((8 * GetDeviceCaps (hDC, LOGPIXELSY)) / 72);
	lf.lfHeight = nHeight;
	lf.lfWidth = 0;
	lf.lfEscapement = 0;
	lf.lfOrientation = 0;
	lf.lfWeight = FW_LIGHT;
	lf.lfItalic = FALSE;
	lf.lfUnderline = FALSE;
	lf.lfStrikeOut = FALSE;
	lf.lfCharSet = DEFAULT_CHARSET;
	lf.lfOutPrecision = OUT_DEFAULT_PRECIS;
	lf.lfClipPrecision = CLIP_DEFAULT_PRECIS;
	lf.lfQuality = PROOF_QUALITY;
	lf.lfPitchAndFamily = FF_DONTCARE;
	strcpy (lf.lfFaceName, "Courier");
	hSmallFont = CreateFontIndirect (&lf);
	if (hSmallFont == NULL)
	{
		handleWin32Error (hwndDlg);
		AbortProcess (IDS_NOFONT);
	}

	nHeight = -((10 * GetDeviceCaps (hDC, LOGPIXELSY)) / 72);
	lf.lfHeight = nHeight;
	lf.lfWeight = FW_BLACK;
	strcpy (lf.lfFaceName, "Arial");
	hSmallBoldFont = CreateFontIndirect (&lf);
	if (hSmallBoldFont == NULL)
	{
		handleWin32Error (hwndDlg);
		AbortProcess (IDS_NOFONT);
	}

	nHeight = -((16 * GetDeviceCaps (hDC, LOGPIXELSY)) / 72);
	lf.lfHeight = nHeight;
	lf.lfWeight = FW_BOLD;
	strcpy (lf.lfFaceName, "Times");
	hBoldFont = CreateFontIndirect (&lf);
	if (hBoldFont == NULL)
	{
		handleWin32Error (hwndDlg);
		AbortProcess (IDS_NOFONT);
	}

	nHeight = -((16 * GetDeviceCaps (hDC, LOGPIXELSY)) / 72);
	lf.lfHeight = nHeight;
	lf.lfWeight = FW_REGULAR;
	hTitleFont = CreateFontIndirect (&lf);
	if (hTitleFont == NULL)
	{
		handleWin32Error (hwndDlg);
		AbortProcess (IDS_NOFONT);
	}

	nHeight = -((9 * GetDeviceCaps (hDC, LOGPIXELSY)) / 72);
	lf.lfHeight = nHeight;
	lf.lfWidth = 0;
	lf.lfEscapement = 0;
	lf.lfOrientation = 0;
	lf.lfWeight = FW_NORMAL;
	lf.lfItalic = FALSE;
	lf.lfUnderline = FALSE;
	lf.lfStrikeOut = FALSE;
	lf.lfCharSet = DEFAULT_CHARSET;
	lf.lfOutPrecision = OUT_DEFAULT_PRECIS;
	lf.lfClipPrecision = CLIP_DEFAULT_PRECIS;
	lf.lfQuality = PROOF_QUALITY;
	lf.lfPitchAndFamily = FF_DONTCARE;
	strcpy (lf.lfFaceName, "Lucida Console");
	hFixedFont = CreateFontIndirect (&lf);
	if (hFixedFont == NULL)
	{
		handleWin32Error (hwndDlg);
		AbortProcess (IDS_NOFONT);
	}

	hMenu = GetSystemMenu (hwndDlg, FALSE);
	AppendMenu (hMenu, MF_SEPARATOR, 0, NULL);
	AppendMenu (hMenu, MF_ENABLED | MF_STRING, IDC_ABOUT, getstr (IDS_ABOUTBOX));
}

HDC
CreateMemBitmap (HINSTANCE hInstance, HWND hwnd, char *resource)
{
	HBITMAP picture = LoadBitmap (hInstance, resource);
	HDC viewDC = GetDC (hwnd), dcMem;

	dcMem = CreateCompatibleDC (viewDC);

	SetMapMode (dcMem, MM_TEXT);

	SelectObject (dcMem, picture);

	ReleaseDC (hwnd, viewDC);

	return dcMem;
}

/* Draw the specified bitmap at the specified location - Stretch to fit. */
void
PaintBitmap (HDC pdcMem, int x, int y, int nWidth, int nHeight, HDC hDC)
{
	HGDIOBJ picture = GetCurrentObject (pdcMem, OBJ_BITMAP);

	BITMAP bitmap;
	GetObject (picture, sizeof (BITMAP), &bitmap);

	BitBlt (hDC, x, y, nWidth, nHeight, pdcMem, 0, 0, SRCCOPY);
}

LRESULT CALLBACK
SplashDlgProc (HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam)
{

	//if (uMsg == WM_ERASEBKGND)
	//{
	//	NONCLIENTMETRICS metric;
	//	HFONT font;


	//	HDC hDC = (HDC) wParam;
	//	char szTmp[64];
	//	HGDIOBJ obj;
	//	WORD bx = LOWORD (GetDialogBaseUnits ());
	//	WORD by = HIWORD (GetDialogBaseUnits ());


	//	DefDlgProc (hwnd, uMsg, wParam, lParam);

	//	SetBkMode (hDC, TRANSPARENT);
	//	SetTextColor (hDC, RGB (0, 0, 100));
	//	obj = SelectObject (hDC, hTitleFont);

	//	metric.cbSize = sizeof (NONCLIENTMETRICS);
	//	SystemParametersInfo (SPI_GETNONCLIENTMETRICS, sizeof(NONCLIENTMETRICS), &metric, 0);
	//	font = CreateFontIndirect (&metric.lfMessageFont);
	//	obj = SelectObject (hDC, font);

	//	TextOut (hDC, (12 * bx) / 4, (70 * by) / 8, szTmp, strlen (szTmp));

	//	SelectObject (hDC, obj);
	//	return TRUE;
	//}

	return DefDlgProc (hwnd, uMsg, wParam, lParam);
}

void
WaitCursor ()
{
	static HCURSOR hcWait;
	if (hcWait == NULL)
		hcWait = LoadCursor (NULL, IDC_WAIT);
	SetCursor (hcWait);
	hCursor = hcWait;
}

void
NormalCursor ()
{
	static HCURSOR hcArrow;
	if (hcArrow == NULL)
		hcArrow = LoadCursor (NULL, IDC_ARROW);
	SetCursor (hcArrow);
	hCursor = NULL;
}

void
ArrowWaitCursor ()
{
	static HCURSOR hcArrowWait;
	if (hcArrowWait == NULL)
		hcArrowWait = LoadCursor (NULL, IDC_APPSTARTING);
	SetCursor (hcArrowWait);
	hCursor = hcArrowWait;
}

LRESULT CALLBACK
CustomDlgProc (HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
	if (uMsg == WM_SETCURSOR && hCursor != NULL)
	{
		SetCursor (hCursor);
		return TRUE;
	}

	return DefDlgProc (hwnd, uMsg, wParam, lParam);
}

/* InitApp - initialize the application, this function is called once in the
   applications WinMain function, but before the main dialog has been created */
void
InitApp (HINSTANCE hInstance)
{
	WNDCLASS wc;
	char *lpszTmp;
	OSVERSIONINFO os;

	/* Save the instance handle for later */
	hInst = hInstance;

	/* Pull down the windows version */
	os.dwOSVersionInfoSize = sizeof (OSVERSIONINFO);
	if (GetVersionEx (&os) == FALSE)
		AbortProcess (IDS_NO_OS_VER);
	else if (os.dwPlatformId == VER_PLATFORM_WIN32_NT)
		nCurrentOS = WIN_NT;
	else if (os.dwPlatformId == VER_PLATFORM_WIN32_WINDOWS && os.dwMajorVersion == 4 && os.dwMinorVersion == 0)
		nCurrentOS = WIN_95;
	else if (os.dwPlatformId == VER_PLATFORM_WIN32_WINDOWS && os.dwMajorVersion == 4 && os.dwMinorVersion == 10)
		nCurrentOS = WIN_98;
	else {
	/*	AbortProcess (IDS_NO_OS_VER); */
		nCurrentOS = WIN_98;
	}

	CurrentOSMajor = os.dwMajorVersion;
	CurrentOSMinor = os.dwMinorVersion;

	/* Get the attributes for the standard dialog class */
	if ((GetClassInfo (hInst, WINDOWS_DIALOG_CLASS, &wc)) == 0)
		AbortProcess (IDS_INIT_REGISTER);

#ifndef SETUP
	wc.hIcon = LoadIcon (hInstance, MAKEINTRESOURCE (IDI_TRUECRYPT_ICON));
#else
#include "../setup/resource.h"
	wc.hIcon = LoadIcon (hInstance, MAKEINTRESOURCE (IDI_SETUP));
#endif
	wc.lpszClassName = TC_DLG_CLASS;
	wc.lpfnWndProc = &CustomDlgProc;
	wc.hCursor = LoadCursor (NULL, IDC_ARROW);
	wc.cbWndExtra = DLGWINDOWEXTRA;

	hDlgClass = RegisterClass (&wc);
	if (hDlgClass == 0)
		AbortProcess (IDS_INIT_REGISTER);

	wc.lpszClassName = TC_SPLASH_CLASS;
	wc.lpfnWndProc = &SplashDlgProc;
	wc.hCursor = LoadCursor (NULL, IDC_ARROW);
	wc.cbWndExtra = DLGWINDOWEXTRA;

	hSplashClass = RegisterClass (&wc);
	if (hSplashClass == 0)
		AbortProcess (IDS_INIT_REGISTER);

	GetModuleFileName (NULL, szHelpFile, sizeof (szHelpFile));
	lpszTmp = strrchr (szHelpFile, '\\');
	if (lpszTmp)
	{
		strcpy (++lpszTmp, "TrueCrypt User Guide.pdf");
	}

	hMutex = CreateMutex (NULL, TRUE, lpszTitle);
	if (hMutex == NULL)
	{
		handleWin32Error (NULL);
		AbortProcess (IDS_INIT_MUTEX);
	}

	if (GetLastError ()== ERROR_ALREADY_EXISTS)
	{
		// If executed twice, just top the first instance and exit
		HWND h = FindWindow (0, lpszTitle);
		if (h != 0)
		{
			ShowWindow (h, SW_SHOWNORMAL);
			SetForegroundWindow (h);
			exit (1);
		}
		else
			AbortProcess (IDS_TWO_INSTANCES);
	}

#ifndef SETUP
	/* Setup the service if it's not present */
	if (CheckService ()== FALSE)
		AbortProcess (IDS_NOSERVICE);
#endif

}

BOOL
InstallService (SC_HANDLE schSCManager, char *SZSERVICENAME, char *SZSERVICEDISPLAYNAME)
{
	SC_HANDLE schService;

	schService = CreateService (
					   schSCManager,	/* SCManager database */
					   SZSERVICENAME,	/* name of service */
					   SZSERVICEDISPLAYNAME,	/* name to display */
					   SERVICE_ALL_ACCESS,	/* desired access */
					   SERVICE_WIN32_OWN_PROCESS,	/* service type */
					   SERVICE_AUTO_START,	/* start type */
					   SERVICE_ERROR_NORMAL,	/* error control type */
					   "TrueCryptService.exe",	/* service's binary */
					   NULL,	/* no load ordering
							   group */
					   NULL,	/* no tag identifier */
					   "",	/* dependencies */
					   NULL,	/* LocalSystem account */
					   NULL);	/* no password */

	if (schService != NULL)
	{
		CloseServiceHandle (schService);
		return TRUE;
	}

	return FALSE;
}

BOOL
CheckService ()
{

	SC_HANDLE schService = NULL;
	SC_HANDLE schSCManager = NULL;
	BOOL bInstall = FALSE;
	BOOL bAdmin = TRUE;
	BOOL bResult = TRUE;

	if (nCurrentOS != WIN_NT)
		return TRUE;

	schSCManager = OpenSCManager (
					     NULL,	/* machine (NULL ==
							   local) */
					     NULL,	/* database (NULL ==
							   default) */
					     SC_MANAGER_ALL_ACCESS	/* access required */
	    );

	if (schSCManager == NULL)
	{
		schSCManager = OpenSCManager (
						     NULL,	/* machine (NULL ==
								   local) */
						     NULL,	/* database (NULL ==
								   default) */
						     SC_MANAGER_CONNECT | SC_MANAGER_ENUMERATE_SERVICE | SC_MANAGER_QUERY_LOCK_STATUS	/* access required */
		    );

		bAdmin = FALSE;
	}

	if (schSCManager == NULL)
		goto error;

	if (bAdmin == TRUE)
		schService = OpenService (schSCManager, "TrueCryptService", SERVICE_ALL_ACCESS);
	else
		schService = OpenService (schSCManager, "TrueCryptService", SERVICE_QUERY_STATUS);

	if (schService == NULL)
	{
		BOOL bOK;

		if (bAdmin == FALSE)
		{
			handleWin32Error (NULL);
			CloseServiceHandle (schSCManager);
#ifndef SETUP
			AbortProcess (IDS_NOSERVICE);
#else
			return FALSE;
#endif
		}

		if (bInstall == TRUE)
			goto error;

		bInstall = TRUE;

		bOK = InstallService (schSCManager, "TrueCryptService", "TrueCrypt Service");

		if (bOK == FALSE)
			goto error;

		schService = OpenService (schSCManager, "TrueCryptService", SERVICE_ALL_ACCESS);
	}

	if (schService != NULL)
	{
		SERVICE_STATUS status;
		BOOL bOK;
		int i;

		bOK = QueryServiceStatus (schService, &status);

		if (bOK == FALSE)
			goto error;

		if (status.dwCurrentState == SERVICE_RUNNING || status.dwCurrentState == SERVICE_START_PENDING)
			goto success;

		if (bAdmin == FALSE)
		{
			CloseServiceHandle (schService);
			CloseServiceHandle (schSCManager);
#ifndef SETUP
			AbortProcess (IDS_SERVICE_NOT_RUNNING);
#else
			return FALSE;
#endif

		}

		bOK = StartService (schService, 0, NULL);

		if (bOK == FALSE)
			goto error;

#define WAIT_PERIOD 3

		for (i = 0; i < WAIT_PERIOD; i++)
		{
			Sleep (1000);
			bOK = QueryServiceStatus (schService, &status);

			if (bOK == FALSE)
				goto error;


			if (status.dwCurrentState == SERVICE_RUNNING)
				break;
		}

		if (i == WAIT_PERIOD)
			bOK = FALSE;

		if (bOK == FALSE)
			goto error;
		else
			goto success;
	}


      error:
	if (GetLastError ()!= 0)
		handleWin32Error (NULL);

	bResult = FALSE;

      success:
	if (schService != NULL)
		CloseServiceHandle (schService);

	if (schSCManager != NULL)
		CloseServiceHandle (schSCManager);

	return bResult;
}

BOOL
OpenDevice (char *lpszPath, OPEN_TEST_STRUCT * driver)
{
	DWORD dwResult;
	BOOL bResult;

	strcpy ((char *) &driver->wszFileName[0], lpszPath);

	if (nCurrentOS == WIN_NT)
		ToUNICODE ((char *) &driver->wszFileName[0]);

	bResult = DeviceIoControl (hDriver, OPEN_TEST,
				   driver, sizeof (OPEN_TEST_STRUCT),
				   &driver, sizeof (OPEN_TEST_STRUCT),
				   &dwResult, NULL);

	if (bResult == FALSE)
	{
		dwResult = GetLastError ();
		if (dwResult == ERROR_SHARING_VIOLATION)
			return TRUE;
		else
			return FALSE;
	}
	else
	{
		if (nCurrentOS == WIN_NT)
			return TRUE;
		else if (driver->nReturnCode == 0)
			return TRUE;
		else
		{
			SetLastError (ERROR_FILE_NOT_FOUND);
			return FALSE;
		}
	}
}

UINT _stdcall
win9x_io (HFILE hFile, char *lpBuffer, UINT uBytes)
{
	DISKIO_STRUCT *win9x_r0 = (DISKIO_STRUCT *) hFile;
	DWORD dwResult;
	BOOL bResult;
	LONG secs;

	win9x_r0->bufferad = (void *) lpBuffer;

	secs = uBytes / SECTOR_SIZE;

	win9x_r0->sectorlen = secs;

	bResult = DeviceIoControl (hDriver, DISKIO, win9x_r0, sizeof (DISKIO_STRUCT), win9x_r0,
				   sizeof (DISKIO_STRUCT), &dwResult, NULL);

	if (bResult == FALSE || win9x_r0->nReturnCode != 0)
		return (UINT) HFILE_ERROR;

	win9x_r0->sectorstart += secs;

	return uBytes;
}

int
GetAvailableFixedDisks (HWND hComboBox, char *lpszRootPath)
{
	int i, n;
	int line = 0;

	for (i = 0; i < 64; i++)
	{
		BOOL drivePresent = FALSE;

		for (n = 1; n <= 32; n++)
		{
			char szTmp[TC_MAX_PATH], item1[100]={0}, item2[100]={0};
			OPEN_TEST_STRUCT driver;

			sprintf (szTmp, lpszRootPath, i, n);
			if (OpenDevice (szTmp, &driver) == TRUE)
			{
				int nDosLinkCreated;
				HANDLE dev;
				DWORD dwResult;
				BOOL bResult;
				PARTITION_INFORMATION diskInfo;
				
				LVITEM LvItem;

				char szDosDevice[TC_MAX_PATH], szCFDevice[TC_MAX_PATH];

				if(!drivePresent)
				{
					LVITEM LvItem;
					memset(&LvItem,0,sizeof(LvItem));
					LvItem.mask=LVIF_TEXT;
					LvItem.iItem= line++;

					sprintf(szDosDevice, " Harddisk %d:", i);
					LvItem.pszText = szDosDevice;
					SendMessage(hComboBox, LVM_INSERTITEM, 0, (LPARAM)&LvItem);
				}
				drivePresent = TRUE;

				if (nCurrentOS == WIN_NT)
				{
					nDosLinkCreated = FakeDosNameForDevice (szTmp, szDosDevice,
						szCFDevice, FALSE);

					dev = CreateFile (szCFDevice, GENERIC_READ, FILE_SHARE_WRITE , NULL, OPEN_EXISTING, FILE_ATTRIBUTE_READONLY, NULL);

					bResult = DeviceIoControl (dev, IOCTL_DISK_GET_PARTITION_INFO, NULL, 0,
						&diskInfo, sizeof (diskInfo), &dwResult, NULL);

					RemoveFakeDosName(szTmp, szDosDevice);
					CloseHandle(dev);

					if (bResult == TRUE)
					{
						char partType[100];

						switch(diskInfo.PartitionType)
						{
						case PARTITION_ENTRY_UNUSED:	strcpy(partType, "Empty"); break;
						case PARTITION_EXTENDED:		strcpy(partType, "Extended"); break;
						case PARTITION_HUGE:			strcpy(partType, "FAT"); break;
						case PARTITION_FAT_12:			strcpy(partType, "FAT12"); break;
						case PARTITION_FAT_16:			strcpy(partType, "FAT16"); break;
						case PARTITION_FAT32:		
						case PARTITION_FAT32_XINT13:	strcpy(partType, "FAT32"); break;
						case 0x11:
						case 0x14:
						case 0x16:
						case 0x1b:
						case 0x1c:
						case 0x1e:						strcpy(partType, "Hidden FAT"); break;
						case PARTITION_IFS:				strcpy(partType, "NTFS"); break;
						case 0x17:						strcpy(partType, "Hidden NTFS"); break;
						case PARTITION_LDM:				strcpy(partType, "LDM"); break;
						case PARTITION_UNIX:			strcpy(partType, "UNIX"); break;
						case 0x83:						strcpy(partType, "Linux"); break;
						case 0x82:						strcpy(partType, "Linux Swap"); break;

						default:						sprintf(partType, "Unknown (0x%02x)", diskInfo.PartitionType); break;
						}

						if(diskInfo.PartitionLength.QuadPart > 1024I64*1024*1024)
							sprintf (item1,"%.1f GB",(double)(diskInfo.PartitionLength.QuadPart/1024.0/1024/1024));
						else
							sprintf (item1,"%d MB", diskInfo.PartitionLength.QuadPart/1024/1024);

						strcpy (item2, partType);
					}
				}

				memset(&LvItem,0,sizeof(LvItem));
				LvItem.mask=LVIF_TEXT;   
				LvItem.iItem= line++;   

				LvItem.pszText=szTmp;
				SendMessage(hComboBox,LVM_INSERTITEM,0,(LPARAM)&LvItem);

				LvItem.iSubItem=1;
				LvItem.pszText=item1;
				SendMessage(hComboBox,LVM_SETITEM,0,(LPARAM)&LvItem); 

				LvItem.iSubItem=2;
				LvItem.pszText=item2;
				SendMessage(hComboBox,LVM_SETITEM,0,(LPARAM)&LvItem); 
			}


		}

		if(drivePresent)
		{
			LVITEM LvItem;
			memset(&LvItem,0,sizeof(LvItem));
			LvItem.mask=LVIF_TEXT;   
			LvItem.iItem= line++;   

			LvItem.pszText="";
			SendMessage(hComboBox,LVM_INSERTITEM,0,(LPARAM)&LvItem);
		}
	}

	i = SendMessage (hComboBox, LVM_GETITEMCOUNT, 0, 0);
	if (i != CB_ERR)
		return i;
	else
		return 0;
}

int
GetAvailableRemovables (HWND hComboBox, char *lpszRootPath)
{
	char szTmp[TC_MAX_PATH];
	int i;
	LVITEM LvItem;

	if (lpszRootPath);	/* Remove unused parameter warning */

	if (nCurrentOS != WIN_NT)
		return 0;

	memset(&LvItem,0,sizeof(LvItem));
	LvItem.mask = LVIF_TEXT;   
	LvItem.iItem = SendMessage (hComboBox, LVM_GETITEMCOUNT, 0, 0)+1;   

	if (QueryDosDevice ("A:", szTmp, sizeof (szTmp)) != 0)
	{
		LvItem.pszText="Floppy (A:)";
		SendMessage(hComboBox,LVM_INSERTITEM,0,(LPARAM)&LvItem);
	}
	if (QueryDosDevice ("B:", szTmp, sizeof (szTmp)) != 0)
	{
		LvItem.pszText="Floppy (B:)";
		SendMessage(hComboBox,LVM_INSERTITEM,0,(LPARAM)&LvItem);
	}

	i = SendMessage (hComboBox, LVM_GETITEMCOUNT, 0, 0);
	if (i != CB_ERR)
		return i;
	else
		return 0;
}

BOOL WINAPI
RawDevicesDlgProc (HWND hwndDlg, UINT msg, WPARAM wParam, LPARAM lParam)
{
	static char *lpszFileName;
	WORD lw = LOWORD (wParam);

	if (lParam);		/* remove warning */

	switch (msg)
	{
	case WM_INITDIALOG:
		{
			int nCount;
			LVCOLUMN LvCol;
			HWND hList = GetDlgItem (hwndDlg, IDC_DEVICELIST);

			SetDefaultUserFont (hwndDlg);

			SendMessage(hList,LVM_SETEXTENDEDLISTVIEWSTYLE,0,
				LVS_EX_FULLROWSELECT|LVS_EX_HEADERDRAGDROP|LVS_EX_TWOCLICKACTIVATE 
				); 

			memset(&LvCol,0,sizeof(LvCol));               
			LvCol.mask = LVCF_TEXT|LVCF_WIDTH|LVCF_SUBITEM|LVCF_FMT;  
			LvCol.pszText = "Device";                           
			LvCol.cx =160;
			LvCol.fmt = LVCFMT_LEFT;
			SendMessage(hList,LVM_INSERTCOLUMN,0,(LPARAM)&LvCol);

			LvCol.pszText = "Size";  
			LvCol.cx = 64;           
			LvCol.fmt = LVCFMT_RIGHT;
			SendMessage(hList,LVM_INSERTCOLUMN,1,(LPARAM)&LvCol);

			LvCol.pszText = "Type";  
			LvCol.cx = 92;
			LvCol.fmt = LVCFMT_LEFT;
			SendMessage(hList,LVM_INSERTCOLUMN,2,(LPARAM)&LvCol);

			nCount = GetAvailableFixedDisks (hList, "\\Device\\Harddisk%d\\Partition%d");
			nCount += GetAvailableRemovables (hList, "\\Device\\Floppy%d");

			if (nCount == 0)
			{
				handleWin32Error (hwndDlg);
				MessageBox (hwndDlg, getstr (IDS_RAWDEVICES), lpszTitle, ICON_HAND);
				EndDialog (hwndDlg, IDCANCEL);
			}

			lpszFileName = (char *) lParam;
			return 1;
		}

	case WM_COMMAND:
	case WM_NOTIFY:

		// catch non-device line selected
		if (msg == WM_NOTIFY && ((LPNMHDR) lParam)->code == LVN_ITEMCHANGED && (((LPNMLISTVIEW) lParam)->uNewState & LVIS_FOCUSED ))
		{
			LVITEM LvItem;
			memset(&LvItem,0,sizeof(LvItem));
			LvItem.mask = LVIF_TEXT;   
			LvItem.iItem = ((LPNMLISTVIEW) lParam)->iItem;
			LvItem.pszText = lpszFileName;
			LvItem.cchTextMax = TC_MAX_PATH;

			SendMessage (GetDlgItem (hwndDlg, IDC_DEVICELIST), LVM_GETITEMTEXT, LvItem.iItem, (LPARAM) &LvItem);
			EnableWindow (GetDlgItem ((HWND) hwndDlg, IDOK), lpszFileName[0] != 0 && lpszFileName[0] != ' ');
			return 1;
		}

		if (msg == WM_COMMAND && lw == IDOK || msg == WM_NOTIFY && ((NMHDR *)lParam)->code == LVN_ITEMACTIVATE)
		{
			LVITEM LvItem;
			memset(&LvItem,0,sizeof(LvItem));
			LvItem.mask = LVIF_TEXT;   
			LvItem.iItem =  SendMessage (GetDlgItem (hwndDlg, IDC_DEVICELIST), LVM_GETSELECTIONMARK, 0, 0);
			LvItem.pszText = lpszFileName;
			LvItem.cchTextMax = TC_MAX_PATH;

			SendMessage (GetDlgItem (hwndDlg, IDC_DEVICELIST), LVM_GETITEMTEXT, LvItem.iItem, (LPARAM) &LvItem);

			if(lpszFileName[0]==0 || lpszFileName[0]==' ')
				break; // non-device line selected

			EndDialog (hwndDlg, IDOK);
			return 0;
		}

		if (lw == IDCANCEL)
		{
			EndDialog (hwndDlg, IDCANCEL);
			return 0;
		}
		return 0;
	}

	return 0;
}

int
DriverAttach (void)
{
	/* Try to open a handle to the device driver. It will be closed
	   later. */

	if (nCurrentOS == WIN_NT)
		hDriver = CreateFile (WIN32_ROOT_PREFIX, 0, 0, NULL, OPEN_EXISTING, 0, NULL);
	else
		hDriver = CreateFile (WIN9X_DRIVER_NAME, 0, 0, NULL, OPEN_EXISTING, 0, NULL);

	if (hDriver == INVALID_HANDLE_VALUE)
	{
		return ERR_OS_ERROR;
	}
#ifndef SETUP // Don't check version during setup to allow removal of older version
	else
	{
		LONG driver = 0;
		DWORD dwResult;

		BOOL bResult = DeviceIoControl (hDriver, DRIVER_VERSION,
				   &driver, 4, &driver, 4, &dwResult, NULL);

		if (bResult == FALSE)
			return ERR_OS_ERROR;
		else if (driver != VERSION_NUM)
			return ERR_DRIVER_VERSION;
	}
#endif

	if (nCurrentOS == WIN_98)
	{
		DWORD dwResult;
		DeviceIoControl (hDriver, ALLOW_FAST_SHUTDOWN, NULL, 0, NULL, 0, &dwResult, NULL);
	}

	return 0;
}

BOOL
BrowseFiles (HWND hwndDlg, UINT nTitleID, char *lpszFileName)
{
	OPENFILENAME ofn;
	char szFileTitle[TC_MAX_PATH];
	ZeroMemory (&ofn, sizeof (OPENFILENAME));

	*szFileTitle = *lpszFileName = 0;
	ofn.lStructSize = OPENFILENAME_SIZE_VERSION_400; //sizeof (OPENFILENAME);
	ofn.hwndOwner = hwndDlg;
	ofn.lpstrFilter = "All Files (*.*)\0*.*\0TrueCrypt Volumes (*.tc)\0*.tc\0";
	ofn.lpstrCustomFilter = NULL;
	ofn.nFilterIndex = 1;
	ofn.lpstrFile = lpszFileName;
	ofn.nMaxFile = TC_MAX_PATH;
	ofn.lpstrFileTitle = szFileTitle;
	ofn.nMaxFileTitle = TC_MAX_PATH;
	ofn.lpstrInitialDir = NULL;
	ofn.lpstrTitle = getstr (nTitleID);
	ofn.Flags = OFN_HIDEREADONLY | OFN_PATHMUSTEXIST;
	//ofn.lpstrDefExt = "tc";

	if (!GetOpenFileName (&ofn))
		return FALSE;
	else
		return TRUE;
}


void
handleError (HWND hwndDlg, int code)
{
	char szTmp[512];

	switch (code)
	{
	case ERR_OS_ERROR:
		handleWin32Error (hwndDlg);
		break;
	case ERR_OUTOFMEMORY:
		MessageBox (hwndDlg, getstr (IDS_OUTOFMEMORY), lpszTitle, ICON_HAND);
		break;
	case ERR_PASSWORD_WRONG:
		MessageBox (hwndDlg, getstr (IDS_PASSWORD_WRONG), lpszTitle, MB_ICONEXCLAMATION);
		break;
	case ERR_VOL_FORMAT_BAD:
		MessageBox (hwndDlg, getstr (IDS_VOL_FORMAT_BAD), lpszTitle, ICON_HAND);
		break;
	case ERR_BAD_DRIVE_LETTER:
		MessageBox (hwndDlg, getstr (IDS_BAD_DRIVE_LETTER), lpszTitle, ICON_HAND);
		break;
	case ERR_DRIVE_NOT_FOUND:
		MessageBox (hwndDlg, getstr (IDS_NOT_FOUND), lpszTitle, ICON_HAND);
		break;
	case ERR_FILES_OPEN:
		MessageBox (hwndDlg, getstr (IDS_OPENFILES_DRIVER), lpszTitle, ICON_HAND);
		break;
	case ERR_FILES_OPEN_LOCK:
		MessageBox (hwndDlg, getstr (IDS_OPENFILES_LOCK), lpszTitle, ICON_HAND);
		break;
	case ERR_VOL_SIZE_WRONG:
		MessageBox (hwndDlg, getstr (IDS_VOL_SIZE_WRONG), lpszTitle, ICON_HAND);
		break;
	case ERR_COMPRESSION_NOT_SUPPORTED:
		MessageBox (hwndDlg, getstr (IDS_COMPRESSION_NOT_SUPPORTED), lpszTitle, ICON_HAND);
		break;
	case ERR_PASSWORD_CHANGE_VOL_TYPE:
		MessageBox (hwndDlg, getstr (IDS_WRONG_VOL_TYPE), lpszTitle, ICON_HAND);
		break;
	case ERR_PASSWORD_CHANGE_VOL_VERSION:
		MessageBox (hwndDlg, getstr (IDS_WRONG_VOL_VERSION), lpszTitle, ICON_HAND);
		break;
	case ERR_VOL_SEEKING:
		MessageBox (hwndDlg, getstr (IDS_VOL_SEEKING), lpszTitle, ICON_HAND);
		break;
	case ERR_VOL_WRITING:
		MessageBox (hwndDlg, getstr (IDS_VOL_WRITING), lpszTitle, ICON_HAND);
		break;
	case ERR_VOL_READING:
		MessageBox (hwndDlg, getstr (IDS_VOL_READING), lpszTitle, ICON_HAND);
		break;
	case ERR_VOL_ALREADY_MOUNTED:
		MessageBox (hwndDlg, getstr (IDS_VOL_ALREADY_MOUNTED), lpszTitle, ICON_HAND);
		break;
	case ERR_FILE_OPEN_FAILED:
		MessageBox (hwndDlg, getstr (IDS_FILE_OPEN_FAILED), lpszTitle, ICON_HAND);
		break;
	case ERR_VOL_MOUNT_FAILED:
		MessageBox (hwndDlg, getstr (IDS_VOL_MOUNT_FAILED), lpszTitle, MB_ICONEXCLAMATION);
		break;
	case ERR_NO_FREE_SLOTS:
		MessageBox (hwndDlg, getstr (IDS_NO_FREE_SLOTS), lpszTitle, ICON_HAND);
		break;
	case ERR_NO_FREE_DRIVES:
		MessageBox (hwndDlg, getstr (IDS_NO_FREE_DRIVES), lpszTitle, ICON_HAND);
		break;
	case ERR_INVALID_DEVICE:
		MessageBox (hwndDlg, getstr (IDS_INVALID_DEVICE), lpszTitle, ICON_HAND);
		break;
	case ERR_ACCESS_DENIED:
		MessageBox (hwndDlg, getstr (IDS_ACCESS_DENIED), lpszTitle, ICON_HAND);
		break;

	case ERR_DRIVER_VERSION:
		sprintf (szTmp, getstr (IDS_DRIVER_VERSION), VERSION_STRING);
		MessageBox (hwndDlg, szTmp, lpszTitle, ICON_HAND);
		break;

	case ERR_NEW_VERSION_REQUIRED:
		MessageBox (hwndDlg, getstr (IDS_NEW_VERSION_REQUIRED), lpszTitle, ICON_HAND);
		break;

	default:
		sprintf (szTmp, getstr (IDS_UNKNOWN), code);
		MessageBox (hwndDlg, szTmp, lpszTitle, ICON_HAND);

	}
}

static BOOL CALLBACK SetDefaultUserFontEnum( HWND hwnd, LPARAM font)
{
	SendMessage (hwnd, WM_SETFONT, (WPARAM) font, 0);
	return TRUE;
}

void SetDefaultUserFont (HWND hwnd)
{
	NONCLIENTMETRICS metric;

	if (hUserFont == 0)
	{
		metric.cbSize = sizeof (NONCLIENTMETRICS);
		SystemParametersInfo (SPI_GETNONCLIENTMETRICS, sizeof(NONCLIENTMETRICS), &metric, 0);

		hUserFont = CreateFontIndirect (&metric.lfMessageFont);

		metric.lfMessageFont.lfUnderline = TRUE;
		hUserUnderlineFont = CreateFontIndirect (&metric.lfMessageFont);

		metric.lfMessageFont.lfUnderline = FALSE;
		metric.lfMessageFont.lfWeight = FW_BOLD;
		hUserBoldFont = CreateFontIndirect (&metric.lfMessageFont);
	}

	EnumChildWindows (hwnd, SetDefaultUserFontEnum, (LPARAM) hUserFont);
}