/* The source code contained in this file has been derived from the source code
   of Encryption for the Masses 2.02a by Paul Le Roux. Modifications and
   additions to that source code contained in this file are Copyright (c) 2004-2005
   TrueCrypt Foundation and Copyright (c) 2004 TrueCrypt Team. Unmodified
   parts are Copyright (c) 1998-99 Paul Le Roux. This is a TrueCrypt Foundation
   release. Please see the file license.txt for full license details. */

#include "TCdefs.h"

#include <stdlib.h>
#include <time.h>
#include <shlobj.h>
#include <dbt.h>

#include "resource.h"
#include "crypto.h"
#include "apidrvr.h"
#include "dlgcode.h"
#include "volumes.h"

char szHelpFile[TC_MAX_PATH];
HFONT hSmallFont = NULL;
HFONT hBoldFont = NULL;
HFONT hSmallBoldFont = NULL;
HFONT hTitleFont = NULL;
HFONT hFixedFont = NULL;

HFONT hUserFont = NULL;
HFONT hUserUnderlineFont = NULL;
HFONT hUserBoldFont = NULL;
HFONT hUserUnderlineBoldFont = NULL;

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

/* Benchmark */
#ifndef SETUP
#define BENCHMARK_MAX_ITEMS 100
#define BENCHMARK_DEFAULT_BUF_SIZE (1*BYTES_PER_MB)

enum 
{
	BENCHMARK_SORT_BY_NAME = 0,
	BENCHMARK_SORT_BY_SPEED
};

typedef struct 
{
	int id;
	char name[100];
	unsigned __int64 encSpeed;
	unsigned __int64 decSpeed;
	unsigned __int64 meanBytesPerSec;
} BENCHMARK_REC;

BENCHMARK_REC benchmarkTable [BENCHMARK_MAX_ITEMS];
int benchmarkTotalItems = 0;
int benchmarkBufferSize = BENCHMARK_DEFAULT_BUF_SIZE;
int benchmarkLastBufferSize = BENCHMARK_DEFAULT_BUF_SIZE;
int benchmarkSortMethod = BENCHMARK_SORT_BY_SPEED;
LARGE_INTEGER benchmarkPerformanceFrequency;
#endif	// #ifndef SETUP


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
	if (hUserUnderlineBoldFont != NULL)
		DeleteObject (hUserUnderlineBoldFont);
	/* Cleanup our dialog class */
	if (hDlgClass)
		UnregisterClass (TC_DLG_CLASS, hInst);
	if (hSplashClass)
		UnregisterClass (TC_SPLASH_CLASS, hInst);
	/* Close the device driver handle */
	if (hDriver != INVALID_HANDLE_VALUE)
	{
		// Unload driver mode if possible (non-install mode) 
		if (IsNonInstallMode ())
			DriverUnload ();
		else
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

void
AbortProcessSilent (void)
{
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

DWORD
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

	return dwError;
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
			char credits[5000];

			SetDefaultUserFont (hwndDlg);

			SendMessage (GetDlgItem (hwndDlg, IDC_HOMEPAGE), WM_SETFONT, (WPARAM) hUserUnderlineFont, 0);
			SendMessage (GetDlgItem (hwndDlg, IDC_FORUMS), WM_SETFONT, (WPARAM) hUserUnderlineFont, 0);

			// Version
			SendMessage (GetDlgItem (hwndDlg, IDT_ABOUT_VERSION), WM_SETFONT, (WPARAM) hUserBoldFont, 0);
			sprintf (szTmp, "TrueCrypt %s", VERSION_STRING);
			SetDlgItemText (hwndDlg, IDT_ABOUT_VERSION, szTmp);

			// Credits
			SendMessage (GetDlgItem (hwndDlg, IDC_ABOUT_CREDITS), WM_SETFONT, (WPARAM) hUserFont, (LPARAM) 0);
			sprintf (credits,"\
Based on E4M by Paul Le Roux.\r\n\
Portions of this software are based in part on the works of the following people: \
Bruce Schneier, \
Horst Feistel, Don Coppersmith, \
Whitfield Diffie, Martin Hellman, Walt Tuchmann, \
Joan Daemen, Vincent Rijmen, \
Lars Knudsen, Ross Anderson, Eli Biham, \
David Wagner, John Kelsey, Niels Ferguson, Doug Whiting, Chris Hall, \
Carlisle Adams, Stafford Tavares, \
Hans Dobbertin, Antoon Bosselaers, Bart Preneel, \
Steve Reid, Peter Gutmann, and many others.\r\n\r\n\
Portions of this software:\r\n\
Copyright \xA9 2004-2005 TrueCrypt Foundation. All Rights Reserved.\r\n\
Copyright \xA9 1998-2000 Paul Le Roux. All Rights Reserved.\r\n\
Copyright \xA9 2004 TrueCrypt Team. All Rights Reserved.\r\n\
Copyright \xA9 1995-1997 Eric Young. All Rights Reserved.\r\n\
Copyright \xA9 1999-2004 Dr. Brian Gladman. All Rights Reserved.\r\n\
Copyright \xA9 2001 Markus Friedl. All Rights Reserved.\r\n\
Copyright \xA9 2000 Dag Arne Osvik. All Rights Reserved.\r\n\r\n\
A TrueCrypt Foundation Release");
			SetWindowText (GetDlgItem (hwndDlg, IDC_ABOUT_CREDITS), credits);

			return 1;
		}

	case WM_COMMAND:
		if (lw == IDOK || lw == IDCANCEL)
		{
			EndDialog (hwndDlg, 0);
			return 1;
		}

		if (lw == IDC_HOMEPAGE)
		{
			char tmpstr [256];

			ArrowWaitCursor ();
			sprintf (tmpstr, "http://truecrypt.sourceforge.net/applink.php?version=%s", VERSION_STRING);
			ShellExecute (NULL, "open", (LPCTSTR) tmpstr, NULL, NULL, SW_SHOWNORMAL);
			Sleep (200);
			NormalCursor ();
			return 1;
		}

		if (lw == IDC_FORUMS)
		{
			char tmpstr [256];

			ArrowWaitCursor ();
			sprintf (tmpstr, "http://truecrypt.sourceforge.net/applink.php?version=%s&dest=forum", VERSION_STRING);
			ShellExecute (NULL, "open", (LPCTSTR) tmpstr, NULL, NULL, SW_SHOWNORMAL);
			Sleep (200);
			NormalCursor ();
			return 1;
		}

		// Disallow modification of credits
		if (HIWORD (wParam) == EN_UPDATE)
		{
			SendMessage (hwndDlg, WM_INITDIALOG, 0, 0);
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

	SetDefaultUserFont(hwndDlg);
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
	
	// OS version check
	if (CurrentOSMajor < 5)
	{
		MessageBox (NULL, "TrueCrypt does not support this operating system.", lpszTitle, MB_ICONSTOP);
		exit (1);
	}

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

#ifndef VOLFORMAT
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
#endif
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
	LVITEM LvItem;
	__int64 deviceSize = 0;

	for (i = 0; i < 64; i++)
	{
		BOOL drivePresent = FALSE;
		BOOL removable = FALSE;

		for (n = 0; n <= 32; n++)
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
				DISK_GEOMETRY driveInfo;
				char szDosDevice[TC_MAX_PATH], szCFDevice[TC_MAX_PATH];

				drivePresent = TRUE;

				if (nCurrentOS == WIN_NT)
				{
					nDosLinkCreated = FakeDosNameForDevice (szTmp, szDosDevice,
						szCFDevice, FALSE);

					dev = CreateFile (szCFDevice, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE , NULL, OPEN_EXISTING, FILE_ATTRIBUTE_READONLY, NULL);

					bResult = DeviceIoControl (dev, IOCTL_DISK_GET_PARTITION_INFO, NULL, 0,
						&diskInfo, sizeof (diskInfo), &dwResult, NULL);

					// Test if device is removable
					if (n == 0 && DeviceIoControl (dev, IOCTL_DISK_GET_DRIVE_GEOMETRY, NULL, 0,
						&driveInfo, sizeof (driveInfo), &dwResult, NULL))
						removable = driveInfo.MediaType == RemovableMedia;

					RemoveFakeDosName(szTmp, szDosDevice);
					CloseHandle(dev);

					if (bResult == TRUE)
					{
						char partType[100];

						// System creates a virtual partition1 for some storage devices without
						// partition table. We try to detect this case by comparing sizes of
						// partition0 and partition1. If they match, no partition of the device
						// is displayed to the user to avoid confusion. Drive letter assigned by
						// system to partition1 is displayed as subitem of partition0

						if (n == 1 && diskInfo.PartitionLength.QuadPart == deviceSize)
						{
							char drive[] = { 0, ':', 0 };
							char device[MAX_PATH * 2];
							int driveNo;

							// Drive letter
							strcpy (device, szTmp);
							ToUNICODE (device);
							driveNo = GetDiskDeviceDriveLetter ((PWSTR) device);
							drive[0] = driveNo == -1 ? 0 : 'A' + driveNo;

							LvItem.iSubItem = 1;
							LvItem.pszText = drive;
							SendMessage (hComboBox,LVM_SETITEM,0,(LPARAM)&LvItem);

							break;
						}

						switch(diskInfo.PartitionType)
						{
						case PARTITION_ENTRY_UNUSED:	strcpy(partType, "Empty/unused"); break;
						case PARTITION_XINT13_EXTENDED:
						case PARTITION_EXTENDED:		strcpy(partType, "Extended"); break;
						case PARTITION_HUGE:			sprintf(partType, "Unformatted (0x%02X)", diskInfo.PartitionType); break;
						case PARTITION_FAT_12:			strcpy(partType, "FAT12"); break;
						case PARTITION_FAT_16:			strcpy(partType, "FAT16"); break;
						case PARTITION_FAT32:		
						case PARTITION_FAT32_XINT13:	strcpy(partType, "FAT32"); break;
						case 0x08:						strcpy(partType, "DELL (spanning)"); break;
						case 0x12:						strcpy(partType, "Config/diagnostics"); break;
						case 0x11:
						case 0x14:
						case 0x16:
						case 0x1b:
						case 0x1c:
						case 0x1e:						strcpy(partType, "Hidden FAT"); break;
						case PARTITION_IFS:				strcpy(partType, "NTFS"); break;
						case 0x17:						strcpy(partType, "Hidden NTFS"); break;
						case 0x3c:						strcpy(partType, "PMagic recovery"); break;
						case 0x3d:						strcpy(partType, "Hidden NetWare"); break;
						case 0x41:						strcpy(partType, "Linux/MINIX"); break;
						case 0x42:						strcpy(partType, "SFS/LDM/Linux Swap"); break;
						case 0x51:
						case 0x64:
						case 0x65:
						case 0x66:
						case 0x67:
						case 0x68:
						case 0x69:						strcpy(partType, "Novell"); break;
						case 0x55:						strcpy(partType, "EZ-Drive"); break;
						case PARTITION_OS2BOOTMGR:		strcpy(partType, "OS/2 BM"); break;
						case PARTITION_XENIX_1:
						case PARTITION_XENIX_2:			strcpy(partType, "Xenix"); break;
						case PARTITION_UNIX:			strcpy(partType, "UNIX"); break;
						case 0x74:						strcpy(partType, "Scramdisk"); break;
						case 0x78:						strcpy(partType, "XOSL FS"); break;
						case 0x80:
						case 0x81:						strcpy(partType, "MINIX"); break;
						case 0x82:						strcpy(partType, "Linux Swap"); break;
						case 0x43:
						case 0x83:						strcpy(partType, "Linux"); break;
						case 0xc2:
						case 0x93:						strcpy(partType, "Hidden Linux"); break;
						case 0x86:
						case 0x87:						strcpy(partType, "NTFS volume set"); break;
						case 0x9f:						strcpy(partType, "BSD/OS"); break;
						case 0xa0:
						case 0xa1:						strcpy(partType, "Hibernation"); break;
						case 0xa5:						strcpy(partType, "BSD"); break;
						case 0xa8:						strcpy(partType, "Mac OS-X"); break;
						case 0xa9:						strcpy(partType, "NetBSD"); break;
						case 0xab:						strcpy(partType, "Mac OS-X Boot"); break;
						case 0xb8:						strcpy(partType, "BSDI BSD/386 swap"); break;
						case 0xc3:						strcpy(partType, "Hidden Linux swap"); break;
						case 0xfb:						strcpy(partType, "VMware"); break;
						case 0xfc:						strcpy(partType, "VMware swap"); break;
						case 0xfd:						strcpy(partType, "Linux RAID"); break;
						case 0xfe:						strcpy(partType, "WinNT hidden"); break;
						default:						sprintf(partType, "0x%02X", diskInfo.PartitionType); break;
						}

						if (diskInfo.PartitionLength.QuadPart > 1024I64*1024*1024*1024*1024*99)
							sprintf (item1,"%d PB", diskInfo.PartitionLength.QuadPart/1024/1024/1024/1024/1024);
						else if (diskInfo.PartitionLength.QuadPart > 1024I64*1024*1024*1024*1024)
							sprintf (item1,"%.1f PB",(double)(diskInfo.PartitionLength.QuadPart/1024.0/1024/1024/1024/1024));
						else if (diskInfo.PartitionLength.QuadPart > 1024I64*1024*1024*1024*99)
							sprintf (item1,"%d TB",diskInfo.PartitionLength.QuadPart/1024.0/1024/1024/1024);
						else if (diskInfo.PartitionLength.QuadPart > 1024I64*1024*1024*1024)
							sprintf (item1,"%.1f TB",(double)(diskInfo.PartitionLength.QuadPart/1024.0/1024/1024/1024));
						else if (diskInfo.PartitionLength.QuadPart > 1024I64*1024*1024*99)
							sprintf (item1,"%d GB",diskInfo.PartitionLength.QuadPart/1024/1024/1024);
						else if (diskInfo.PartitionLength.QuadPart > 1024I64*1024*1024)
							sprintf (item1,"%.1f GB",(double)(diskInfo.PartitionLength.QuadPart/1024.0/1024/1024));
						else
							sprintf (item1,"%d MB", diskInfo.PartitionLength.QuadPart/1024/1024);

						strcpy (item2, partType);
					}
				}

				if (n == 0)
				{
					deviceSize = diskInfo.PartitionLength.QuadPart;
					sprintf (szTmp, "Harddisk %d:", i);
				}

				memset (&LvItem,0,sizeof(LvItem));
				LvItem.mask = LVIF_TEXT;   
				LvItem.iItem = line++;   

				// Device Name
				LvItem.pszText = szTmp;
				SendMessage (hComboBox,LVM_INSERTITEM,0,(LPARAM)&LvItem);

				// Size
				LvItem.iSubItem = 2;
				LvItem.pszText = item1;
				SendMessage (hComboBox,LVM_SETITEM,0,(LPARAM)&LvItem); 

				// Device type removable
				if (n == 0 && removable)
				{
					LvItem.iSubItem = 3;
					LvItem.pszText = "Removable";
					SendMessage (hComboBox,LVM_SETITEM,0,(LPARAM)&LvItem);
				}

				if (n > 0)
				{
					char drive[] = { 0, ':', 0 };
					char device[MAX_PATH * 2];
					int driveNo;

					// Drive letter
					strcpy (device, szTmp);
					ToUNICODE (device);
					driveNo = GetDiskDeviceDriveLetter ((PWSTR) device);
					drive[0] = driveNo == -1 ? 0 : 'A' + driveNo;

					LvItem.iSubItem = 1;
					LvItem.pszText = drive;
					SendMessage (hComboBox,LVM_SETITEM,0,(LPARAM)&LvItem);

					// Partition type
					LvItem.iSubItem = 3;
					LvItem.pszText = item2;
					SendMessage (hComboBox,LVM_SETITEM,0,(LPARAM)&LvItem);
				}

				// Mark device with partitions, removable drives are not marked to allow
				// users silent overwrite of existing partitions as system does not
				// support partition management of removable drives

				if (n == 1 && !removable)
				{
					LvItem.iItem = line - 2;
					LvItem.iSubItem = 3;
					LvItem.pszText = " ";
					SendMessage (hComboBox,LVM_SETITEM,0,(LPARAM)&LvItem);
				}
			}
			else if (n == 0)
				break;
		}

		if (drivePresent)
		{
			memset (&LvItem,0,sizeof(LvItem));
			LvItem.mask = LVIF_TEXT;   
			LvItem.iItem = line++;   

			LvItem.pszText = "";
			SendMessage (hComboBox,LVM_INSERTITEM,0,(LPARAM)&LvItem);
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

	memset (&LvItem,0,sizeof(LvItem));
	LvItem.mask = LVIF_TEXT;   
	LvItem.iItem = SendMessage (hComboBox, LVM_GETITEMCOUNT, 0, 0)+1;   

	if (QueryDosDevice ("A:", szTmp, sizeof (szTmp)) != 0)
	{
		LvItem.pszText = "\\Device\\Floppy0";
		LvItem.iItem = SendMessage (hComboBox,LVM_INSERTITEM,0,(LPARAM)&LvItem);

		LvItem.iSubItem = 1;
		LvItem.pszText = "A:";
		SendMessage (hComboBox,LVM_SETITEM,0,(LPARAM)&LvItem);

	}
	if (QueryDosDevice ("B:", szTmp, sizeof (szTmp)) != 0)
	{
		LvItem.pszText = "\\Device\\Floppy1";
		LvItem.iSubItem = 0;
		LvItem.iItem = SendMessage (hComboBox, LVM_GETITEMCOUNT, 0, 0)+1;   
		LvItem.iItem = SendMessage (hComboBox,LVM_INSERTITEM,0,(LPARAM)&LvItem);

		LvItem.iSubItem = 1;
		LvItem.pszText = "B:";
		SendMessage (hComboBox,LVM_SETITEM,0,(LPARAM)&LvItem);
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

			SendMessage (hList,LVM_SETEXTENDEDLISTVIEWSTYLE,0,
				LVS_EX_FULLROWSELECT|LVS_EX_HEADERDRAGDROP|LVS_EX_TWOCLICKACTIVATE 
				); 

			memset (&LvCol,0,sizeof(LvCol));               
			LvCol.mask = LVCF_TEXT|LVCF_WIDTH|LVCF_SUBITEM|LVCF_FMT;  
			LvCol.pszText = "Device";                           
			LvCol.cx =154;
			LvCol.fmt = LVCFMT_LEFT;
			SendMessage (hList,LVM_INSERTCOLUMN,0,(LPARAM)&LvCol);

			LvCol.pszText = "Drive";  
			LvCol.cx = 38;           
			LvCol.fmt = LVCFMT_LEFT;
			SendMessage (hList,LVM_INSERTCOLUMN,1,(LPARAM)&LvCol);

			LvCol.pszText = "Size";  
			LvCol.cx = 62;           
			LvCol.fmt = LVCFMT_RIGHT;
			SendMessage (hList,LVM_INSERTCOLUMN,2,(LPARAM)&LvCol);

			LvCol.pszText = "Type";  
			LvCol.cx = 112;
			LvCol.fmt = LVCFMT_LEFT;
			SendMessage (hList,LVM_INSERTCOLUMN,3,(LPARAM)&LvCol);

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
			memset (&LvItem,0,sizeof(LvItem));
			LvItem.mask = LVIF_TEXT;   
			LvItem.iItem =  SendMessage (GetDlgItem (hwndDlg, IDC_DEVICELIST), LVM_GETSELECTIONMARK, 0, 0);
			LvItem.pszText = lpszFileName;
			LvItem.cchTextMax = TC_MAX_PATH;

			SendMessage (GetDlgItem (hwndDlg, IDC_DEVICELIST), LVM_GETITEMTEXT, LvItem.iItem, (LPARAM) &LvItem);

			if (lpszFileName[0] == 'H')
			{
				// Whole device selected
				int driveNo;

				sscanf (lpszFileName, "Harddisk %d", &driveNo);
				sprintf (lpszFileName, "\\Device\\Harddisk%d\\Partition0", driveNo);

#ifdef VOLFORMAT
				// Warn if device contains partitions
				{
					char tmp[10];
					LvItem.iSubItem = 3;
					LvItem.pszText = tmp;
					SendMessage (GetDlgItem (hwndDlg, IDC_DEVICELIST), LVM_GETITEMTEXT, LvItem.iItem, (LPARAM) &LvItem);
					if (tmp[0] == ' ')
					{
						if (IDNO == MessageBox (hwndDlg, getstr (IDS_DEVICE_PARTITIONS_WARN),
							lpszTitle, MB_YESNO|MB_ICONWARNING|MB_DEFBUTTON2))
							break;
					}
				}
#endif
			}

			if (lpszFileName[0] == 0)
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


// Install and start driver service and mark it for removal (non-install mode)
static int DriverLoad ()
{
	HANDLE file;
	WIN32_FIND_DATA find;
	SC_HANDLE hManager, hService = NULL;
	char driverPath[TC_MAX_PATH*2];
	BOOL res;
	char *tmp;

	GetModuleFileName (NULL, driverPath, sizeof (driverPath));
	tmp = strrchr (driverPath, '\\');
	if (!tmp)
	{
		strcpy (driverPath, ".");
		tmp = driverPath + 1;
	}

	strcpy (tmp, "\\truecrypt.sys");

	file = FindFirstFile (driverPath, &find);

	if (file == INVALID_HANDLE_VALUE)
	{
		MessageBox (0, getstr (IDS_DRIVER_NOT_FOUND), lpszTitle, ICON_HAND);
		return ERR_DONT_REPORT;
	}

	FindClose (file);

	hManager = OpenSCManager (NULL, NULL, SC_MANAGER_ALL_ACCESS);
	if (hManager == NULL)
	{
		if (GetLastError () == ERROR_ACCESS_DENIED)
		{
			MessageBox (0, getstr (IDS_ADMIN_PRIVILEGES_DRIVER), lpszTitle, ICON_HAND);
			return ERR_DONT_REPORT;
		}

		return ERR_OS_ERROR;
	}

	hService = CreateService (hManager, "truecrypt", "truecrypt",
		SERVICE_ALL_ACCESS, SERVICE_KERNEL_DRIVER, SERVICE_DEMAND_START, SERVICE_ERROR_NORMAL,
		driverPath, NULL, NULL, NULL, NULL, NULL);

	if (hService == NULL)
	{
		CloseServiceHandle (hManager);
		return ERR_OS_ERROR;
	}

	res = StartService (hService, 0, NULL);

	DeleteService (hService);
	CloseServiceHandle (hManager);
	CloseServiceHandle (hService);

	return !res ? ERR_OS_ERROR : ERROR_SUCCESS;
}


BOOL DriverUnload ()
{
	MOUNT_LIST_STRUCT driver;
	int refCount;
	DWORD dwResult;
	BOOL bResult;

	SC_HANDLE hManager, hService = NULL;
	BOOL bOK = FALSE, bRet;
	SERVICE_STATUS status;
	int x;

	if (hDriver == INVALID_HANDLE_VALUE)
		return TRUE;

	// Test for mounted volumes
	bResult = DeviceIoControl (hDriver, MOUNT_LIST, &driver, sizeof (driver), &driver,
		sizeof (driver), &dwResult, NULL);

	if (bResult == TRUE)
	{
		if (driver.ulMountedDrives != 0)
			return FALSE;
	}
	else
		return TRUE;

	// Test for any applications attached to driver
	bResult = DeviceIoControl (hDriver, DEVICE_REFCOUNT, &refCount, sizeof (refCount), &refCount,
		sizeof (refCount), &dwResult, NULL);

	if (bResult == TRUE)
	{
		if (refCount > 1)
			return FALSE;
	}
	else
		return TRUE;

	CloseHandle (hDriver);

	// Stop driver service

	hManager = OpenSCManager (NULL, NULL, SC_MANAGER_ALL_ACCESS);
	if (hManager == NULL)
		goto error;

	hService = OpenService (hManager, "truecrypt", SERVICE_ALL_ACCESS);
	if (hService == NULL)
		goto error;

	bRet = QueryServiceStatus (hService, &status);
	if (bRet != TRUE)
		goto error;

	if (status.dwCurrentState != SERVICE_STOPPED)
	{
		ControlService (hService, SERVICE_CONTROL_STOP, &status);

		for (x = 0; x < 5; x++)
		{
			bRet = QueryServiceStatus (hService, &status);
			if (bRet != TRUE)
				goto error;

			if (status.dwCurrentState == SERVICE_STOPPED)
				break;

			Sleep (200);
		}
	}

error:
	if (hService != NULL)
		CloseServiceHandle (hService);

	if (hManager != NULL)
		CloseServiceHandle (hManager);

	if (status.dwCurrentState == SERVICE_STOPPED)
	{
		hDriver = INVALID_HANDLE_VALUE;
		return TRUE;
	}

	return FALSE;
}


int
DriverAttach (void)
{
	/* Try to open a handle to the device driver. It will be closed later. */

	hDriver = CreateFile (WIN32_ROOT_PREFIX, 0, 0, NULL, OPEN_EXISTING, 0, NULL);

	if (hDriver == INVALID_HANDLE_VALUE)
	{
#ifndef SETUP
		// Attempt to load driver (non-install mode)
		BOOL res = DriverLoad ();

		if (res != ERROR_SUCCESS)
			return res;

		hDriver = CreateFile (WIN32_ROOT_PREFIX, 0, 0, NULL, OPEN_EXISTING, 0, NULL);
#endif
		if (hDriver == INVALID_HANDLE_VALUE)
			return ERR_OS_ERROR;
	}
#ifndef SETUP // Don't check version during setup to allow removal of another version

	if (hDriver != INVALID_HANDLE_VALUE)
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

	return 0;
}


// Sets file pointer to hidden volume header
BOOL SeekHiddenVolHeader (HFILE dev, unsigned __int64 volSize, BOOL deviceFlag)
{
	LARGE_INTEGER offset, offsetNew;

	if (deviceFlag)
	{
		// Partition/device

		offset.QuadPart = volSize - HIDDEN_VOL_HEADER_OFFSET;

		if (SetFilePointerEx ((HANDLE) dev, offset, &offsetNew, FILE_BEGIN) == 0)
			return FALSE;

		if (offsetNew.QuadPart != offset.QuadPart)
			return FALSE;
	}
	else
	{
		// File-hosted volume

		offset.QuadPart = - HIDDEN_VOL_HEADER_OFFSET;

		if (SetFilePointerEx ((HANDLE) dev, offset, &offsetNew, FILE_END) == 0)
			return FALSE;
	}

	return TRUE;
}


BOOL
BrowseFiles (HWND hwndDlg, UINT nTitleID, char *lpszFileName, BOOL keepHistory)
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
	ofn.Flags = OFN_HIDEREADONLY | OFN_PATHMUSTEXIST | (keepHistory ? 0 : OFN_DONTADDTORECENT);
	//ofn.lpstrDefExt = "tc";

	if (!GetOpenFileName (&ofn))
		return FALSE;
	else
		return TRUE;
}


static int CALLBACK
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
BrowseDirectories (HWND hwndDlg, char *lpszTitle, char *dirName)
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
		bi.lParam = (LPARAM)dirName;

		pidl = SHBrowseForFolder(&bi);
		if (pidl!=NULL) 
		{
			if (SHGetPathFromIDList(pidl, dirName)==TRUE) 
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
		MessageBox (hwndDlg, getstr (CheckCapsLock (NULL, TRUE) ? IDS_PASSWORD_WRONG_CAPSLOCK_ON : IDS_PASSWORD_WRONG), lpszTitle, MB_ICONEXCLAMATION);
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
		MessageBox (hwndDlg, getstr (CheckCapsLock (NULL, TRUE) ? IDS_VOL_MOUNT_FAILED_CAPSLOCK_ON : IDS_VOL_MOUNT_FAILED), lpszTitle, MB_ICONEXCLAMATION);
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

	case ERR_DONT_REPORT:
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

		metric.lfMessageFont.lfHeight = -11;
		metric.lfMessageFont.lfWidth = 0;

		hUserFont = CreateFontIndirect (&metric.lfMessageFont);

		metric.lfMessageFont.lfUnderline = TRUE;
		hUserUnderlineFont = CreateFontIndirect (&metric.lfMessageFont);

		metric.lfMessageFont.lfUnderline = FALSE;
		metric.lfMessageFont.lfWeight = FW_BOLD;
		hUserBoldFont = CreateFontIndirect (&metric.lfMessageFont);

		metric.lfMessageFont.lfUnderline = TRUE;
		metric.lfMessageFont.lfWeight = FW_BOLD;
		hUserUnderlineBoldFont = CreateFontIndirect (&metric.lfMessageFont);
	}

	EnumChildWindows (hwnd, SetDefaultUserFontEnum, (LPARAM) hUserFont);
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

static BOOL explorerCloseSent;

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
			explorerCloseSent = TRUE;
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
			{
				PostMessage (hwnd, WM_CLOSE, 0, 0);
				explorerCloseSent = TRUE;
			}
		}
	}
	return TRUE;
}

BOOL CloseVolumeExplorerWindows (HWND hwnd, int driveNo)
{
	explorerCloseSent = FALSE;
	EnumWindows (CloseVolumeExplorerWindowsEnum, (LPARAM) driveNo);

	return explorerCloseSent;
}


#ifndef SETUP
void GetSpeedString (unsigned __int64 speed, char *str)
{
	if (speed > 1024I64*1024*1024*1024*1024*99)
		sprintf (str,"%d PB/s", speed/1024/1024/1024/1024/1024);
	else if (speed > 1024I64*1024*1024*1024*1024)
		sprintf (str,"%.1f PB/s",(double)(speed/1024.0/1024/1024/1024/1024));
	else if (speed > 1024I64*1024*1024*1024*99)
		sprintf (str,"%d TB/s",speed/1024/1024/1024/1024);
	else if (speed > 1024I64*1024*1024*1024)
		sprintf (str,"%.1f TB/s",(double)(speed/1024.0/1024/1024/1024));
	else if (speed > 1024I64*1024*1024*99)
		sprintf (str,"%d GB/s",speed/1024/1024/1024);
	else if (speed > 1024I64*1024*1024)
		sprintf (str,"%.1f GB/s",(double)(speed/1024.0/1024/1024));
	else if (speed > 1024I64*1024*99)
		sprintf (str,"%d MB/s", speed/1024/1024);
	else if (speed > 1024I64*1024)
		sprintf (str,"%.1f MB/s",(double)(speed/1024.0/1024));
	else
		sprintf (str,"%d KB/s", speed/1024);
}

static void DisplayBenchmarkResults (HWND hwndDlg)
{
	BENCHMARK_REC tmp_line;
	char item1[100]={0};
	int line = 0;
	LVITEM LvItem;
	HWND hList = GetDlgItem (hwndDlg, IDC_RESULTS);
	int ea, i;
	BOOL unsorted = TRUE;

	/* Sort the list */

	switch (benchmarkSortMethod)
	{
	case BENCHMARK_SORT_BY_SPEED:

		while (unsorted)
		{
			unsorted = FALSE;
			for (i = 0; i < benchmarkTotalItems - 1; i++)
			{
				if (benchmarkTable[i].meanBytesPerSec < benchmarkTable[i+1].meanBytesPerSec)
				{
					unsorted = TRUE;
					memcpy (&tmp_line, &benchmarkTable[i], sizeof(BENCHMARK_REC));
					memcpy (&benchmarkTable[i], &benchmarkTable[i+1], sizeof(BENCHMARK_REC));
					memcpy (&benchmarkTable[i+1], &tmp_line, sizeof(BENCHMARK_REC));
				}
			}
		}
		break;

	case BENCHMARK_SORT_BY_NAME:

		while (unsorted)
		{
			unsorted = FALSE;
			for (i = 0; i < benchmarkTotalItems - 1; i++)
			{
				if (benchmarkTable[i].id > benchmarkTable[i+1].id)
				{
					unsorted = TRUE;
					memcpy (&tmp_line, &benchmarkTable[i], sizeof(BENCHMARK_REC));
					memcpy (&benchmarkTable[i], &benchmarkTable[i+1], sizeof(BENCHMARK_REC));
					memcpy (&benchmarkTable[i+1], &tmp_line, sizeof(BENCHMARK_REC));
				}
			}
		}
		break;
	}
  
	/* Render the results */

	SendMessage (hList,LVM_DELETEALLITEMS,0,(LPARAM)&LvItem);

	for (i = 0; i < benchmarkTotalItems; i++)
	{
		ea = benchmarkTable[i].id;

		memset (&LvItem,0,sizeof(LvItem));
		LvItem.mask = LVIF_TEXT;
		LvItem.iItem = line++;
		LvItem.iSubItem = 0;
		LvItem.pszText = benchmarkTable[i].name;

		SendMessage (hList,LVM_INSERTITEM,0,(LPARAM)&LvItem);

		GetSpeedString((unsigned __int64) (benchmarkLastBufferSize / ((float) benchmarkTable[i].encSpeed / benchmarkPerformanceFrequency.QuadPart)), item1);
		LvItem.iSubItem = 1;
		LvItem.pszText = item1;

		SendMessage (hList,LVM_SETITEM,0,(LPARAM)&LvItem); 
		GetSpeedString((unsigned __int64) (benchmarkLastBufferSize / ((float) benchmarkTable[i].decSpeed / benchmarkPerformanceFrequency.QuadPart)), item1);
		LvItem.iSubItem = 2;
		LvItem.pszText = item1;

		SendMessage (hList,LVM_SETITEM,0,(LPARAM)&LvItem); 

		GetSpeedString(benchmarkTable[i].meanBytesPerSec, item1);
		LvItem.iSubItem = 3;
		LvItem.pszText = item1;

		SendMessage (hList,LVM_SETITEM,0,(LPARAM)&LvItem); 
	}
}

static BOOL PerformBenchmark(HWND hwndDlg)
{
    LARGE_INTEGER performanceCountStart, performanceCountEnd;
	BYTE *lpTestBuffer;
	HWND hList = GetDlgItem (hwndDlg, IDC_RESULTS);
	int ea;
	unsigned char iv[DISK_IV_SIZE];
	unsigned char ks[MAX_EXPANDED_KEY];
	unsigned char key[DISKKEY_SIZE];

	if (QueryPerformanceFrequency (&benchmarkPerformanceFrequency) == 0)
	{
		MessageBox (hwndDlg, "Error: Your hardware does not support a high-resolution performance counter.", lpszTitle, ICON_HAND);
		return FALSE;
	}

	ArrowWaitCursor ();

	lpTestBuffer = malloc(benchmarkBufferSize - (benchmarkBufferSize % 16));
	if (lpTestBuffer == NULL)
	{
		NormalCursor ();
		MessageBox (hwndDlg, "Error: Cannot allocate memory.", lpszTitle, ICON_HAND);
		return FALSE;
	}
	VirtualLock (lpTestBuffer, benchmarkBufferSize - (benchmarkBufferSize % 16));

	benchmarkTotalItems = 0;
	
	for (ea = EAGetFirst(); ea != 0; ea = EAGetNext(ea))
	{
		EAInit (ea, key, ks);
        
		if (QueryPerformanceCounter (&performanceCountStart) == 0)
			goto counter_error;

		EncryptBuffer ((unsigned long *) lpTestBuffer, (unsigned __int64) benchmarkBufferSize, ks, iv, iv, ea);

		if (QueryPerformanceCounter (&performanceCountEnd) == 0)
			goto counter_error;

		benchmarkTable[benchmarkTotalItems].encSpeed = performanceCountEnd.QuadPart - performanceCountStart.QuadPart;

		if (QueryPerformanceCounter (&performanceCountStart) == 0)
			goto counter_error;

		DecryptBuffer ((unsigned long *) lpTestBuffer, (unsigned __int64) benchmarkBufferSize, ks, iv, iv, ea);
		
		if (QueryPerformanceCounter (&performanceCountEnd) == 0)
			goto counter_error;

		benchmarkTable[benchmarkTotalItems].decSpeed = performanceCountEnd.QuadPart - performanceCountStart.QuadPart;
		benchmarkTable[benchmarkTotalItems].id = ea;
		benchmarkTable[benchmarkTotalItems].meanBytesPerSec = ((unsigned __int64) (benchmarkBufferSize / ((float) benchmarkTable[benchmarkTotalItems].encSpeed / benchmarkPerformanceFrequency.QuadPart)) + (unsigned __int64) (benchmarkBufferSize / ((float) benchmarkTable[benchmarkTotalItems].decSpeed / benchmarkPerformanceFrequency.QuadPart))) / 2;
		EAGetName (benchmarkTable[benchmarkTotalItems].name, ea);

		benchmarkTotalItems++;

	}

	VirtualUnlock (lpTestBuffer, benchmarkBufferSize - (benchmarkBufferSize % 16));

	free(lpTestBuffer);

	benchmarkLastBufferSize = benchmarkBufferSize;

	DisplayBenchmarkResults(hwndDlg);

	EnableWindow (GetDlgItem (hwndDlg, ID_PERFORM_BENCHMARK), TRUE);
	EnableWindow (GetDlgItem (hwndDlg, IDCLOSE), TRUE);

	NormalCursor ();
	return TRUE;

counter_error:

	VirtualUnlock (lpTestBuffer, benchmarkBufferSize - (benchmarkBufferSize % 16));

	free(lpTestBuffer);

	NormalCursor ();

	EnableWindow (GetDlgItem (hwndDlg, ID_PERFORM_BENCHMARK), TRUE);
	EnableWindow (GetDlgItem (hwndDlg, IDCLOSE), TRUE);

	MessageBox (hwndDlg, "Error: Could not retrieve value of performance counter.", lpszTitle, ICON_HAND);
	return FALSE;
}


BOOL WINAPI BenchmarkDlgProc (HWND hwndDlg, UINT msg, WPARAM wParam, LPARAM lParam)
{
	WORD lw = LOWORD (wParam);
	LPARAM nIndex;
	HWND hCboxSortMethod = GetDlgItem (hwndDlg, IDC_BENCHMARK_SORT_METHOD);
	HWND hCboxBufferSize = GetDlgItem (hwndDlg, IDC_BENCHMARK_BUFFER_SIZE);

	switch (msg)
	{
	case WM_INITDIALOG:
		{
			LVCOLUMN LvCol;
			HWND hList = GetDlgItem (hwndDlg, IDC_RESULTS);

			SetDefaultUserFont (hwndDlg);

			benchmarkBufferSize = BENCHMARK_DEFAULT_BUF_SIZE;
			benchmarkSortMethod = BENCHMARK_SORT_BY_SPEED;

			SendMessage (hList,LVM_SETEXTENDEDLISTVIEWSTYLE,0,
				LVS_EX_FULLROWSELECT|LVS_EX_HEADERDRAGDROP|LVS_EX_TWOCLICKACTIVATE 
				); 

			memset (&LvCol,0,sizeof(LvCol));               
			LvCol.mask = LVCF_TEXT|LVCF_WIDTH|LVCF_SUBITEM|LVCF_FMT;  
			LvCol.pszText = "Algorithm";                           
			LvCol.cx =114;
			LvCol.fmt = LVCFMT_LEFT;
			SendMessage (hList,LVM_INSERTCOLUMN,0,(LPARAM)&LvCol);

			LvCol.pszText = "Encryption";  
			LvCol.cx = 80;           
			LvCol.fmt = LVCFMT_RIGHT;
			SendMessage (hList,LVM_INSERTCOLUMN,1,(LPARAM)&LvCol);

			LvCol.pszText = "Decryption";  
			LvCol.cx = 80;
			LvCol.fmt = LVCFMT_RIGHT;
			SendMessage (hList,LVM_INSERTCOLUMN,2,(LPARAM)&LvCol);

			LvCol.pszText = "Mean";  
			LvCol.cx = 80;
			LvCol.fmt = LVCFMT_RIGHT;
			SendMessage (hList,LVM_INSERTCOLUMN,3,(LPARAM)&LvCol);

			/* Combo boxes */

			// Sort method

			SendMessage (hCboxSortMethod, CB_RESETCONTENT, 0, 0);

			nIndex = SendMessage (hCboxSortMethod, CB_ADDSTRING, 0, (LPARAM) "Alphabetical/Categorized");
			SendMessage (hCboxSortMethod, CB_SETITEMDATA, nIndex, (LPARAM) 0);

			nIndex = SendMessage (hCboxSortMethod, CB_ADDSTRING, 0, (LPARAM) "Mean Speed (Descending)");
			SendMessage (hCboxSortMethod, CB_SETITEMDATA, nIndex, (LPARAM) 0);

			SendMessage (hCboxSortMethod, CB_SETCURSEL, 1, 0);		// Default sort method

			// Buffer size

			SendMessage (hCboxBufferSize, CB_RESETCONTENT, 0, 0);

			nIndex = SendMessage (hCboxBufferSize, CB_ADDSTRING, 0, (LPARAM) "5 KB");
			SendMessage (hCboxBufferSize, CB_SETITEMDATA, nIndex, (LPARAM) 5 * BYTES_PER_KB);

			nIndex = SendMessage (hCboxBufferSize, CB_ADDSTRING, 0, (LPARAM) "100 KB");
			SendMessage (hCboxBufferSize, CB_SETITEMDATA, nIndex, (LPARAM) 100 * BYTES_PER_KB);

			nIndex = SendMessage (hCboxBufferSize, CB_ADDSTRING, 0, (LPARAM) "500 KB");
			SendMessage (hCboxBufferSize, CB_SETITEMDATA, nIndex, (LPARAM) 500 * BYTES_PER_KB);

			nIndex = SendMessage (hCboxBufferSize, CB_ADDSTRING, 0, (LPARAM) "1 MB");
			SendMessage (hCboxBufferSize, CB_SETITEMDATA, nIndex, (LPARAM) 1 * BYTES_PER_MB);

			nIndex = SendMessage (hCboxBufferSize, CB_ADDSTRING, 0, (LPARAM) "5 MB");
			SendMessage (hCboxBufferSize, CB_SETITEMDATA, nIndex, (LPARAM) 5 * BYTES_PER_MB);

			nIndex = SendMessage (hCboxBufferSize, CB_ADDSTRING, 0, (LPARAM) "10 MB");
			SendMessage (hCboxBufferSize, CB_SETITEMDATA, nIndex, (LPARAM) 10 * BYTES_PER_MB);

			nIndex = SendMessage (hCboxBufferSize, CB_ADDSTRING, 0, (LPARAM) "50 MB");
			SendMessage (hCboxBufferSize, CB_SETITEMDATA, nIndex, (LPARAM) 50 * BYTES_PER_MB);

			nIndex = SendMessage (hCboxBufferSize, CB_ADDSTRING, 0, (LPARAM) "100 MB");
			SendMessage (hCboxBufferSize, CB_SETITEMDATA, nIndex, (LPARAM) 100 * BYTES_PER_MB);

			nIndex = SendMessage (hCboxBufferSize, CB_ADDSTRING, 0, (LPARAM) "200 MB");
			SendMessage (hCboxBufferSize, CB_SETITEMDATA, nIndex, (LPARAM) 200 * BYTES_PER_MB);

			nIndex = SendMessage (hCboxBufferSize, CB_ADDSTRING, 0, (LPARAM) "500 MB");
			SendMessage (hCboxBufferSize, CB_SETITEMDATA, nIndex, (LPARAM) 500 * BYTES_PER_MB);

			nIndex = SendMessage (hCboxBufferSize, CB_ADDSTRING, 0, (LPARAM) "1 GB");
			SendMessage (hCboxBufferSize, CB_SETITEMDATA, nIndex, (LPARAM) 1 * BYTES_PER_GB);

			SendMessage (hCboxBufferSize, CB_SETCURSEL, 3, 0);		// Default size

			return 1;
		}
		break;

	case WM_COMMAND:
	case WM_NOTIFY:

		if (lw == IDC_BENCHMARK_SORT_METHOD)
		{
			nIndex = SendMessage (hCboxSortMethod, CB_GETCURSEL, 0, 0);
			if (nIndex != benchmarkSortMethod)
			{
				benchmarkSortMethod = nIndex;
				DisplayBenchmarkResults (hwndDlg);
			}
		}

		if (lw == ID_PERFORM_BENCHMARK)
		{
			nIndex = SendMessage (hCboxBufferSize, CB_GETCURSEL, 0, 0);
			benchmarkBufferSize = SendMessage (hCboxBufferSize, CB_GETITEMDATA, nIndex, 0);

			if (PerformBenchmark(hwndDlg) == FALSE)
			{
				EndDialog (hwndDlg, IDCLOSE);
			}
			return 0;
		}
		if (lw == IDCLOSE)
		{
			EndDialog (hwndDlg, IDCLOSE);
			return 0;
		}
		return 0;

		break;

	case WM_CLOSE:
		EndDialog (hwndDlg, IDCLOSE);
		return 0;

		break;

	}

	return 0;
}
#endif	// #ifndef SETUP


BOOL CheckCapsLock (HWND hwnd, BOOL quiet)
{
	if ((GetKeyState(VK_CAPITAL) & 1) != 0)	
	{
		if (!quiet)
		{
			MessageBox (hwnd, getstr (IDS_CAPSLOCK_ON), lpszTitle, MB_ICONEXCLAMATION);
		}
		return TRUE;
	}
	return FALSE;
}


BOOL CheckPasswordLength (HWND hwndDlg, HWND hwndItem)			
{
	if (GetWindowTextLength (hwndItem) < PASSWORD_LEN_WARNING)
	{
		if (MessageBox (hwndDlg, getstr (IDS_PASSWORD_LENGTH_WARNING), lpszTitle, MB_YESNO|MB_ICONWARNING|MB_DEFBUTTON2) != IDYES)
			return FALSE;
	}
	return TRUE;
}


int GetFirstAvailableDrive ()
{
	DWORD dwUsedDrives = GetLogicalDrives();
	int i;

	for (i = 3; i < 26; i++)
	{
		if (!(dwUsedDrives & 1 << i))
			return i;
	}

	return -1;
}


int GetLastAvailableDrive ()
{
	DWORD dwUsedDrives = GetLogicalDrives();
	int i;

	for (i = 25; i > 2; i--)
	{
		if (!(dwUsedDrives & 1 << i))
			return i;
	}

	return -1;
}


BOOL IsDriveAvailable (int driveNo)
{
	return (GetLogicalDrives() & (1 << driveNo)) == 0;
}


int DriverUnmountVolume (HWND hwndDlg, int nDosDriveNo, BOOL forced)
{
	UNMOUNT_STRUCT unmount;
	DWORD dwResult;

	BOOL bResult;
	
	unmount.nDosDriveNo = nDosDriveNo;
	unmount.ignoreOpenFiles = forced;

	bResult = DeviceIoControl (hDriver, UNMOUNT, &unmount,
		sizeof (unmount), &unmount, sizeof (unmount), &dwResult, NULL);

	if (bResult == FALSE)
	{
		handleWin32Error (hwndDlg);
		return 1;
	}

	return unmount.nReturnCode;
}


void BroadcastDeviceChange (WPARAM message, int nDosDriveNo, DWORD driveMap)
{
	DEV_BROADCAST_VOLUME dbv;
	char root[] = {0, ':', '\\', 0 };
	DWORD dwResult;
	LONG event = 0;
	int i;

	if (message == DBT_DEVICEARRIVAL) event = SHCNE_DRIVEADD;
	if (message == DBT_DEVICEREMOVECOMPLETE) event = SHCNE_DRIVEREMOVED;

	if (driveMap == 0)
	{
		root[0] = nDosDriveNo + 'A';
		SHChangeNotify(event, SHCNF_PATH, root, NULL);
	}
	else
	{
		for (i = 0; i < 26; i++)
		{
			if (driveMap & (1 << i))
			{
				root[0] = i + 'A';
				SHChangeNotify(event, SHCNF_PATH, root, NULL);
			}
		}
	}

	dbv.dbcv_size = sizeof(dbv); 
	dbv.dbcv_devicetype = DBT_DEVTYP_VOLUME; 
	dbv.dbcv_reserved = 0;
	dbv.dbcv_unitmask = (driveMap != 0) ? driveMap : (1 << nDosDriveNo);
	dbv.dbcv_flags = 0; 

	SendMessageTimeout (HWND_BROADCAST, WM_DEVICECHANGE, message, (LPARAM)(&dbv), 0, 500, &dwResult);
}


// Returns:
// -1 = user aborted mount / error
// 0  = mount failed
// 1  = mount OK
// 2  = mount OK in shared mode

int MountVolume (HWND hwndDlg,
				 int driveNo,
				 char *volumePath,
				 char *szPassword,
				 BOOL cachePassword,
				 BOOL sharedAccess,
				 MountOptions *mountOptions,
				 BOOL quiet)
{
	MOUNT_STRUCT driver;
	DWORD dwResult;
	BOOL bResult, bDevice;

	if (IsMountedVolume (volumePath))
	{
		if (!quiet)
			MessageBox(0, getstr (IDS_ALREADY_MOUNTED), lpszTitle, MB_ICONASTERISK);
		return -1;
	}

	if (!IsDriveAvailable (driveNo))
		return -1;

	// If using cached passwords, check cache status first
	if (szPassword[0] == 0 && IsPasswordCacheEmpty ())
		return 0;

	ZeroMemory (&driver, sizeof (driver));
	driver.bExclusiveAccess = sharedAccess ? FALSE : TRUE;
retry:
	driver.nDosDriveNo = driveNo;
	driver.bCache = cachePassword;
	driver.time = time (NULL);
	driver.nPasswordLen = strlen (szPassword);
	strcpy (driver.szPassword, szPassword);
	driver.bMountReadOnly = mountOptions->ReadOnly;
	driver.bMountRemovable = mountOptions->Removable;
	driver.bMountManager = TRUE;

	// Windows 2000 mount manager causes problems with remounted volumes
	if (CurrentOSMajor == 5 && CurrentOSMinor == 0)
		driver.bMountManager = FALSE;

	CreateFullVolumePath ((char *) driver.wszVolume, volumePath, &bDevice);

	if (nCurrentOS == WIN_NT)
		ToUNICODE ((char *) driver.wszVolume);

	bResult = DeviceIoControl (hDriver, MOUNT, &driver,
		sizeof (driver), &driver, sizeof (driver), &dwResult, NULL);

	burn (&driver.szPassword, sizeof (driver.szPassword));

	if (bResult == FALSE)
	{
		// Volume already open by another process
		if (GetLastError() == ERROR_SHARING_VIOLATION)
		{
			if (driver.bExclusiveAccess == FALSE)
			{
				if (!quiet)
					MessageBox (hwndDlg, getstr (bDevice ? IDS_DEVICE_IN_USE_FAILED : IDS_FILE_IN_USE_FAILED),
						lpszTitle, MB_ICONSTOP);

				return -1;
			}
			else
			{
				if (quiet)
				{
					driver.bExclusiveAccess = FALSE;
					goto retry;
				}

				// Ask user 
				if (IDYES == MessageBox (hwndDlg, getstr (bDevice ? IDS_DEVICE_IN_USE : IDS_FILE_IN_USE),
					lpszTitle, MB_YESNO | MB_DEFBUTTON2 | MB_ICONEXCLAMATION))
				{
					driver.bExclusiveAccess = FALSE;
					goto retry;
				}
			}

			return -1;
		}

		if (!quiet)
			handleWin32Error (hwndDlg);

		return -1;
	}

	if (driver.nReturnCode != 0)
	{
		// If using cached passwords, do not report wrong password
		if (szPassword[0] == 0 && driver.nReturnCode == ERR_PASSWORD_WRONG)
			return 0;

		if (!quiet)	handleError (hwndDlg, driver.nReturnCode);

		return 0;
	}

	BroadcastDeviceChange (DBT_DEVICEARRIVAL, driveNo, 0);

	if (driver.bExclusiveAccess == FALSE)
		return 2;

	return 1;
}


BOOL UnmountVolume (HWND hwndDlg , int nDosDriveNo, BOOL forceUnmount)
{
	int result;
	BOOL forced = forceUnmount;
	int dismountMaxRetries = UNMOUNT_MAX_AUTO_RETRIES;

	//BroadcastDeviceChange (DBT_DEVICEREMOVEPENDING, nDosDriveNo);

retry:
	do
	{
		result = DriverUnmountVolume (hwndDlg, nDosDriveNo, forced);

		if (result == ERR_FILES_OPEN)
			Sleep (UNMOUNT_AUTO_RETRY_DELAY);
		else
			break;

	} while (--dismountMaxRetries > 0);

	if (result != 0)
	{
		if (result == ERR_FILES_OPEN)
		{
			if (IDYES == MessageBox (hwndDlg, getstr (IDS_UNMOUNT_LOCK_FAILED),
				lpszTitle, MB_YESNO | MB_DEFBUTTON2 | MB_ICONEXCLAMATION))
			{
				forced = TRUE;
				goto retry;
			}

			return FALSE;
		}

		MessageBox (hwndDlg, getstr (IDS_UNMOUNT_FAILED),
				lpszTitle, MB_ICONERROR);

		return FALSE;
	} 
	
	BroadcastDeviceChange (DBT_DEVICEREMOVECOMPLETE, nDosDriveNo, 0);

	return TRUE;
}


BOOL IsPasswordCacheEmpty (void)
{
	DWORD dw;
	return !DeviceIoControl (hDriver, CACHE_STATUS, 0, 0, 0, 0, &dw, 0);
}

BOOL IsMountedVolume (char *volname)
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


BOOL IsAdmin (void)
{
	HANDLE hAccessToken;
	UCHAR InfoBuffer[1024];
	PTOKEN_GROUPS ptgGroups = (PTOKEN_GROUPS) InfoBuffer;
	DWORD dwInfoBufferSize;
	PSID psidAdministrators;
	SID_IDENTIFIER_AUTHORITY siaNtAuthority = SECURITY_NT_AUTHORITY;
	BOOL bSuccess;
	UINT x;

	if (!OpenThreadToken (GetCurrentThread (), TOKEN_QUERY, TRUE,
			      &hAccessToken))
	{
		if (GetLastError ()!= ERROR_NO_TOKEN)
			return FALSE;

		/* Retry against process token if no thread token exists */
		if (!OpenProcessToken (GetCurrentProcess (), TOKEN_QUERY,
				       &hAccessToken))
			return FALSE;
	}

	bSuccess = GetTokenInformation (hAccessToken, TokenGroups, InfoBuffer,
					1024, &dwInfoBufferSize);

	CloseHandle (hAccessToken);

	if (!bSuccess)
		return FALSE;

	if (!AllocateAndInitializeSid (&siaNtAuthority, 2,
				       SECURITY_BUILTIN_DOMAIN_RID,
				       DOMAIN_ALIAS_RID_ADMINS,
				       0, 0, 0, 0, 0, 0,
				       &psidAdministrators))
		return FALSE;
 
	/* Assume that we don't find the admin SID. */
	bSuccess = FALSE;

	for (x = 0; x < ptgGroups->GroupCount; x++)
	{
		if (EqualSid (psidAdministrators, ptgGroups->Groups[x].Sid))
		{
			bSuccess = TRUE;
			break;
		}

	}

	FreeSid (psidAdministrators);
	return bSuccess;
}


BOOL ResolveSymbolicLink (PWSTR symLinkName, PWSTR targetName)
{
	BOOL bResult;
	DWORD dwResult;
	RESOLVE_SYMLINK_STRUCT resolve;

	memset (&resolve, 0, sizeof(resolve));
	wcscpy ((PWSTR) &resolve.symLinkName, symLinkName);

	bResult = DeviceIoControl (hDriver, RESOLVE_SYMLINK, &resolve,
		sizeof (resolve), &resolve, sizeof (resolve), &dwResult,
		NULL);

	wcscpy (targetName, (PWSTR) &resolve.targetName);

	return bResult;
}


// Returns drive letter number assigned to device (-1 if none)
int GetDiskDeviceDriveLetter (PWSTR deviceName)
{
	int i;
	WCHAR link[MAX_PATH];
	WCHAR target[MAX_PATH];
	WCHAR device[MAX_PATH];

	if (!ResolveSymbolicLink (deviceName, device))
		wcscpy (device, deviceName);

	for (i = 0; i < 26; i++)
	{
		WCHAR drive[] = { i + 'A', ':', 0 };

		wcscpy (link, L"\\DosDevices\\");
		wcscat (link, drive);

		ResolveSymbolicLink (link, target);

		if (wcscmp (device, target) == 0)
			return i;
	}

	return -1;
}


HANDLE DismountDrive (int driveNo)
{
	char volMountName[32];
	char dosName[3];
	DWORD dwResult;
	BOOL bResult;
	HANDLE hVolume;

	dosName[0] = (char) (driveNo + 'A');
	dosName[1] = ':';
	dosName[2] = 0;

	sprintf (volMountName, "\\\\.\\%s", dosName);

	hVolume = CreateFile (volMountName, GENERIC_READ | GENERIC_WRITE,
		FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);

	bResult = DeviceIoControl (hVolume, FSCTL_LOCK_VOLUME, NULL, 0, NULL, 0, &dwResult, NULL);
	bResult = DeviceIoControl (hVolume, FSCTL_DISMOUNT_VOLUME, NULL, 0, NULL, 0, &dwResult, NULL);

	return hVolume;
}

// System CopyFile() copies source file attributes (like FILE_ATTRIBUTE_ENCRYPTED)
// so we need to use our own copy function
BOOL TCCopyFile (char *sourceFileName, char *destinationFile)
{
	__int8 *buffer;
	HANDLE src, dst;
	FILETIME fileTime;
	DWORD bytesRead, bytesWritten;
	BOOL res;

	src = CreateFile (sourceFileName,
		GENERIC_READ,
		FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);

	if (src == INVALID_HANDLE_VALUE)
		return FALSE;

	dst = CreateFile (destinationFile,
		GENERIC_WRITE,
		0, NULL, CREATE_ALWAYS, 0, NULL);

	if (dst == INVALID_HANDLE_VALUE)
	{
		CloseHandle (src);
		return FALSE;
	}

	buffer = malloc (64 * 1024);
	if (!buffer)
	{
		CloseHandle (src);
		CloseHandle (dst);
		return FALSE;
	}

	while (res = ReadFile (src, buffer, 64 * 1024, &bytesRead, NULL))
	{
		if (bytesRead == 0)
		{
			res = 1;
			break;
		}

		if (!WriteFile (dst, buffer, bytesRead, &bytesWritten, NULL)
			|| bytesRead != bytesWritten)
		{
			res = 0;
			break;
		}
	}

	GetFileTime (src, NULL, NULL, &fileTime);
	SetFileTime (dst, NULL, NULL, &fileTime);

	CloseHandle (src);
	CloseHandle (dst);

	free (buffer);
	return res != 0;
}


BOOL IsNonInstallMode ()
{
	HANDLE fh;
	WIN32_FIND_DATA fd;
	char fileName[TC_MAX_PATH];

	GetSystemDirectory (fileName, sizeof (fileName));
	strcat (fileName, "\\Drivers\\truecrypt.sys");

	fh = FindFirstFile (fileName, &fd);

	if (fh == INVALID_HANDLE_VALUE)
		return TRUE;

	FindClose (fh);
	return FALSE;
}


BOOL WINAPI
MountOptionsDlgProc (HWND hwndDlg, UINT msg, WPARAM wParam, LPARAM lParam)
{
	static MountOptions *mountOptions;
	WORD lw = LOWORD (wParam);

	switch (msg)
	{
	case WM_INITDIALOG:
		{
			mountOptions = (MountOptions *) lParam;

			SetDefaultUserFont (hwndDlg);
		
			SendDlgItemMessage (hwndDlg, IDC_MOUNT_READONLY, BM_SETCHECK,
				mountOptions->ReadOnly ? BST_CHECKED : BST_UNCHECKED, 0);
			SendDlgItemMessage (hwndDlg, IDC_MOUNT_REMOVABLE, BM_SETCHECK,
				mountOptions->Removable ? BST_CHECKED : BST_UNCHECKED, 0);

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
			mountOptions->ReadOnly = IsButtonChecked (GetDlgItem (hwndDlg, IDC_MOUNT_READONLY));
			mountOptions->Removable = IsButtonChecked (GetDlgItem (hwndDlg, IDC_MOUNT_REMOVABLE));

			EndDialog (hwndDlg, lw);
			return 1;
		}
		return 0;
	}

	return 0;
}
