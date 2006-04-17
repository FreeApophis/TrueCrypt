/* Legal Notice: The source code contained in this file has been derived from
   the source code of Encryption for the Masses 2.02a, which is Copyright (c)
   1998-99 Paul Le Roux and which is covered by the 'License Agreement for
   Encryption for the Masses'. Modifications and additions to that source code
   contained in this file are Copyright (c) 2004-2006 TrueCrypt Foundation and
   Copyright (c) 2004 TrueCrypt Team, and are covered by TrueCrypt License 2.0
   the full text of which is contained in the file License.txt included in
   TrueCrypt binary and source code distribution archives.  */

#include "Tcdefs.h"

#include <dbt.h>
#include <fcntl.h>
#include <io.h>
#include <shlobj.h>
#include <sys/stat.h>
#include <stdlib.h>
#include <time.h>

#include "Resource.h"

#include "Apidrvr.h"
#include "Crypto.h"
#include "Dictionary.h"
#include "Dlgcode.h"
#include "Endian.h"
#include "Language.h"
#include "Keyfiles.h"
#include "Pkcs5.h"
#include "Random.h"
#include "Registry.h"
#include "Tests.h"
#include "Volumes.h"
#include "Xml.h"

char szHelpFile[TC_MAX_PATH];
char szHelpFile2[TC_MAX_PATH];
HFONT hFixedDigitFont = NULL;
HFONT hBoldFont = NULL;
HFONT hTitleFont = NULL;
HFONT hFixedFont = NULL;

HFONT hUserFont = NULL;
HFONT hUserUnderlineFont = NULL;
HFONT hUserBoldFont = NULL;
HFONT hUserUnderlineBoldFont = NULL;

HWND MainDlg = NULL;
wchar_t *lpszTitle = NULL;

BOOL Silent = FALSE;
BOOL bPreserveTimestamp = TRUE;

int nCurrentOS = 0;
int CurrentOSMajor = 0;
int CurrentOSMinor = 0;

/* Globals used by Mount and Format (separately per instance) */ 
BOOL	KeyFilesEnable = FALSE;
KeyFile	*FirstKeyFile = NULL;
KeyFilesDlgParam		defaultKeyFilesParam;

/* Handle to the device driver */
HANDLE hDriver = INVALID_HANDLE_VALUE;
HINSTANCE hInst = NULL;
HANDLE hMutex = NULL;
HCURSOR hCursor = NULL;

ATOM hDlgClass, hSplashClass;

static FILE *ConfigFileHandle;
static char *ConfigBuffer;

#define RANDOM_POOL_DISPLAY_REFRESH_INTERVAL	30

/* Windows dialog class */
#define WINDOWS_DIALOG_CLASS "#32770"

/* Custom class names */
#define TC_DLG_CLASS "CustomDlg"
#define TC_SPLASH_CLASS "SplashDlg"

/* Benchmarks */

#ifndef SETUP

#define BENCHMARK_MAX_ITEMS 100
#define BENCHMARK_DEFAULT_BUF_SIZE	BYTES_PER_MB
#define HASH_FNC_BENCHMARKS	FALSE 	// For development purposes only. Must be FALSE when building a public release.
#define PKCS5_BENCHMARKS	FALSE	// For development purposes only. Must be FALSE when building a public release.
#if PKCS5_BENCHMARKS && HASH_FNC_BENCHMARKS
#error PKCS5_BENCHMARKS and HASH_FNC_BENCHMARKS are both TRUE (at least one of them should be FALSE).
#endif

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
	if (hFixedDigitFont != NULL)
		DeleteObject (hFixedDigitFont);
	if (hBoldFont != NULL)
		DeleteObject (hBoldFont);
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

	if (ConfigBuffer != NULL)
	{
		free (ConfigBuffer);
		ConfigBuffer = NULL;
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


void
AbortProcess (char *stringId)
{
	MessageBeep (MB_ICONEXCLAMATION);
	MessageBoxW (NULL, GetString (stringId), lpszTitle, ICON_HAND);
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
	AbortProcess ("OUTOFMEMORY");
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
	PWSTR lpMsgBuf;
	DWORD dwError = GetLastError ();

	if (Silent) return dwError;

	FormatMessageW (
		FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM,
			      NULL,
			      dwError,
			      MAKELANGID (LANG_NEUTRAL, SUBLANG_DEFAULT),	/* Default language */
			      (PWSTR) &lpMsgBuf,
			      0,
			      NULL
	    );

	MessageBoxW (hwndDlg, lpMsgBuf, lpszTitle, ICON_HAND);
	LocalFree (lpMsgBuf);

	// Device not ready
	if (dwError == ERROR_NOT_READY)
		CheckSystemAutoMount();

	return dwError;
}

BOOL
translateWin32Error (wchar_t *lpszMsgBuf, int nSizeOfBuf)
{
	DWORD dwError = GetLastError ();

	if (FormatMessageW (FORMAT_MESSAGE_FROM_SYSTEM, NULL, dwError,
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
			char szTmp[100];

			LocalizeDialog (hwndDlg, "IDD_ABOUT_DLG");

			SetWindowText (GetDlgItem (hwndDlg, IDC_HOMEPAGE), "www.truecrypt.org");
			SendMessage (GetDlgItem (hwndDlg, IDC_HOMEPAGE), WM_SETFONT, (WPARAM) hUserUnderlineFont, 0);

			// Version
			SendMessage (GetDlgItem (hwndDlg, IDT_ABOUT_VERSION), WM_SETFONT, (WPARAM) hUserBoldFont, 0);
			sprintf (szTmp, "TrueCrypt %s", VERSION_STRING);
#ifdef _DEBUG
			strcat (szTmp, "  (debug)");
#endif
			SetDlgItemText (hwndDlg, IDT_ABOUT_VERSION, szTmp);

			// Credits
			SendMessage (GetDlgItem (hwndDlg, IDC_ABOUT_CREDITS), WM_SETFONT, (WPARAM) hUserFont, (LPARAM) 0);
			SetWindowText (GetDlgItem (hwndDlg, IDC_ABOUT_CREDITS), "\
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
Paulo Barreto, Brian Gladman, Wei Dai, Peter Gutmann, and many others.\r\n\r\n\
Portions of this software:\r\n\
Copyright \xA9 2004-2006 TrueCrypt Foundation. All Rights Reserved.\r\n\
Copyright \xA9 1998-2000 Paul Le Roux. All Rights Reserved.\r\n\
Copyright \xA9 2004 TrueCrypt Team. All Rights Reserved.\r\n\
Copyright \xA9 1999-2005 Dr. Brian Gladman. All Rights Reserved.\r\n\
Copyright \xA9 1995-1997 Eric Young. All Rights Reserved.\r\n\
Copyright \xA9 2001 Markus Friedl. All Rights Reserved.\r\n\r\n\
A TrueCrypt Foundation Release");

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
			sprintf (tmpstr, "http://www.truecrypt.org/applink.php?version=%s", VERSION_STRING);
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
	NONCLIENTMETRICSW metric;
	static BOOL aboutMenuAppended = FALSE;

	HDC hDC;
	int nHeight;
	LOGFONTW lf;
	HMENU hMenu;
	Font *font;

	hDC = GetDC (hwndDlg);

	// Normal
	font = GetFont ("font_normal");

	metric.cbSize = sizeof (metric);
	SystemParametersInfoW (SPI_GETNONCLIENTMETRICS, sizeof(metric), &metric, 0);

	metric.lfMessageFont.lfHeight = !font ? -11 : -font->Size;
	metric.lfMessageFont.lfWidth = 0;

	if (font && wcscmp (font->FaceName, L"default") != 0)
		wcsncpy ((WCHAR *)metric.lfMessageFont.lfFaceName,
		font->FaceName, sizeof (metric.lfMessageFont.lfFaceName)/2);

	hUserFont = CreateFontIndirectW (&metric.lfMessageFont);

	metric.lfMessageFont.lfUnderline = TRUE;
	hUserUnderlineFont = CreateFontIndirectW (&metric.lfMessageFont);

	metric.lfMessageFont.lfUnderline = FALSE;
	metric.lfMessageFont.lfWeight = FW_BOLD;
	hUserBoldFont = CreateFontIndirectW (&metric.lfMessageFont);

	metric.lfMessageFont.lfUnderline = TRUE;
	metric.lfMessageFont.lfWeight = FW_BOLD;
	hUserUnderlineBoldFont = CreateFontIndirectW (&metric.lfMessageFont);

	// Fixed digits
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
	wcscpy (lf.lfFaceName, L"Courier New");
	hFixedDigitFont = CreateFontIndirectW (&lf);
	if (hFixedDigitFont == NULL)
	{
		handleWin32Error (hwndDlg);
		AbortProcess ("NOFONT");
	}

	// Bold
	font = GetFont ("font_bold");

	nHeight = -(((!font ? 10 : font->Size) * GetDeviceCaps (hDC, LOGPIXELSY)) / 72);
	lf.lfHeight = nHeight;
	lf.lfWeight = FW_BLACK;
	wcsncpy (lf.lfFaceName, !font ? L"Arial" : font->FaceName, sizeof (lf.lfFaceName)/2);
	hBoldFont = CreateFontIndirectW (&lf);
	if (hBoldFont == NULL)
	{
		handleWin32Error (hwndDlg);
		AbortProcess ("NOFONT");
	}

	// Title
	font = GetFont ("font_title");

	nHeight = -(((!font ? 16 : font->Size) * GetDeviceCaps (hDC, LOGPIXELSY)) / 72);
	lf.lfHeight = nHeight;
	lf.lfWeight = FW_REGULAR;
	wcsncpy (lf.lfFaceName, !font ? L"Times New Roman" : font->FaceName, sizeof (lf.lfFaceName)/2);
	hTitleFont = CreateFontIndirectW (&lf);
	if (hTitleFont == NULL)
	{
		handleWin32Error (hwndDlg);
		AbortProcess ("NOFONT");
	}

	// Fixed
	font = GetFont ("font_fixed");

	nHeight = -(((!font ? 9 : font->Size) * GetDeviceCaps (hDC, LOGPIXELSY)) / 72);
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
	wcsncpy (lf.lfFaceName, !font ? L"Lucida Console" : font->FaceName, sizeof (lf.lfFaceName)/2);
	hFixedFont = CreateFontIndirectW (&lf);
	if (hFixedFont == NULL)
	{
		handleWin32Error (hwndDlg);
		AbortProcess ("NOFONT");
	}

	if (!aboutMenuAppended)
	{
		hMenu = GetSystemMenu (hwndDlg, FALSE);
		AppendMenu (hMenu, MF_SEPARATOR, 0, NULL);
		AppendMenuW (hMenu, MF_ENABLED | MF_STRING, IDC_ABOUT, GetString ("ABOUTBOX"));

		aboutMenuAppended = TRUE;
	}
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
RedTick (HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
  if (uMsg == WM_CREATE)
    {
    }
  else if (uMsg == WM_DESTROY)
    {
    }
  else if (uMsg == WM_TIMER)
    {
    }
  else if (uMsg == WM_PAINT)
    {
      PAINTSTRUCT tmp;
      HPEN hPen;
      HDC hDC;
      BOOL bEndPaint;
      RECT Rect;

      if (GetUpdateRect (hwnd, NULL, FALSE))
	{
	  hDC = BeginPaint (hwnd, &tmp);
	  bEndPaint = TRUE;
	  if (hDC == NULL)
	    return DefWindowProc (hwnd, uMsg, wParam, lParam);
	}
      else
	{
	  hDC = GetDC (hwnd);
	  bEndPaint = FALSE;
	}

      GetClientRect (hwnd, &Rect);

      hPen = CreatePen (PS_SOLID, 2, RGB (0, 255, 0));
      if (hPen != NULL)
	{
	  HGDIOBJ hObj = SelectObject (hDC, hPen);
	  WORD bx = LOWORD (GetDialogBaseUnits ());
	  WORD by = HIWORD (GetDialogBaseUnits ());

	  MoveToEx (hDC, (Rect.right - Rect.left) / 2, Rect.bottom, NULL);
	  LineTo (hDC, Rect.right, Rect.top);
	  MoveToEx (hDC, (Rect.right - Rect.left) / 2, Rect.bottom, NULL);

	  LineTo (hDC, (3 * bx) / 4, (2 * by) / 8);

	  SelectObject (hDC, hObj);
	  DeleteObject (hPen);
	}

      if (bEndPaint)
	EndPaint (hwnd, &tmp);
      else
	ReleaseDC (hwnd, hDC);

      return TRUE;
    }

  return DefWindowProc (hwnd, uMsg, wParam, lParam);
}

BOOL
RegisterRedTick (HINSTANCE hInstance)
{
  WNDCLASS wc;
  ULONG rc;

  memset(&wc, 0 , sizeof wc);

  wc.style = CS_HREDRAW | CS_VREDRAW;
  wc.cbClsExtra = 0;
  wc.cbWndExtra = 4;
  wc.hInstance = hInstance;
  wc.hIcon = LoadIcon (NULL, IDI_APPLICATION);
  wc.hCursor = NULL;
  wc.hbrBackground = GetStockObject (LTGRAY_BRUSH);
  wc.lpszClassName = "REDTICK";
  wc.lpfnWndProc = &RedTick; 
  
  rc = (ULONG) RegisterClass (&wc);

  return rc == 0 ? FALSE : TRUE;
}

BOOL
UnregisterRedTick (HINSTANCE hInstance)
{
  return UnregisterClass ("REDTICK", hInstance);
}

LRESULT CALLBACK
SplashDlgProc (HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
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
void
AddComboPair (HWND hComboBox, char *lpszItem, int value)
{
	LPARAM nIndex;

	nIndex = SendMessage (hComboBox, CB_ADDSTRING, 0, (LPARAM) lpszItem);
	nIndex = SendMessage (hComboBox, CB_SETITEMDATA, nIndex, (LPARAM) value);
}

void
AddComboPairW (HWND hComboBox, wchar_t *lpszItem, int value)
{
	LPARAM nIndex;

	nIndex = SendMessageW (hComboBox, CB_ADDSTRING, 0, (LPARAM) lpszItem);
	nIndex = SendMessage (hComboBox, CB_SETITEMDATA, nIndex, (LPARAM) value);
}

void
SelectAlgo (HWND hComboBox, int *algo_id)
{
	LPARAM nCount = SendMessage (hComboBox, CB_GETCOUNT, 0, 0);
	LPARAM x, i;

	for (i = 0; i < nCount; i++)
	{
		x = SendMessage (hComboBox, CB_GETITEMDATA, i, 0);
		if (x == (LPARAM) * algo_id)
		{
			SendMessage (hComboBox, CB_SETCURSEL, i, 0);
			return;
		}
	}

	/* Something went wrong ; couldn't find the requested algo id so we drop
	   back to a default */

	*algo_id = SendMessage (hComboBox, CB_GETITEMDATA, 0, 0);

	SendMessage (hComboBox, CB_SETCURSEL, 0, 0);

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


LONG __stdcall ExceptionHandler (EXCEPTION_POINTERS *ep)
{
	wchar_t msg[1024];
	char url[1024];

	SetUnhandledExceptionFilter (NULL);

	sprintf (url, "http://www.truecrypt.org/applink.php?version=%s&dest=err-report&app=%s&err=%x&addr=%x"
		, VERSION_STRING
#ifdef TCMOUNT
		,"main"
#endif
#ifdef VOLFORMAT
		,"format"
#endif
#ifdef SETUP
		,"setup"
#endif
		, ep->ExceptionRecord->ExceptionCode
		, ep->ExceptionRecord->ExceptionAddress);

	wsprintfW (msg, GetString ("EXCEPTION_REPORT"), url);
	if (IDYES == MessageBoxW (MainDlg, msg,
		GetString ("EXCEPTION_REPORT_TITLE"),
		MB_ICONERROR | MB_YESNO | MB_DEFBUTTON1 | MB_SETFOREGROUND | MB_TOPMOST))
		ShellExecute (NULL, "open", (LPCTSTR) url, NULL, NULL, SW_SHOWNORMAL);
	else
		UnhandledExceptionFilter (ep);

	return EXCEPTION_EXECUTE_HANDLER;
}


/* InitApp - initialize the application, this function is called once in the
   applications WinMain function, but before the main dialog has been created */
void
InitApp (HINSTANCE hInstance)
{
	WNDCLASS wc;
	OSVERSIONINFO os;
	char langId[6];

	/* Save the instance handle for later */
	hInst = hInstance;

	SetPreferredLangId (ConfigReadString ("Language", "", langId, sizeof (langId)));
	
	if (langId[0] == 0)
		DialogBoxParamW (hInst, MAKEINTRESOURCEW (IDD_LANGUAGE), NULL,
			(DLGPROC) LanguageDlgProc, (LPARAM) 1);

	LoadLanguageFile ();

	SetUnhandledExceptionFilter (ExceptionHandler);

	/* Pull down the windows version */
	os.dwOSVersionInfoSize = sizeof (OSVERSIONINFO);

	if (GetVersionEx (&os) == FALSE)
		AbortProcess ("NO_OS_VER");

	CurrentOSMajor = os.dwMajorVersion;
	CurrentOSMinor = os.dwMinorVersion;

	if (os.dwPlatformId == VER_PLATFORM_WIN32_NT && CurrentOSMajor == 5 && CurrentOSMinor == 0)
		nCurrentOS = WIN_2000;
	else if (os.dwPlatformId == VER_PLATFORM_WIN32_NT && CurrentOSMajor == 5 && CurrentOSMinor == 1)
		nCurrentOS = WIN_XP;
	else if (os.dwPlatformId == VER_PLATFORM_WIN32_NT && CurrentOSMajor == 5 && CurrentOSMinor == 2)
		nCurrentOS = WIN_XP64_OR_2003;
	else if (os.dwPlatformId == VER_PLATFORM_WIN32_NT && CurrentOSMajor == 6 && CurrentOSMinor == 0)
		nCurrentOS = WIN_VISTA;
	else if (os.dwPlatformId == VER_PLATFORM_WIN32_NT && CurrentOSMajor == 6 && CurrentOSMinor > 0)
		nCurrentOS = WIN_AFTER_VISTA;
	else if (os.dwPlatformId == VER_PLATFORM_WIN32_NT && CurrentOSMajor >= 7)
		nCurrentOS = WIN_AFTER_VISTA;
	else if (os.dwPlatformId == VER_PLATFORM_WIN32_NT && CurrentOSMajor == 4)
		nCurrentOS = WIN_NT4;
	else if (os.dwPlatformId == VER_PLATFORM_WIN32_WINDOWS && os.dwMajorVersion == 4 && os.dwMinorVersion == 0)
		nCurrentOS = WIN_95;
	else if (os.dwPlatformId == VER_PLATFORM_WIN32_WINDOWS && os.dwMajorVersion == 4 && os.dwMinorVersion == 10)
		nCurrentOS = WIN_98;
	else if (os.dwPlatformId == VER_PLATFORM_WIN32_WINDOWS && os.dwMajorVersion == 4 && os.dwMinorVersion == 90)
		nCurrentOS = WIN_ME;
	else if (os.dwPlatformId == VER_PLATFORM_WIN32s)
		nCurrentOS = WIN_31;
	else
		nCurrentOS = WIN_UNKNOWN;

	// OS version check
	if (CurrentOSMajor < 5)
	{
		MessageBoxW (NULL, GetString ("UNSUPPORTED_OS"), lpszTitle, MB_ICONSTOP);
		exit (1);
	}
	else
	{
		OSVERSIONINFOEX osEx;

		// Service pack check
		osEx.dwOSVersionInfoSize = sizeof (OSVERSIONINFOEX);
		if (GetVersionEx ((LPOSVERSIONINFOA) &osEx) != 0)
		{
			switch (nCurrentOS)
			{
			case WIN_2000:
				if (osEx.wServicePackMajor < 3)
					Warning ("LARGE_IDE_WARNING_2K");
				break;
			case WIN_XP:
				if (osEx.wServicePackMajor < 1)
					Warning ("LARGE_IDE_WARNING_XP");
				break;
			}
		}
	}

	/* Get the attributes for the standard dialog class */
	if ((GetClassInfo (hInst, WINDOWS_DIALOG_CLASS, &wc)) == 0)
		AbortProcess ("INIT_REGISTER");

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
		AbortProcess ("INIT_REGISTER");

	wc.lpszClassName = TC_SPLASH_CLASS;
	wc.lpfnWndProc = &SplashDlgProc;
	wc.hCursor = LoadCursor (NULL, IDC_ARROW);
	wc.cbWndExtra = DLGWINDOWEXTRA;

	hSplashClass = RegisterClass (&wc);
	if (hSplashClass == 0)
		AbortProcess ("INIT_REGISTER");

	InitHelpFileName ();
}

void InitHelpFileName (void)
{
	char *lpszTmp;

	GetModuleFileName (NULL, szHelpFile, sizeof (szHelpFile));
	lpszTmp = strrchr (szHelpFile, '\\');
	if (lpszTmp)
	{
		char szTemp[TC_MAX_PATH];

		// Primary file name
		if (strcmp (GetPreferredLangId(), "en") == 0
			|| GetPreferredLangId() == NULL)
		{
			strcpy (++lpszTmp, "TrueCrypt User Guide.pdf");
		}
		else
		{
			sprintf (szTemp, "TrueCrypt User Guide.%s.pdf", GetPreferredLangId());
			strcpy (++lpszTmp, szTemp);
		}

		// Secondary file name (used when localized documentation is not found).
		GetModuleFileName (NULL, szHelpFile2, sizeof (szHelpFile2));
		lpszTmp = strrchr (szHelpFile2, '\\');
		if (lpszTmp)
		{
			strcpy (++lpszTmp, "TrueCrypt User Guide.pdf");
		}
	}
}

BOOL
OpenDevice (char *lpszPath, OPEN_TEST_STRUCT * driver)
{
	DWORD dwResult;
	BOOL bResult;

	strcpy ((char *) &driver->wszFileName[0], lpszPath);
	ToUNICODE ((char *) &driver->wszFileName[0]);

	bResult = DeviceIoControl (hDriver, OPEN_TEST,
				   driver, sizeof (OPEN_TEST_STRUCT),
				   NULL, 0,
				   &dwResult, NULL);

	if (bResult == FALSE)
	{
		dwResult = GetLastError ();

		if (dwResult == ERROR_SHARING_VIOLATION)
			return TRUE;
		else
			return FALSE;
	}
		
	return TRUE;
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
			char szTmp[TC_MAX_PATH];
			wchar_t size[100] = {0}, partTypeStr[1024] = {0}, *partType = partTypeStr;
			OPEN_TEST_STRUCT driver;

			sprintf (szTmp, lpszRootPath, i, n);
			if (OpenDevice (szTmp, &driver))
			{
				int nDosLinkCreated;
				HANDLE dev;
				DWORD dwResult;
				BOOL bResult;
				PARTITION_INFORMATION diskInfo;
				DISK_GEOMETRY driveInfo;
				char szDosDevice[TC_MAX_PATH], szCFDevice[TC_MAX_PATH];

				drivePresent = TRUE;

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

				if (bResult)
				{

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
					case PARTITION_ENTRY_UNUSED:	partType = GetString ("EMPTY_UNUSED"); break;
					case PARTITION_XINT13_EXTENDED:
					case PARTITION_EXTENDED:		partType = L"Extended"; break;
					case PARTITION_HUGE:			wsprintfW (partTypeStr, L"%s (0x%02X)", GetString ("UNFORMATTED"), diskInfo.PartitionType); partType = partTypeStr; break;
					case PARTITION_FAT_12:			partType = L"FAT12"; break;
					case PARTITION_FAT_16:			partType = L"FAT16"; break;
					case PARTITION_FAT32:		
					case PARTITION_FAT32_XINT13:	partType = L"FAT32"; break;
					case 0x08:						partType = L"DELL (spanning)"; break;
					case 0x12:						partType = L"Config/diagnostics"; break;
					case 0x11:
					case 0x14:
					case 0x16:
					case 0x1b:
					case 0x1c:
					case 0x1e:						partType = L"Hidden FAT"; break;
					case PARTITION_IFS:				partType = L"NTFS"; break;
					case 0x17:						partType = L"Hidden NTFS"; break;
					case 0x3c:						partType = L"PMagic recovery"; break;
					case 0x3d:						partType = L"Hidden NetWare"; break;
					case 0x41:						partType = L"Linux/MINIX"; break;
					case 0x42:						partType = L"SFS/LDM/Linux Swap"; break;
					case 0x51:
					case 0x64:
					case 0x65:
					case 0x66:
					case 0x67:
					case 0x68:
					case 0x69:						partType = L"Novell"; break;
					case 0x55:						partType = L"EZ-Drive"; break;
					case PARTITION_OS2BOOTMGR:		partType = L"OS/2 BM"; break;
					case PARTITION_XENIX_1:
					case PARTITION_XENIX_2:			partType = L"Xenix"; break;
					case PARTITION_UNIX:			partType = L"UNIX"; break;
					case 0x74:						partType = L"Scramdisk"; break;
					case 0x78:						partType = L"XOSL FS"; break;
					case 0x80:
					case 0x81:						partType = L"MINIX"; break;
					case 0x82:						partType = L"Linux Swap"; break;
					case 0x43:
					case 0x83:						partType = L"Linux"; break;
					case 0xc2:
					case 0x93:						partType = L"Hidden Linux"; break;
					case 0x86:
					case 0x87:						partType = L"NTFS volume set"; break;
					case 0x9f:						partType = L"BSD/OS"; break;
					case 0xa0:
					case 0xa1:						partType = L"Hibernation"; break;
					case 0xa5:						partType = L"BSD"; break;
					case 0xa8:						partType = L"Mac OS-X"; break;
					case 0xa9:						partType = L"NetBSD"; break;
					case 0xab:						partType = L"Mac OS-X Boot"; break;
					case 0xb8:						partType = L"BSDI BSD/386 swap"; break;
					case 0xc3:						partType = L"Hidden Linux swap"; break;
					case 0xfb:						partType = L"VMware"; break;
					case 0xfc:						partType = L"VMware swap"; break;
					case 0xfd:						partType = L"Linux RAID"; break;
					case 0xfe:						partType = L"WinNT hidden"; break;
					default:						wsprintfW (partTypeStr, L"0x%02X", diskInfo.PartitionType); partType = partTypeStr; break;
					}

					GetSizeString (diskInfo.PartitionLength.QuadPart, size);
				}


				memset (&LvItem,0,sizeof(LvItem));
				LvItem.mask = LVIF_TEXT;   
				LvItem.iItem = line++;   

				// Device Name
				if (n == 0)
				{
					wchar_t s[1024];
					deviceSize = diskInfo.PartitionLength.QuadPart;
					wsprintfW (s, L"Harddisk %d:", i);
					ListItemAddW (hComboBox, LvItem.iItem, s);
				}
				else
				{
					LvItem.pszText = szTmp;
					SendMessage (hComboBox,LVM_INSERTITEM,0,(LPARAM)&LvItem);
				}

				// Size
				LvItem.iSubItem = 2;
				LvItem.pszText = (char *) size;
				SendMessageW (hComboBox,LVM_SETITEMW,0,(LPARAM)&LvItem); 

				// Device type removable
				if (n == 0 && removable)
				{
					ListSubItemSetW (hComboBox, LvItem.iItem, 3, GetString ("REMOVABLE"));
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
					ListSubItemSetW (hComboBox, LvItem.iItem, 3, partType);
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

BOOL WINAPI LegalNoticesDlgProc (HWND hwndDlg, UINT msg, WPARAM wParam, LPARAM lParam)
{
	WORD lw = LOWORD (wParam);
	if (lParam);		/* remove warning */

	switch (msg)
	{

	case WM_INITDIALOG:
		{
			LocalizeDialog (hwndDlg, "IDD_LEGAL_NOTICES_DLG");
			SetWindowText (GetDlgItem (hwndDlg, IDC_LEGAL_NOTICES), GetLegalNotices ());
			return 1;
		}

	case WM_COMMAND:
		if (lw == IDOK || lw == IDCANCEL)
		{
			EndDialog (hwndDlg, 0);
			return 1;
		}

		// Disallow modification
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


char * GetLegalNotices ()
{
	static char *resource;

	if (resource == NULL)
		resource = MapResource ("Text", IDR_LICENSE, NULL);

	return resource;
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
			LVCOLUMNW LvCol;
			HWND hList = GetDlgItem (hwndDlg, IDC_DEVICELIST);

			LocalizeDialog (hwndDlg, "IDD_RAWDEVICES_DLG");

			SendMessage (hList,LVM_SETEXTENDEDLISTVIEWSTYLE,0,
				LVS_EX_FULLROWSELECT|LVS_EX_HEADERDRAGDROP|LVS_EX_TWOCLICKACTIVATE|LVS_EX_LABELTIP 
				); 

			memset (&LvCol,0,sizeof(LvCol));               
			LvCol.mask = LVCF_TEXT|LVCF_WIDTH|LVCF_SUBITEM|LVCF_FMT;  
			LvCol.pszText = GetString ("DEVICE");
			LvCol.cx = 154;
			LvCol.fmt = LVCFMT_LEFT;
			SendMessage (hList,LVM_INSERTCOLUMNW,0,(LPARAM)&LvCol);

			LvCol.pszText = GetString ("DRIVE");  
			LvCol.cx = 49;           
			LvCol.fmt = LVCFMT_RIGHT;
			SendMessage (hList,LVM_INSERTCOLUMNW,1,(LPARAM)&LvCol);

			LvCol.pszText = GetString ("SIZE");  
			LvCol.cx = 66;           
			LvCol.fmt = LVCFMT_RIGHT;
			SendMessage (hList,LVM_INSERTCOLUMNW,2,(LPARAM)&LvCol);

			LvCol.pszText = GetString ("TYPE");  
			LvCol.cx = 112;
			LvCol.fmt = LVCFMT_LEFT;
			SendMessage (hList,LVM_INSERTCOLUMNW,3,(LPARAM)&LvCol);

			nCount = GetAvailableFixedDisks (hList, "\\Device\\Harddisk%d\\Partition%d");
			nCount += GetAvailableRemovables (hList, "\\Device\\Floppy%d");

			if (nCount == 0)
			{
				handleWin32Error (hwndDlg);
				MessageBoxW (hwndDlg, GetString ("RAWDEVICES"), lpszTitle, ICON_HAND);
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
					LVITEMW LvItemW;
					wchar_t tmp[64];
					memset (&LvItemW, 0, sizeof(LvItemW));
					LvItemW.mask = LVIF_TEXT;   
					LvItemW.iItem = LvItem.iItem;
					LvItemW.iSubItem = 3;
					LvItemW.pszText = tmp;
					LvItemW.cchTextMax = sizeof (tmp);
					SendMessageW (GetDlgItem (hwndDlg, IDC_DEVICELIST), LVM_GETITEMTEXTW, LvItemW.iItem, (LPARAM) &LvItemW);

					if (wcscmp (tmp, GetString ("REMOVABLE")) != 0)
					{
						// Device with partitions
						if (wcscmp (tmp, L" ") == 0 &&
							AskWarnNoYes ("DEVICE_PARTITIONS_WARN") == IDNO)
							return 1;

						if (AskWarnNoYes ("WHOLE_DEVICE_WARNING") == IDNO)
							return 1;

						Warning ("WHOLE_DEVICE_NOTE");
					}
				}
#endif
			}

			if (lpszFileName[0] == 0)
				return 1; // non-device line selected

			EndDialog (hwndDlg, IDOK);
			return 1;
		}

		if (lw == IDCANCEL)
		{
			EndDialog (hwndDlg, IDCANCEL);
			return 1;
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

	strcpy (tmp, !Is64BitOs () ? "\\truecrypt.sys" : "\\truecrypt-x64.sys");

	file = FindFirstFile (driverPath, &find);

	if (file == INVALID_HANDLE_VALUE)
	{
		MessageBoxW (0, GetString ("DRIVER_NOT_FOUND"), lpszTitle, ICON_HAND);
		return ERR_DONT_REPORT;
	}

	FindClose (file);

	hManager = OpenSCManager (NULL, NULL, SC_MANAGER_ALL_ACCESS);
	if (hManager == NULL)
	{
		if (GetLastError () == ERROR_ACCESS_DENIED)
		{
			MessageBoxW (0, GetString ("ADMIN_PRIVILEGES_DRIVER"), lpszTitle, ICON_HAND);
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
	BOOL bRet;
	SERVICE_STATUS status;
	int x;

	if (hDriver == INVALID_HANDLE_VALUE)
		return TRUE;

	// Test for mounted volumes
	bResult = DeviceIoControl (hDriver, MOUNT_LIST, &driver, sizeof (driver), &driver,
		sizeof (driver), &dwResult, NULL);

	if (bResult)
	{
		if (driver.ulMountedDrives != 0)
			return FALSE;
	}
	else
		return TRUE;

	// Test for any applications attached to driver
	refCount = GetDriverRefCount ();

	if (refCount > 1)
		return FALSE;

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

#ifndef SETUP
retry:
#endif
	hDriver = CreateFile (WIN32_ROOT_PREFIX, 0, 0, NULL, OPEN_EXISTING, 0, NULL);

	if (hDriver == INVALID_HANDLE_VALUE)
	{
#ifndef SETUP
		SC_HANDLE hManager, hService = NULL;
		SERVICE_STATUS status;

		// Windows lets users log in before all services scheduled to start on
		// boot are started. Retry if the system is running only for a few minutes
		// and the driver is not available.

		if ((hManager = OpenSCManager (NULL, NULL, SC_MANAGER_ENUMERATE_SERVICE))
			&& (hService = OpenService (hManager, "truecrypt", SERVICE_QUERY_STATUS))
			&& QueryServiceStatus (hService, &status)
			&& status.dwCurrentState != SERVICE_RUNNING
			&& GetTickCount () < 300 * 1000)
		{
			if (hService != NULL) CloseServiceHandle (hService);
			if (hManager != NULL) CloseServiceHandle (hManager);

			Sleep (2000);
			goto retry;
		}

		if (hService != NULL) CloseServiceHandle (hService);
		if (hManager != NULL) CloseServiceHandle (hManager);

		// Attempt to load driver (non-install mode)
		{
			BOOL res = DriverLoad ();

			if (res != ERROR_SUCCESS)
				return res;

			hDriver = CreateFile (WIN32_ROOT_PREFIX, 0, 0, NULL, OPEN_EXISTING, 0, NULL);
		}
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
BrowseFiles (HWND hwndDlg, char *stringId, char *lpszFileName, BOOL keepHistory, BOOL saveMode)
{
	OPENFILENAMEW ofn;
	wchar_t file[TC_MAX_PATH] = { 0 };
	wchar_t filter[1024];

	ZeroMemory (&ofn, sizeof (OPENFILENAME));

	*lpszFileName = 0;
	ofn.lStructSize = OPENFILENAME_SIZE_VERSION_400;
	ofn.hwndOwner = hwndDlg;
	wsprintfW (filter, L"%ls (*.*)%c*.*%c%ls (*.tc)%c*.tc%c",
		GetString ("ALL_FILES"), 0, 0, GetString ("TC_VOLUMES"), 0, 0);
	ofn.lpstrFilter = filter;
	ofn.lpstrCustomFilter = NULL;
	ofn.nFilterIndex = 1;
	ofn.lpstrFile = file;
	ofn.nMaxFile = TC_MAX_PATH;
	ofn.lpstrFileTitle = NULL;
	ofn.nMaxFileTitle = TC_MAX_PATH;
	ofn.lpstrInitialDir = NULL;
	ofn.lpstrTitle = GetString (stringId);
	ofn.Flags = OFN_HIDEREADONLY
		| OFN_PATHMUSTEXIST
		| (keepHistory ? 0 : OFN_DONTADDTORECENT)
		| (saveMode ? OFN_OVERWRITEPROMPT : 0);
	
	if (!saveMode)
	{
		if (!GetOpenFileNameW (&ofn))
			return FALSE;
	}
	else
	{
		if (!GetSaveFileNameW (&ofn))
			return FALSE;
	}

	if (!keepHistory)
		CleanLastVisitedMRU ();

	WideCharToMultiByte (CP_ACP, 0, file, -1, lpszFileName, MAX_PATH, NULL, NULL);

	// Reset current directory to user's home if the file is located on a removable
	// drive to enable its safe removal later. Unfortunately, Windows does not seem
	// to be sending DBT_DEVICEREMOVEPENDING message before trying to lock the drive.
	if (lpszFileName[1] == ':')
	{
		char root[] = { lpszFileName[0], ':', '\\', 0 };

		if (GetDriveType (root) == DRIVE_REMOVABLE)
		{
			char p[MAX_PATH];
			SHGetFolderPath (NULL, CSIDL_PERSONAL, NULL, 0, p);
			SetCurrentDirectory (p);
		}
	}

	return TRUE;
}


static char SelectMultipleFilesPath[MAX_PATH];
static int SelectMultipleFilesOffset;

BOOL SelectMultipleFiles (HWND hwndDlg, char *stringId, char *lpszFileName, BOOL keepHistory)
{
	OPENFILENAMEW ofn;
	wchar_t file[TC_MAX_PATH] = { 0 };
	wchar_t filter[1024];

	ZeroMemory (&ofn, sizeof (OPENFILENAME));

	*lpszFileName = 0;
	ofn.lStructSize = OPENFILENAME_SIZE_VERSION_400;
	ofn.hwndOwner = hwndDlg;
	wsprintfW (filter, L"%ls (*.*)%c*.*%c%ls (*.tc)%c*.tc%c",
		GetString ("ALL_FILES"), 0, 0, GetString ("TC_VOLUMES"), 0, 0);
	ofn.lpstrFilter = filter;
	ofn.lpstrCustomFilter = NULL;
	ofn.nFilterIndex = 1;
	ofn.lpstrFile = file;
	ofn.nMaxFile = TC_MAX_PATH;
	ofn.lpstrFileTitle = NULL;
	ofn.nMaxFileTitle = TC_MAX_PATH;
	ofn.lpstrInitialDir = NULL;
	ofn.lpstrTitle = GetString (stringId);
	ofn.Flags = OFN_HIDEREADONLY
		| OFN_EXPLORER
		| OFN_PATHMUSTEXIST
		| OFN_ALLOWMULTISELECT
		| (keepHistory ? 0 : OFN_DONTADDTORECENT);
	
	if (!GetOpenFileNameW (&ofn))
		return FALSE;

	if (!keepHistory)
		CleanLastVisitedMRU ();

	if (file[ofn.nFileOffset - 1] != 0)
	{
		// Single file selected
		WideCharToMultiByte (CP_ACP, 0, file, -1, lpszFileName, MAX_PATH, NULL, NULL);
		SelectMultipleFilesOffset = 0;
	}
	else
	{
		// Multiple files selected
		int n;
		wchar_t *f = file;
		char *s = SelectMultipleFilesPath;
		while ((n = WideCharToMultiByte (CP_ACP, 0, f, -1, s, MAX_PATH, NULL, NULL)) > 1)
		{
			f += n;
			s += n;
		}

		SelectMultipleFilesOffset = ofn.nFileOffset;
		SelectMultipleFilesNext (lpszFileName);
	}

	// Reset current directory to user's home if the file is located on a removable
	// drive to enable its safe removal later. Unfortunately, Windows does not seem
	// to be sending DBT_DEVICEREMOVEPENDING message before trying to lock the drive.
	if (lpszFileName[1] == ':')
	{
		char root[] = { lpszFileName[0], ':', '\\', 0 };

		if (GetDriveType (root) == DRIVE_REMOVABLE)
		{
			char p[MAX_PATH];
			SHGetFolderPath (NULL, CSIDL_PERSONAL, NULL, 0, p);
			SetCurrentDirectory (p);
		}
	}

	return TRUE;
}


BOOL SelectMultipleFilesNext (char *lpszFileName)
{
	if (SelectMultipleFilesOffset == 0)
		return FALSE;

	strncpy (lpszFileName, SelectMultipleFilesPath, sizeof (SelectMultipleFilesPath));

	if (lpszFileName[strlen (lpszFileName) - 1] != '\\')
		strcat (lpszFileName, "\\");

	strcat (lpszFileName, SelectMultipleFilesPath + SelectMultipleFilesOffset);

	SelectMultipleFilesOffset += strlen (SelectMultipleFilesPath + SelectMultipleFilesOffset) + 1;
	if (SelectMultipleFilesPath[SelectMultipleFilesOffset] == 0)
		SelectMultipleFilesOffset = 0;

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
	   SendMessage (hwnd,BFFM_SETSELECTION,TRUE,(LPARAM)pData);
	   break;
	}

	case BFFM_SELCHANGED: 
	{
		char szDir[TC_MAX_PATH];

	   /* Set the status window to the currently selected path. */
	   if (SHGetPathFromIDList((LPITEMIDLIST) lp ,szDir)) 
	   {
		  SendMessage (hwnd,BFFM_SETSTATUSTEXT,0,(LPARAM)szDir);
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
	BROWSEINFOW bi;
	LPITEMIDLIST pidl;
	LPMALLOC pMalloc;
	BOOL bOK  = FALSE;

	if (SUCCEEDED(SHGetMalloc(&pMalloc))) 
	{
		ZeroMemory(&bi,sizeof(bi));
		bi.hwndOwner = hwndDlg;
		bi.pszDisplayName = 0;
		bi.lpszTitle = GetString (lpszTitle);
		bi.pidlRoot = 0;
		bi.ulFlags = BIF_RETURNONLYFSDIRS | BIF_STATUSTEXT /*| BIF_EDITBOX*/;
		bi.lpfn = BrowseCallbackProc;
		bi.lParam = (LPARAM)dirName;

		pidl = SHBrowseForFolderW (&bi);
		if (pidl!=NULL) 
		{
			if (SHGetPathFromIDList(pidl, dirName)) 
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
	WCHAR szTmp[1024];

	if (Silent) return;

	switch (code)
	{
	case ERR_OS_ERROR:
		handleWin32Error (hwndDlg);
		break;
	case ERR_OUTOFMEMORY:
		MessageBoxW (hwndDlg, GetString ("OUTOFMEMORY"), lpszTitle, ICON_HAND);
		break;

	case ERR_PASSWORD_WRONG:
		wsprintfW (szTmp, GetString (KeyFilesEnable ? "PASSWORD_OR_KEYFILE_WRONG" : "PASSWORD_WRONG"));
		if (CheckCapsLock (hwndDlg, TRUE))
			wcscat (szTmp, GetString ("PASSWORD_WRONG_CAPSLOCK_ON"));

		MessageBoxW (hwndDlg, szTmp, lpszTitle, MB_ICONWARNING);
		break;

	case ERR_VOL_FORMAT_BAD:
		MessageBoxW (hwndDlg, GetString ("VOL_FORMAT_BAD"), lpszTitle, ICON_HAND);
		break;
	case ERR_BAD_DRIVE_LETTER:
		MessageBoxW (hwndDlg, GetString ("BAD_DRIVE_LETTER"), lpszTitle, ICON_HAND);
		break;
	case ERR_DRIVE_NOT_FOUND:
		MessageBoxW (hwndDlg, GetString ("NOT_FOUND"), lpszTitle, ICON_HAND);
		break;
	case ERR_FILES_OPEN:
		MessageBoxW (hwndDlg, GetString ("OPENFILES_DRIVER"), lpszTitle, ICON_HAND);
		break;
	case ERR_FILES_OPEN_LOCK:
		MessageBoxW (hwndDlg, GetString ("OPENFILES_LOCK"), lpszTitle, ICON_HAND);
		break;
	case ERR_VOL_SIZE_WRONG:
		MessageBoxW (hwndDlg, GetString ("VOL_SIZE_WRONG"), lpszTitle, ICON_HAND);
		break;
	case ERR_COMPRESSION_NOT_SUPPORTED:
		MessageBoxW (hwndDlg, GetString ("COMPRESSION_NOT_SUPPORTED"), lpszTitle, ICON_HAND);
		break;
	case ERR_PASSWORD_CHANGE_VOL_TYPE:
		MessageBoxW (hwndDlg, GetString ("WRONG_VOL_TYPE"), lpszTitle, ICON_HAND);
		break;
	case ERR_VOL_SEEKING:
		MessageBoxW (hwndDlg, GetString ("VOL_SEEKING"), lpszTitle, ICON_HAND);
		break;
	case ERR_VOL_WRITING:
		MessageBoxW (hwndDlg, GetString ("VOL_WRITING"), lpszTitle, ICON_HAND);
		break;
	case ERR_VOL_READING:
		MessageBoxW (hwndDlg, GetString ("VOL_READING"), lpszTitle, ICON_HAND);
		break;
	case ERR_CIPHER_INIT_FAILURE:
		MessageBoxW (hwndDlg, GetString ("ERR_CIPHER_INIT_FAILURE"), lpszTitle, ICON_HAND);
		break;
	case ERR_CIPHER_INIT_WEAK_KEY:
		MessageBoxW (hwndDlg, GetString ("ERR_CIPHER_INIT_WEAK_KEY"), lpszTitle, ICON_HAND);
		break;
	case ERR_VOL_ALREADY_MOUNTED:
		MessageBoxW (hwndDlg, GetString ("VOL_ALREADY_MOUNTED"), lpszTitle, ICON_HAND);
		break;
	case ERR_FILE_OPEN_FAILED:
		MessageBoxW (hwndDlg, GetString ("FILE_OPEN_FAILED"), lpszTitle, ICON_HAND);
		break;
	case ERR_VOL_MOUNT_FAILED:
		MessageBoxW (hwndDlg, GetString  ("VOL_MOUNT_FAILED"), lpszTitle, ICON_HAND);
		break;
	case ERR_NO_FREE_DRIVES:
		MessageBoxW (hwndDlg, GetString ("NO_FREE_DRIVES"), lpszTitle, ICON_HAND);
		break;
	case ERR_INVALID_DEVICE:
		MessageBoxW (hwndDlg, GetString ("INVALID_DEVICE"), lpszTitle, ICON_HAND);
		break;
	case ERR_ACCESS_DENIED:
		MessageBoxW (hwndDlg, GetString ("ACCESS_DENIED"), lpszTitle, ICON_HAND);
		break;

	case ERR_DRIVER_VERSION:
		wsprintfW (szTmp, GetString ("DRIVER_VERSION"), VERSION_STRING);
		MessageBoxW (hwndDlg, szTmp, lpszTitle, ICON_HAND);
		break;

	case ERR_NEW_VERSION_REQUIRED:
		MessageBoxW (hwndDlg, GetString ("NEW_VERSION_REQUIRED"), lpszTitle, ICON_HAND);
		break;

	case ERR_SELF_TESTS_FAILED:
		Error ("ERR_SELF_TESTS_FAILED");
		break;

	case ERR_DONT_REPORT:
		break;

	default:
		wsprintfW (szTmp, GetString ("ERR_UNKNOWN"), code);
		MessageBoxW (hwndDlg, szTmp, lpszTitle, ICON_HAND);
	}
}

static BOOL CALLBACK LocalizeDialogEnum( HWND hwnd, LPARAM font)
{
	// Localization of controls

	if (LocalizationActive)
	{
		int ctrlId = GetDlgCtrlID (hwnd);
		if (ctrlId != 0)
		{
			char name[10] = { 0 };
			GetClassName (hwnd, name, sizeof (name));

			if (_stricmp (name, "Button") == 0 || _stricmp (name, "Static") == 0)
			{
				wchar_t *str = GetDictionaryValueByInt (ctrlId);
				if (str != NULL)
					SetWindowTextW (hwnd, str);
			}
		}
	}

	// Font
	SendMessage (hwnd, WM_SETFONT, (WPARAM) font, 0);
	
	return TRUE;
}

void LocalizeDialog (HWND hwnd, char *stringId)
{
	SetWindowLongPtr (hwnd, GWLP_USERDATA, (LONG_PTR) 'TRUE');
	SendMessage (hwnd, WM_SETFONT, (WPARAM) hUserFont, 0);

	if (LocalizationActive && stringId != NULL)
		SetWindowTextW (hwnd, GetString (stringId));

	if (hUserFont != 0)
		EnumChildWindows (hwnd, LocalizeDialogEnum, (LPARAM) hUserFont);
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

void GetSizeString (unsigned __int64 size, wchar_t *str)
{
	static wchar_t *b, *kb, *mb, *gb, *tb, *pb;
	static int serNo;

	if (b == NULL || serNo != LocalizationSerialNo)
	{
		serNo = LocalizationSerialNo;
		kb = GetString ("KB");
		mb = GetString ("MB");
		gb = GetString ("GB");
		tb = GetString ("TB");
		pb = GetString ("PB");
		b = GetString ("BYTE");
	}

	if (size > 1024I64*1024*1024*1024*1024*99)
		swprintf (str, L"%I64d %s", size/1024/1024/1024/1024/1024, pb);
	else if (size > 1024I64*1024*1024*1024*1024)
		swprintf (str, L"%.1f %s",(double)(size/1024.0/1024/1024/1024/1024), pb);
	else if (size > 1024I64*1024*1024*1024*99)
		swprintf (str, L"%I64d %s",size/1024/1024/1024/1024, tb);
	else if (size > 1024I64*1024*1024*1024)
		swprintf (str, L"%.1f %s",(double)(size/1024.0/1024/1024/1024), tb);
	else if (size > 1024I64*1024*1024*99)
		swprintf (str, L"%I64d %s",size/1024/1024/1024, gb);
	else if (size > 1024I64*1024*1024)
		swprintf (str, L"%.1f %s",(double)(size/1024.0/1024/1024), gb);
	else if (size > 1024I64*1024*99)
		swprintf (str, L"%I64d %s", size/1024/1024, mb);
	else if (size > 1024I64*1024)
		swprintf (str, L"%.1f %s",(double)(size/1024.0/1024), mb);
	else if (size > 1024I64)
		swprintf (str, L"%I64d %s", size/1024, kb);
	else
		swprintf (str, L"%I64d %s", size, b);
}

#ifndef SETUP
void GetSpeedString (unsigned __int64 speed, wchar_t *str)
{
	static wchar_t *b, *kb, *mb, *gb, *tb, *pb;
	static int serNo;
	
	if (b == NULL || serNo != LocalizationSerialNo)
	{
		serNo = LocalizationSerialNo;
		kb = GetString ("KB_PER_SEC");
		mb = GetString ("MB_PER_SEC");
		gb = GetString ("GB_PER_SEC");
		tb = GetString ("TB_PER_SEC");
		pb = GetString ("PB_PER_SEC");
		b = GetString ("B_PER_SEC");
	}

	if (speed > 1024I64*1024*1024*1024*1024*99)
		swprintf (str, L"%I64d %s", speed/1024/1024/1024/1024/1024, pb);
	else if (speed > 1024I64*1024*1024*1024*1024)
		swprintf (str, L"%.1f %s",(double)(speed/1024.0/1024/1024/1024/1024), pb);
	else if (speed > 1024I64*1024*1024*1024*99)
		swprintf (str, L"%I64d %s",speed/1024/1024/1024/1024, tb);
	else if (speed > 1024I64*1024*1024*1024)
		swprintf (str, L"%.1f %s",(double)(speed/1024.0/1024/1024/1024), tb);
	else if (speed > 1024I64*1024*1024*99)
		swprintf (str, L"%I64d %s",speed/1024/1024/1024, gb);
	else if (speed > 1024I64*1024*1024)
		swprintf (str, L"%.1f %s",(double)(speed/1024.0/1024/1024), gb);
	else if (speed > 1024I64*1024*99)
		swprintf (str, L"%I64d %s", speed/1024/1024, mb);
	else if (speed > 1024I64*1024)
		swprintf (str, L"%.1f %s",(double)(speed/1024.0/1024), mb);
	else if (speed > 1024I64)
		swprintf (str, L"%I64d %s", speed/1024, kb);
	else
		swprintf (str, L"%I64d %s", speed, b);
}

static void DisplayBenchmarkResults (HWND hwndDlg)
{
	wchar_t item1[100]={0};
	LVITEMW LvItem;
	HWND hList = GetDlgItem (hwndDlg, IDC_RESULTS);
	int ea, i;
	BOOL unsorted = TRUE;
	BENCHMARK_REC tmp_line;

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
		LvItem.iItem = i;
		LvItem.iSubItem = 0;
		LvItem.pszText = (LPWSTR) benchmarkTable[i].name;
		SendMessageW (hList, LVM_INSERTITEM, 0, (LPARAM)&LvItem); 

#if PKCS5_BENCHMARKS
		wcscpy (item1, L"-");
#else
		GetSpeedString ((unsigned __int64) (benchmarkLastBufferSize / ((float) benchmarkTable[i].encSpeed / benchmarkPerformanceFrequency.QuadPart)), item1);
#endif
		LvItem.iSubItem = 1;
		LvItem.pszText = item1;

		SendMessageW (hList, LVM_SETITEMW, 0, (LPARAM)&LvItem); 

#if PKCS5_BENCHMARKS
		wcscpy (item1, L"-");
#else
		GetSpeedString ((unsigned __int64) (benchmarkLastBufferSize / ((float) benchmarkTable[i].decSpeed / benchmarkPerformanceFrequency.QuadPart)), item1);
#endif
		LvItem.iSubItem = 2;
		LvItem.pszText = item1;

		SendMessageW (hList, LVM_SETITEMW, 0, (LPARAM)&LvItem); 

#if PKCS5_BENCHMARKS
		swprintf (item1, L"%d t", benchmarkTable[i].encSpeed);
#else
		GetSpeedString (benchmarkTable[i].meanBytesPerSec, item1);
#endif
		LvItem.iSubItem = 3;
		LvItem.pszText = item1;

		SendMessageW (hList, LVM_SETITEMW, 0, (LPARAM)&LvItem); 
	}
}

static BOOL PerformBenchmark(HWND hwndDlg)
{
    LARGE_INTEGER performanceCountStart, performanceCountEnd;
	BYTE *lpTestBuffer;
	PCRYPTO_INFO ci = NULL;
#if !(PKCS5_BENCHMARKS || HASH_FNC_BENCHMARKS)
	ci = crypto_open ();
	if (!ci)
		return FALSE;
#endif

	if (QueryPerformanceFrequency (&benchmarkPerformanceFrequency) == 0)
	{
		MessageBoxW (hwndDlg, GetString ("ERR_PERF_COUNTER"), lpszTitle, ICON_HAND);
		return FALSE;
	}

	ArrowWaitCursor ();

	lpTestBuffer = malloc(benchmarkBufferSize - (benchmarkBufferSize % 16));
	if (lpTestBuffer == NULL)
	{
		NormalCursor ();
		MessageBoxW (hwndDlg, GetString ("ERR_MEM_ALLOC"), lpszTitle, ICON_HAND);
		return FALSE;
	}
	VirtualLock (lpTestBuffer, benchmarkBufferSize - (benchmarkBufferSize % 16));

	benchmarkTotalItems = 0;

#if HASH_FNC_BENCHMARKS

	/* Measures the speed at which each of the hash algorithms processes the message to produce
	   a single digest. 

	   The hash algorithm benchmarks are included here for development purposes only. Do not enable 
	   them when building a public release (the benchmark GUI strings wouldn't make sense). */

	{
		BYTE *digest [MAX_DIGESTSIZE];
		WHIRLPOOL_CTX	wctx;
		RMD160_CTX		rctx;
		sha1_ctx		sctx;
		int hid;

		for (hid = 1; hid <= LAST_PRF_ID; hid++) 
		{
			if (QueryPerformanceCounter (&performanceCountStart) == 0)
				goto counter_error;

			switch (hid)
			{
			case SHA1:
				sha1_begin (&sctx);
				sha1_hash (lpTestBuffer, benchmarkBufferSize, &sctx);
				sha1_end ((unsigned char *) digest, &sctx);
				break;

			case RIPEMD160:
				RMD160Init(&rctx);
				RMD160Update(&rctx, lpTestBuffer, benchmarkBufferSize);
				RMD160Final((unsigned char *) digest, &rctx);
				break;

			case WHIRLPOOL:
				WHIRLPOOL_init (&wctx);
				WHIRLPOOL_add (lpTestBuffer, benchmarkBufferSize * 8, &wctx);
				WHIRLPOOL_finalize (&wctx, (unsigned char *) digest);
				break;
			}

			if (QueryPerformanceCounter (&performanceCountEnd) == 0)
				goto counter_error;

			benchmarkTable[benchmarkTotalItems].encSpeed = performanceCountEnd.QuadPart - performanceCountStart.QuadPart;

			benchmarkTable[benchmarkTotalItems].decSpeed = benchmarkTable[benchmarkTotalItems].encSpeed;
			benchmarkTable[benchmarkTotalItems].id = hid;
			benchmarkTable[benchmarkTotalItems].meanBytesPerSec = ((unsigned __int64) (benchmarkBufferSize / ((float) benchmarkTable[benchmarkTotalItems].encSpeed / benchmarkPerformanceFrequency.QuadPart)) + (unsigned __int64) (benchmarkBufferSize / ((float) benchmarkTable[benchmarkTotalItems].decSpeed / benchmarkPerformanceFrequency.QuadPart))) / 2;
			sprintf (benchmarkTable[benchmarkTotalItems].name, "%s", HashGetName(hid));

			benchmarkTotalItems++;
		}
	}

#elif PKCS5_BENCHMARKS	// #if HASH_FNC_BENCHMARKS

	/* Measures the time that it takes for the PKCS-5 routine to derive a header key using
	   each of the implemented PRF algorithms. 

	   The PKCS-5 benchmarks are included here for development purposes only. Do not enable 
	   them when building a public release (the benchmark GUI strings wouldn't make sense). */
	{
		int thid, i;
		char dk[HEADER_DISKKEY];
		char *tmp_salt = {"\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xAA\xBB\xCC\xDD\xEE\xFF\x01\x23\x45\x67\x89\xAB\xCD\xEF\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xAA\xBB\xCC\xDD\xEE\xFF\x01\x23\x45\x67\x89\xAB\xCD\xEF\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xAA\xBB\xCC\xDD\xEE\xFF"};

		for (thid = 1; thid <= LAST_PRF_ID; thid++) 
		{
			if (QueryPerformanceCounter (&performanceCountStart) == 0)
				goto counter_error;

			for (i = 1; i <= 5; i++) 
			{
				switch (thid)
				{
				case SHA1:
					/* PKCS-5 test with HMAC-SHA-1 used as the PRF */
					derive_key_sha1 ("passphrase-1234567890", 21, tmp_salt, 64, get_pkcs5_iteration_count(thid), dk, HEADER_DISKKEY);
					break;

				case RIPEMD160:
					/* PKCS-5 test with HMAC-RIPEMD-160 used as the PRF */
					derive_key_ripemd160 ("passphrase-1234567890", 21, tmp_salt, 64, get_pkcs5_iteration_count(thid), dk, HEADER_DISKKEY);
					break;

				case WHIRLPOOL:
					/* PKCS-5 test with HMAC-Whirlpool used as the PRF */
					derive_key_whirlpool ("passphrase-1234567890", 21, tmp_salt, 64, get_pkcs5_iteration_count(thid), dk, HEADER_DISKKEY);
					break;
				}
			}

			if (QueryPerformanceCounter (&performanceCountEnd) == 0)
				goto counter_error;

			benchmarkTable[benchmarkTotalItems].encSpeed = performanceCountEnd.QuadPart - performanceCountStart.QuadPart;
			benchmarkTable[benchmarkTotalItems].id = thid;
			sprintf (benchmarkTable[benchmarkTotalItems].name, "%s", get_pkcs5_prf_name (thid));

			benchmarkTotalItems++;
		}
	}

#else	// #elif PKCS5_BENCHMARKS

	/* Encryption algorithm benchmarks */
		
	for (ci->ea = EAGetFirst(); ci->ea != 0; ci->ea = EAGetNext(ci->ea))
	{
		if (EAGetFirstMode (ci->ea) != LRW)
			continue;

		EAInit (ci->ea, ci->master_key, ci->ks);

		ci->mode = LRW;
		if (!EAInitMode (ci))
			break;

		if (QueryPerformanceCounter (&performanceCountStart) == 0)
			goto counter_error;

		EncryptBuffer ((unsigned __int32 *) lpTestBuffer, (unsigned __int64) benchmarkBufferSize, ci);

		if (QueryPerformanceCounter (&performanceCountEnd) == 0)
			goto counter_error;

		benchmarkTable[benchmarkTotalItems].encSpeed = performanceCountEnd.QuadPart - performanceCountStart.QuadPart;

		if (QueryPerformanceCounter (&performanceCountStart) == 0)
			goto counter_error;

		DecryptBuffer ((unsigned __int32 *) lpTestBuffer, (unsigned __int64) benchmarkBufferSize, ci);

		if (QueryPerformanceCounter (&performanceCountEnd) == 0)
			goto counter_error;

		benchmarkTable[benchmarkTotalItems].decSpeed = performanceCountEnd.QuadPart - performanceCountStart.QuadPart;
		benchmarkTable[benchmarkTotalItems].id = ci->ea;
		benchmarkTable[benchmarkTotalItems].meanBytesPerSec = ((unsigned __int64) (benchmarkBufferSize / ((float) benchmarkTable[benchmarkTotalItems].encSpeed / benchmarkPerformanceFrequency.QuadPart)) + (unsigned __int64) (benchmarkBufferSize / ((float) benchmarkTable[benchmarkTotalItems].decSpeed / benchmarkPerformanceFrequency.QuadPart))) / 2;
		EAGetName (benchmarkTable[benchmarkTotalItems].name, ci->ea);

		benchmarkTotalItems++;
	}

#endif	// #elif PKCS5_BENCHMARKS (#else)

	if (ci)
		crypto_close (ci);

	VirtualUnlock (lpTestBuffer, benchmarkBufferSize - (benchmarkBufferSize % 16));

	free(lpTestBuffer);

	benchmarkLastBufferSize = benchmarkBufferSize;

	DisplayBenchmarkResults(hwndDlg);

	EnableWindow (GetDlgItem (hwndDlg, IDC_PERFORM_BENCHMARK), TRUE);
	EnableWindow (GetDlgItem (hwndDlg, IDCLOSE), TRUE);

	NormalCursor ();
	return TRUE;

counter_error:
	
	if (ci)
		crypto_close (ci);

	VirtualUnlock (lpTestBuffer, benchmarkBufferSize - (benchmarkBufferSize % 16));

	free(lpTestBuffer);

	NormalCursor ();

	EnableWindow (GetDlgItem (hwndDlg, IDC_PERFORM_BENCHMARK), TRUE);
	EnableWindow (GetDlgItem (hwndDlg, IDCLOSE), TRUE);

	MessageBoxW (hwndDlg, GetString ("ERR_PERF_COUNTER"), lpszTitle, ICON_HAND);
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
			LVCOLUMNW LvCol;
			wchar_t s[128];
			HWND hList = GetDlgItem (hwndDlg, IDC_RESULTS);

			LocalizeDialog (hwndDlg, "IDD_BENCHMARK_DLG");

			benchmarkBufferSize = BENCHMARK_DEFAULT_BUF_SIZE;
			benchmarkSortMethod = BENCHMARK_SORT_BY_SPEED;

			SendMessage (hList,LVM_SETEXTENDEDLISTVIEWSTYLE,0,
				LVS_EX_FULLROWSELECT|LVS_EX_HEADERDRAGDROP|LVS_EX_LABELTIP 
				); 

			memset (&LvCol,0,sizeof(LvCol));               
			LvCol.mask = LVCF_TEXT|LVCF_WIDTH|LVCF_SUBITEM|LVCF_FMT;  
			LvCol.pszText = GetString ("ALGORITHM");                           
			LvCol.cx = 114;
			LvCol.fmt = LVCFMT_LEFT;
			SendMessage (hList,LVM_INSERTCOLUMNW,0,(LPARAM)&LvCol);

			LvCol.pszText = GetString ("ENCRYPTION");  
			LvCol.cx = 80;           
			LvCol.fmt = LVCFMT_RIGHT;
			SendMessageW (hList,LVM_INSERTCOLUMNW,1,(LPARAM)&LvCol);

			LvCol.pszText = GetString ("DECRYPTION");  
			LvCol.cx = 80;
			LvCol.fmt = LVCFMT_RIGHT;
			SendMessageW (hList,LVM_INSERTCOLUMNW,2,(LPARAM)&LvCol);

			LvCol.pszText = GetString ("MEAN");  
			LvCol.cx = 80;
			LvCol.fmt = LVCFMT_RIGHT;
			SendMessageW (hList,LVM_INSERTCOLUMNW,3,(LPARAM)&LvCol);

			/* Combo boxes */

			// Sort method

			SendMessage (hCboxSortMethod, CB_RESETCONTENT, 0, 0);

			nIndex = SendMessageW (hCboxSortMethod, CB_ADDSTRING, 0, (LPARAM) GetString ("ALPHABETICAL_CATEGORIZED"));
			SendMessage (hCboxSortMethod, CB_SETITEMDATA, nIndex, (LPARAM) 0);

			nIndex = SendMessageW (hCboxSortMethod, CB_ADDSTRING, 0, (LPARAM) GetString ("MEAN_SPEED"));
			SendMessage (hCboxSortMethod, CB_SETITEMDATA, nIndex, (LPARAM) 0);

			SendMessage (hCboxSortMethod, CB_SETCURSEL, 1, 0);		// Default sort method

			// Buffer size

			SendMessage (hCboxBufferSize, CB_RESETCONTENT, 0, 0);

			swprintf (s, L"5 %s", GetString ("KB"));
			nIndex = SendMessageW (hCboxBufferSize, CB_ADDSTRING, 0, (LPARAM) s);
			SendMessage (hCboxBufferSize, CB_SETITEMDATA, nIndex, (LPARAM) 5 * BYTES_PER_KB);

			swprintf (s, L"100 %s", GetString ("KB"));
			nIndex = SendMessageW (hCboxBufferSize, CB_ADDSTRING, 0, (LPARAM) s);
			SendMessage (hCboxBufferSize, CB_SETITEMDATA, nIndex, (LPARAM) 100 * BYTES_PER_KB);

			swprintf (s, L"500 %s", GetString ("KB"));
			nIndex = SendMessageW (hCboxBufferSize, CB_ADDSTRING, 0, (LPARAM) s);
			SendMessage (hCboxBufferSize, CB_SETITEMDATA, nIndex, (LPARAM) 500 * BYTES_PER_KB);

			swprintf (s, L"1 %s", GetString ("MB"));
			nIndex = SendMessageW (hCboxBufferSize, CB_ADDSTRING, 0, (LPARAM) s);
			SendMessage (hCboxBufferSize, CB_SETITEMDATA, nIndex, (LPARAM) 1 * BYTES_PER_MB);

			swprintf (s, L"5 %s", GetString ("MB"));
			nIndex = SendMessageW (hCboxBufferSize, CB_ADDSTRING, 0, (LPARAM) s);
			SendMessage (hCboxBufferSize, CB_SETITEMDATA, nIndex, (LPARAM) 5 * BYTES_PER_MB);

			swprintf (s, L"10 %s", GetString ("MB"));
			nIndex = SendMessageW (hCboxBufferSize, CB_ADDSTRING, 0, (LPARAM) s);
			SendMessage (hCboxBufferSize, CB_SETITEMDATA, nIndex, (LPARAM) 10 * BYTES_PER_MB);

			swprintf (s, L"50 %s", GetString ("MB"));
			nIndex = SendMessageW (hCboxBufferSize, CB_ADDSTRING, 0, (LPARAM) s);
			SendMessage (hCboxBufferSize, CB_SETITEMDATA, nIndex, (LPARAM) 50 * BYTES_PER_MB);

			swprintf (s, L"100 %s", GetString ("MB"));
			nIndex = SendMessageW (hCboxBufferSize, CB_ADDSTRING, 0, (LPARAM) s);
			SendMessage (hCboxBufferSize, CB_SETITEMDATA, nIndex, (LPARAM) 100 * BYTES_PER_MB);

			swprintf (s, L"200 %s", GetString ("MB"));
			nIndex = SendMessageW (hCboxBufferSize, CB_ADDSTRING, 0, (LPARAM) s);
			SendMessage (hCboxBufferSize, CB_SETITEMDATA, nIndex, (LPARAM) 200 * BYTES_PER_MB);

			swprintf (s, L"500 %s", GetString ("MB"));
			nIndex = SendMessageW (hCboxBufferSize, CB_ADDSTRING, 0, (LPARAM) s);
			SendMessage (hCboxBufferSize, CB_SETITEMDATA, nIndex, (LPARAM) 500 * BYTES_PER_MB);

			swprintf (s, L"1 %s", GetString ("GB"));
			nIndex = SendMessageW (hCboxBufferSize, CB_ADDSTRING, 0, (LPARAM) s);
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
			return 1;
		}

		if (lw == IDC_PERFORM_BENCHMARK)
		{
			nIndex = SendMessage (hCboxBufferSize, CB_GETCURSEL, 0, 0);
			benchmarkBufferSize = SendMessage (hCboxBufferSize, CB_GETITEMDATA, nIndex, 0);

			if (PerformBenchmark(hwndDlg) == FALSE)
			{
				EndDialog (hwndDlg, IDCLOSE);
			}
			return 1;
		}
		if (lw == IDCLOSE || lw == IDCANCEL)
		{
			EndDialog (hwndDlg, IDCLOSE);
			return 1;
		}
		return 0;

		break;

	case WM_CLOSE:
		EndDialog (hwndDlg, IDCLOSE);
		return 1;

		break;

	}
	return 0;
}



/* Except in response to the WM_INITDIALOG message, the dialog box procedure
   should return nonzero if it processes the message, and zero if it does
   not. - see DialogProc */
BOOL WINAPI
KeyfileGeneratorDlgProc (HWND hwndDlg, UINT msg, WPARAM wParam, LPARAM lParam)
{
	WORD lw = LOWORD (wParam);
	WORD hw = HIWORD (wParam);
	static unsigned char randPool [RNG_POOL_SIZE];
	static unsigned char lastRandPool [RNG_POOL_SIZE];
	static char outputDispBuffer [RNG_POOL_SIZE*3+34];
	static bDisplayPoolContents = TRUE;
	int hash_algo = RandGetHashFunction();
	int hid;

	if (lParam);		/* remove warning */

	switch (msg)
	{
	case WM_INITDIALOG:
		{
			HWND hComboBox = GetDlgItem (hwndDlg, IDC_PRF_ID);

			VirtualLock (randPool, sizeof(randPool));
			VirtualLock (lastRandPool, sizeof(lastRandPool));
			VirtualLock (outputDispBuffer, sizeof(outputDispBuffer));

			LocalizeDialog (hwndDlg, "IDD_KEYFILE_GENERATOR_DLG");

			SendMessage (hComboBox, CB_RESETCONTENT, 0, 0);
			for (hid = 1; hid <= LAST_PRF_ID; hid++)
			{
				AddComboPair (hComboBox, HashGetName(hid), hid);
			}
			SelectAlgo (hComboBox, &hash_algo);

			SetCheckBox (hwndDlg, IDC_DISPLAY_POOL_CONTENTS, bDisplayPoolContents);

#ifndef VOLFORMAT			
			if (Randinit ()) 
			{
				Error ("INIT_RAND");
				EndDialog (hwndDlg, IDCLOSE);
			}
#endif
			SetTimer (hwndDlg, 0xfd, RANDOM_POOL_DISPLAY_REFRESH_INTERVAL, NULL);
			SendMessage (GetDlgItem (hwndDlg, IDC_POOL_CONTENTS), WM_SETFONT, (WPARAM) hFixedDigitFont, (LPARAM) TRUE);
			return 1;
		}

	case WM_TIMER:
		{
			char tmp[4];
			int col, row;

			if (bDisplayPoolContents)
			{
				RandpeekBytes (randPool, sizeof (randPool));

				if (memcmp (lastRandPool, randPool, sizeof(lastRandPool)) != 0)
				{
					outputDispBuffer[0] = 0;

					for (row = 0; row < 16; row++)
					{
						for (col = 0; col < 20; col++)
						{
							sprintf (tmp, "%02X ", randPool[row * 20 + col]);
							strcat (outputDispBuffer, tmp);
						}
						strcat (outputDispBuffer, "\n");
					}
					SetWindowText (GetDlgItem (hwndDlg, IDC_POOL_CONTENTS), outputDispBuffer);

					memcpy (lastRandPool, randPool, sizeof(lastRandPool));
				}
			}
			return 1;
		}

	case WM_COMMAND:

		if (lw == IDCLOSE || lw == IDCANCEL)
		{
			goto exit;
		}

		if (lw == IDC_PRF_ID && hw == CBN_SELCHANGE)
		{
			hid = (int) SendMessage (GetDlgItem (hwndDlg, IDC_PRF_ID), CB_GETCURSEL, 0, 0);
			hash_algo = (int) SendMessage (GetDlgItem (hwndDlg, IDC_PRF_ID), CB_GETITEMDATA, hid, 0);
			RandSetHashFunction (hash_algo);
			return 1;
		}

		if (lw == IDC_DISPLAY_POOL_CONTENTS)
		{
			if (!(bDisplayPoolContents = GetCheckBox (hwndDlg, IDC_DISPLAY_POOL_CONTENTS)))
				SetWindowText (GetDlgItem (hwndDlg, IDC_POOL_CONTENTS), "");
		}

		if (lw == IDC_GENERATE_AND_SAVE_KEYFILE)
		{
			char szFileName [TC_MAX_PATH];
			unsigned char keyfile [MAX_PASSWORD];
			int fhKeyfile = -1;

			/* Select filename */
			if (!BrowseFiles (hwndDlg, "OPEN_TITLE", szFileName, FALSE, TRUE))
				return 1;

			/* Conceive the file */
			if ((fhKeyfile = _open(szFileName, _O_CREAT|_O_TRUNC|_O_WRONLY|_O_BINARY, _S_IREAD|_S_IWRITE)) == -1)
			{
				Error ("ERROR_CANNOT_MAKE");
				return 1;
			}

			/* Generate the keyfile */ 
			WaitCursor();
			RandgetBytes (keyfile, sizeof(keyfile), TRUE);
			NormalCursor();

			/* Write the keyfile */
			if (_write (fhKeyfile, keyfile, sizeof(keyfile)) == -1)
				handleWin32Error (hwndDlg);
			else
				Info("KEYFILE_CREATED");

			memset (keyfile, 0, sizeof(keyfile));
			_close (fhKeyfile);
			return 1;
		}
		return 0;

	case WM_CLOSE:
		{
			char tmp[RNG_POOL_SIZE+1];
exit:
			KillTimer (hwndDlg, 0xfd);

#ifndef VOLFORMAT			
			Randfree ();
#endif
			/* Cleanup */

			memset (randPool, 0, sizeof(randPool));
			memset (lastRandPool, 0, sizeof(lastRandPool));
			memset (outputDispBuffer, 0, sizeof(outputDispBuffer));

			// Attempt to wipe the pool contents in the GUI text area
			memset (tmp, 'X', RNG_POOL_SIZE);
			tmp [RNG_POOL_SIZE] = 0;
			SetWindowText (GetDlgItem (hwndDlg, IDC_POOL_CONTENTS), tmp);

			EndDialog (hwndDlg, IDCLOSE);
			return 1;
		}
	}
	return 0;
}



/* Except in response to the WM_INITDIALOG message, the dialog box procedure
should return nonzero if it processes the message, and zero if it does
not. - see DialogProc */
BOOL CALLBACK
CipherTestDialogProc (HWND hwndDlg, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
	static int idTestCipher = -1;		/* Currently selected cipher for the test vector facility (none = -1). */
	static BOOL bLRWTestEnabled = TRUE;

	PCRYPTO_INFO ci;
	WORD lw = LOWORD (wParam);
	WORD hw = HIWORD (wParam);

	if (lParam);		/* Remove unused parameter warning */

	switch (uMsg)
	{
	case WM_INITDIALOG:
		{
			int ea;
			char buf[100];

			LocalizeDialog (hwndDlg, "IDD_CIPHER_TEST_DLG");

			SendMessage(GetDlgItem(hwndDlg, IDC_TESTS_MESSAGE), WM_SETFONT, (WPARAM)hBoldFont, MAKELPARAM(TRUE,0));
			SendMessage(GetDlgItem(hwndDlg, IDC_KEY), EM_LIMITTEXT, 128,0);
			SendMessage(GetDlgItem(hwndDlg, IDC_KEY), WM_SETFONT, (WPARAM)hFixedDigitFont, MAKELPARAM(1,0));
			SendMessage(GetDlgItem(hwndDlg, IDC_PLAINTEXT), EM_LIMITTEXT,128,0);
			SendMessage(GetDlgItem(hwndDlg, IDC_PLAINTEXT), WM_SETFONT, (WPARAM)hFixedDigitFont, MAKELPARAM(1,0));
			SendMessage(GetDlgItem(hwndDlg, IDC_CIPHERTEXT), EM_LIMITTEXT,128,0);
			SendMessage(GetDlgItem(hwndDlg, IDC_CIPHERTEXT), WM_SETFONT, (WPARAM)hFixedDigitFont, MAKELPARAM(1,0));
			SendMessage(GetDlgItem(hwndDlg, IDC_LRW_KEY), EM_LIMITTEXT,128,0);
			SendMessage(GetDlgItem(hwndDlg, IDC_LRW_KEY), WM_SETFONT, (WPARAM)hFixedDigitFont, MAKELPARAM(1,0));
			SendMessage(GetDlgItem(hwndDlg, IDC_LRW_BLOCK_INDEX), EM_LIMITTEXT,128,0);
			SendMessage(GetDlgItem(hwndDlg, IDC_LRW_BLOCK_INDEX), WM_SETFONT, (WPARAM)hFixedDigitFont, MAKELPARAM(1,0));
			SetCheckBox (hwndDlg, IDC_LRW_MODE_ENABLED, bLRWTestEnabled);
			SetCheckBox (hwndDlg, IDC_LRW_INDEX_LSB, TRUE);
			EnableWindow (GetDlgItem (hwndDlg, IDC_LRW_KEY), bLRWTestEnabled);
			EnableWindow (GetDlgItem (hwndDlg, IDT_LRW_KEY), bLRWTestEnabled);
			EnableWindow (GetDlgItem (hwndDlg, IDC_LRW_BLOCK_INDEX), bLRWTestEnabled);
			EnableWindow (GetDlgItem (hwndDlg, IDT_LRW_BLOCK_INDEX), bLRWTestEnabled);

			if (idTestCipher == -1)
				idTestCipher = (int) lParam;

			SendMessage (GetDlgItem (hwndDlg, IDC_CIPHER), CB_RESETCONTENT, 0, 0);
			for (ea = EAGetFirst (); ea != 0; ea = EAGetNext (ea))
			{
				if (EAGetCipherCount (ea) == 1 && EAGetFirstMode (ea) == LRW)
					AddComboPair (GetDlgItem (hwndDlg, IDC_CIPHER), EAGetName (buf, ea), ea);
			}

			ResetCipherTest(hwndDlg, idTestCipher);

			SelectAlgo (GetDlgItem (hwndDlg, IDC_CIPHER), &idTestCipher);

			return 1;
		}

	case WM_COMMAND:

		if (hw == CBN_SELCHANGE && lw == IDC_CIPHER)
		{
			idTestCipher = (int) SendMessage (GetDlgItem (hwndDlg, IDC_CIPHER), CB_GETITEMDATA, SendMessage (GetDlgItem (hwndDlg, IDC_CIPHER), CB_GETCURSEL, 0, 0), 0);
			ResetCipherTest(hwndDlg, idTestCipher);
			SendMessage (hwndDlg, WM_INITDIALOG, 0, 0);
			return 1;
		}

		if (hw == CBN_SELCHANGE && lw == IDC_KEY_SIZE)
		{
			// NOP
			return 1;
		}

		if (lw == IDC_RESET)
		{
			ResetCipherTest(hwndDlg, idTestCipher);

			return 1;
		}

		if (lw == IDC_AUTO)
		{
			if (!AutoTestAlgorithms())
			{
				ShowWindow(GetDlgItem(hwndDlg, IDC_TESTS_MESSAGE), SW_SHOWNORMAL);
				SetWindowTextW(GetDlgItem(hwndDlg, IDC_TESTS_MESSAGE), GetString ("TESTS_FAILED"));
			} 
			else
			{
				ShowWindow(GetDlgItem(hwndDlg, IDC_TESTS_MESSAGE), SW_SHOWNORMAL);
				SetWindowTextW(GetDlgItem(hwndDlg, IDC_TESTS_MESSAGE), GetString ("TESTS_PASSED"));
				ShowWindow(GetDlgItem(hwndDlg, IDC_REDTICK), SW_SHOWNORMAL);
			}

			return 1;

		}

		if (lw == IDC_LRW_MODE_ENABLED)
		{
			bLRWTestEnabled = GetCheckBox (hwndDlg, IDC_LRW_MODE_ENABLED);
			EnableWindow (GetDlgItem (hwndDlg, IDC_LRW_KEY), bLRWTestEnabled);
			EnableWindow (GetDlgItem (hwndDlg, IDT_LRW_KEY), bLRWTestEnabled);
			EnableWindow (GetDlgItem (hwndDlg, IDT_LRW_BLOCK_INDEX), bLRWTestEnabled);
			EnableWindow (GetDlgItem (hwndDlg, IDC_LRW_BLOCK_INDEX), bLRWTestEnabled);
			EnableWindow (GetDlgItem (hwndDlg, IDC_LRW_INDEX_LSB), bLRWTestEnabled);
			EnableWindow (GetDlgItem (hwndDlg, IDC_KEY_SIZE), !bLRWTestEnabled);
			if (bLRWTestEnabled)
				SendMessage(GetDlgItem(hwndDlg, IDC_KEY_SIZE), CB_SETCURSEL, 0,0);
		}

		if (lw == IDOK || lw == IDC_ENCRYPT || lw == IDC_DECRYPT)
		{
			char key[128], inputtext[128], lrwKey[16], lrwIndex[16], szTmp[128];
			int ks, pt, n;
			BOOL bEncrypt;

			ShowWindow(GetDlgItem(hwndDlg, IDC_TESTS_MESSAGE), SW_HIDE);
			ShowWindow(GetDlgItem(hwndDlg, IDC_REDTICK), SW_HIDE);

			ks = (int) SendMessage(GetDlgItem(hwndDlg, IDC_KEY_SIZE), CB_GETCURSEL, 0,0);
			ks = (int) SendMessage(GetDlgItem(hwndDlg, IDC_KEY_SIZE), CB_GETITEMDATA, ks,0);
			pt = (int) SendMessage(GetDlgItem(hwndDlg, IDC_PLAINTEXT_SIZE), CB_GETITEMDATA, 0,0);

			bEncrypt = lw == IDC_ENCRYPT;

			memset(key,0,sizeof(key));
			memset(szTmp,0,sizeof(szTmp));
			n = GetWindowText(GetDlgItem(hwndDlg, IDC_KEY), szTmp, sizeof(szTmp));
			if (n != ks * 2)
			{
				MessageBoxW (hwndDlg, GetString ("TEST_KEY_SIZE"), lpszTitle, ICON_HAND);
				return 1;
			}

			for (n = 0; n < ks; n ++)
			{
				char szTmp2[3], *ptr;
				long x;

				szTmp2[2] = 0;
				szTmp2[0] = szTmp[n * 2];
				szTmp2[1] = szTmp[n * 2 + 1];

				x = strtol(szTmp2, &ptr, 16);

				key[n] = (char) x;
			}

			memset(inputtext, 0, sizeof(inputtext));
			memset(lrwKey, 0, sizeof(lrwKey));
			memset(lrwIndex, 0, sizeof(lrwIndex));
			memset(szTmp, 0, sizeof(szTmp));

			if (bEncrypt)
			{
				n = GetWindowText(GetDlgItem(hwndDlg, IDC_PLAINTEXT), szTmp, sizeof(szTmp));
			}
			else
			{
				n = GetWindowText(GetDlgItem(hwndDlg, IDC_CIPHERTEXT), szTmp, sizeof(szTmp));
			}

			if (n != pt * 2)
			{
				if (bEncrypt)
				{
					MessageBoxW (hwndDlg, GetString ("TEST_PLAINTEXT_SIZE"), lpszTitle, ICON_HAND);
					return 1;
				}
				else
				{
					MessageBoxW (hwndDlg, GetString ("TEST_CIPHERTEXT_SIZE"), lpszTitle, ICON_HAND);
					return 1;
				}
			}

			for (n = 0; n < pt; n ++)
			{
				char szTmp2[3], *ptr;
				long x;

				szTmp2[2] = 0;
				szTmp2[0] = szTmp[n * 2];
				szTmp2[1] = szTmp[n * 2 + 1];

				x = strtol(szTmp2, &ptr, 16);

				inputtext[n] = (char) x;
			}
			
			// LRW
			if (bLRWTestEnabled)
			{
				if (GetWindowText(GetDlgItem(hwndDlg, IDC_LRW_KEY), szTmp, sizeof(szTmp)) != pt * 2)
				{
					Warning ("TEST_INCORRECT_LRW_KEY_SIZE");
					return 1;
				}

				// LRW key

				for (n = 0; n < pt; n ++)
				{
					char szTmp2[3], *ptr;
					long x;

					szTmp2[2] = 0;
					szTmp2[0] = szTmp[n * 2];
					szTmp2[1] = szTmp[n * 2 + 1];

					x = strtol(szTmp2, &ptr, 16);

					lrwKey[n] = (char) x;
				}

				// LRW block index

				if (GetWindowText(GetDlgItem(hwndDlg, IDC_LRW_BLOCK_INDEX), szTmp, sizeof(szTmp)) != pt * 2)
				{
					Warning ("TEST_INCORRECT_LRW_INDEX_SIZE");
					return 1;
				}
				for (n = 0; n < pt; n ++)
				{
					char szTmp2[3], *ptr;
					long x;

					szTmp2[2] = 0;
					szTmp2[0] = szTmp[n * 2];
					szTmp2[1] = szTmp[n * 2 + 1];

					x = strtol(szTmp2, &ptr, 16);

					lrwIndex[n] = (char) x;
				}

				if (GetCheckBox (hwndDlg, IDC_LRW_INDEX_LSB))
				{
					if (pt == 8)
						MirrorBits64 (lrwIndex);
					else if (pt == 16)
						MirrorBits128 (lrwIndex);
				}
			}

			
			/* Perform the actual tests */

			if (ks != CB_ERR && pt != CB_ERR) 
			{
				char tmp[128];
				int tmpRetVal;

				/* Copy the plain/ciphertext */
				memcpy(tmp,inputtext, pt);

				if (bLRWTestEnabled)
				{
					/* LRW mode */

					ci = crypto_open ();
					if (!ci)
						return 1;

					ci->mode = LRW;
					ci->ea = idTestCipher;

					if (idTestCipher == BLOWFISH)
					{
						/* Convert to little-endian, this is needed here and not in
						above auto-tests because BF_ecb_encrypt above correctly converts
						from big to little endian, and EncipherBlock does not! */
						LongReverse((void*)tmp, pt);
					}

					if ((tmpRetVal = EAInit (ci->ea, key, ci->ks)) != 0)
					{
						handleError (hwndDlg, tmpRetVal);
						return 1;
					}

					memcpy (&ci->iv, lrwKey, sizeof (lrwKey));
					if (!EAInitMode (ci))
						return 1;

					if (pt == 16)
					{
						if (((unsigned __int64 *)lrwIndex)[0])
						{
							Error ("TEST_LRW_INDEX_OVERRUN");
							return 1;
						}

						if (bEncrypt)
							EncryptBufferLRW128 (tmp, pt, BE64(((unsigned __int64 *)lrwIndex)[1]), ci);
						else
							DecryptBufferLRW128 (tmp, pt, BE64(((unsigned __int64 *)lrwIndex)[1]), ci);
					}
					else if (pt == 8)
					{
						if (bEncrypt)
							EncryptBufferLRW64 (tmp, pt, BE64(((unsigned __int64 *)lrwIndex)[0]), ci);
						else
							DecryptBufferLRW64 (tmp, pt, BE64(((unsigned __int64 *)lrwIndex)[0]), ci);
					}

					if (idTestCipher == BLOWFISH)
					{
						/* Convert to little-endian, this is needed here and not in
						above auto-tests because BF_ecb_encrypt above correctly converts
						from big to little endian, and EncipherBlock does not! */
						LongReverse((void*)tmp, pt);
					}

					crypto_close (ci);
				}
				else
				{
					if (idTestCipher == BLOWFISH)
					{
						/* Convert to little-endian, this is needed here and not in
						above auto-tests because BF_ecb_encrypt above correctly converts
						from big to little endian, and EncipherBlock does not! */
						LongReverse((void*)tmp, pt);
					}

					CipherInit2(idTestCipher, key, ks_tmp, ks);

					if (bEncrypt)
					{
						EncipherBlock(idTestCipher, tmp, ks_tmp);
					}
					else
					{
						DecipherBlock(idTestCipher, tmp, ks_tmp);
					}

					if (idTestCipher == BLOWFISH)
					{
						/* Convert back to big-endian */
						LongReverse((void*)tmp, pt);
					}
				}
				*szTmp = 0;

				for (n = 0; n < pt; n ++)
				{
					char szTmp2[3];
					sprintf(szTmp2, "%02x", (int)((unsigned char)tmp[n]));
					strcat(szTmp, szTmp2);
				}

				if (bEncrypt)
					SetWindowText(GetDlgItem(hwndDlg,IDC_CIPHERTEXT), szTmp);
				else
					SetWindowText(GetDlgItem(hwndDlg,IDC_PLAINTEXT), szTmp);
			}

			return 1;
		}

		if (lw == IDCLOSE || lw == IDCANCEL)
		{
			idTestCipher = -1;
			EndDialog (hwndDlg, 0);
			return 1;
		}
		break;

	case WM_CLOSE:
		idTestCipher = -1;
		EndDialog (hwndDlg, 0);
		return 1;
	}

	return 0;
}

void 
ResetCipherTest(HWND hwndDlg, int idTestCipher)
{
	int ndx;

	ShowWindow(GetDlgItem(hwndDlg, IDC_TESTS_MESSAGE), SW_HIDE);
	ShowWindow(GetDlgItem(hwndDlg, IDC_REDTICK), SW_HIDE);

	if (idTestCipher == BLOWFISH && !GetCheckBox (hwndDlg, IDC_LRW_MODE_ENABLED))
		EnableWindow(GetDlgItem(hwndDlg,IDC_KEY_SIZE), TRUE);
	else
		EnableWindow(GetDlgItem(hwndDlg,IDC_KEY_SIZE), FALSE);

	/* Setup the keysize and plaintext sizes for the selected cipher */

	SendMessage (GetDlgItem(hwndDlg, IDC_PLAINTEXT_SIZE), CB_RESETCONTENT, 0,0);
	SendMessage (GetDlgItem(hwndDlg, IDC_KEY_SIZE), CB_RESETCONTENT, 0,0);

	ndx = SendMessage (GetDlgItem(hwndDlg, IDC_PLAINTEXT_SIZE), CB_ADDSTRING, 0,(LPARAM) "64");
	SendMessage(GetDlgItem(hwndDlg, IDC_PLAINTEXT_SIZE), CB_SETITEMDATA, ndx,(LPARAM) 8);
	SendMessage(GetDlgItem(hwndDlg, IDC_PLAINTEXT_SIZE), CB_SETCURSEL, ndx,0);

	SetWindowText(GetDlgItem(hwndDlg, IDC_LRW_KEY), "0000000000000000");
	SetWindowText(GetDlgItem(hwndDlg, IDC_LRW_BLOCK_INDEX), "0000000000000000");

	if (idTestCipher == BLOWFISH)
	{
		ndx = SendMessage (GetDlgItem(hwndDlg, IDC_KEY_SIZE), CB_ADDSTRING, 0,(LPARAM) "448");
		SendMessage(GetDlgItem(hwndDlg, IDC_KEY_SIZE), CB_SETITEMDATA, ndx,(LPARAM) 56);
		ndx = SendMessage (GetDlgItem(hwndDlg, IDC_KEY_SIZE), CB_ADDSTRING, 0,(LPARAM) "256");
		SendMessage(GetDlgItem(hwndDlg, IDC_KEY_SIZE), CB_SETITEMDATA, ndx,(LPARAM) 32);
		ndx = SendMessage (GetDlgItem(hwndDlg, IDC_KEY_SIZE), CB_ADDSTRING, 0,(LPARAM) "128");
		SendMessage(GetDlgItem(hwndDlg, IDC_KEY_SIZE), CB_SETITEMDATA, ndx,(LPARAM) 16);
		ndx = SendMessage (GetDlgItem(hwndDlg, IDC_KEY_SIZE), CB_ADDSTRING, 0,(LPARAM) "64");
		SendMessage(GetDlgItem(hwndDlg, IDC_KEY_SIZE), CB_SETITEMDATA, ndx,(LPARAM) 8);
		SendMessage(GetDlgItem(hwndDlg, IDC_KEY_SIZE), CB_SETCURSEL, 0,0);
		SetWindowText(GetDlgItem(hwndDlg, IDC_KEY), "0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000");
	} 


	if (idTestCipher == CAST)
	{
		ndx = SendMessage (GetDlgItem(hwndDlg, IDC_KEY_SIZE), CB_ADDSTRING, 0,(LPARAM) "128");
		SendMessage(GetDlgItem(hwndDlg, IDC_KEY_SIZE), CB_SETITEMDATA, ndx,(LPARAM) 16);
		SendMessage(GetDlgItem(hwndDlg, IDC_KEY_SIZE), CB_SETCURSEL, ndx,0);
		SetWindowText(GetDlgItem(hwndDlg, IDC_KEY), "00000000000000000000000000000000");
	}

	if (idTestCipher == TRIPLEDES)
	{
		ndx = SendMessage (GetDlgItem(hwndDlg, IDC_KEY_SIZE), CB_ADDSTRING, 0,(LPARAM) "168");
		SendMessage(GetDlgItem(hwndDlg, IDC_KEY_SIZE), CB_SETITEMDATA, ndx,(LPARAM) 24);
		SendMessage(GetDlgItem(hwndDlg, IDC_KEY_SIZE), CB_SETCURSEL, ndx,0);
		SetWindowText(GetDlgItem(hwndDlg, IDC_KEY), "000000000000000000000000000000000000000000000000");
	}

	if (idTestCipher == DES56)
	{
		ndx = SendMessage (GetDlgItem(hwndDlg, IDC_KEY_SIZE), CB_ADDSTRING, 0,(LPARAM) "56");
		SendMessage(GetDlgItem(hwndDlg, IDC_KEY_SIZE), CB_SETITEMDATA, ndx,(LPARAM) 7);
		SendMessage(GetDlgItem(hwndDlg, IDC_KEY_SIZE), CB_SETCURSEL, 0,0);
		SetWindowText(GetDlgItem(hwndDlg, IDC_KEY), "0000000000000000");
	}
	
	SetWindowText(GetDlgItem(hwndDlg, IDC_PLAINTEXT), "0000000000000000");
	SetWindowText(GetDlgItem(hwndDlg, IDC_CIPHERTEXT), "0000000000000000");

	if (idTestCipher == AES || idTestCipher == SERPENT || idTestCipher == TWOFISH)
	{
		ndx = SendMessage (GetDlgItem(hwndDlg, IDC_KEY_SIZE), CB_ADDSTRING, 0,(LPARAM) "256");
		SendMessage(GetDlgItem(hwndDlg, IDC_KEY_SIZE), CB_SETITEMDATA, ndx,(LPARAM) 32);
		SendMessage(GetDlgItem(hwndDlg, IDC_KEY_SIZE), CB_SETCURSEL, ndx,0);

		SendMessage (GetDlgItem(hwndDlg, IDC_PLAINTEXT_SIZE), CB_RESETCONTENT, 0,0);
		ndx = SendMessage (GetDlgItem(hwndDlg, IDC_PLAINTEXT_SIZE), CB_ADDSTRING, 0,(LPARAM) "128");
		SendMessage(GetDlgItem(hwndDlg, IDC_PLAINTEXT_SIZE), CB_SETITEMDATA, ndx,(LPARAM) 16);
		SendMessage(GetDlgItem(hwndDlg, IDC_PLAINTEXT_SIZE), CB_SETCURSEL, ndx,0);

		SetWindowText(GetDlgItem(hwndDlg, IDC_KEY), "0000000000000000000000000000000000000000000000000000000000000000");
		SetWindowText(GetDlgItem(hwndDlg, IDC_PLAINTEXT), "00000000000000000000000000000000");
		SetWindowText(GetDlgItem(hwndDlg, IDC_CIPHERTEXT), "00000000000000000000000000000000");

		SetWindowText(GetDlgItem(hwndDlg, IDC_LRW_KEY), "00000000000000000000000000000000");
		SetWindowText(GetDlgItem(hwndDlg, IDC_LRW_BLOCK_INDEX), "00000000000000000000000000000000");
	}
}

#endif	// #ifndef SETUP


BOOL CheckCapsLock (HWND hwnd, BOOL quiet)
{
	if ((GetKeyState(VK_CAPITAL) & 1) != 0)	
	{
		if (!quiet)
		{
			MessageBoxW (hwnd, GetString ("CAPSLOCK_ON"), lpszTitle, MB_ICONEXCLAMATION);
		}
		return TRUE;
	}
	return FALSE;
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


// Use only cached passwords if password = NULL
//
// Returns:
// -1 = user aborted mount / error
// 0  = mount failed
// 1  = mount OK
// 2  = mount OK in shared mode

int MountVolume (HWND hwndDlg,
				 int driveNo,
				 char *volumePath,
				 Password *password,
				 BOOL cachePassword,
				 BOOL sharedAccess,
				 MountOptions *mountOptions,
				 BOOL quiet,
				 BOOL bReportWrongPassword)
{
	MOUNT_STRUCT mount;
	DWORD dwResult;
	BOOL bResult, bDevice;

	if (IsMountedVolume (volumePath))
	{
		if (!quiet)
			MessageBoxW(0, GetString ("ALREADY_MOUNTED"), lpszTitle, MB_ICONASTERISK);
		return -1;
	}

	if (!IsDriveAvailable (driveNo))
		return -1;

	// If using cached passwords, check cache status first
	if (password == NULL && IsPasswordCacheEmpty ())
		return 0;

	ZeroMemory (&mount, sizeof (mount));
	mount.bExclusiveAccess = sharedAccess ? FALSE : TRUE;
retry:
	mount.nDosDriveNo = driveNo;
	mount.bCache = cachePassword;

	if (password != NULL)
		mount.VolumePassword = *password;
	else
		mount.VolumePassword.Length = 0;

	if (!mountOptions->ReadOnly && mountOptions->ProtectHiddenVolume)
	{
		mount.ProtectedHidVolPassword = mountOptions->ProtectedHidVolPassword;
		mount.bProtectHiddenVolume = TRUE;
	}
	else
		mount.bProtectHiddenVolume = FALSE;

	mount.bMountReadOnly = mountOptions->ReadOnly;
	mount.bMountRemovable = mountOptions->Removable;
	mount.bSystemVolume = mountOptions->SystemVolume;
	mount.bPersistentVolume = mountOptions->PersistentVolume;
	mount.bPreserveTimestamp = mountOptions->PreserveTimestamp;

	mount.bMountManager = TRUE;

	// Windows 2000 mount manager causes problems with remounted volumes
	if (CurrentOSMajor == 5 && CurrentOSMinor == 0)
		mount.bMountManager = FALSE;

	CreateFullVolumePath ((char *) mount.wszVolume, volumePath, &bDevice);

	// UNC path
	if (volumePath[0] == '\\' && volumePath[1] == '\\')
	{
		_snprintf ((char *)mount.wszVolume, MAX_PATH, "UNC%s", volumePath + 1);
		mount.bUserContext = TRUE;
	}

	// Network drive
	if (volumePath[1] == ':')
	{
		char root[] = { volumePath[0], ':', '\\', 0 };

		if (GetDriveType (root) == DRIVE_REMOTE)
			mount.bUserContext = TRUE;
	}

	ToUNICODE ((char *) mount.wszVolume);

	bResult = DeviceIoControl (hDriver, MOUNT, &mount,
		sizeof (mount), &mount, sizeof (mount), &dwResult, NULL);

	burn (&mount.VolumePassword, sizeof (mount.VolumePassword));
	burn (&mount.ProtectedHidVolPassword, sizeof (mount.ProtectedHidVolPassword));

	if (bResult == FALSE)
	{
		// Volume already open by another process
		if (GetLastError () == ERROR_SHARING_VIOLATION)
		{
			if (mount.bExclusiveAccess == FALSE)
			{
				if (!quiet)
					MessageBoxW (hwndDlg, GetString ("FILE_IN_USE_FAILED"),
						lpszTitle, MB_ICONSTOP);

				return -1;
			}
			else
			{
				if (quiet)
				{
					mount.bExclusiveAccess = FALSE;
					goto retry;
				}

				// Ask user 
				if (IDYES == MessageBoxW (hwndDlg, GetString ("FILE_IN_USE"),
					lpszTitle, MB_YESNO | MB_DEFBUTTON2 | MB_ICONEXCLAMATION))
				{
					mount.bExclusiveAccess = FALSE;
					goto retry;
				}
			}

			return -1;
		}

		// Mount failed in kernel space => retry in user process context
		if (!mount.bUserContext)
		{
			mount.bUserContext = TRUE;
			goto retry;
		}

		if (!quiet)
			handleWin32Error (hwndDlg);

		return -1;
	}

	if (mount.nReturnCode != 0)
	{
		if (mount.nReturnCode == ERR_PASSWORD_WRONG)
		{
			// Do not report wrong password, if not instructed to 
			if (bReportWrongPassword)
				handleError (hwndDlg, mount.nReturnCode);

			return 0;
		}

		if (!quiet)
			handleError (hwndDlg, mount.nReturnCode);

		return 0;
	}

	BroadcastDeviceChange (DBT_DEVICEARRIVAL, driveNo, 0);

	if (mount.bExclusiveAccess == FALSE)
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
		if (result == ERR_FILES_OPEN && !Silent)
		{
			if (IDYES == AskWarnNoYes("UNMOUNT_LOCK_FAILED"))
			{
				forced = TRUE;
				goto retry;
			}

			return FALSE;
		}

		Error ("UNMOUNT_FAILED");

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

	if (strstr (volname, "\\Device\\") != volname)
		sprintf(volume, "\\??\\%s", volname);
	ToUNICODE (volume);

	memset (&mlist, 0, sizeof (mlist));
	DeviceIoControl (hDriver, MOUNT_LIST, &mlist,
		sizeof (mlist), &mlist, sizeof (mlist), &dwResult,
		NULL);

	for (i=0 ; i<26; i++)
		if (0 == wcscmp (mlist.wszVolume[i], (WCHAR *)volume))
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

int BackupVolumeHeader (HWND hwndDlg, BOOL bRequireConfirmation, char *lpszVolume)
{
	int nDosLinkCreated = 0, nStatus;
	char szDiskFile[TC_MAX_PATH], szCFDevice[TC_MAX_PATH];
	char szFileName[TC_MAX_PATH];
	char szDosDevice[TC_MAX_PATH];
	char buffer[HEADER_SIZE];
	void *dev = INVALID_HANDLE_VALUE;
	DWORD dwError;
	BOOL bDevice;
	unsigned __int64 volSize = 0;
	wchar_t szTmp[1024];
	int volumeType;
	int fBackup = -1;


	if (IsMountedVolume (lpszVolume))
	{
		Warning ("DISMOUNT_FIRST");
		return 0;
	}

	wsprintfW (szTmp, GetString ("CONFIRM_VOL_HEADER_BAK"), lpszVolume);

	if (bRequireConfirmation 
		&& (MessageBoxW (hwndDlg, szTmp, lpszTitle, YES_NO|MB_ICONQUESTION|MB_DEFBUTTON1) == IDNO))
		return 0;


	/* Select backup file */
	if (!BrowseFiles (hwndDlg, "OPEN_TITLE", szFileName, FALSE, TRUE))
		return 0;

	/* Conceive the backup file */
	if ((fBackup = _open(szFileName, _O_CREAT|_O_TRUNC|_O_WRONLY|_O_BINARY, _S_IREAD|_S_IWRITE)) == -1)
		return ERROR_CANNOT_MAKE;


	/* Read the volume headers and write them to the backup file */

	CreateFullVolumePath (szDiskFile, lpszVolume, &bDevice);

	if (bDevice == FALSE)
	{
		strcpy (szCFDevice, szDiskFile);
	}
	else
	{
		nDosLinkCreated = FakeDosNameForDevice (szDiskFile, szDosDevice, szCFDevice, FALSE);
		if (nDosLinkCreated != 0)
		{
			nStatus = nDosLinkCreated;
			goto error0;
		}
	}

	dev = CreateFile (szCFDevice, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);

	if (bDevice)
	{
		/* This is necessary to determine the hidden volume header offset */

		if (dev == INVALID_HANDLE_VALUE)
		{
			nStatus = ERR_OS_ERROR;
			goto error0;
		}
		else
		{
			PARTITION_INFORMATION diskInfo;
			DWORD dwResult;
			BOOL bResult;

			bResult = DeviceIoControl (dev, IOCTL_DISK_GET_PARTITION_INFO, NULL, 0,
				&diskInfo, sizeof (diskInfo), &dwResult, NULL);

			if (bResult)
			{
				volSize = diskInfo.PartitionLength.QuadPart;
			}
			else
			{
				DISK_GEOMETRY driveInfo;

				bResult = DeviceIoControl (dev, IOCTL_DISK_GET_DRIVE_GEOMETRY, NULL, 0,
					&driveInfo, sizeof (driveInfo), &dwResult, NULL);

				if (!bResult)
				{
					nStatus = ERR_OS_ERROR;
					goto error;
				}

				volSize = driveInfo.Cylinders.QuadPart * driveInfo.BytesPerSector *
					driveInfo.SectorsPerTrack * driveInfo.TracksPerCylinder;
			}

			if (volSize == 0)
			{
				nStatus = ERR_VOL_SIZE_WRONG;
				goto error;
			}
		}
	}

	if (dev == INVALID_HANDLE_VALUE) return ERR_OS_ERROR;

	for (volumeType = VOLUME_TYPE_NORMAL; volumeType < NBR_VOLUME_TYPES; volumeType++)
	{
		/* Read in volume header */

		if (volumeType == VOLUME_TYPE_HIDDEN)
		{
			if (!SeekHiddenVolHeader ((HFILE) dev, volSize, bDevice))
			{
				nStatus = ERR_VOL_SEEKING;
				goto error;
			}
		}

		nStatus = _lread ((HFILE) dev, buffer, sizeof (buffer));
		if (nStatus != sizeof (buffer))
		{
			nStatus = ERR_VOL_SIZE_WRONG;
			goto error;
		}

		/* Write the header to the backup file */

		if (_write (fBackup, buffer, sizeof(buffer)) == -1)
			goto error;
	}

	/* Backup has been successfully created */
	nStatus = 0;
	Info("VOL_HEADER_BACKED_UP");

error:

	dwError = GetLastError ();

	CloseHandle ((HANDLE) dev);
	_close (fBackup);

	if (bDevice && nDosLinkCreated != 0)
	{
		int x = RemoveFakeDosName (szDiskFile, szDosDevice);
		if (x != 0)
		{
			dwError = GetLastError ();
			nStatus = x;
		}
	}

	SetLastError (dwError);

	return nStatus;

error0:

	dwError = GetLastError ();
	_close (fBackup);
	SetLastError (dwError);

	return nStatus;
}

int RestoreVolumeHeader (HWND hwndDlg, char *lpszVolume)
{
	int nDosLinkCreated = 0, nStatus = 0;
	char szDiskFile[TC_MAX_PATH], szCFDevice[TC_MAX_PATH];
	char szFileName[TC_MAX_PATH];
	char szDosDevice[TC_MAX_PATH];
	char buffer[HEADER_SIZE];
	void *dev = INVALID_HANDLE_VALUE;
	DWORD dwError;
	BOOL bDevice;
	unsigned __int64 volSize = 0;
	FILETIME ftCreationTime;
	FILETIME ftLastWriteTime;
	FILETIME ftLastAccessTime;
	wchar_t szTmp[1024];
	BOOL bRestoreHiddenVolHeader = FALSE;
	BOOL bTimeStampValid = FALSE;
	int fBackup = -1;


	if (IsMountedVolume (lpszVolume))
	{
		Warning ("DISMOUNT_FIRST");
		return 0;
	}

	wsprintfW (szTmp, GetString ("CONFIRM_VOL_HEADER_RESTORE"), lpszVolume);

	if (MessageBoxW (hwndDlg, szTmp, lpszTitle, YES_NO|MB_ICONWARNING|MB_DEFBUTTON2) == IDNO)
		return 0;


	/* Select backup file */
	if (!BrowseFiles (hwndDlg, "OPEN_TITLE", szFileName, FALSE, FALSE))
		return 0;


	if (AskNoYes("CONFIRM_HIDVOL_HEADER_RESTORE") == IDYES)
		bRestoreHiddenVolHeader = TRUE;


	/* Open the backup file */
	if ((fBackup = _open(szFileName, _O_BINARY|_O_RDONLY)) == -1)
		return ERROR_OPEN_FAILED;


	CreateFullVolumePath (szDiskFile, lpszVolume, &bDevice);

	if (bDevice == FALSE)
	{
		strcpy (szCFDevice, szDiskFile);
	}
	else
	{
		nDosLinkCreated = FakeDosNameForDevice (szDiskFile, szDosDevice, szCFDevice, FALSE);
		if (nDosLinkCreated != 0)
		{
			nStatus = nDosLinkCreated;
			goto error0;
		}
	}

	dev = CreateFile (szCFDevice, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);

	if (bDevice)
	{
		/* This is necessary to determine the hidden volume header offset */

		if (dev == INVALID_HANDLE_VALUE)
		{
			nStatus = ERR_OS_ERROR;
			goto error0;
		}
		else
		{
			PARTITION_INFORMATION diskInfo;
			DWORD dwResult;
			BOOL bResult;

			bResult = DeviceIoControl (dev, IOCTL_DISK_GET_PARTITION_INFO, NULL, 0,
				&diskInfo, sizeof (diskInfo), &dwResult, NULL);

			if (bResult)
			{
				volSize = diskInfo.PartitionLength.QuadPart;
			}
			else
			{
				DISK_GEOMETRY driveInfo;

				bResult = DeviceIoControl (dev, IOCTL_DISK_GET_DRIVE_GEOMETRY, NULL, 0,
					&driveInfo, sizeof (driveInfo), &dwResult, NULL);

				if (!bResult)
				{
					nStatus = ERR_OS_ERROR;
					goto error;
				}

				volSize = driveInfo.Cylinders.QuadPart * driveInfo.BytesPerSector *
					driveInfo.SectorsPerTrack * driveInfo.TracksPerCylinder;
			}

			if (volSize == 0)
			{
				nStatus =  ERR_VOL_SIZE_WRONG;
				goto error;
			}
		}
	}

	if (dev == INVALID_HANDLE_VALUE) 
		return ERR_OS_ERROR;

	if (!bDevice && bPreserveTimestamp)
	{
		/* Remember the container modification/creation date and time. */

		if (GetFileTime ((HANDLE) dev, &ftCreationTime, &ftLastAccessTime, &ftLastWriteTime) == 0)
		{
			bTimeStampValid = FALSE;
			Warning ("GETFILETIME_FAILED_GENERIC");
		}
		else
			bTimeStampValid = TRUE;
	}

	/* Read the volume header from the backup file */

	if (_lseek(fBackup, bRestoreHiddenVolHeader ? HEADER_SIZE : 0, SEEK_SET) == -1L)
	{
		nStatus = ERROR_SEEK;
		goto error;
	}

	if (_read (fBackup, buffer, HEADER_SIZE) == -1)
		goto error;


	/* Restore/write the volume header */

	// Seek
	if (bRestoreHiddenVolHeader)
	{
		if (!SeekHiddenVolHeader ((HFILE) dev, volSize, bDevice))
		{
			nStatus = ERR_VOL_SEEKING;
			goto error;
		}
	}
	else
	{
		nStatus = _llseek ((HFILE) dev, 0, FILE_BEGIN);

		if (nStatus != 0)
		{
			nStatus = ERR_VOL_SEEKING;
			goto error;
		}
	}

	// Write
	if ((_lwrite ((HFILE) dev, buffer, HEADER_SIZE)) != HEADER_SIZE)
	{
		nStatus = ERR_VOL_WRITING;
		goto error;
	}

	if (nStatus != 0)
		goto error;


	/* Volume header has been successfully restored */

	nStatus = 0;
	Info("VOL_HEADER_RESTORED");

error:

	dwError = GetLastError ();

	if (bTimeStampValid)
	{
		// Restore the container timestamp (to preserve plausible deniability of possible hidden volume). 
		if (SetFileTime (dev, &ftCreationTime, &ftLastAccessTime, &ftLastWriteTime) == 0)
			MessageBoxW (hwndDlg, GetString ("SETFILETIME_FAILED_PW"), L"TrueCrypt", MB_OK | MB_ICONEXCLAMATION);
	}

	CloseHandle ((HANDLE) dev);
	_close (fBackup);

	if (bDevice && nDosLinkCreated != 0)
	{
		int x = RemoveFakeDosName (szDiskFile, szDosDevice);
		if (x != 0)
		{
			dwError = GetLastError ();
			nStatus = x;
		}
	}

	SetLastError (dwError);

	return nStatus;

error0:

	dwError = GetLastError ();
	_close (fBackup);
	SetLastError (dwError);

	return nStatus;
}

BOOL IsNonInstallMode ()
{
	static int cachedMode = -1;

	if (cachedMode == -1)
	{
		HANDLE fh;
		WIN32_FIND_DATA fd;
		char fileName[TC_MAX_PATH];

		if (!Is64BitOs ())
			GetSystemDirectory (fileName, sizeof (fileName));
		else
			GetWindowsDirectory (fileName, sizeof (fileName));
		strcat (fileName, !Is64BitOs () ? "\\Drivers\\truecrypt.sys" : "\\SysWOW64\\Drivers\\truecrypt.sys");

		fh = FindFirstFile (fileName, &fd);

		if (fh == INVALID_HANDLE_VALUE)
		{
			cachedMode = 1;		
			return TRUE;
		}
		else
			cachedMode = 0;

		FindClose (fh);
	}

	return cachedMode == 1;
}


LRESULT SetCheckBox (HWND hwndDlg, int dlgItem, BOOL state)
{
	return SendDlgItemMessage (hwndDlg, dlgItem, BM_SETCHECK, state ? BST_CHECKED : BST_UNCHECKED, 0);
}


BOOL GetCheckBox (HWND hwndDlg, int dlgItem)
{
	return IsButtonChecked (GetDlgItem (hwndDlg, dlgItem));
}


// Delete the last used Windows file selector path for TrueCrypt from the registry file
// at HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\LastVisitedMRU
void CleanLastVisitedMRU (void)
{
	WCHAR exeFilename[MAX_PATH];
	WCHAR *strToMatch;

	WCHAR strTmp[MAX_PATH*2];
	char key[2] = {0, 0};
	int i, len;

	GetModuleFileNameW (NULL, exeFilename, sizeof (exeFilename));
	strToMatch = wcsrchr (exeFilename, '\\') + 1;

	for (i = 'a'; i <= 'z'; i++)
	{
		*strTmp = 0;
		key [0] = i;
		if ((len = ReadRegistryBytes ("Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\ComDlg32\\LastVisitedMRU",
			key, (char *) strTmp, sizeof (strTmp))) > 0)
		{
			if (wcsstr (strTmp, strToMatch) != NULL) 
			{
				// Overwrite the entry with zeroes while keeping its original size
				memset (strTmp, 0, len);
				if (!WriteRegistryBytes ("Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\ComDlg32\\LastVisitedMRU",
					key, (char *) strTmp, len))
					MessageBoxW (NULL, GetString ("CLEAN_WINMRU_FAILED"), lpszTitle, ICON_HAND);

				// Overwrite the entry with 4 zero bytes
				WriteRegistryBytes ("Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\ComDlg32\\LastVisitedMRU",
					key, (char *) strTmp, 4);
			}
		}
	}
}


LRESULT ListItemAdd (HWND list, int index, char *string)
{
	LVITEM li;
	memset (&li, 0, sizeof(li));

	li.mask = LVIF_TEXT;
	li.pszText = string;
	li.iItem = index; 
	li.iSubItem = 0;
	return ListView_InsertItem (list, &li);
}


LRESULT ListItemAddW (HWND list, int index, wchar_t *string)
{
	LVITEMW li;
	memset (&li, 0, sizeof(li));

	li.mask = LVIF_TEXT;
	li.pszText = string;
	li.iItem = index; 
	li.iSubItem = 0;
	return SendMessageW (list, LVM_INSERTITEMW, 0, (LPARAM)(&li));
}


LRESULT ListSubItemSet (HWND list, int index, int subIndex, char *string)
{
	LVITEM li;
	memset (&li, 0, sizeof(li));

	li.mask = LVIF_TEXT;
	li.pszText = string;
	li.iItem = index; 
	li.iSubItem = subIndex;
	return ListView_SetItem (list, &li);
}


LRESULT ListSubItemSetW (HWND list, int index, int subIndex, wchar_t *string)
{
	LVITEMW li;
	memset (&li, 0, sizeof(li));

	li.mask = LVIF_TEXT;
	li.pszText = string;
	li.iItem = index; 
	li.iSubItem = subIndex;
	return SendMessageW (list, LVM_SETITEMW, 0, (LPARAM)(&li));
}


BOOL GetMountList (MOUNT_LIST_STRUCT *list)
{
	DWORD dwResult;

	memset (list, 0, sizeof (*list));
	return DeviceIoControl (hDriver, MOUNT_LIST, list,
		sizeof (*list), list, sizeof (*list), &dwResult,
		NULL);
}


int GetDriverRefCount ()
{
	DWORD dwResult;
	BOOL bResult;
	int refCount;

	bResult = DeviceIoControl (hDriver, DEVICE_REFCOUNT, &refCount, sizeof (refCount), &refCount,
		sizeof (refCount), &dwResult, NULL);

	if (bResult)
		return refCount;
	else
		return -1;
}


char *LoadFile (char *fileName, DWORD *size)
{
	char *buf;
	HANDLE h = CreateFile (fileName, GENERIC_READ, 0, NULL, OPEN_EXISTING, 0, NULL);
	if (h == INVALID_HANDLE_VALUE)
		return NULL;

	*size = GetFileSize (h, NULL);
	buf = malloc (*size + 1);
	ZeroMemory (buf, *size + 1);

	if (buf != NULL)
		ReadFile (h, buf, *size, size, NULL);

	CloseHandle (h);
	return buf;
}


char *GetConfigPath (char *fileName)
{
	static char path[MAX_PATH];

	if (!IsNonInstallMode ())
	{
		// User application data folder
		SHGetFolderPath (NULL, CSIDL_APPDATA, NULL, 0, path);
		strcat (path, "\\TrueCrypt\\");
		CreateDirectory (path, NULL);
		strcat (path, fileName);
	}
	else
	{
		// Application directory
		GetModuleFileName (NULL, path, sizeof (path));
		strrchr (path, '\\')[1] = 0;
		strcat (path, fileName);
	}

	return path;
}


int Info (char *stringId)
{
	if (Silent) return 0;
	return MessageBoxW (MainDlg, GetString (stringId), lpszTitle, MB_ICONINFORMATION | MB_SETFOREGROUND | MB_TOPMOST);
}


int Warning (char *stringId)
{
	if (Silent) return 0;
	return MessageBoxW (MainDlg, GetString (stringId), lpszTitle, MB_ICONWARNING | MB_SETFOREGROUND | MB_TOPMOST);
}


int Error (char *stringId)
{
	if (Silent) return 0;
	return MessageBoxW (MainDlg, GetString (stringId), lpszTitle, MB_ICONERROR | MB_SETFOREGROUND | MB_TOPMOST);
}


int AskYesNo (char *stringId)
{
	if (Silent) return 0;
	return MessageBoxW (MainDlg, GetString (stringId), lpszTitle, MB_ICONQUESTION | MB_YESNO | MB_DEFBUTTON1 | MB_SETFOREGROUND | MB_TOPMOST);
}


int AskNoYes (char *stringId)
{
	if (Silent) return 0;
	return MessageBoxW (MainDlg, GetString (stringId), lpszTitle, MB_ICONQUESTION | MB_YESNO | MB_DEFBUTTON2 | MB_SETFOREGROUND | MB_TOPMOST);
}


int AskWarnYesNo (char *stringId)
{
	if (Silent) return 0;
	return MessageBoxW (MainDlg, GetString (stringId), lpszTitle, MB_ICONWARNING | MB_YESNO | MB_DEFBUTTON1 | MB_SETFOREGROUND | MB_TOPMOST);
}


int AskWarnNoYes (char *stringId)
{
	if (Silent) return 0;
	return MessageBoxW (MainDlg, GetString (stringId), lpszTitle, MB_ICONWARNING | MB_YESNO | MB_DEFBUTTON2 | MB_SETFOREGROUND | MB_TOPMOST);
}


int AskWarnCancelOk (char *stringId)
{
	if (Silent) return 0;
	return MessageBoxW (MainDlg, GetString (stringId), lpszTitle, MB_ICONWARNING | MB_OKCANCEL | MB_DEFBUTTON2 | MB_SETFOREGROUND | MB_TOPMOST);
}


BOOL ConfigWriteBegin ()
{
	DWORD size;
	if (ConfigFileHandle != NULL) return FALSE;

	if (ConfigBuffer == NULL)
		ConfigBuffer = LoadFile (GetConfigPath (FILE_CONFIGURATION), &size);

	ConfigFileHandle = fopen (GetConfigPath (FILE_CONFIGURATION), "w");
	if (ConfigFileHandle == NULL)
	{
		free (ConfigBuffer);
		ConfigBuffer = NULL;
		return FALSE;
	}
	XmlWriteHeader (ConfigFileHandle);
	fputs ("\n\t<configuration>", ConfigFileHandle);

	return TRUE;
}


BOOL ConfigWriteEnd ()
{
	char *xml = ConfigBuffer;
	char key[128], value[2048];

	if (ConfigFileHandle == NULL) return FALSE;

	// Write unmodified values
	while (xml && (xml = XmlFindElement (xml, "config")))
	{
		XmlAttribute (xml, "key", key, sizeof (key));
		XmlNodeText (xml, value, sizeof (value));

		fprintf (ConfigFileHandle, "\n\t\t<config key=\"%s\">%s</config>", key, value);
		xml++;
	}

	fputs ("\n\t</configuration>", ConfigFileHandle);
	XmlWriteFooter (ConfigFileHandle);

	fclose (ConfigFileHandle);
	ConfigFileHandle = NULL;

	if (ConfigBuffer != NULL)
	{
		DWORD size;
		free (ConfigBuffer);
		ConfigBuffer = LoadFile (GetConfigPath (FILE_CONFIGURATION), &size);
	}

	return TRUE;
}


BOOL ConfigWriteString (char *configKey, char *configValue)
{
	char *c;
	if (ConfigFileHandle == NULL)
		return FALSE;

	// Mark previous config value as updated
	if (ConfigBuffer != NULL)
	{
		c = XmlFindElementByAttributeValue (ConfigBuffer, "config", "key", configKey);
		if (c != NULL)
			c[1] = '!';
	}

	return 0 != fprintf (
		ConfigFileHandle, "\n\t\t<config key=\"%s\">%s</config>",
		configKey, configValue);
}


BOOL ConfigWriteInt (char *configKey, int configValue)
{
	char val[32];
	sprintf (val, "%d", configValue);
	return ConfigWriteString (configKey, val);
}


static BOOL ConfigRead (char *configKey, char *configValue, int maxValueSize)
{
	DWORD size;
	char *xml;

	if (ConfigBuffer == NULL)
		ConfigBuffer = LoadFile (GetConfigPath (FILE_CONFIGURATION), &size);

	xml = ConfigBuffer;
	if (xml != NULL)
	{
		xml = XmlFindElementByAttributeValue (xml, "config", "key", configKey);
		if (xml != NULL)
		{
			XmlNodeText (xml, configValue, maxValueSize);
			return TRUE;
		}
	}

	return FALSE;
}


int ConfigReadInt (char *configKey, int defaultValue)
{
	char s[32];

	if (ConfigRead (configKey, s, sizeof (s)))
		return atoi (s);
	else
		return defaultValue;
}


char *ConfigReadString (char *configKey, char *defaultValue, char *str, int maxLen)
{
	if (ConfigRead (configKey, str, maxLen))
		return str;
	else
		return defaultValue;
}


void OpenPageHelp (HWND hwndDlg, int nPage)
{
	int r = (int)ShellExecute (NULL, "open", szHelpFile, NULL, NULL, SW_SHOWNORMAL);
	if (nPage);		/* Remove warning */

	if (r == ERROR_FILE_NOT_FOUND)
	{
		// Try the secondary help file
		r = (int)ShellExecute (NULL, "open", szHelpFile2, NULL, NULL, SW_SHOWNORMAL);

		if (r == ERROR_FILE_NOT_FOUND)
			MessageBoxW (hwndDlg, GetString ("HELP_ERROR"), lpszTitle, MB_ICONERROR);
	}
	if (r == SE_ERR_NOASSOC)
		MessageBoxW (hwndDlg, GetString ("HELP_READER_ERROR"), lpszTitle, MB_ICONERROR);
}


#ifndef SETUP

void RestoreDefaultKeyFilesParam (void)
{
	KeyFileRemoveAll (&FirstKeyFile);
	if (defaultKeyFilesParam.FirstKeyFile != NULL)
	{
		FirstKeyFile = KeyFileCloneAll (defaultKeyFilesParam.FirstKeyFile);
		KeyFilesEnable = defaultKeyFilesParam.EnableKeyFiles;
	}
	else
		KeyFilesEnable = FALSE;
}


BOOL LoadDefaultKeyFilesParam (void)
{
	BOOL status = TRUE;
	DWORD size;
	char *defaultKeyfilesFile = LoadFile (GetConfigPath (FILE_DEFAULT_KEYFILES), &size);
	char *xml = defaultKeyfilesFile;
	KeyFile *kf;

	if (xml == NULL) 
		return FALSE;

	KeyFileRemoveAll (&defaultKeyFilesParam.FirstKeyFile);

	while (xml = XmlFindElement (xml, "keyfile"))
	{
		kf = malloc (sizeof (KeyFile));

		if (XmlNodeText (xml, kf->FileName, sizeof (kf->FileName)) != NULL)
			defaultKeyFilesParam.FirstKeyFile = KeyFileAdd (defaultKeyFilesParam.FirstKeyFile, kf);
		else
			free (kf);

		xml++;
	}

	free (defaultKeyfilesFile);
	KeyFilesEnable = defaultKeyFilesParam.EnableKeyFiles;

	return status;
}

#endif /* #ifndef SETUP */


void Debug (char *format, ...)
{
	char buf[1024];
	va_list val;

	va_start(val, format);
	_vsnprintf (buf, sizeof (buf), format, val);
	va_end(val);

	OutputDebugString (buf);
}


void DebugMsgBox (char *format, ...)
{
	char buf[1024];
	va_list val;

	va_start(val, format);
	_vsnprintf (buf, sizeof (buf), format, val);
	va_end(val);

	MessageBox (MainDlg, buf, "TrueCrypt debug", 0);
}


BOOL Is64BitOs ()
{
    static BOOL isWow64 = FALSE;
	static BOOL valid = FALSE;
	typedef BOOL (__stdcall *LPFN_ISWOW64PROCESS ) (HANDLE hProcess,PBOOL Wow64Process);
	LPFN_ISWOW64PROCESS fnIsWow64Process;

	if (valid)
		return isWow64;

	fnIsWow64Process = (LPFN_ISWOW64PROCESS) GetProcAddress (GetModuleHandle("kernel32"), "IsWow64Process");

    if (fnIsWow64Process != NULL)
        if (!fnIsWow64Process (GetCurrentProcess(), &isWow64))
			isWow64 = FALSE;

	valid = TRUE;
    return isWow64;
}


char *RelativePath2Absolute (char *szFileName)
{
	if (szFileName[0] != '\\'
		&& strchr (szFileName, ':') == 0
		&& strstr (szFileName, "Volume{") != szFileName)
	{
		char path[MAX_PATH*2];
		GetCurrentDirectory (MAX_PATH, path);

		if (path[strlen (path) - 1] != '\\')
			strcat (path, "\\");

		strcat (path, szFileName);
		strncpy (szFileName, path, MAX_PATH-1);
	}

	return szFileName;
}


void CheckSystemAutoMount ()
{
	HKEY hkey = 0;
	DWORD value = 0, size = sizeof (DWORD);

	if (RegOpenKeyEx (HKEY_LOCAL_MACHINE, "SYSTEM\\ControlSet001\\Services\\MountMgr",
		0, KEY_READ, &hkey) != ERROR_SUCCESS)
		return;

	if (RegQueryValueEx (hkey, "NoAutoMount", 0, 0, (LPBYTE) &value, &size) == ERROR_SUCCESS
		&& value != 0)
		Warning ("SYS_AUTOMOUNT_DISABLED");
	
	RegCloseKey (hkey);
}


BOOL CALLBACK CloseTCWindowsEnum (HWND hwnd, LPARAM lParam)
{
	if (GetWindowLongPtr (hwnd, GWLP_USERDATA) == (LONG_PTR) 'TRUE')
	{
		char name[32] = { 0 };
		GetWindowText (hwnd, name, sizeof (name) - 1);
		if (hwnd != MainDlg && strstr (name, "TrueCrypt") == name)
		{
			PostMessage (hwnd, WM_ENDSESSION, 0, 0);
			PostMessage (hwnd, WM_CLOSE, 0, 0);

			if (lParam != 0)
				*((BOOL *)lParam) = TRUE;
		}
	}
	return TRUE;
}


BOOL CALLBACK FindTCWindowEnum (HWND hwnd, LPARAM lParam)
{
	if (*(HWND *)lParam == hwnd)
		return TRUE;

	if (GetWindowLongPtr (hwnd, GWLP_USERDATA) == (LONG_PTR) 'TRUE')
	{
		char name[32] = { 0 };
		GetWindowText (hwnd, name, sizeof (name) - 1);
		if (hwnd != MainDlg && strcmp (name, "TrueCrypt") == 0)
		{
			if (lParam != 0)
				*((HWND *)lParam) = hwnd;
		}
	}
	return TRUE;
}


BYTE *MapResource (char *resourceType, int resourceId, PDWORD size)
{
	HGLOBAL hResL; 
    HRSRC hRes;

	hRes = FindResource (NULL, MAKEINTRESOURCE(resourceId), resourceType);
	hResL = LoadResource (NULL, hRes);

	if (size != NULL)
		*size = SizeofResource (NULL, hRes);
  
	return (BYTE *) LockResource (hResL);
}