/*
 Legal Notice: Some portions of the source code contained in this file were
 derived from the source code of Encryption for the Masses 2.02a, which is
 Copyright (c) 1998-2000 Paul Le Roux and which is governed by the 'License
 Agreement for Encryption for the Masses'. Modifications and additions to
 the original source code (contained in this file) and all other portions of
 this file are Copyright (c) 2003-2008 TrueCrypt Foundation and are governed
 by the TrueCrypt License 2.5 the full text of which is contained in the
 file License.txt included in TrueCrypt binary and source code distribution
 packages. */

#include "Tcdefs.h"

#include <dbt.h>
#include <fcntl.h>
#include <io.h>
#include <math.h>
#include <shlobj.h>
#include <sys/stat.h>
#include <stdlib.h>
#include <time.h>

#include "Resource.h"

#include "Apidrvr.h"
#include "BootEncryption.h"
#include "Combo.h"
#include "Crc.h"
#include "Crypto.h"
#include "Dictionary.h"
#include "Dlgcode.h"
#include "EncryptionThreadPool.h"
#include "Endian.h"
#include "Language.h"
#include "Keyfiles.h"
#include "Mount/Mount.h"
#include "Pkcs5.h"
#include "Random.h"
#include "Registry.h"
#include "Tests.h"
#include "Volumes.h"
#include "Wipe.h"
#include "Xml.h"
#include "Xts.h"

using namespace TrueCrypt;

#ifdef VOLFORMAT
#include "Format/Tcformat.h"
#endif

#ifdef SETUP
#include "Setup/Setup.h"
#endif

LONG DriverVersion;

char *LastDialogId;
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

int ScreenDPI = USER_DEFAULT_SCREEN_DPI;
double DPIScaleFactorX = 1;
double DPIScaleFactorY = 1;
double DlgAspectRatio = 1;

HWND MainDlg = NULL;
wchar_t *lpszTitle = NULL;

BOOL Silent = FALSE;
BOOL bPreserveTimestamp = TRUE;
BOOL bStartOnLogon = FALSE;
BOOL bMountDevicesOnLogon = FALSE;
BOOL bMountFavoritesOnLogon = FALSE;

BOOL bHistory = FALSE;

// Status of detection of hidden sectors (whole-system-drive encryption). 
// 0 - Unknown/undetermined/success, 1: Detection is or was in progress (but did not complete e.g. due to system crash).
int HiddenSectorDetectionStatus = 0;	

int nCurrentOS = 0;
int CurrentOSMajor = 0;
int CurrentOSMinor = 0;
int CurrentOSServicePack = 0;
BOOL RemoteSession = FALSE;
BOOL UacElevated = FALSE;

BOOL bTravelerModeConfirmed = FALSE;		// TRUE if it is certain that the instance is running in traveler mode

/* Globals used by Mount and Format (separately per instance) */ 
BOOL KeyFilesEnable = FALSE;
KeyFile	*FirstKeyFile = NULL;
KeyFilesDlgParam		defaultKeyFilesParam;

BOOL IgnoreWmDeviceChange = FALSE;

/* Handle to the device driver */
HANDLE hDriver = INVALID_HANDLE_VALUE;

/* This mutex is used to prevent multiple instances of the wizard or main app from dealing with system encryption */
volatile HANDLE hSysEncMutex = NULL;		

/* This mutex is used to prevent multiple instances of the wizard or main app from trying to install or
register the driver or from trying to launch it in traveler mode at the same time. */
volatile HANDLE hDriverSetupMutex = NULL;

/* This mutex is used to prevent users from running the main TrueCrypt app or the wizard while an instance
of the TrueCrypt installer is running (which is also useful for enforcing restart before the apps can be used). */
volatile HANDLE hAppSetupMutex = NULL;

HINSTANCE hInst = NULL;
HCURSOR hCursor = NULL;

ATOM hDlgClass, hSplashClass;

/* This value may changed only by calling ChangeSystemEncryptionStatus(). Only the wizard can change it
(others may still read it though). */
int SystemEncryptionStatus = SYSENC_STATUS_NONE;	

/* Only the wizard can change this value (others may only read it). */
WipeAlgorithmId nWipeMode = TC_WIPE_NONE;

BOOL bSysPartitionSelected = FALSE;		/* TRUE if the user selected the system partition via the Select Device dialog */
BOOL bSysDriveSelected = FALSE;			/* TRUE if the user selected the system drive via the Select Device dialog */

/* To populate these arrays, call GetSysDevicePaths(). If they contain valid paths, bCachedSysDevicePathsValid is TRUE. */
char SysPartitionDevicePath [TC_MAX_PATH];
char SysDriveDevicePath [TC_MAX_PATH];
char bCachedSysDevicePathsValid = FALSE;
BOOL bRawDevicesDlgProcInstantExit = FALSE;

BOOL bHyperLinkBeingTracked = FALSE;

int WrongPwdRetryCounter = 0;

static FILE *ConfigFileHandle;
char *ConfigBuffer;

#define RANDPOOL_DISPLAY_REFRESH_INTERVAL	30
#define RANDPOOL_DISPLAY_ROWS 20
#define RANDPOOL_DISPLAY_COLUMNS 32

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


void cleanup ()
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
		{
			// If a dismount was forced in the lifetime of the driver, Windows may later prevent it to be loaded again from
			// the same path. Therefore, the driver will not be unloaded even though it was loaded in non-install mode.
			int refDevDeleted;
			DWORD dwResult;

			if (!DeviceIoControl (hDriver, TC_IOCTL_WAS_REFERENCED_DEVICE_DELETED, NULL, 0, &refDevDeleted, sizeof (refDevDeleted), &dwResult, NULL))
				refDevDeleted = 0;

			if (!refDevDeleted)
				DriverUnload ();
			else
			{
				CloseHandle (hDriver);
				hDriver = INVALID_HANDLE_VALUE;
			}
		}
		else
		{
			CloseHandle (hDriver);
			hDriver = INVALID_HANDLE_VALUE;
		}
	}

	if (ConfigBuffer != NULL)
	{
		free (ConfigBuffer);
		ConfigBuffer = NULL;
	}

	CoUninitialize ();

	CloseSysEncMutex ();

#ifndef SETUP
	EncryptionThreadPoolStop();
#endif
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


BOOL IsVolumeDeviceHosted (char *lpszDiskFile)
{
	return strstr (lpszDiskFile, "\\Device\\") == lpszDiskFile
		|| strstr (lpszDiskFile, "\\DEVICE\\") == lpszDiskFile;
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
		return ERR_OS_ERROR;
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
	// Note that this function also causes localcleanup() to be called (see atexit())
	MessageBeep (MB_ICONEXCLAMATION);
	MessageBoxW (NULL, GetString (stringId), lpszTitle, ICON_HAND);
	exit (1);
}

void
AbortProcessSilent (void)
{
	// Note that this function also causes localcleanup() to be called (see atexit())
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

	if (Silent || dwError == 0 || dwError == ERROR_INVALID_WINDOW_HANDLE)
		return dwError;

	// Access denied
	if (dwError == ERROR_ACCESS_DENIED && !IsAdmin ())
	{
		Error ("ERR_ACCESS_DENIED");
		SetLastError (dwError);		// Preserve the original error code
		return dwError;
	}

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

	// User-friendly hardware error explanation
	if (dwError == ERROR_CRC || dwError == ERROR_IO_DEVICE || dwError == ERROR_BAD_CLUSTERS
		|| dwError == ERROR_SEM_TIMEOUT) // Semaphore timeout is sometimes reported instead of an I/O error
	{
		Error ("ERR_HARDWARE_ERROR");
	}

	// Device not ready
	if (dwError == ERROR_NOT_READY)
		CheckSystemAutoMount();

	SetLastError (dwError);		// Preserve the original error code

	return dwError;
}

BOOL
translateWin32Error (wchar_t *lpszMsgBuf, int nWSizeOfBuf)
{
	DWORD dwError = GetLastError ();

	if (FormatMessageW (FORMAT_MESSAGE_FROM_SYSTEM, NULL, dwError,
			   MAKELANGID (LANG_NEUTRAL, SUBLANG_DEFAULT),	/* Default language */
			   lpszMsgBuf, nWSizeOfBuf, NULL))
	{
		SetLastError (dwError);		// Preserve the original error code
		return TRUE;
	}

	SetLastError (dwError);			// Preserve the original error code
	return FALSE;
}


// If the user has a non-default screen DPI, all absolute font sizes must be
// converted using this function.
int CompensateDPIFont (int val)
{
	if (ScreenDPI == USER_DEFAULT_SCREEN_DPI)
		return val;
	else
	{
		double tmpVal = (double) val * DPIScaleFactorY * DlgAspectRatio * 0.999;

		if (tmpVal > 0)
			return (int) floor(tmpVal);
		else
			return (int) ceil(tmpVal);
	}
}


// If the user has a non-default screen DPI, some screen coordinates and sizes must
// be converted using this function
int CompensateXDPI (int val)
{
	if (ScreenDPI == USER_DEFAULT_SCREEN_DPI)
		return val;
	else
	{
		double tmpVal = (double) val * DPIScaleFactorX;

		if (tmpVal > 0)
			return (int) floor(tmpVal);
		else
			return (int) ceil(tmpVal);
	}
}


// If the user has a non-default screen DPI, some screen coordinates and sizes must
// be converted using this function
int CompensateYDPI (int val)
{
	if (ScreenDPI == USER_DEFAULT_SCREEN_DPI)
		return val;
	else
	{
		double tmpVal = (double) val * DPIScaleFactorY;

		if (tmpVal > 0)
			return (int) floor(tmpVal);
		else
			return (int) ceil(tmpVal);
	}
}


int GetTextGfxWidth (HWND hwndDlgItem, wchar_t *text, HFONT hFont)
{
	SIZE sizes;
	TEXTMETRIC textMetrics;
	HDC hdc = GetDC (hwndDlgItem); 

	SelectObject(hdc, (HGDIOBJ) hFont);

	GetTextExtentPoint32W (hdc, text, wcslen (text), &sizes);

	GetTextMetrics(hdc, &textMetrics);	// Necessary for non-TrueType raster fonts (tmOverhang)

	ReleaseDC (hwndDlgItem, hdc); 

	return ((int) sizes.cx - (int) textMetrics.tmOverhang);
}


int GetTextGfxHeight (HWND hwndDlgItem, wchar_t *text, HFONT hFont)
{
	SIZE sizes;
	HDC hdc = GetDC (hwndDlgItem); 

	SelectObject(hdc, (HGDIOBJ) hFont);

	GetTextExtentPoint32W (hdc, text, wcslen (text), &sizes);

	ReleaseDC (hwndDlgItem, hdc); 

	return ((int) sizes.cy);
}


static LRESULT CALLBACK HyperlinkProc (HWND hwnd, UINT message, WPARAM wParam, LPARAM lParam)
{
	WNDPROC wp = (WNDPROC) GetWindowLongPtr (hwnd, GWL_USERDATA);

	switch (message)
	{
	case WM_SETCURSOR:
		if (!bHyperLinkBeingTracked)
		{
			TRACKMOUSEEVENT	trackMouseEvent;

			trackMouseEvent.cbSize = sizeof(trackMouseEvent);
			trackMouseEvent.dwFlags = TME_LEAVE;
			trackMouseEvent.hwndTrack = hwnd;

			bHyperLinkBeingTracked = TrackMouseEvent(&trackMouseEvent);

			HandCursor();
		}
		return 0;

	case WM_MOUSELEAVE:
		bHyperLinkBeingTracked = FALSE;
		NormalCursor();
		return 0;
	}

	return CallWindowProc (wp, hwnd, message, wParam, lParam);
}


BOOL ToHyperlink (HWND hwndDlg, UINT ctrlId)
{
	HWND hwndCtrl = GetDlgItem (hwndDlg, ctrlId);

	SendMessage (hwndCtrl, WM_SETFONT, (WPARAM) hUserUnderlineFont, 0);

	SetWindowLongPtr (hwndCtrl, GWL_USERDATA, (LONG_PTR) GetWindowLongPtr (hwndCtrl, GWL_WNDPROC));
	SetWindowLongPtr (hwndCtrl, GWL_WNDPROC, (LONG_PTR) HyperlinkProc);

	// Resize the field according to its actual length in pixels and move if centered or right-aligned.
	// This should be done again if the link text changes.
	AccommodateTextField (hwndDlg, ctrlId, TRUE);

	return TRUE;
}


// Resizes a text field according to its actual width in pixels (font size is taken into account) and moves
// it accordingly if the field is centered or right-aligned. Should be used on all hyperlinks upon dialog init
// after localization (bFirstUpdate should be TRUE) and later whenever a hyperlink text changes (bFirstUpdate
// must be FALSE).
void AccommodateTextField (HWND hwndDlg, UINT ctrlId, BOOL bFirstUpdate)
{
	RECT rec, wrec, trec;
	HWND hwndCtrl = GetDlgItem (hwndDlg, ctrlId);
	int width, origWidth, origHeight;
	int horizSubOffset, vertOffset, alignPosDiff = 0;
	wchar_t text [MAX_URL_LENGTH];
	WINDOWINFO windowInfo;
	BOOL bBorderlessWindow = !(GetWindowLongPtr (hwndDlg, GWL_STYLE) & (WS_BORDER | WS_DLGFRAME));

	// Resize the field according to its length and font size and move if centered or right-aligned

	GetWindowTextW (hwndCtrl, text, sizeof (text) / sizeof (wchar_t));

	width = GetTextGfxWidth (hwndCtrl, text, hUserUnderlineFont);

	GetClientRect (hwndCtrl, &rec);		
	origWidth = rec.right;
	origHeight = rec.bottom;

	if (width >= 0
		&& (!bFirstUpdate || origWidth > width))	// The original width of the field is the maximum allowed size 
	{
		horizSubOffset = origWidth - width;

		// Window coords
		GetWindowRect(hwndDlg, &wrec);
		GetClientRect(hwndDlg, &trec);

		// Vertical "title bar" offset
		vertOffset = wrec.bottom - wrec.top - trec.bottom - (bBorderlessWindow ? 0 : GetSystemMetrics(SM_CYFIXEDFRAME));

		// Text field coords
		GetWindowRect(hwndCtrl, &rec);

		// Alignment offset
		windowInfo.cbSize = sizeof(windowInfo);
		GetWindowInfo (hwndCtrl, &windowInfo);

		if (windowInfo.dwStyle & SS_CENTER)
			alignPosDiff = horizSubOffset / 2;
		else if (windowInfo.dwStyle & SS_RIGHT)
			alignPosDiff = horizSubOffset;
		
		// Resize/move
		if (alignPosDiff > 0)
		{
			// Resize and move the text field
			MoveWindow (hwndCtrl,
				rec.left - wrec.left - (bBorderlessWindow ? 0 : GetSystemMetrics(SM_CXFIXEDFRAME)) + alignPosDiff,
				rec.top - wrec.top - vertOffset,
				origWidth - horizSubOffset,
				origHeight,
				TRUE);
		}
		else
		{
			// Resize the text field
			SetWindowPos (hwndCtrl, 0, 0, 0,
				origWidth - horizSubOffset,
				origHeight,
				SWP_NOMOVE | SWP_NOZORDER);
		}

		SetWindowPos (hwndCtrl, HWND_BOTTOM, 0, 0, 0, 0, SWP_NOMOVE | SWP_NOSIZE);

		InvalidateRect (hwndCtrl, NULL, TRUE);
	}
}


// Protects an input field from having its content updated by a Paste action (call ToBootPwdField() to use this).
static LRESULT CALLBACK BootPwdFieldProc (HWND hwnd, UINT message, WPARAM wParam, LPARAM lParam)
{
	WNDPROC wp = (WNDPROC) GetWindowLongPtr (hwnd, GWL_USERDATA);

	switch (message)
	{
	case WM_PASTE:
		return 1;
	}

	return CallWindowProc (wp, hwnd, message, wParam, lParam);
}


// Protects an input field from having its content updated by a Paste action. Used for pre-boot password
// input fields (only the US keyboard layout is supported in pre-boot environment so we must prevent the 
// user from pasting a password typed using a non-US keyboard layout).
void ToBootPwdField (HWND hwndDlg, UINT ctrlId)
{
	HWND hwndCtrl = GetDlgItem (hwndDlg, ctrlId);

	SetWindowLongPtr (hwndCtrl, GWL_USERDATA, (LONG_PTR) GetWindowLongPtr (hwndCtrl, GWL_WNDPROC));
	SetWindowLongPtr (hwndCtrl, GWL_WNDPROC, (LONG_PTR) BootPwdFieldProc);
}



// This function currently serves the following purposes:
// - Determines scaling factors for current screen DPI and GUI aspect ratio.
// - Determines how Windows skews the GUI aspect ratio (which happens when the user has a non-default DPI).
// The determined values must be used when performing some GUI operations and calculations.
BOOL CALLBACK AuxiliaryDlgProc (HWND hwndDlg, UINT msg, WPARAM wParam, LPARAM lParam)
{
	switch (msg)
	{
	case WM_INITDIALOG:
		{
			HDC hDC = GetDC (hwndDlg);

			ScreenDPI = GetDeviceCaps (hDC, LOGPIXELSY);
			ReleaseDC (hwndDlg, hDC); 

			DPIScaleFactorX = 1;
			DPIScaleFactorY = 1;
			DlgAspectRatio = 1;

			if (ScreenDPI != USER_DEFAULT_SCREEN_DPI)
			{
				// Windows skews the GUI aspect ratio if the user has a non-default DPI. Hence, working with 
				// actual screen DPI is redundant and leads to incorrect results. What really matters here is
				// how Windows actually renders our GUI. This is determined by comparing the expected and current
				// sizes of a hidden calibration text field.

				RECT trec;

				trec.right = 0;
				trec.bottom = 0;

				GetClientRect (GetDlgItem (hwndDlg, IDC_ASPECT_RATIO_CALIBRATION_BOX), &trec);

				if (trec.right != 0 && trec.bottom != 0)
				{
					// The size of the 282x282 IDC_ASPECT_RATIO_CALIBRATION_BOX rendered at the default DPI (96) is 423x458
					DPIScaleFactorX = (double) trec.right / 423;
					DPIScaleFactorY = (double) trec.bottom / 458;
					DlgAspectRatio = DPIScaleFactorX / DPIScaleFactorY;
				}
			}

			EndDialog (hwndDlg, 0);
			return 1;
		}

	case WM_CLOSE:
		EndDialog (hwndDlg, 0);
		return 1;
	}

	return 0;
}


/* Except in response to the WM_INITDIALOG message, the dialog box procedure
   should return nonzero if it processes the message, and zero if it does
   not. - see DialogProc */
BOOL CALLBACK
AboutDlgProc (HWND hwndDlg, UINT msg, WPARAM wParam, LPARAM lParam)
{
	WORD lw = LOWORD (wParam);
	static HBITMAP hbmTextualLogoBitmapRescaled = NULL;

	switch (msg)
	{
	case WM_INITDIALOG:
		{
			char szTmp[100];
			RECT rec;

			LocalizeDialog (hwndDlg, "IDD_ABOUT_DLG");

			// Hyperlink
			SetWindowText (GetDlgItem (hwndDlg, IDC_HOMEPAGE), "www.truecrypt.org");
			ToHyperlink (hwndDlg, IDC_HOMEPAGE);

			// Logo area background (must not keep aspect ratio; must retain Windows-imposed distortion)
			GetClientRect (GetDlgItem (hwndDlg, IDC_ABOUT_LOGO_AREA), &rec);
			SetWindowPos (GetDlgItem (hwndDlg, IDC_ABOUT_BKG), HWND_TOP, 0, 0, rec.right, rec.bottom, SWP_NOMOVE);

			// Resize the logo bitmap if the user has a non-default DPI 
			if (ScreenDPI != USER_DEFAULT_SCREEN_DPI)
			{
				// Logo (must recreate and keep the original aspect ratio as Windows distorts it)
				hbmTextualLogoBitmapRescaled = RenderBitmap (MAKEINTRESOURCE (IDB_TEXTUAL_LOGO_288DPI),
					GetDlgItem (hwndDlg, IDC_TEXTUAL_LOGO_IMG),
					0, 0, 0, 0, FALSE, TRUE);

				SetWindowPos (GetDlgItem (hwndDlg, IDC_ABOUT_BKG), HWND_TOP, 0, 0, 0, 0, SWP_NOMOVE | SWP_NOSIZE);
			}

			// Version
			SendMessage (GetDlgItem (hwndDlg, IDT_ABOUT_VERSION), WM_SETFONT, (WPARAM) hUserBoldFont, 0);
			sprintf (szTmp, "TrueCrypt %s", VERSION_STRING);
#ifdef _DEBUG
			strcat (szTmp, "  (debug)");
#endif
			SetDlgItemText (hwndDlg, IDT_ABOUT_VERSION, szTmp);

			// Credits
			SendMessage (GetDlgItem (hwndDlg, IDC_ABOUT_CREDITS), WM_SETFONT, (WPARAM) hUserFont, (LPARAM) 0);
			SendMessage (hwndDlg, WM_APP, 0, 0);
			return 1;
		}

	case WM_APP:
		SetWindowText (GetDlgItem (hwndDlg, IDC_ABOUT_CREDITS),
			"Portions of this software are based in part on the works of the following people: "
			"Paul Le Roux, "
			"Bruce Schneier, John Kelsey, Doug Whiting, David Wagner, Chris Hall, Niels Ferguson, "
			"Lars Knudsen, Ross Anderson, Eli Biham, "
			"Joan Daemen, Vincent Rijmen, "
			"Phillip Rogaway, "
			"Hans Dobbertin, Antoon Bosselaers, Bart Preneel, "
			"Paulo Barreto, Brian Gladman, Wei Dai, Peter Gutmann, and many others.\r\n\r\n"

			"Portions of this software:\r\n"
			"Copyright \xA9 2003-2008 TrueCrypt Foundation. All Rights Reserved.\r\n"
			"Copyright \xA9 1998-2000 Paul Le Roux. All Rights Reserved.\r\n"
			"Copyright \xA9 1998-2008 Brian Gladman. All Rights Reserved.\r\n"
			"Copyright \xA9 1995-1997 Eric Young. All Rights Reserved.\r\n"
			"Copyright \xA9 2001 Markus Friedl. All Rights Reserved.\r\n"
			"Copyright \xA9 2002-2004 Mark Adler. All Rights Reserved.\r\n\r\n"

			"This software as a whole:\r\n"
			"Copyright \xA9 2008 TrueCrypt Foundation. All rights reserved.\r\n\r\n"

			"A TrueCrypt Foundation Release");

		return 1;

	case WM_COMMAND:
		if (lw == IDOK || lw == IDCANCEL)
		{
			PostMessage (hwndDlg, WM_CLOSE, 0, 0);
			return 1;
		}

		if (lw == IDC_HOMEPAGE)
		{
			Applink ("main", TRUE, "");
			return 1;
		}

		if (lw == IDC_DONATIONS)
		{
			Applink ("donate", FALSE, "");
			return 1;
		}

		// Disallow modification of credits
		if (HIWORD (wParam) == EN_UPDATE)
		{
			SendMessage (hwndDlg, WM_APP, 0, 0);
			return 1;
		}

		return 0;

	case WM_CLOSE:
		/* Delete buffered bitmaps (if any) */
		if (hbmTextualLogoBitmapRescaled != NULL)
		{
			DeleteObject ((HGDIOBJ) hbmTextualLogoBitmapRescaled);
			hbmTextualLogoBitmapRescaled = NULL;
		}

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


void LeftPadString (char *szTmp, int len, int targetLen, char filler)
{
	int i;

	if (targetLen <= len)
		return;

	for (i = targetLen-1; i >= (targetLen-len); i--)
		szTmp [i] = szTmp [i-(targetLen-len)];

	memset (szTmp, filler, targetLen-len);
	szTmp [targetLen] = 0;
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
			wcscpy ((LPWSTR) lpszText, (LPWSTR) WIDE (""));
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

	int nHeight;
	LOGFONTW lf;
	HMENU hMenu;
	Font *font;

	/* Fonts */

	// Normal
	font = GetFont ("font_normal");

	metric.cbSize = sizeof (metric);
	SystemParametersInfoW (SPI_GETNONCLIENTMETRICS, sizeof(metric), &metric, 0);

	metric.lfMessageFont.lfHeight = CompensateDPIFont (!font ? -11 : -font->Size);
	metric.lfMessageFont.lfWidth = 0;

	if (font && wcscmp (font->FaceName, L"default") != 0)
	{
		wcsncpy ((WCHAR *)metric.lfMessageFont.lfFaceName, font->FaceName, sizeof (metric.lfMessageFont.lfFaceName)/2);
	}
	else if (nCurrentOS == WIN_VISTA_OR_LATER)
	{
		// Vista's new default font (size and spacing) breaks compatibility with Windows 2k/XP applications.
		// Force use of Tahoma (as Microsoft does in many dialogs) until a native Vista look is implemented.
		wcsncpy ((WCHAR *)metric.lfMessageFont.lfFaceName, L"Tahoma", sizeof (metric.lfMessageFont.lfFaceName)/2);
	}

	hUserFont = CreateFontIndirectW (&metric.lfMessageFont);

	metric.lfMessageFont.lfUnderline = TRUE;
	hUserUnderlineFont = CreateFontIndirectW (&metric.lfMessageFont);

	metric.lfMessageFont.lfUnderline = FALSE;
	metric.lfMessageFont.lfWeight = FW_BOLD;
	hUserBoldFont = CreateFontIndirectW (&metric.lfMessageFont);

	metric.lfMessageFont.lfUnderline = TRUE;
	metric.lfMessageFont.lfWeight = FW_BOLD;
	hUserUnderlineBoldFont = CreateFontIndirectW (&metric.lfMessageFont);

	// Fixed-size (hexadecimal digits)
	nHeight = CompensateDPIFont (-12);
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

	nHeight = CompensateDPIFont (!font ? -13 : -font->Size);
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

	nHeight = CompensateDPIFont (!font ? -21 : -font->Size);
	lf.lfHeight = nHeight;
	lf.lfWeight = FW_REGULAR;
	wcsncpy (lf.lfFaceName, !font ? L"Times New Roman" : font->FaceName, sizeof (lf.lfFaceName)/2);
	hTitleFont = CreateFontIndirectW (&lf);
	if (hTitleFont == NULL)
	{
		handleWin32Error (hwndDlg);
		AbortProcess ("NOFONT");
	}

	// Fixed-size
	font = GetFont ("font_fixed");

	nHeight = CompensateDPIFont (!font ? -12 : -font->Size);
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

HDC CreateMemBitmap (HINSTANCE hInstance, HWND hwnd, char *resource)
{
	HBITMAP picture = LoadBitmap (hInstance, resource);
	HDC viewDC = GetDC (hwnd), dcMem;

	dcMem = CreateCompatibleDC (viewDC);

	SetMapMode (dcMem, MM_TEXT);

	SelectObject (dcMem, picture);

	DeleteObject (picture);

	ReleaseDC (hwnd, viewDC);

	return dcMem;
}


/* Renders the specified bitmap at the specified location and stretches it to fit (anti-aliasing is applied). 
If bDirectRender is FALSE and both nWidth and nHeight are zero, the width and height of hwndDest are
retrieved and adjusted according to screen DPI (the width and height of the resultant image are adjusted the
same way); furthermore, if bKeepAspectRatio is TRUE, the smaller DPI factor of the two (i.e. horiz. or vert.)
is used both for horiz. and vert. scaling (note that the overall GUI aspect ratio changes irregularly in
both directions depending on the DPI). If bDirectRender is TRUE, bKeepAspectRatio is ignored. 
This function returns a handle to the scaled bitmap. When the bitmap is no longer needed, it should be
deleted by calling DeleteObject() with the handle passed as the parameter. 
Known Windows issues: 
- For some reason, anti-aliasing is not applied if the source bitmap contains less than 16K pixels. 
- Windows 2000 may produce slightly inaccurate colors even when source, buffer, and target are 24-bit true color. */
HBITMAP RenderBitmap (char *resource, HWND hwndDest, int x, int y, int nWidth, int nHeight, BOOL bDirectRender, BOOL bKeepAspectRatio)
{
	LRESULT lResult = 0;

	HDC hdcSrc = CreateMemBitmap (hInst, hwndDest, resource);

	HGDIOBJ picture = GetCurrentObject (hdcSrc, OBJ_BITMAP);

	HBITMAP hbmpRescaled;
	BITMAP bitmap;

	HDC hdcRescaled;

	if (!bDirectRender && nWidth == 0 && nHeight == 0)
	{
		RECT rec;

		GetClientRect (hwndDest, &rec);

		if (bKeepAspectRatio)
		{
			if (DlgAspectRatio > 1)
			{
				// Do not fix this, it's correct. We use the Y scale factor intentionally for both
				// directions to maintain aspect ratio (see above for more info).
				nWidth = CompensateYDPI (rec.right);
				nHeight = CompensateYDPI (rec.bottom);
			}
			else
			{
				// Do not fix this, it's correct. We use the X scale factor intentionally for both
				// directions to maintain aspect ratio (see above for more info).
				nWidth = CompensateXDPI (rec.right);
				nHeight = CompensateXDPI (rec.bottom);
			}
		}
		else
		{
			nWidth = CompensateXDPI (rec.right);
			nHeight = CompensateYDPI (rec.bottom);
		}
	}

	GetObject (picture, sizeof (BITMAP), &bitmap);

    hdcRescaled = CreateCompatibleDC (hdcSrc); 
 
    hbmpRescaled = CreateCompatibleBitmap (hdcSrc, nWidth, nHeight); 
 
    SelectObject (hdcRescaled, hbmpRescaled);

	/* Anti-aliasing mode (HALFTONE is the only anti-aliasing algorithm natively supported by Windows 2000.
	   TODO: GDI+ offers higher quality -- InterpolationModeHighQualityBicubic) */
	SetStretchBltMode (hdcRescaled, HALFTONE);

	StretchBlt (hdcRescaled,
		0,
		0,
		nWidth,
		nHeight,
		hdcSrc,
		0,
		0,
		bitmap.bmWidth, 
		bitmap.bmHeight,
		SRCCOPY);

	DeleteDC (hdcSrc);

	if (bDirectRender)
	{
		HDC hdcDest = GetDC (hwndDest);

		BitBlt (hdcDest, x, y, nWidth, nHeight, hdcRescaled, 0, 0, SRCCOPY);
		DeleteDC (hdcDest);
	}
	else
	{
		lResult = SendMessage (hwndDest, (UINT) STM_SETIMAGE, (WPARAM) IMAGE_BITMAP, (LPARAM) (HANDLE) hbmpRescaled);
	}

	if ((HGDIOBJ) lResult != NULL && (HGDIOBJ) lResult != (HGDIOBJ) hbmpRescaled)
		DeleteObject ((HGDIOBJ) lResult);

	DeleteDC (hdcRescaled);

	return hbmpRescaled;
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
  wc.hbrBackground = (HBRUSH) GetStockObject (LTGRAY_BRUSH);
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

void HandCursor ()
{
	static HCURSOR hcHand;
	if (hcHand == NULL)
		hcHand = LoadCursor (NULL, IDC_HAND);
	SetCursor (hcHand);
	hCursor = hcHand;
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
		if (x == (LPARAM) *algo_id)
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

void PopulateWipeModeCombo (HWND hComboBox, BOOL bNA)
{
	if (bNA)
	{
		AddComboPairW (hComboBox, GetString ("N_A_UISTR"), TC_WIPE_NONE);
	}
	else
	{
		AddComboPairW (hComboBox, GetString ("WIPE_MODE_NONE"), TC_WIPE_NONE);
		AddComboPairW (hComboBox, GetString ("WIPE_MODE_3_DOD_5220"), TC_WIPE_3_DOD_5220);
		AddComboPairW (hComboBox, GetString ("WIPE_MODE_7_DOD_5220"), TC_WIPE_7_DOD_5220);
		AddComboPairW (hComboBox, GetString ("WIPE_MODE_35_GUTMANN"), TC_WIPE_35_GUTMANN);
	}
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


void ExceptionHandlerThread (void *ept)
{
#define MAX_RET_ADDR_COUNT 8
	EXCEPTION_POINTERS *ep = (EXCEPTION_POINTERS *) ept;
	DWORD addr, retAddr[MAX_RET_ADDR_COUNT];
	DWORD exCode = ep->ExceptionRecord->ExceptionCode;
	SYSTEM_INFO si;
	wchar_t msg[8192];
	char modPath[MAX_PATH];
	int crc = 0;
	char url[MAX_URL_LENGTH];
	char lpack[128];
	int i;

	addr = (DWORD) ep->ExceptionRecord->ExceptionAddress;
	ZeroMemory (retAddr, sizeof (retAddr));

	switch (exCode)
	{
	case 0x80000003:
	case 0x80000004:
	case 0xc0000006:
	case 0xc000001d:
	case 0xc000001e:
	case 0xc0000096:
	case 0xeedfade:
		// Exception not caused by TrueCrypt
		MessageBoxW (0, GetString ("EXCEPTION_REPORT_EXT"),
			GetString ("EXCEPTION_REPORT_TITLE"),
			MB_ICONERROR | MB_OK | MB_SETFOREGROUND | MB_TOPMOST);
		return;

	default:
		{
			// Call stack
			PDWORD sp = (PDWORD) ep->ContextRecord->Esp, stackTop;
			int i = 0, e = 0;
			MEMORY_BASIC_INFORMATION mi;

			VirtualQuery (sp, &mi, sizeof (mi));
			stackTop = (PDWORD)((char *)mi.BaseAddress + mi.RegionSize);

			while (&sp[i] < stackTop && e < MAX_RET_ADDR_COUNT)
			{
				if (sp[i] > 0x400000 && sp[i] < 0x500000)
				{
					int ee = 0;

					// Skip duplicates
					while (ee < MAX_RET_ADDR_COUNT && retAddr[ee] != sp[i])
						ee++;
					if (ee != MAX_RET_ADDR_COUNT)
					{
						i++;
						continue;
					}

					retAddr[e++] = sp[i];
				}
				i++;
			}
		}
	}

	// Checksum of the module
	if (GetModuleFileName (NULL, modPath, sizeof (modPath)))
	{
		HANDLE h = CreateFile (modPath, FILE_READ_DATA | FILE_READ_ATTRIBUTES, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
		if (h != INVALID_HANDLE_VALUE)
		{
			BY_HANDLE_FILE_INFORMATION fi;
			if (GetFileInformationByHandle (h, &fi))
			{
				char *buf = (char *) malloc (fi.nFileSizeLow);
				if (buf)
				{
					DWORD bytesRead;
					if (ReadFile (h, buf, fi.nFileSizeLow, &bytesRead, NULL) && bytesRead == fi.nFileSizeLow)
						crc = GetCrc32 ((unsigned char *) buf, fi.nFileSizeLow);
					free (buf);
				}
			}
			CloseHandle (h);
		}
	}

	GetSystemInfo (&si);

	if (LocalizationActive)
		sprintf_s (lpack, sizeof (lpack), "&langpack=%s_%s", GetPreferredLangId (), GetActiveLangPackVersion ());
	else
		lpack[0] = 0;

	sprintf (url, TC_APPLINK_SECURE "&dest=err-report%s&os=Windows&osver=%d.%d.%d&arch=%s&cpus=%d&app=%s&cksum=%x&dlg=%s&err=%x&addr=%x"
		, lpack
		, CurrentOSMajor
		, CurrentOSMinor
		, CurrentOSServicePack
		, Is64BitOs () ? "x64" : "x86"
		, si.dwNumberOfProcessors
#ifdef TCMOUNT
		,"main"
#endif
#ifdef VOLFORMAT
		,"format"
#endif
#ifdef SETUP
		,"setup"
#endif
		, crc
		, LastDialogId ? LastDialogId : "-"
		, exCode
		, addr);

	for (i = 0; i < MAX_RET_ADDR_COUNT && retAddr[i]; i++)
		sprintf (url + strlen(url), "&st%d=%x", i, retAddr[i]);

	swprintf (msg, GetString ("EXCEPTION_REPORT"), url);

	if (IDYES == MessageBoxW (0, msg, GetString ("EXCEPTION_REPORT_TITLE"), MB_ICONERROR | MB_YESNO | MB_DEFBUTTON1))
		ShellExecute (NULL, "open", (LPCTSTR) url, NULL, NULL, SW_SHOWNORMAL);
	else
		UnhandledExceptionFilter (ep);
}


LONG __stdcall ExceptionHandler (EXCEPTION_POINTERS *ep)
{
	SetUnhandledExceptionFilter (NULL);
	WaitForSingleObject ((HANDLE) _beginthread (ExceptionHandlerThread, 0, (void *)ep), INFINITE);

	return EXCEPTION_EXECUTE_HANDLER;
}


static LRESULT CALLBACK NonInstallUacWndProc (HWND hWnd, UINT message, WPARAM wParam, LPARAM lParam)
{
	return DefWindowProc (hWnd, message, wParam, lParam);
}


// Mutex handling to prevent multiple instances of the wizard or main app from dealing with system encryption.
// Returns TRUE if the mutex is (or had been) successfully acquired (otherwise FALSE). 
BOOL CreateSysEncMutex (void)
{
	return TCCreateMutex (&hSysEncMutex, TC_MUTEX_NAME_SYSENC);
}


BOOL InstanceHasSysEncMutex (void)
{
	return (hSysEncMutex != NULL);
}


// Mutex handling to prevent multiple instances of the wizard from dealing with system encryption
void CloseSysEncMutex (void)
{
	TCCloseMutex (&hSysEncMutex);
}


// Mutex handling to prevent multiple instances of the wizard or main app from trying to install
// or register the driver or from trying to launch it in traveler mode at the same time.
// Returns TRUE if the mutex is (or had been) successfully acquired (otherwise FALSE). 
BOOL CreateDriverSetupMutex (void)
{
	return TCCreateMutex (&hDriverSetupMutex, "Global\\TrueCrypt Driver Setup");
}


void CloseDriverSetupMutex (void)
{
	TCCloseMutex (&hDriverSetupMutex);
}


BOOL CreateAppSetupMutex (void)
{
	return TCCreateMutex (&hAppSetupMutex, TC_MUTEX_NAME_APP_SETUP);
}


void CloseAppSetupMutex (void)
{
	TCCloseMutex (&hAppSetupMutex);
}


BOOL IsTrueCryptInstallerRunning (void)
{
	return (MutexExistsOnSystem (TC_MUTEX_NAME_APP_SETUP));
}


// Returns TRUE if the mutex is (or had been) successfully acquired (otherwise FALSE). 
BOOL TCCreateMutex (volatile HANDLE *hMutex, char *name)
{
	if (*hMutex != NULL)
		return TRUE;	// This instance already has the mutex

	*hMutex = CreateMutex (NULL, TRUE, name);
	if (*hMutex == NULL)
	{
		// In multi-user configurations, the OS returns "Access is denied" here when a user attempts
		// to acquire the mutex if another user already has. However, on Vista, "Access is denied" is
		// returned also if the mutex is owned by a process with admin rights while we have none.

		return FALSE;
	}

	if (GetLastError () == ERROR_ALREADY_EXISTS)
	{
		ReleaseMutex (*hMutex);
		CloseHandle (*hMutex);

		*hMutex = NULL;
		return FALSE;
	}

	return TRUE;
}


void TCCloseMutex (volatile HANDLE *hMutex)
{
	if (*hMutex != NULL)
	{
		if (ReleaseMutex (*hMutex)
			&& CloseHandle (*hMutex))
			*hMutex = NULL;
	}
}


// Returns TRUE if a process running on the system has the specified mutex (otherwise FALSE). 
BOOL MutexExistsOnSystem (char *name)
{
	if (name[0] == 0)
		return FALSE;

	HANDLE hMutex = OpenMutex (MUTEX_ALL_ACCESS, FALSE, name);

	if (hMutex == NULL)
	{
		if (GetLastError () == ERROR_FILE_NOT_FOUND)
			return FALSE;

		if (GetLastError () == ERROR_ACCESS_DENIED) // On Vista, this is returned if the owner of the mutex is elevated while we are not
			return TRUE;		

		// The call failed and it is not certain whether the mutex exists or not
		return FALSE;
	}

	CloseHandle (hMutex);
	return TRUE;
}


BOOL LoadSysEncSettings (HWND hwndDlg)
{
	BOOL status = TRUE;
	DWORD size = 0;
	char *sysEncCfgFileBuf = LoadFile (GetConfigPath (FILE_SYSTEM_ENCRYPTION_CFG), &size);
	char *xml = sysEncCfgFileBuf;
	char paramName[100], paramVal[MAX_PATH];

	// Defaults
	int newSystemEncryptionStatus = SYSENC_STATUS_NONE;
	WipeAlgorithmId newnWipeMode = TC_WIPE_NONE;

	if (!FileExists (GetConfigPath (FILE_SYSTEM_ENCRYPTION_CFG)))
	{
		SystemEncryptionStatus = newSystemEncryptionStatus;
		nWipeMode = newnWipeMode;
	}

	if (xml == NULL)
	{
		return FALSE;
	}

	while (xml = XmlFindElement (xml, "config"))
	{
		XmlGetAttributeText (xml, "key", paramName, sizeof (paramName));
		XmlGetNodeText (xml, paramVal, sizeof (paramVal));

		if (strcmp (paramName, "SystemEncryptionStatus") == 0)
		{
			newSystemEncryptionStatus = atoi (paramVal);
		}
		else if (strcmp (paramName, "WipeMode") == 0)
		{
			newnWipeMode = (WipeAlgorithmId) atoi (paramVal);
		}

		xml++;
	}

	SystemEncryptionStatus = newSystemEncryptionStatus;
	nWipeMode = newnWipeMode;

	free (sysEncCfgFileBuf);
	return status;
}


void SavePostInstallTasksSettings (int command)
{
	FILE *f = NULL;

	switch (command)
	{
	case TC_POST_INSTALL_CFG_REMOVE_ALL:
		remove (GetConfigPath (FILE_POST_INSTALL_CFG_TUTORIAL));
		remove (GetConfigPath (FILE_POST_INSTALL_CFG_RELEASE_NOTES));
		break;

	case TC_POST_INSTALL_CFG_TUTORIAL:
		f = fopen (GetConfigPath (FILE_POST_INSTALL_CFG_TUTORIAL), "w");
		break;

	case TC_POST_INSTALL_CFG_RELEASE_NOTES:
		f = fopen (GetConfigPath (FILE_POST_INSTALL_CFG_RELEASE_NOTES), "w");
		break;

	default:
		return;
	}

	if (f == NULL)
		return;

	if (fputs ("1", f) < 0)
	{
		// Error
		fclose (f);
		return;
	}

	TCFlushFile (f);

	fclose (f);
}


void DoPostInstallTasks (void)
{
	BOOL bDone = FALSE;

	if (FileExists (GetConfigPath (FILE_POST_INSTALL_CFG_TUTORIAL)))
	{
		if (AskYesNo ("AFTER_INSTALL_TUTORIAL") == IDYES)
			Applink ("beginnerstutorial", TRUE, "");

		bDone = TRUE;
	}

	if (FileExists (GetConfigPath (FILE_POST_INSTALL_CFG_RELEASE_NOTES)))
	{
		if (AskYesNo ("AFTER_UPGRADE_RELEASE_NOTES") == IDYES)
			Applink ("releasenotes", TRUE, "");

		bDone = TRUE;
	}

	if (bDone)
		SavePostInstallTasksSettings (TC_POST_INSTALL_CFG_REMOVE_ALL);
}


/* InitApp - initialize the application, this function is called once in the
   applications WinMain function, but before the main dialog has been created */
void InitApp (HINSTANCE hInstance, char *lpszCommandLine)
{
	WNDCLASS wc;
	OSVERSIONINFO os;
	char langId[6];

	/* Save the instance handle for later */
	hInst = hInstance;

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
	{
		OSVERSIONINFOEX osEx;

		osEx.dwOSVersionInfoSize = sizeof (OSVERSIONINFOEX);
		GetVersionEx ((LPOSVERSIONINFOA) &osEx);

		if (osEx.wProductType == VER_NT_SERVER || osEx.wProductType == VER_NT_DOMAIN_CONTROLLER)
			nCurrentOS = WIN_SERVER_2003;
		else
			nCurrentOS = WIN_XP64;
	}
	else if (os.dwPlatformId == VER_PLATFORM_WIN32_NT && CurrentOSMajor >= 6)
		nCurrentOS = WIN_VISTA_OR_LATER;
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

	CoInitialize (NULL);

	langId[0] = 0;
	SetPreferredLangId (ConfigReadString ("Language", "", langId, sizeof (langId)));
	
	if (langId[0] == 0)
		DialogBoxParamW (hInst, MAKEINTRESOURCEW (IDD_LANGUAGE), NULL,
			(DLGPROC) LanguageDlgProc, (LPARAM) 1);

	LoadLanguageFile ();

#ifndef SETUP
	// UAC elevation moniker cannot be used in traveler mode.
	// A new instance of the application must be created with elevated privileges.
	if (IsNonInstallMode () && !IsAdmin () && IsUacSupported ())
	{
		char modPath[MAX_PATH], newCmdLine[4096];
		WNDCLASSEX wcex;
		HWND hWnd;

		if (strstr (lpszCommandLine, "/q UAC ") == lpszCommandLine)
		{
			Error ("UAC_INIT_ERROR");
			exit (1);
		}

		memset (&wcex, 0, sizeof (wcex));
		wcex.cbSize = sizeof(WNDCLASSEX); 
		wcex.lpfnWndProc = (WNDPROC) NonInstallUacWndProc;
		wcex.hInstance = hInstance;
		wcex.lpszClassName = "TrueCrypt";
		RegisterClassEx (&wcex);

		// A small transparent window is necessary to bring the new instance to foreground
		hWnd = CreateWindowEx (WS_EX_TOOLWINDOW | WS_EX_LAYERED,
			"TrueCrypt", "TrueCrypt", 0,
			GetSystemMetrics (SM_CXSCREEN)/2,
			GetSystemMetrics (SM_CYSCREEN)/2,
			1, 1, NULL, NULL, hInstance, NULL);

		SetLayeredWindowAttributes (hWnd, 0, 0, LWA_ALPHA);
		ShowWindow (hWnd, SW_SHOWNORMAL);

		GetModuleFileName (NULL, modPath, sizeof (modPath));

		strcpy (newCmdLine, "/q UAC ");
		strcat_s (newCmdLine, sizeof (newCmdLine), lpszCommandLine);

		if ((int)ShellExecute (hWnd, "runas", modPath, newCmdLine, NULL, SW_SHOWNORMAL) <= 32)
			exit (1);

		Sleep (2000);
		exit (0);
	}
#endif

	SetUnhandledExceptionFilter (ExceptionHandler);

	RemoteSession = GetSystemMetrics (SM_REMOTESESSION) != 0;

	// OS version check
	if (CurrentOSMajor < 5)
	{
		MessageBoxW (NULL, GetString ("UNSUPPORTED_OS"), lpszTitle, MB_ICONSTOP);
		exit (1);
	}
	else
	{
		OSVERSIONINFOEX osEx;

		// Service pack check & warnings about critical MS issues
		osEx.dwOSVersionInfoSize = sizeof (OSVERSIONINFOEX);
		if (GetVersionEx ((LPOSVERSIONINFOA) &osEx) != 0)
		{
			CurrentOSServicePack = osEx.wServicePackMajor;
			switch (nCurrentOS)
			{
			case WIN_2000:
				if (osEx.wServicePackMajor < 3)
					Warning ("LARGE_IDE_WARNING_2K");
				else
				{
					DWORD val = 0, size = sizeof(val);
					HKEY hkey;

					if (RegOpenKeyEx (HKEY_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Services\\Atapi\\Parameters", 0, KEY_READ, &hkey) == ERROR_SUCCESS
						&& (RegQueryValueEx (hkey, "EnableBigLba", 0, 0, (LPBYTE) &val, &size) != ERROR_SUCCESS
						|| val != 1))

					{
						Warning ("LARGE_IDE_WARNING_2K_REGISTRY");
					}
					RegCloseKey (hkey);
				}
				break;

			case WIN_XP:
				if (osEx.wServicePackMajor < 1)
				{
					HKEY k;
					// PE environment does not report version of SP
					if (RegOpenKeyEx (HKEY_LOCAL_MACHINE, "System\\CurrentControlSet\\Control\\minint", 0, KEY_READ, &k) != ERROR_SUCCESS)
						Warning ("LARGE_IDE_WARNING_XP");
					else
						RegCloseKey (k);
				}
				break;
			}
		}

#ifndef SETUP
		if (CurrentOSMajor == 6 && CurrentOSMinor == 0 && osEx.dwBuildNumber < 6000)
		{
			Error ("UNSUPPORTED_BETA_OS");
			exit (0);
		}
#endif
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

	// DPI and GUI aspect ratio
	DialogBoxParamW (hInst, MAKEINTRESOURCEW (IDD_AUXILIARY_DLG), NULL,
		(DLGPROC) AuxiliaryDlgProc, (LPARAM) 1);

	InitHelpFileName ();

#ifndef SETUP
	if (!EncryptionThreadPoolStart())
	{
		handleWin32Error (NULL);
		exit (1);
	}
#endif
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

BOOL OpenDevice (char *lpszPath, OPEN_TEST_STRUCT *driver)
{
	DWORD dwResult;
	BOOL bResult;

	strcpy ((char *) &driver->wszFileName[0], lpszPath);
	ToUNICODE ((char *) &driver->wszFileName[0]);

	driver->bDetectTCBootLoader = FALSE;

	bResult = DeviceIoControl (hDriver, TC_IOCTL_OPEN_TEST,
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


// Tells the driver that it's running in traveler mode
void NotifyDriverOfTravelerMode (void)
{
	if (hDriver != INVALID_HANDLE_VALUE)
	{
		DWORD dwResult;

		DeviceIoControl (hDriver, TC_IOCTL_SET_TRAVELER_MODE_STATUS, NULL, 0, NULL, 0, &dwResult, NULL);
	}
}


BOOL GetDriveLabel (int driveNo, wchar_t *label, int labelSize)
{
	DWORD fileSystemFlags;
	wchar_t root[] = { L'A' + driveNo, L':', L'\\', 0 };

	return GetVolumeInformationW (root, label, labelSize / 2, NULL, NULL, &fileSystemFlags, NULL, 0);
}


// This function also populates SysPartitionDevicePath and SysDriveDevicePath for later use.
int GetAvailableFixedDisks (HWND hComboBox, char *lpszRootPath)
{
	int i, n;
	int line = 0;
	LVITEM LvItem;
	__int64 deviceSize = 0;

	for (i = 0; i < 64; i++)
	{
		BOOL drivePresent = FALSE;
		BOOL removable = FALSE;

		LvItem.lParam = 0;

		for (n = 0; n <= 32; n++)
		{
			char szTmp[TC_MAX_PATH];
			wchar_t size[100] = {0};
			OPEN_TEST_STRUCT driver;

			sprintf (szTmp, lpszRootPath, i, n);

			if (OpenDevice (szTmp, &driver))
			{
				BOOL bResult;
				PARTITION_INFORMATION diskInfo;
				DISK_GEOMETRY driveInfo;

				drivePresent = TRUE;
				bResult = GetPartitionInfo (szTmp, &diskInfo);

				// Test if device is removable
				if (n == 0 && GetDriveGeometry (szTmp, &driveInfo))
					removable = driveInfo.MediaType == RemovableMedia;

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
						LvItem.mask = LVIF_TEXT;
						SendMessage (hComboBox,LVM_SETITEM,0,(LPARAM)&LvItem);

						// Label				
						if (driveNo != -1)
						{
							wchar_t name[64];

							if (GetDriveLabel (driveNo, name, sizeof (name)))
								ListSubItemSetW (hComboBox, LvItem.iItem, 3, name);
						}

						// Mark the device as containing a virtual partition
						LvItem.iSubItem = 0;
						LvItem.mask = LVIF_PARAM;
						LvItem.lParam |= SELDEVFLAG_VIRTUAL_PARTITION;
						SendMessage (hComboBox, LVM_SETITEM, 0, (LPARAM) &LvItem);

						break;
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

					if (removable)
						wsprintfW (s, L"Harddisk %d (%s):", i, GetString ("REMOVABLE"));
					else
						wsprintfW (s, L"Harddisk %d:", i);

					ListItemAddW (hComboBox, LvItem.iItem, s);
				}
				else
				{
					LvItem.pszText = szTmp;
					SendMessage (hComboBox,LVM_INSERTITEM,0,(LPARAM)&LvItem);
				}

				// Size
				ListSubItemSetW (hComboBox, LvItem.iItem, 2, size);

				// Device type removable
				if (removable)
				{
					// Mark as removable
					LvItem.iSubItem = 0;
					LvItem.mask = LVIF_PARAM;
					LvItem.lParam |= SELDEVFLAG_REMOVABLE_HOST_DEVICE;
					SendMessage (hComboBox, LVM_SETITEM, 0, (LPARAM) &LvItem);

					LvItem.mask = LVIF_TEXT;   
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

					if (driveNo != -1
						&& GetSystemDriveLetter() == 'A' + driveNo)
					{
						// Mark the partition as the system partition

						LvItem.iSubItem = 0;
						LvItem.mask = LVIF_PARAM;
						LvItem.lParam |= SELDEVFLAG_SYSTEM_PARTITION;
						SendMessage (hComboBox, LVM_SETITEM, 0, (LPARAM) &LvItem);

						LvItem.mask = LVIF_TEXT; 

						// Store the device path of the system partition for later use (to save time significantly)
						sprintf (SysPartitionDevicePath, lpszRootPath, i, n);

						// Find the line of the drive containing this partition
						{
							char tmpDevicePath [TC_MAX_PATH];
							char *ptrTmpDevicePath = tmpDevicePath;
							LVITEM tmpLvItem;

							memset (&tmpLvItem, 0, sizeof(tmpLvItem));

							tmpLvItem.mask = LVIF_TEXT | LVIF_PARAM;   
							tmpLvItem.pszText = ptrTmpDevicePath;
							tmpLvItem.cchTextMax = TC_MAX_PATH;

							for (tmpLvItem.iItem = LvItem.iItem - 1;
								tmpLvItem.iItem >= 0
								&& tmpLvItem.iItem >= LvItem.iItem - n;
							tmpLvItem.iItem--)
							{
								SendMessage (hComboBox, LVM_GETITEM, tmpLvItem.iItem, (LPARAM) &tmpLvItem);

								if (ptrTmpDevicePath[0] == 'H')
								{
									if (sscanf (ptrTmpDevicePath, "Harddisk %d", &i) == 1)
									{
										// Mark the drive as a system drive
										tmpLvItem.iSubItem = 0;
										tmpLvItem.mask = LVIF_TEXT | LVIF_PARAM;
										tmpLvItem.lParam |= SELDEVFLAG_SYSTEM_DRIVE;
										SendMessage (hComboBox, LVM_SETITEM, 0, (LPARAM) &tmpLvItem);

										// Store the device path of the system drive for later use (to save time significantly)
										sprintf (SysDriveDevicePath, lpszRootPath, i, 0);

										if (bRawDevicesDlgProcInstantExit
											&& strlen (SysPartitionDevicePath) > 1)
										{
											bCachedSysDevicePathsValid = TRUE;
											return 1;
										}

										break;
									}
								}
							}
						}
					}

					LvItem.iSubItem = 1;
					LvItem.pszText = drive;
					LvItem.mask = LVIF_TEXT;   
					SendMessage (hComboBox,LVM_SETITEM,0,(LPARAM)&LvItem);

					// Label				
					if (driveNo != -1)
					{
						wchar_t name[64];

						if (GetDriveLabel (driveNo, name, sizeof (name)))
							ListSubItemSetW (hComboBox, LvItem.iItem, 3, name);
					}
				}

				if (n == 1)
				{
					// Mark the device as containing a partition
					{
						// Retrieve the whole-device item data so that we preserve its existing flags in LvItem.lParam

						char tmpDevicePath [TC_MAX_PATH];
						char *ptrTmpDevicePath = tmpDevicePath;
						LVITEM tmpLvItem;

						memset (&tmpLvItem, 0, sizeof(tmpLvItem));

						tmpLvItem.iSubItem = 0;
						tmpLvItem.iItem = line - 2;
						tmpLvItem.mask = LVIF_TEXT | LVIF_PARAM;   
						tmpLvItem.pszText = ptrTmpDevicePath;
						tmpLvItem.cchTextMax = sizeof(tmpDevicePath);

						SendMessage (hComboBox, LVM_GETITEM, tmpLvItem.iItem, (LPARAM) &tmpLvItem);

						if (ptrTmpDevicePath[0] == 'H')
						{
							if (sscanf (ptrTmpDevicePath, "Harddisk %d", &i) == 1)
							{
								tmpLvItem.iSubItem = 0;
								tmpLvItem.mask = LVIF_TEXT | LVIF_PARAM;

								// Mark the device as containing partition preserving existing flags
								tmpLvItem.lParam |= SELDEVFLAG_CONTAINS_PARTITIONS;
								SendMessage (hComboBox, LVM_SETITEM, 0, (LPARAM) &tmpLvItem);
							}
						}
					}
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

int GetAvailableRemovables (HWND hComboBox, char *lpszRootPath)
{
	char szTmp[TC_MAX_PATH];
	int i;
	LVITEM LvItem;

	memset (&LvItem,0,sizeof(LvItem));
	LvItem.mask = LVIF_TEXT;   
	LvItem.iItem = SendMessage (hComboBox, LVM_GETITEMCOUNT, 0, 0)+1;   

	if (QueryDosDevice ("A:", szTmp, sizeof (szTmp)) != 0 && GetDriveType ("A:\\") == DRIVE_REMOVABLE)
	{
		LvItem.pszText = "\\Device\\Floppy0";
		LvItem.iItem = SendMessage (hComboBox,LVM_INSERTITEM,0,(LPARAM)&LvItem);

		LvItem.iSubItem = 1;
		LvItem.pszText = "A:";
		SendMessage (hComboBox,LVM_SETITEM,0,(LPARAM)&LvItem);

	}
	if (QueryDosDevice ("B:", szTmp, sizeof (szTmp)) != 0 && GetDriveType ("B:\\") == DRIVE_REMOVABLE)
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

/* Stores the device path of the system partition in SysPartitionDevicePath and the device path of the system drive
in SysDriveDevicePath.
IMPORTANT: As this may take a very long time if called for the first time, it should be called only before performing 
           a dangerous operation (such as header backup restore or formatting a supposedly non-system device) never 
		   at WM_INITDIALOG or any other GUI events -- instead call IsSystemDevicePath (path, hwndDlg, FALSE) for 
		   very fast preliminary GUI checks; also note that right after the "Select Device" dialog exits with an OK 
		   return code, you can use the global flags bSysPartitionSelected and bSysDriveSelected to see if the user
		   selected the system partition/device.
After this function completes successfully, the results are cached for the rest of the session and repeated
executions complete very fast. Returns TRUE if successful (otherwise FALSE). */
BOOL GetSysDevicePaths (HWND hwndDlg)
{
	if (!bCachedSysDevicePathsValid
		|| strlen (SysPartitionDevicePath) <= 1 
		|| strlen (SysDriveDevicePath) <= 1)
	{
		int nResult;
		char tmp [TC_MAX_PATH];

		bRawDevicesDlgProcInstantExit = TRUE;

		nResult = DialogBoxParamW (hInst, MAKEINTRESOURCEW (IDD_RAWDEVICES_DLG), hwndDlg,
			(DLGPROC) RawDevicesDlgProc, (LPARAM) & tmp[0]);

		bRawDevicesDlgProcInstantExit = FALSE;
	}

	return (bCachedSysDevicePathsValid 
		&& strlen (SysPartitionDevicePath) > 1 
		&& strlen (SysDriveDevicePath) > 1);
}

/* Determines whether the device path is the path of the system partition or of the system drive (or neither). 
If bReliableRequired is TRUE, very fast execution is guaranteed, but the results cannot be relied upon. 
If it's FALSE and the function is called for the first time, execution may take up to one minute but the
results are reliable.
IMPORTANT: As the execution may take a very long time if called for the first time with bReliableRequired set
           to TRUE, it should be called with bReliableRequired set to TRUE only before performing a dangerous
		   operation (such as header backup restore or formatting a supposedly non-system device) never at 
		   WM_INITDIALOG or any other GUI events (use IsSystemDevicePath(path, hwndDlg, FALSE) for fast 
		   preliminary GUI checks; also note that right after the "Select Device" dialog exits with an OK 
		   return code, you can use the global flags bSysPartitionSelected and bSysDriveSelected to see if the
		   user selected the system partition/device).
After this function completes successfully, the results are cached for the rest of the session, bReliableRequired
is ignored (TRUE implied), repeated executions complete very fast, and the results are always reliable. 
Return codes:
1  - it is the system partition path (e.g. \Device\Harddisk0\Partition1)
2  - it is the system drive path (e.g. \Device\Harddisk0\Partition0)
0  - it's not the system partition/drive path
-1 - the result can't be determined, isn't reliable, or there was an error. */
int IsSystemDevicePath (char *path, HWND hwndDlg, BOOL bReliableRequired)
{
	if (!bCachedSysDevicePathsValid
		&& bReliableRequired)
	{
		if (!GetSysDevicePaths (hwndDlg))
			return -1;
	}

	if (strlen (SysPartitionDevicePath) <= 1 || strlen (SysDriveDevicePath) <= 1)
		return -1;

	if (strncmp (path, SysPartitionDevicePath, max (strlen(path), strlen(SysPartitionDevicePath))) == 0)
		return 1;
	else if (strncmp (path, SysDriveDevicePath, max (strlen(path), strlen(SysDriveDevicePath))) == 0)
		return 2;

	return 0;
}

BOOL TextInfoDialogBox (int nID)
{
	return DialogBoxParamW (hInst, MAKEINTRESOURCEW (IDD_TEXT_INFO_DIALOG_BOX_DLG), MainDlg, (DLGPROC) TextInfoDialogBoxDlgProc, (LPARAM) nID);
}

BOOL CALLBACK TextInfoDialogBoxDlgProc (HWND hwndDlg, UINT msg, WPARAM wParam, LPARAM lParam)
{
	WORD lw = LOWORD (wParam);
	static int nID = 0;

	switch (msg)
	{
	case WM_INITDIALOG:
		{
			nID = (int) lParam;

			ShowWindow(GetDlgItem(hwndDlg, IDC_PRINT), SW_HIDE);

			switch (nID)
			{
			case TC_TBXID_LEGAL_NOTICES:
				LocalizeDialog (hwndDlg, "LEGAL_NOTICES_DLG_TITLE");
				break;

			case TC_TBXID_SYS_ENCRYPTION_PRETEST:
				LocalizeDialog (hwndDlg, NULL);
				ShowWindow(GetDlgItem(hwndDlg, IDC_PRINT), SW_SHOW);
				break;

			case TC_TBXID_SYS_ENC_RESCUE_DISK:
				LocalizeDialog (hwndDlg, NULL);
				ShowWindow(GetDlgItem(hwndDlg, IDC_PRINT), SW_SHOW);
				break;
			}

			SendMessage (hwndDlg, TC_APPMSG_LOAD_TEXT_BOX_CONTENT, 0, 0);
		}
		return 0;

	case WM_COMMAND:
		if (lw == IDOK || lw == IDCANCEL)
		{
			NormalCursor ();
			EndDialog (hwndDlg, 0);
			return 1;
		}

		if (lw == IDC_PRINT)
		{
			switch (nID)
			{
			case TC_TBXID_SYS_ENCRYPTION_PRETEST:
				PrintHardCopyTextUTF16 (GetString ("SYS_ENCRYPTION_PRETEST_INFO2"), "Pre-Boot Troubleshooting", wcslen (GetString ("SYS_ENCRYPTION_PRETEST_INFO2")) * 2);
				break;

			case TC_TBXID_SYS_ENC_RESCUE_DISK:
				PrintHardCopyTextUTF16 (GetString ("RESCUE_DISK_HELP"), "TrueCrypt Rescue Disk Help", wcslen (GetString ("RESCUE_DISK_HELP")) * 2);
				break;
			}
			return 1;
		}

		// Disallow modification
		if (HIWORD (wParam) == EN_UPDATE)
		{
			SendMessage (hwndDlg, TC_APPMSG_LOAD_TEXT_BOX_CONTENT, 0, 0);
			return 1;
		}

		return 0;

	case TC_APPMSG_LOAD_TEXT_BOX_CONTENT:
		{
			char *r = NULL;

			switch (nID)
			{
			case TC_TBXID_LEGAL_NOTICES:
				LocalizeDialog (hwndDlg, "LEGAL_NOTICES_DLG_TITLE");
				r = GetLegalNotices ();
				if (r != NULL)
				{
					SetWindowText (GetDlgItem (hwndDlg, IDC_INFO_BOX_TEXT), r);
					free (r);
				}
				break;

			case TC_TBXID_SYS_ENCRYPTION_PRETEST:
				LocalizeDialog (hwndDlg, NULL);
				SetWindowTextW (GetDlgItem (hwndDlg, IDC_INFO_BOX_TEXT), GetString ("SYS_ENCRYPTION_PRETEST_INFO2"));
				break;

			case TC_TBXID_SYS_ENC_RESCUE_DISK:
				LocalizeDialog (hwndDlg, NULL);
				SetWindowTextW (GetDlgItem (hwndDlg, IDC_INFO_BOX_TEXT), GetString ("RESCUE_DISK_HELP"));
				break;
			}
		}
		return 1;

	case WM_CLOSE:
		NormalCursor ();
		EndDialog (hwndDlg, 0);
		return 1;
	}

	return 0;
}


char * GetLegalNotices ()
{
	static char *resource;
	static DWORD size;
	char *buf = NULL;

	if (resource == NULL)
		resource = (char *) MapResource ("Text", IDR_LICENSE, &size);

	if (resource != NULL)
	{
		buf = (char *) malloc (size + 1);
		if (buf != NULL)
		{
			memcpy (buf, resource, size);
			buf[size] = 0;
		}
	}

	return buf;
}


BOOL CALLBACK
RawDevicesDlgProc (HWND hwndDlg, UINT msg, WPARAM wParam, LPARAM lParam)
{
	static char *lpszFileName;		// This is actually a pointer to a GLOBAL array
	WORD lw = LOWORD (wParam);

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
			LvCol.cx = CompensateXDPI (186);
			LvCol.fmt = LVCFMT_LEFT;
			SendMessage (hList,LVM_INSERTCOLUMNW,0,(LPARAM)&LvCol);

			LvCol.pszText = GetString ("DRIVE");  
			LvCol.cx = CompensateXDPI (38);
			LvCol.fmt = LVCFMT_LEFT;
			SendMessage (hList,LVM_INSERTCOLUMNW,1,(LPARAM)&LvCol);

			LvCol.pszText = GetString ("SIZE");
			LvCol.cx = CompensateXDPI (64);
			LvCol.fmt = LVCFMT_RIGHT;
			SendMessage (hList,LVM_INSERTCOLUMNW,2,(LPARAM)&LvCol);

			LvCol.pszText = GetString ("VOLUME_LABEL");
			LvCol.cx = CompensateXDPI (128);
			LvCol.fmt = LVCFMT_LEFT;
			SendMessage (hList,LVM_INSERTCOLUMNW,3,(LPARAM)&LvCol);

			nCount = GetAvailableFixedDisks (hList, "\\Device\\Harddisk%d\\Partition%d");

			if (bRawDevicesDlgProcInstantExit)
			{
				EndDialog (hwndDlg, IDCANCEL);
				return 1;
			}

			nCount += GetAvailableRemovables (hList, "\\Device\\Floppy%d");

			if (nCount == 0)
			{
				handleWin32Error (hwndDlg);
				MessageBoxW (hwndDlg, GetString ("RAWDEVICES"), lpszTitle, ICON_HAND);
				NormalCursor ();
				EndDialog (hwndDlg, IDCANCEL);
			}

			lpszFileName = (char *) lParam;

#ifdef VOLFORMAT
			EnableWindow (GetDlgItem (hwndDlg, IDOK), FALSE);
#endif
			return 1;
		}

	case WM_COMMAND:
	case WM_NOTIFY:
		// catch non-device line selected
		if (msg == WM_NOTIFY && ((LPNMHDR) lParam)->code == LVN_ITEMCHANGED && (((LPNMLISTVIEW) lParam)->uNewState & LVIS_FOCUSED ))
		{
			LVITEM LvItem;
			memset(&LvItem,0,sizeof(LvItem));
			LvItem.mask = LVIF_TEXT | LVIF_PARAM;   
			LvItem.iItem = ((LPNMLISTVIEW) lParam)->iItem;
			LvItem.pszText = lpszFileName;
			LvItem.cchTextMax = TC_MAX_PATH;

			SendMessage (GetDlgItem (hwndDlg, IDC_DEVICELIST), LVM_GETITEM, LvItem.iItem, (LPARAM) &LvItem);
			EnableWindow (GetDlgItem ((HWND) hwndDlg, IDOK), lpszFileName[0] != 0 && lpszFileName[0] != ' ');

			return 1;
		}

		if (msg == WM_COMMAND && lw == IDOK || msg == WM_NOTIFY && ((NMHDR *)lParam)->code == LVN_ITEMACTIVATE)
		{
			LVITEM LvItem;
			memset (&LvItem,0,sizeof(LvItem));
			LvItem.mask = LVIF_TEXT | LVIF_PARAM;   
			LvItem.iItem =  SendMessage (GetDlgItem (hwndDlg, IDC_DEVICELIST), LVM_GETSELECTIONMARK, 0, 0);
			LvItem.pszText = lpszFileName;
			LvItem.cchTextMax = TC_MAX_PATH;

			SendMessage (GetDlgItem (hwndDlg, IDC_DEVICELIST), LVM_GETITEM, LvItem.iItem, (LPARAM) &LvItem);

			if (lpszFileName[0] == 0)
				return 1; // non-device line selected

#ifdef VOLFORMAT
			if (LvItem.lParam & SELDEVFLAG_SYSTEM_PARTITION)
			{
				if (WizardMode != WIZARD_MODE_SYS_DEVICE)
				{
					if (AskYesNo ("CONFIRM_SYSTEM_ENCRYPTION_MODE") == IDNO)
					{
						EndDialog (hwndDlg, IDCANCEL);
						return 1;
					}

					bSysPartitionSelected = TRUE;
					bSysDriveSelected = FALSE;
					lpszFileName[0] = 0;
					SwitchWizardToSysEncMode ();

					NormalCursor ();
					EndDialog (hwndDlg, IDOK);
					return 1;
				}
				else
				{
					// This should never be the case because the Select Device dialog is not available in this wizard mode
					bSysPartitionSelected = TRUE;
					bSysDriveSelected = FALSE;
					lpszFileName[0] = 0;
					SwitchWizardToSysEncMode ();
					NormalCursor ();
					EndDialog (hwndDlg, IDCANCEL);
					return 1;
				}
			}

			if (!(LvItem.lParam & SELDEVFLAG_SYSTEM_DRIVE))
			{
				if (bWarnDeviceFormatAdvanced
					&& !bHiddenVolDirect
					&& AskWarnNoYes("FORMAT_DEVICE_FOR_ADVANCED_ONLY") == IDNO)
				{
					if (AskNoYes("CONFIRM_CHANGE_WIZARD_MODE_TO_FILE_CONTAINER") == IDYES)
					{
						SwitchWizardToFileContainerMode ();
					}
					EndDialog (hwndDlg, IDCANCEL);
					return 1;
				}

				if (!bHiddenVolDirect)
					bWarnDeviceFormatAdvanced = FALSE;
			}

#else	// #ifdef VOLFORMAT

			bSysPartitionSelected = LvItem.lParam & SELDEVFLAG_SYSTEM_PARTITION;
			bSysDriveSelected = FALSE;

#endif	// #ifdef VOLFORMAT

			if (lpszFileName[0] == 'H')
			{
				// Whole device selected
				int driveNo;

				if (sscanf (lpszFileName, "Harddisk %d", &driveNo) != 1)
				{
					EnableWindow (GetDlgItem (hwndDlg, IDOK), FALSE);
					return 1;
				}

#ifdef VOLFORMAT
				if (LvItem.lParam & SELDEVFLAG_SYSTEM_DRIVE)
				{
					if (WizardMode != WIZARD_MODE_SYS_DEVICE)
					{
						if (AskYesNo ("CONFIRM_SYSTEM_ENCRYPTION_MODE") == IDNO)
						{
							NormalCursor ();
							EndDialog (hwndDlg, IDCANCEL);
							return 1;
						}

						bSysDriveSelected = TRUE;
						bSysPartitionSelected = FALSE;
						lpszFileName[0] = 0;
						SwitchWizardToSysEncMode ();

						NormalCursor ();
						EndDialog (hwndDlg, IDOK);
						return 1;
					}
					else
					{
						// This should never be the case because the Select Device dialog is not available in this wizard mode
						bSysDriveSelected = TRUE;
						bSysPartitionSelected = FALSE;
						lpszFileName[0] = 0;
						SwitchWizardToSysEncMode ();
						NormalCursor ();
						EndDialog (hwndDlg, IDCANCEL);
						return 1;
					}
				}

				// Disallow format if the device contains partitions, but not if the partition is virtual or system 
				if (!(LvItem.lParam & SELDEVFLAG_VIRTUAL_PARTITION)
					&& !bHiddenVolDirect)
				{
					if (LvItem.lParam & SELDEVFLAG_CONTAINS_PARTITIONS)
					{
						EnableWindow (GetDlgItem (hwndDlg, IDOK), FALSE);
						Error ("DEVICE_PARTITIONS_ERR");
						return 1;
					}
				}
#else	// #ifdef VOLFORMAT

				bSysDriveSelected = LvItem.lParam & SELDEVFLAG_SYSTEM_DRIVE;
				bSysPartitionSelected = FALSE;

#endif	// #ifdef VOLFORMAT

				sprintf (lpszFileName, 
					(LvItem.lParam & SELDEVFLAG_VIRTUAL_PARTITION) ? 
					"\\Device\\Harddisk%d\\Partition1" : "\\Device\\Harddisk%d\\Partition0",
					driveNo);
			}
			else 
				bSysDriveSelected = FALSE;

#ifdef VOLFORMAT
			bRemovableHostDevice = LvItem.lParam & SELDEVFLAG_REMOVABLE_HOST_DEVICE;
#endif
			NormalCursor ();
			EndDialog (hwndDlg, IDOK);
			return 1;
		}

		if (lw == IDCANCEL)
		{
			NormalCursor ();
			EndDialog (hwndDlg, IDCANCEL);
			return 1;
		}
		return 0;
	}
	return 0;
}


BOOL DoDriverInstall (HWND hwndDlg)
{
#ifdef SETUP
	if (SystemEncryptionUpgrade)
		return TRUE;
#endif

	SC_HANDLE hManager, hService = NULL;
	BOOL bOK = FALSE, bRet;

	hManager = OpenSCManager (NULL, NULL, SC_MANAGER_ALL_ACCESS);
	if (hManager == NULL)
		goto error;

#ifdef SETUP
	StatusMessage (hwndDlg, "INSTALLING_DRIVER");
#endif

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

#ifdef SETUP
	StatusMessage (hwndDlg, "STARTING_DRIVER");
#endif

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

	hService = OpenService (hManager, "truecrypt", SERVICE_ALL_ACCESS);
	if (hService != NULL)
	{
		// Remove stale service (driver is not loaded but service exists)
		DeleteService (hService);
		CloseServiceHandle (hService);
		Sleep (500);
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
	int volumesMounted;
	DWORD dwResult;
	BOOL bResult;

	SC_HANDLE hManager, hService = NULL;
	BOOL bRet;
	SERVICE_STATUS status;
	int x;

	if (hDriver == INVALID_HANDLE_VALUE)
		return TRUE;
	
	try
	{
		if (BootEncryption (NULL).GetStatus().DeviceFilterActive)
			return FALSE;
	}
	catch (...) { }

	// Test for mounted volumes
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
			return FALSE;
	}
	else
		return TRUE;

	// Test for any applications attached to driver
	refCount = GetDriverRefCount ();

	if (refCount > 1)
		return FALSE;

	CloseHandle (hDriver);
	hDriver = INVALID_HANDLE_VALUE;

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


int DriverAttach (void)
{
	/* Try to open a handle to the device driver. It will be closed later. */

#ifndef SETUP

	int nLoadRetryCount = 0;
start:

#endif

	hDriver = CreateFile (WIN32_ROOT_PREFIX, 0, 0, NULL, OPEN_EXISTING, 0, NULL);

	if (hDriver == INVALID_HANDLE_VALUE)
	{
#ifndef SETUP

		LoadSysEncSettings (NULL);

		if (!CreateDriverSetupMutex ())
		{
			// Another instance is already attempting to install, register or start the driver

			while (!CreateDriverSetupMutex ())
			{
				Sleep (100);	// Wait until the other instance finishes
			}

			// Try to open a handle to the driver again (keep the mutex in case the other instance failed)
			goto start;		
		}
		else
		{
			// No other instance is currently attempting to install, register or start the driver

			if (SystemEncryptionStatus != SYSENC_STATUS_NONE)
			{
				// This is an inconsistent state. The config file indicates system encryption should be
				// active, but the driver is not running. This may happen e.g. when the pretest fails and 
				// the user selects "Last Known Good Configuration" from the Windows boot menu.
				// To fix this, we're going to reinstall the driver, start it, and register it for boot.

				if (DoDriverInstall (NULL))
				{
					Sleep (1000);
					RegisterBootDriver ();
				}

				CloseDriverSetupMutex ();
			}
			else
			{
				// Attempt to load the driver (non-install/traveler mode)
load:
				BOOL res = DriverLoad ();

				CloseDriverSetupMutex ();

				if (res != ERROR_SUCCESS)
					return res;

				bTravelerModeConfirmed = TRUE;
			}

			hDriver = CreateFile (WIN32_ROOT_PREFIX, 0, 0, NULL, OPEN_EXISTING, 0, NULL);

			if (bTravelerModeConfirmed)
				NotifyDriverOfTravelerMode ();
		}

#endif	// #ifndef SETUP

		if (hDriver == INVALID_HANDLE_VALUE)
			return ERR_OS_ERROR;
	}

	CloseDriverSetupMutex ();

	if (hDriver != INVALID_HANDLE_VALUE)
	{
		DWORD dwResult;

		BOOL bResult = DeviceIoControl (hDriver, TC_IOCTL_GET_DRIVER_VERSION, NULL, 0, &DriverVersion, sizeof (DriverVersion), &dwResult, NULL);

		if (!bResult)
			bResult = DeviceIoControl (hDriver, TC_IOCTL_LEGACY_GET_DRIVER_VERSION, NULL, 0, &DriverVersion, sizeof (DriverVersion), &dwResult, NULL);

#ifndef SETUP // Don't check version during setup to allow removal of another version
		if (bResult == FALSE)
		{
			return ERR_OS_ERROR;
		}
		else if (DriverVersion != VERSION_NUM)
		{
			// Unload an incompatbile version of the driver loaded in non-install mode and load the required version
			if (IsNonInstallMode () && CreateDriverSetupMutex () && DriverUnload () && nLoadRetryCount++ < 3)
				goto load;

			CloseDriverSetupMutex ();
			CloseHandle (hDriver);
			hDriver = INVALID_HANDLE_VALUE;
			return ERR_DRIVER_VERSION;
		}
#else
		if (!bResult)
			DriverVersion = 0;
#endif
	}

	return 0;
}


void ResetCurrentDirectory ()
{
	char p[MAX_PATH];
	if (!IsNonInstallMode () && SHGetFolderPath (NULL, CSIDL_PROFILE, NULL, 0, p) == ERROR_SUCCESS)
	{
		SetCurrentDirectory (p);
	}
	else
	{
		GetModPath (p, sizeof (p));
		SetCurrentDirectory (p);
	}
}


BOOL BrowseFiles (HWND hwndDlg, char *stringId, char *lpszFileName, BOOL keepHistory, BOOL saveMode)
{
	return BrowseFilesInDir (hwndDlg, stringId, NULL, lpszFileName, keepHistory, saveMode);
}


BOOL BrowseFilesInDir (HWND hwndDlg, char *stringId, char *initialDir, char *lpszFileName, BOOL keepHistory, BOOL saveMode)
{
	OPENFILENAMEW ofn;
	wchar_t file[TC_MAX_PATH] = { 0 };
	wchar_t wInitialDir[TC_MAX_PATH] = { 0 };
	wchar_t filter[1024];
	BOOL status = FALSE;

	CoInitialize (NULL);

	ZeroMemory (&ofn, sizeof (ofn));
	*lpszFileName = 0;

	if (initialDir)
	{
		swprintf_s (wInitialDir, sizeof (wInitialDir) / 2, L"%hs", initialDir);
		ofn.lpstrInitialDir			= wInitialDir;
	}

	ofn.lStructSize				= sizeof (ofn);
	ofn.hwndOwner				= hwndDlg;
	wsprintfW (filter, L"%ls (*.*)%c*.*%c%ls (*.tc)%c*.tc%c%c",
		GetString ("ALL_FILES"), 0, 0, GetString ("TC_VOLUMES"), 0, 0, 0);
	ofn.lpstrFilter				= filter;
	ofn.nFilterIndex			= 1;
	ofn.lpstrFile				= file;
	ofn.nMaxFile				= sizeof (file) / sizeof (file[0]);
	ofn.lpstrTitle				= GetString (stringId);
	ofn.Flags					= OFN_HIDEREADONLY
		| OFN_PATHMUSTEXIST
		| (keepHistory ? 0 : OFN_DONTADDTORECENT)
		| (saveMode ? OFN_OVERWRITEPROMPT : 0);
	
	if (!keepHistory)
		CleanLastVisitedMRU ();

	if (!saveMode)
	{
		if (!GetOpenFileNameW (&ofn))
			goto ret;
	}
	else
	{
		if (!GetSaveFileNameW (&ofn))
			goto ret;
	}

	WideCharToMultiByte (CP_ACP, 0, file, -1, lpszFileName, MAX_PATH, NULL, NULL);

	if (!keepHistory)
		CleanLastVisitedMRU ();

	ResetCurrentDirectory ();
	status = TRUE;

ret:
	CoUninitialize();
	return status;
}


static char SelectMultipleFilesPath[MAX_PATH];
static int SelectMultipleFilesOffset;

BOOL SelectMultipleFiles (HWND hwndDlg, char *stringId, char *lpszFileName, BOOL keepHistory)
{
	OPENFILENAMEW ofn;
	wchar_t file[TC_MAX_PATH] = { 0 };
	wchar_t filter[1024];
	BOOL status = FALSE;

	CoInitialize (NULL);

	ZeroMemory (&ofn, sizeof (ofn));

	*lpszFileName = 0;
	ofn.lStructSize				= sizeof (ofn);
	ofn.hwndOwner				= hwndDlg;
	wsprintfW (filter, L"%ls (*.*)%c*.*%c%ls (*.tc)%c*.tc%c%c",
		GetString ("ALL_FILES"), 0, 0, GetString ("TC_VOLUMES"), 0, 0, 0);
	ofn.lpstrFilter				= filter;
	ofn.nFilterIndex			= 1;
	ofn.lpstrFile				= file;
	ofn.nMaxFile				= sizeof (file) / sizeof (file[0]);
	ofn.lpstrTitle				= GetString (stringId);
	ofn.Flags					= OFN_HIDEREADONLY
		| OFN_EXPLORER
		| OFN_PATHMUSTEXIST
		| OFN_ALLOWMULTISELECT
		| (keepHistory ? 0 : OFN_DONTADDTORECENT);
	
	if (!keepHistory)
		CleanLastVisitedMRU ();

	if (!GetOpenFileNameW (&ofn))
		goto ret;

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

	if (!keepHistory)
		CleanLastVisitedMRU ();

	ResetCurrentDirectory ();
	status = TRUE;
	
ret:
	CoUninitialize();
	return status;
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

	CoInitialize (NULL);

	if (SUCCEEDED (SHGetMalloc (&pMalloc))) 
	{
		ZeroMemory (&bi, sizeof(bi));
		bi.hwndOwner = hwndDlg;
		bi.pszDisplayName = 0;
		bi.lpszTitle = GetString (lpszTitle);
		bi.pidlRoot = 0;
		bi.ulFlags = BIF_RETURNONLYFSDIRS | BIF_STATUSTEXT;
		bi.lpfn = BrowseCallbackProc;
		bi.lParam = (LPARAM)dirName;

		pidl = SHBrowseForFolderW (&bi);
		if (pidl != NULL) 
		{
			if (SHGetPathFromIDList(pidl, dirName)) 
			{
				bOK = TRUE;
			}

			pMalloc->Free (pidl);
			pMalloc->Release();
		}
	}

	CoUninitialize();

	return bOK;
}


void handleError (HWND hwndDlg, int code)
{
	WCHAR szTmp[4096];

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
		swprintf (szTmp, GetString (KeyFilesEnable ? "PASSWORD_OR_KEYFILE_WRONG" : "PASSWORD_WRONG"));
		if (CheckCapsLock (hwndDlg, TRUE))
			wcscat (szTmp, GetString ("PASSWORD_WRONG_CAPSLOCK_ON"));

#ifdef TCMOUNT
		if (TCBootLoaderOnInactiveSysEncDrive ())
		{
			swprintf (szTmp, GetString (KeyFilesEnable ? "PASSWORD_OR_KEYFILE_OR_MODE_WRONG" : "PASSWORD_OR_MODE_WRONG"));

			if (CheckCapsLock (hwndDlg, TRUE))
				wcscat (szTmp, GetString ("PASSWORD_WRONG_CAPSLOCK_ON"));

			wcscat (szTmp, GetString ("SYSENC_MOUNT_WITHOUT_PBA_NOTE"));
		}
#endif

		MessageBoxW (hwndDlg, szTmp, lpszTitle, MB_ICONWARNING);
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

	case ERR_VOL_FORMAT_BAD:
		Error ("ERR_VOL_FORMAT_BAD");
		break;

	case ERR_ENCRYPTION_NOT_COMPLETED:
		Error ("ERR_ENCRYPTION_NOT_COMPLETED");
		break;

	case ERR_SYS_HIDVOL_HEAD_REENC_MODE_WRONG:
		Error ("ERR_SYS_HIDVOL_HEAD_REENC_MODE_WRONG");
		break;

	case ERR_PARAMETER_INCORRECT:
		Error ("ERR_PARAMETER_INCORRECT");
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
				wchar_t *str = (wchar_t *) GetDictionaryValueByInt (ctrlId);
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
	LastDialogId = stringId;
	SetWindowLongPtr (hwnd, GWLP_USERDATA, (LONG_PTR) 'TRUE');
	SendMessage (hwnd, WM_SETFONT, (WPARAM) hUserFont, 0);

	if (stringId == NULL)
		SetWindowText (hwnd, "TrueCrypt");
	else
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
static HWND explorerTopLevelWindow;

static BOOL CALLBACK CloseVolumeExplorerWindowsChildEnum (HWND hwnd, LPARAM driveStr)
{
	char s[MAX_PATH];
	SendMessage (hwnd, WM_GETTEXT, sizeof (s), (LPARAM) s);

	if (strstr (s, (char *) driveStr) != NULL)
	{
		PostMessage (explorerTopLevelWindow, WM_CLOSE, 0, 0);
		explorerCloseSent = TRUE;
		return FALSE;
	}

	return TRUE;
}

static BOOL CALLBACK CloseVolumeExplorerWindowsEnum (HWND hwnd, LPARAM driveNo)
{
	char driveStr[10];
	char s[MAX_PATH];

	sprintf (driveStr, "%c:\\", driveNo + 'A');

	GetClassName (hwnd, s, sizeof s);
	if (strcmp (s, "CabinetWClass") == 0)
	{
		GetWindowText (hwnd, s, sizeof s);
		if (strstr (s, driveStr) != NULL)
		{
			PostMessage (hwnd, WM_CLOSE, 0, 0);
			explorerCloseSent = TRUE;
			return TRUE;
		}

		explorerTopLevelWindow = hwnd;
		EnumChildWindows (hwnd, CloseVolumeExplorerWindowsChildEnum, (LPARAM) driveStr);
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
	UINT64_STRUCT startDataUnitNo;

	startDataUnitNo.Value = 0;

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

	lpTestBuffer = (BYTE *) malloc(benchmarkBufferSize - (benchmarkBufferSize % 16));
	if (lpTestBuffer == NULL)
	{
		MessageBoxW (hwndDlg, GetString ("ERR_MEM_ALLOC"), lpszTitle, ICON_HAND);
		return FALSE;
	}
	VirtualLock (lpTestBuffer, benchmarkBufferSize - (benchmarkBufferSize % 16));

	WaitCursor ();
	benchmarkTotalItems = 0;

#if !(PKCS5_BENCHMARKS || HASH_FNC_BENCHMARKS)
	// CPU "warm up" (an attempt to prevent skewed results on systems where CPU frequency
	// gradually changes depending on CPU load).
	ci->ea = EAGetFirst();
	if (!EAInit (ci->ea, ci->master_keydata, ci->ks))
	{
		ci->mode = FIRST_MODE_OF_OPERATION_ID;
		if (EAInitMode (ci))
		{
			int i;

			for (i = 0; i < 2; i++)
			{
				EncryptDataUnits (lpTestBuffer, &startDataUnitNo, (TC_LARGEST_COMPILER_UINT) benchmarkBufferSize / ENCRYPTION_DATA_UNIT_SIZE, ci);
				DecryptDataUnits (lpTestBuffer, &startDataUnitNo, (TC_LARGEST_COMPILER_UINT) benchmarkBufferSize / ENCRYPTION_DATA_UNIT_SIZE, ci);
			}
		}
	}
#endif

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
		sha512_ctx		s2ctx;
		int hid;

		for (hid = FIRST_PRF_ID; hid <= LAST_PRF_ID; hid++) 
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

			case SHA512:
				sha512_begin (&s2ctx);
				sha512_hash (lpTestBuffer, benchmarkBufferSize, &s2ctx);
				sha512_end ((unsigned char *) digest, &s2ctx);
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
		char dk[MASTER_KEYDATA_SIZE];
		char *tmp_salt = {"\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xAA\xBB\xCC\xDD\xEE\xFF\x01\x23\x45\x67\x89\xAB\xCD\xEF\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xAA\xBB\xCC\xDD\xEE\xFF\x01\x23\x45\x67\x89\xAB\xCD\xEF\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xAA\xBB\xCC\xDD\xEE\xFF"};

		for (thid = FIRST_PRF_ID; thid <= LAST_PRF_ID; thid++) 
		{
			if (QueryPerformanceCounter (&performanceCountStart) == 0)
				goto counter_error;

			for (i = 1; i <= 5; i++) 
			{
				switch (thid)
				{
				case SHA1:
					/* PKCS-5 test with HMAC-SHA-1 used as the PRF */
					derive_key_sha1 ("passphrase-1234567890", 21, tmp_salt, 64, get_pkcs5_iteration_count(thid, FALSE), dk, MASTER_KEYDATA_SIZE);
					break;

				case SHA512:
					/* PKCS-5 test with HMAC-SHA-512 used as the PRF */
					derive_key_sha512 ("passphrase-1234567890", 21, tmp_salt, 64, get_pkcs5_iteration_count(thid, FALSE), dk, MASTER_KEYDATA_SIZE);
					break;

				case RIPEMD160:
					/* PKCS-5 test with HMAC-RIPEMD-160 used as the PRF */
					derive_key_ripemd160 ("passphrase-1234567890", 21, tmp_salt, 64, get_pkcs5_iteration_count(thid, FALSE), dk, MASTER_KEYDATA_SIZE);
					break;

				case WHIRLPOOL:
					/* PKCS-5 test with HMAC-Whirlpool used as the PRF */
					derive_key_whirlpool ("passphrase-1234567890", 21, tmp_salt, 64, get_pkcs5_iteration_count(thid, FALSE), dk, MASTER_KEYDATA_SIZE);
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
		if (!EAIsFormatEnabled (ci->ea))
			continue;

		EAInit (ci->ea, ci->master_keydata, ci->ks);

		ci->mode = FIRST_MODE_OF_OPERATION_ID;
		if (!EAInitMode (ci))
			break;

		if (QueryPerformanceCounter (&performanceCountStart) == 0)
			goto counter_error;

		EncryptDataUnits (lpTestBuffer, &startDataUnitNo, (TC_LARGEST_COMPILER_UINT) benchmarkBufferSize / ENCRYPTION_DATA_UNIT_SIZE, ci);

		if (QueryPerformanceCounter (&performanceCountEnd) == 0)
			goto counter_error;

		benchmarkTable[benchmarkTotalItems].encSpeed = performanceCountEnd.QuadPart - performanceCountStart.QuadPart;

		if (QueryPerformanceCounter (&performanceCountStart) == 0)
			goto counter_error;

		DecryptDataUnits (lpTestBuffer, &startDataUnitNo, (TC_LARGEST_COMPILER_UINT) benchmarkBufferSize / ENCRYPTION_DATA_UNIT_SIZE, ci);

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


BOOL CALLBACK BenchmarkDlgProc (HWND hwndDlg, UINT msg, WPARAM wParam, LPARAM lParam)
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
			LvCol.cx = CompensateXDPI (114);
			LvCol.fmt = LVCFMT_LEFT;
			SendMessage (hList,LVM_INSERTCOLUMNW,0,(LPARAM)&LvCol);

			LvCol.pszText = GetString ("ENCRYPTION");
			LvCol.cx = CompensateXDPI (80);
			LvCol.fmt = LVCFMT_RIGHT;
			SendMessageW (hList,LVM_INSERTCOLUMNW,1,(LPARAM)&LvCol);

			LvCol.pszText = GetString ("DECRYPTION");
			LvCol.cx = CompensateXDPI (80);
			LvCol.fmt = LVCFMT_RIGHT;
			SendMessageW (hList,LVM_INSERTCOLUMNW,2,(LPARAM)&LvCol);

			LvCol.pszText = GetString ("MEAN");
			LvCol.cx = CompensateXDPI (80);
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

			SendMessage (hCboxBufferSize, CB_SETCURSEL, 3, 0);		// Default buffer size

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

			if (PerformBenchmark (hwndDlg) == FALSE)
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
BOOL CALLBACK
KeyfileGeneratorDlgProc (HWND hwndDlg, UINT msg, WPARAM wParam, LPARAM lParam)
{
	WORD lw = LOWORD (wParam);
	WORD hw = HIWORD (wParam);
	static unsigned char randPool [RNG_POOL_SIZE];
	static unsigned char lastRandPool [RNG_POOL_SIZE];
	static char outputDispBuffer [RNG_POOL_SIZE * 3 + RANDPOOL_DISPLAY_ROWS + 2];
	static BOOL bDisplayPoolContents = TRUE;
	static BOOL bRandPoolDispAscii = FALSE;
	int hash_algo = RandGetHashFunction();
	int hid;

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
			for (hid = FIRST_PRF_ID; hid <= LAST_PRF_ID; hid++)
			{
				if (!HashIsDeprecated (hid))
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
			SetTimer (hwndDlg, 0xfd, RANDPOOL_DISPLAY_REFRESH_INTERVAL, NULL);
			SendMessage (GetDlgItem (hwndDlg, IDC_POOL_CONTENTS), WM_SETFONT, (WPARAM) hFixedDigitFont, (LPARAM) TRUE);
			return 1;
		}

	case WM_TIMER:
		{
			char tmp[4];
			unsigned char tmpByte;
			int col, row;

			if (bDisplayPoolContents)
			{
				RandpeekBytes (randPool, sizeof (randPool));

				if (memcmp (lastRandPool, randPool, sizeof(lastRandPool)) != 0)
				{
					outputDispBuffer[0] = 0;

					for (row = 0; row < RANDPOOL_DISPLAY_ROWS; row++)
					{
						for (col = 0; col < RANDPOOL_DISPLAY_COLUMNS; col++)
						{
							tmpByte = randPool[row * RANDPOOL_DISPLAY_COLUMNS + col];

							sprintf (tmp, bRandPoolDispAscii ? ((tmpByte >= 32 && tmpByte < 255 && tmpByte != '&') ? " %c " : " . ") : "%02X ", tmpByte);
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
			{
				char tmp[RNG_POOL_SIZE+1];

				memset (tmp, ' ', sizeof(tmp));
				tmp [RNG_POOL_SIZE] = 0;
				SetWindowText (GetDlgItem (hwndDlg, IDC_POOL_CONTENTS), tmp);
			}
		}

		if (lw == IDC_GENERATE_AND_SAVE_KEYFILE)
		{
			char szFileName [TC_MAX_PATH];
			unsigned char keyfile [MAX_PASSWORD];
			int fhKeyfile = -1;

			/* Select filename */
			if (!BrowseFiles (hwndDlg, "OPEN_TITLE", szFileName, bHistory, TRUE))
				return 1;

			/* Conceive the file */
			if ((fhKeyfile = _open(szFileName, _O_CREAT|_O_TRUNC|_O_WRONLY|_O_BINARY, _S_IREAD|_S_IWRITE)) == -1)
			{
				handleWin32Error (hwndDlg);
				return 1;
			}

			/* Generate the keyfile */ 
			WaitCursor();
			if (!RandgetBytes (keyfile, sizeof(keyfile), TRUE))
			{
				_close (fhKeyfile);
				DeleteFile (szFileName);
				NormalCursor();
				return 1;
			}
			NormalCursor();

			/* Write the keyfile */
			if (_write (fhKeyfile, keyfile, sizeof(keyfile)) == -1)
				handleWin32Error (hwndDlg);
			else
				Info("KEYFILE_CREATED");

			burn (keyfile, sizeof(keyfile));
			_close (fhKeyfile);
			return 1;
		}
		return 0;

	case WM_CLOSE:
		{
			char tmp[RNG_POOL_SIZE+1];
exit:
			WaitCursor();
			KillTimer (hwndDlg, 0xfd);

#ifndef VOLFORMAT			
			Randfree ();
#endif
			/* Cleanup */

			burn (randPool, sizeof(randPool));
			burn (lastRandPool, sizeof(lastRandPool));
			burn (outputDispBuffer, sizeof(outputDispBuffer));

			// Attempt to wipe the pool contents in the GUI text area
			memset (tmp, 'X', RNG_POOL_SIZE);
			tmp [RNG_POOL_SIZE] = 0;
			SetWindowText (GetDlgItem (hwndDlg, IDC_POOL_CONTENTS), tmp);

			EndDialog (hwndDlg, IDCLOSE);
			NormalCursor ();
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
	static BOOL bXTSTestEnabled = FALSE;

	PCRYPTO_INFO ci;
	WORD lw = LOWORD (wParam);
	WORD hw = HIWORD (wParam);

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
			SendMessage(GetDlgItem(hwndDlg, IDC_PLAINTEXT), EM_LIMITTEXT,64,0);
			SendMessage(GetDlgItem(hwndDlg, IDC_PLAINTEXT), WM_SETFONT, (WPARAM)hFixedDigitFont, MAKELPARAM(1,0));
			SendMessage(GetDlgItem(hwndDlg, IDC_CIPHERTEXT), EM_LIMITTEXT,64,0);
			SendMessage(GetDlgItem(hwndDlg, IDC_CIPHERTEXT), WM_SETFONT, (WPARAM)hFixedDigitFont, MAKELPARAM(1,0));
			SendMessage(GetDlgItem(hwndDlg, IDC_SECONDARY_KEY), EM_LIMITTEXT, 128,0);
			SendMessage(GetDlgItem(hwndDlg, IDC_SECONDARY_KEY), WM_SETFONT, (WPARAM)hFixedDigitFont, MAKELPARAM(1,0));
			SendMessage(GetDlgItem(hwndDlg, IDC_TEST_DATA_UNIT_NUMBER), EM_LIMITTEXT,32,0);
			SendMessage(GetDlgItem(hwndDlg, IDC_TEST_DATA_UNIT_NUMBER), WM_SETFONT, (WPARAM)hFixedDigitFont, MAKELPARAM(1,0));
			SetCheckBox (hwndDlg, IDC_XTS_MODE_ENABLED, bXTSTestEnabled);
			EnableWindow (GetDlgItem (hwndDlg, IDC_SECONDARY_KEY), bXTSTestEnabled);
			EnableWindow (GetDlgItem (hwndDlg, IDT_SECONDARY_KEY), bXTSTestEnabled);
			EnableWindow (GetDlgItem (hwndDlg, IDC_TEST_BLOCK_NUMBER), bXTSTestEnabled);
			EnableWindow (GetDlgItem (hwndDlg, IDT_TEST_BLOCK_NUMBER), bXTSTestEnabled);
			EnableWindow (GetDlgItem (hwndDlg, IDC_TEST_DATA_UNIT_NUMBER), bXTSTestEnabled);
			EnableWindow (GetDlgItem (hwndDlg, IDT_TEST_DATA_UNIT_NUMBER), bXTSTestEnabled);

			if (idTestCipher == -1)
				idTestCipher = (int) lParam;

			SendMessage (GetDlgItem (hwndDlg, IDC_CIPHER), CB_RESETCONTENT, 0, 0);
			for (ea = EAGetFirst (); ea != 0; ea = EAGetNext (ea))
			{
				if (EAGetCipherCount (ea) == 1 && EAIsFormatEnabled (ea))
					AddComboPair (GetDlgItem (hwndDlg, IDC_CIPHER), EAGetName (buf, ea), EAGetFirstCipher (ea));
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
			WaitCursor ();
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
			NormalCursor ();

			return 1;

		}

		if (lw == IDC_XTS_MODE_ENABLED)
		{
			bXTSTestEnabled = GetCheckBox (hwndDlg, IDC_XTS_MODE_ENABLED);
			EnableWindow (GetDlgItem (hwndDlg, IDC_SECONDARY_KEY), bXTSTestEnabled);
			EnableWindow (GetDlgItem (hwndDlg, IDT_SECONDARY_KEY), bXTSTestEnabled);
			EnableWindow (GetDlgItem (hwndDlg, IDC_TEST_BLOCK_NUMBER), bXTSTestEnabled);
			EnableWindow (GetDlgItem (hwndDlg, IDT_TEST_BLOCK_NUMBER), bXTSTestEnabled);
			EnableWindow (GetDlgItem (hwndDlg, IDT_TEST_DATA_UNIT_NUMBER), bXTSTestEnabled);
			EnableWindow (GetDlgItem (hwndDlg, IDC_TEST_DATA_UNIT_NUMBER), bXTSTestEnabled);
			if (bXTSTestEnabled)
				SendMessage(GetDlgItem(hwndDlg, IDC_KEY_SIZE), CB_SETCURSEL, 0,0);
		}

		if (lw == IDOK || lw == IDC_ENCRYPT || lw == IDC_DECRYPT)
		{
			char key[128+1], inputtext[128+1], secondaryKey[64+1], dataUnitNo[16+1], szTmp[128+1];
			int ks, pt, n, tlen, blockNo = 0;
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
				Warning ("TEST_KEY_SIZE");
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
			memset(secondaryKey, 0, sizeof(secondaryKey));
			memset(dataUnitNo, 0, sizeof(dataUnitNo));
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
					Warning ("TEST_PLAINTEXT_SIZE");
					return 1;
				}
				else
				{
					Warning  ("TEST_CIPHERTEXT_SIZE");
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
			
			// XTS
			if (bXTSTestEnabled)
			{
				// Secondary key

				if (GetWindowText(GetDlgItem(hwndDlg, IDC_SECONDARY_KEY), szTmp, sizeof(szTmp)) != 64)
				{
					Warning ("TEST_INCORRECT_SECONDARY_KEY_SIZE");
					return 1;
				}

				for (n = 0; n < 64; n ++)
				{
					char szTmp2[3], *ptr;
					long x;

					szTmp2[2] = 0;
					szTmp2[0] = szTmp[n * 2];
					szTmp2[1] = szTmp[n * 2 + 1];

					x = strtol(szTmp2, &ptr, 16);

					secondaryKey[n] = (char) x;
				}

				// Data unit number

				tlen = GetWindowText(GetDlgItem(hwndDlg, IDC_TEST_DATA_UNIT_NUMBER), szTmp, sizeof(szTmp));

				if (tlen > 16 || tlen < 1)
				{
					Warning ("TEST_INCORRECT_TEST_DATA_UNIT_SIZE");
					return 1;
				}

				LeftPadString (szTmp, tlen, 16, '0');

				for (n = 0; n < 16; n ++)
				{
					char szTmp2[3], *ptr;
					long x;

					szTmp2[2] = 0;
					szTmp2[0] = szTmp[n * 2];
					szTmp2[1] = szTmp[n * 2 + 1];

					x = strtol(szTmp2, &ptr, 16);

					dataUnitNo[n] = (char) x;
				}

				// Block number

				blockNo = (int) SendMessage (GetDlgItem (hwndDlg, IDC_TEST_BLOCK_NUMBER), CB_GETITEMDATA, SendMessage (GetDlgItem (hwndDlg, IDC_TEST_BLOCK_NUMBER), CB_GETCURSEL, 0, 0), 0);
			}	// if (bXTSTestEnabled)

			
			/* Perform the actual tests */

			if (ks != CB_ERR && pt != CB_ERR) 
			{
				char tmp[128];
				int tmpRetVal;

				/* Copy the plain/ciphertext */
				memcpy(tmp,inputtext, pt);

				if (bXTSTestEnabled)
				{
					UINT64_STRUCT structDataUnitNo;

					/* XTS mode */

					ci = crypto_open ();
					if (!ci)
						return 1;

					ci->mode = XTS;

					for (ci->ea = EAGetFirst (); ci->ea != 0 ; ci->ea = EAGetNext (ci->ea))
						if (EAGetCipherCount (ci->ea) == 1 && EAGetFirstCipher (ci->ea) == idTestCipher)
							break;

					if ((tmpRetVal = EAInit (ci->ea, (unsigned char *) key, ci->ks)) != ERR_SUCCESS)
					{
						handleError (hwndDlg, tmpRetVal);
						return 1;
					}

					memcpy (&ci->k2, secondaryKey, sizeof (secondaryKey));
					if (!EAInitMode (ci))
						return 1;

					structDataUnitNo.Value = BE64(((unsigned __int64 *)dataUnitNo)[0]);

					if (bEncrypt)
						EncryptBufferXTS ((unsigned char *) tmp, pt, &structDataUnitNo, blockNo, (unsigned char *) (ci->ks), (unsigned char *) ci->ks2, idTestCipher);
					else
						DecryptBufferXTS ((unsigned char *) tmp, pt, &structDataUnitNo, blockNo, (unsigned char *) (ci->ks), (unsigned char *) ci->ks2, idTestCipher);

					crypto_close (ci);
				}
				else
				{
					if (idTestCipher == BLOWFISH)
					{
						/* Deprecated/legacy */

						/* Convert to little-endian, this is needed here and not in
						above auto-tests because BF_ecb_encrypt above correctly converts
						from big to little endian, and EncipherBlock does not! */
						LongReverse((unsigned int *) tmp, pt);
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
						/* Deprecated/legacy */

						/* Convert back to big-endian */
						LongReverse((unsigned int *) tmp, pt);
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

	EnableWindow(GetDlgItem(hwndDlg,IDC_KEY_SIZE), FALSE);

	/* Setup the keysize and plaintext sizes for the selected cipher */

	SendMessage (GetDlgItem(hwndDlg, IDC_PLAINTEXT_SIZE), CB_RESETCONTENT, 0,0);
	SendMessage (GetDlgItem(hwndDlg, IDC_KEY_SIZE), CB_RESETCONTENT, 0,0);
	SendMessage (GetDlgItem(hwndDlg, IDC_TEST_BLOCK_NUMBER), CB_RESETCONTENT, 0,0);

	ndx = SendMessage (GetDlgItem(hwndDlg, IDC_PLAINTEXT_SIZE), CB_ADDSTRING, 0,(LPARAM) "64");
	SendMessage(GetDlgItem(hwndDlg, IDC_PLAINTEXT_SIZE), CB_SETITEMDATA, ndx,(LPARAM) 8);
	SendMessage(GetDlgItem(hwndDlg, IDC_PLAINTEXT_SIZE), CB_SETCURSEL, ndx,0);

	for (ndx = 0; ndx < BLOCKS_PER_XTS_DATA_UNIT; ndx++)
	{
		char tmpStr [16];

		sprintf (tmpStr, "%d", ndx);

		ndx = SendMessage (GetDlgItem(hwndDlg, IDC_TEST_BLOCK_NUMBER), CB_ADDSTRING, 0,(LPARAM) tmpStr);
		SendMessage(GetDlgItem(hwndDlg, IDC_TEST_BLOCK_NUMBER), CB_SETITEMDATA, ndx,(LPARAM) ndx);
	}

	SendMessage(GetDlgItem(hwndDlg, IDC_TEST_BLOCK_NUMBER), CB_SETCURSEL, 0, 0);

	SetWindowText(GetDlgItem(hwndDlg, IDC_SECONDARY_KEY), "0000000000000000000000000000000000000000000000000000000000000000");
	SetWindowText(GetDlgItem(hwndDlg, IDC_TEST_DATA_UNIT_NUMBER), "0");

	if (idTestCipher == BLOWFISH)
	{
		/* Deprecated/legacy */

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
		/* Deprecated/legacy */

		ndx = SendMessage (GetDlgItem(hwndDlg, IDC_KEY_SIZE), CB_ADDSTRING, 0,(LPARAM) "128");
		SendMessage(GetDlgItem(hwndDlg, IDC_KEY_SIZE), CB_SETITEMDATA, ndx,(LPARAM) 16);
		SendMessage(GetDlgItem(hwndDlg, IDC_KEY_SIZE), CB_SETCURSEL, ndx,0);
		SetWindowText(GetDlgItem(hwndDlg, IDC_KEY), "00000000000000000000000000000000");
	}

	if (idTestCipher == TRIPLEDES)
	{
		/* Deprecated/legacy */

		ndx = SendMessage (GetDlgItem(hwndDlg, IDC_KEY_SIZE), CB_ADDSTRING, 0,(LPARAM) "168");
		SendMessage(GetDlgItem(hwndDlg, IDC_KEY_SIZE), CB_SETITEMDATA, ndx,(LPARAM) 24);
		SendMessage(GetDlgItem(hwndDlg, IDC_KEY_SIZE), CB_SETCURSEL, ndx,0);
		SetWindowText(GetDlgItem(hwndDlg, IDC_KEY), "000000000000000000000000000000000000000000000000");
	}

	if (idTestCipher == DES56)
	{
		/* Deprecated/legacy */

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
	}
}

#endif	// #ifndef SETUP


BOOL CALLBACK MultiChoiceDialogProc (HWND hwndDlg, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
	char **pStr = (char **) lParam;
	char **pStrOrig = pStr;
	wchar_t **pwStr = (wchar_t **) lParam;
	wchar_t **pwStrOrig = pwStr;
	int nChoiceIDs [MAX_MULTI_CHOICES+1] = { IDC_MULTI_CHOICE_MSG, IDC_CHOICE1, IDC_CHOICE2, IDC_CHOICE3,
		IDC_CHOICE4, IDC_CHOICE5, IDC_CHOICE6, IDC_CHOICE7, IDC_CHOICE8, IDC_CHOICE9, IDC_CHOICE10 };
	int nBaseButtonWidth = 0;
	int nBaseButtonHeight = 0;
	int nActiveChoices = -1;
	int nStr = 0;
	int vertSubOffset, horizSubOffset, vertMsgHeightOffset;
	int vertOffset = 0;
	int nLongestButtonCaptionWidth = 6;
	int nLongestButtonCaptionCharLen = 1;
	int nTextGfxLineHeight = 0;
	int nMainTextLenInChars = 0;
	RECT rec, wrec, wtrec, trec;
	BOOL bResolve;

	WORD lw = LOWORD (wParam);

	switch (uMsg)
	{
	case WM_INITDIALOG:
		{
  			LocalizeDialog (hwndDlg, NULL);

			SetWindowPos (hwndDlg, HWND_TOPMOST, 0, 0, 0, 0, SWP_NOMOVE | SWP_NOSIZE);
			SetWindowPos (hwndDlg, HWND_NOTOPMOST, 0, 0, 0, 0, SWP_NOMOVE | SWP_NOSIZE);

			bResolve = (*pStr == NULL);

			// Process the strings
			pStr++;
			pwStr++;

			do 
			{
				if (*pStr != 0)
				{
					SetWindowTextW (GetDlgItem(hwndDlg, nChoiceIDs[nStr]), bResolve ? GetString(*pStr) : *pwStr);

					if (nStr > 0)
					{
						nLongestButtonCaptionWidth = max (
							GetTextGfxWidth (GetDlgItem(hwndDlg, IDC_CHOICE1),
											bResolve ? GetString(*pStr) : *pwStr,
											hUserFont),
							nLongestButtonCaptionWidth);

						nLongestButtonCaptionCharLen = max (nLongestButtonCaptionCharLen, 
							(int) wcslen ((const wchar_t *) (bResolve ? GetString(*pStr) : *pwStr)));
					}

					nActiveChoices++;
					pStr++;
					pwStr++;
				}
				else
				{
					ShowWindow(GetDlgItem(hwndDlg, nChoiceIDs[nStr]), SW_HIDE);
				}
				nStr++;

			} while (nStr < MAX_MULTI_CHOICES+1);

			// Length of main message in characters (not bytes)
			nMainTextLenInChars = wcslen ((const wchar_t *) (bResolve ? GetString(*(pStrOrig+1)) : *(pwStrOrig+1)));

			if (nMainTextLenInChars > 240 
				&& nMainTextLenInChars / nLongestButtonCaptionCharLen >= 10)
			{
				// As the main text is longer than 240 characters, we will "pad" the widest button caption with 
				// spaces (if it is not wide enough) so as to increase the width of the whole dialog window. 
				// Otherwise, it would look too tall (dialog boxes look better when they are more wide than tall).
				nLongestButtonCaptionWidth = CompensateXDPI (max (
					nLongestButtonCaptionWidth, 
					min (350, nMainTextLenInChars)));
			}

			// Get the window coords
			GetWindowRect(hwndDlg, &wrec);

			// Get the base button size
			GetClientRect(GetDlgItem(hwndDlg, IDC_CHOICE1), &rec);
			nBaseButtonWidth = rec.right + 2;
			nBaseButtonHeight = rec.bottom + 2;

			// Increase in width based on the gfx length of the widest button caption
			horizSubOffset = min (CompensateXDPI (500), max (0, nLongestButtonCaptionWidth + CompensateXDPI (50) - nBaseButtonWidth));

			// Vertical "title bar" offset
			GetClientRect(hwndDlg, &wtrec);
			vertOffset = wrec.bottom - wrec.top - wtrec.bottom - GetSystemMetrics(SM_CYFIXEDFRAME);

			// Height/width of the message text
			GetClientRect(GetDlgItem(hwndDlg, IDC_MULTI_CHOICE_MSG), &trec);

			nTextGfxLineHeight = GetTextGfxHeight (GetDlgItem(hwndDlg, IDC_MULTI_CHOICE_MSG),
								bResolve ? GetString(*(pStrOrig+1)) : *(pwStrOrig+1),
								hUserFont);

			vertMsgHeightOffset = ((GetTextGfxWidth (GetDlgItem(hwndDlg, IDC_MULTI_CHOICE_MSG),
								bResolve ? GetString(*(pStrOrig+1)) : *(pwStrOrig+1),
								hUserFont) / (trec.right + horizSubOffset) + 1)	* nTextGfxLineHeight) - trec.bottom;

			vertMsgHeightOffset = min (CompensateYDPI (350), vertMsgHeightOffset + 2*nTextGfxLineHeight + (trec.bottom + vertMsgHeightOffset) / 10);

			// Reduction in height according to the number of shown buttons
			vertSubOffset = ((MAX_MULTI_CHOICES - nActiveChoices) * nBaseButtonHeight);

			if (horizSubOffset > 0 
				|| vertMsgHeightOffset > 0 
				|| vertOffset > 0)
			{
				// Resize/move each button if necessary
				for (nStr = 1; nStr < MAX_MULTI_CHOICES+1; nStr++)
				{
					GetWindowRect(GetDlgItem(hwndDlg, nChoiceIDs[nStr]), &rec);

					MoveWindow (GetDlgItem(hwndDlg, nChoiceIDs[nStr]),
						rec.left - wrec.left - GetSystemMetrics(SM_CXFIXEDFRAME),
						rec.top - wrec.top - vertOffset + vertMsgHeightOffset,
						nBaseButtonWidth + horizSubOffset,
						nBaseButtonHeight,
						TRUE);
				}

				// Resize/move the remaining GUI elements
				GetWindowRect(GetDlgItem(hwndDlg, IDC_MULTI_CHOICE_MSG), &rec);
				GetClientRect(GetDlgItem(hwndDlg, IDC_MULTI_CHOICE_MSG), &trec);
				MoveWindow (GetDlgItem(hwndDlg, IDC_MULTI_CHOICE_MSG),
					rec.left - wrec.left - GetSystemMetrics(SM_CXFIXEDFRAME),
					rec.top - wrec.top - vertOffset,
					trec.right + 2 + horizSubOffset,
					trec.bottom + 2 + vertMsgHeightOffset,
					TRUE);

				GetWindowRect(GetDlgItem(hwndDlg, IDC_MC_DLG_HR1), &rec);
				GetClientRect(GetDlgItem(hwndDlg, IDC_MC_DLG_HR1), &trec);
				MoveWindow (GetDlgItem(hwndDlg, IDC_MC_DLG_HR1),
					rec.left - wrec.left - GetSystemMetrics(SM_CXFIXEDFRAME),
					rec.top - wrec.top - vertOffset,
					trec.right + 2 + horizSubOffset,
					trec.bottom + 2,
					TRUE);
				
				GetWindowRect(GetDlgItem(hwndDlg, IDC_MC_DLG_HR2), &rec);
				GetClientRect(GetDlgItem(hwndDlg, IDC_MC_DLG_HR2), &trec);
				MoveWindow (GetDlgItem(hwndDlg, IDC_MC_DLG_HR2),
					rec.left - wrec.left - GetSystemMetrics(SM_CXFIXEDFRAME),
					rec.top - wrec.top - vertOffset + vertMsgHeightOffset,
					trec.right + 2 + horizSubOffset,
					trec.bottom + 2,
					TRUE);
			}

			// Resize the window according to number of shown buttons and the longest button caption
			MoveWindow (hwndDlg,
				wrec.left - horizSubOffset / 2,
				wrec.top + vertSubOffset / 2 - vertMsgHeightOffset / 2,
				wrec.right - wrec.left + horizSubOffset,
				wrec.bottom - wrec.top - vertSubOffset + 1 + vertMsgHeightOffset,
				TRUE);

			return 1;
		}

	case WM_COMMAND:

		if (lw == IDCLOSE || lw == IDCANCEL)
		{
			EndDialog (hwndDlg, 0);
			return 1;
		}

		for (nStr = 1; nStr < MAX_MULTI_CHOICES+1; nStr++)
		{
			if (lw == nChoiceIDs[nStr])
			{
				EndDialog (hwndDlg, nStr);
				return 1;
			}
		}
		break;

	case WM_CLOSE:
		EndDialog (hwndDlg, 0);
		return 1;
	}

	return 0;
}


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


// Checks whether the file extension is not used for executable files or similarly problematic, which often
// causes Windows and antivirus software to interfere with the container 
BOOL CheckFileExtension (char *fileName)
{
	int i = 0;
	char *ext = strrchr (fileName, '.');
	static char *problemFileExt[] = {
		// These are protected by the Windows Resource Protection
		".asa", ".asp", ".aspx", ".ax", ".bas", ".bat", ".bin", ".cer", ".chm", ".clb", ".cmd", ".cnt", ".cnv",
		".com", ".cpl", ".cpx", ".crt", ".csh", ".dll", ".drv", ".dtd", ".exe", ".fxp", ".grp", ".h1s", ".hlp",
		".hta", ".ime", ".inf", ".ins", ".isp", ".its", ".js", ".jse", ".ksh", ".lnk", ".mad", ".maf", ".mag",
		".mam", ".man", ".maq", ".mar", ".mas", ".mat", ".mau", ".mav", ".maw", ".mda", ".mdb", ".mde", ".mdt",
		".mdw", ".mdz", ".msc", ".msi", ".msp", ".mst", ".mui", ".nls", ".ocx", ".ops", ".pal", ".pcd", ".pif",
		".prf", ".prg", ".pst", ".reg", ".scf", ".scr", ".sct", ".shb", ".shs", ".sys", ".tlb", ".tsp", ".url",
		".vb", ".vbe", ".vbs", ".vsmacros", ".vss", ".vst", ".vsw", ".ws", ".wsc", ".wsf", ".wsh", ".xsd", ".xsl",
		// These additional file extensions are usually watched by antivirus programs
		".386", ".acm", ".ade", ".adp", ".ani", ".app", ".asd", ".asf", ".asx", ".awx", ".ax", ".boo", ".bz2", ".cdf",
		".class", ".dhtm", ".dhtml",".dlo", ".emf", ".eml", ".flt", ".fot", ".gz", ".hlp", ".htm", ".html", ".ini", 
		".j2k", ".jar", ".jff", ".jif", ".jmh", ".jng", ".jp2", ".jpe", ".jpeg", ".jpg", ".lsp", ".mod", ".nws",
		".obj", ".olb", ".osd", ".ov1", ".ov2", ".ov3", ".ovl", ".ovl", ".ovr", ".pdr", ".pgm", ".php", ".pkg",
		".pl", ".png", ".pot", ".pps", ".ppt", ".rar", ".rpl", ".rtf", ".sbf", ".script", ".sh", ".sha", ".shtm",
		".shtml", ".spl", ".swf", ".tar", ".tgz", ".tmp", ".ttf", ".vcs", ".vlm", ".vxd", ".vxo", ".wiz", ".wll", ".wmd",
		".wmf",	".wms", ".wmz", ".wpc", ".wsc", ".wsh", ".wwk", ".xhtm", ".xhtml", ".xl", ".xml", ".zip", ".7z", 0};

	if (!ext)
		return FALSE;

	while (problemFileExt[i])
	{
		if (!_stricmp (ext, problemFileExt[i++]))
			return TRUE;
	}

	return FALSE;
}


void IncreaseWrongPwdRetryCount (int count)
{
	WrongPwdRetryCounter += count;
}


void ResetWrongPwdRetryCount (void)
{
	WrongPwdRetryCounter = 0;
}


BOOL WrongPwdRetryCountOverLimit (void)
{
	return (WrongPwdRetryCounter > TC_TRY_HEADER_BAK_AFTER_NBR_WRONG_PWD_TRIES);
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


BOOL IsDeviceMounted (char *deviceName)
{
	BOOL bResult = FALSE;
	DWORD dwResult;
	HANDLE dev = INVALID_HANDLE_VALUE;

	if ((dev = CreateFile (deviceName,
		GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE,
		NULL,
		OPEN_EXISTING,
		0,
		NULL)) != INVALID_HANDLE_VALUE)
	{
		bResult = DeviceIoControl (dev, FSCTL_IS_VOLUME_MOUNTED, NULL, 0, NULL, 0, &dwResult, NULL);
		CloseHandle (dev);
	}

	return bResult;
}


int DriverUnmountVolume (HWND hwndDlg, int nDosDriveNo, BOOL forced)
{
	UNMOUNT_STRUCT unmount;
	DWORD dwResult;

	BOOL bResult;
	
	unmount.nDosDriveNo = nDosDriveNo;
	unmount.ignoreOpenFiles = forced;

	bResult = DeviceIoControl (hDriver, TC_IOCTL_DISMOUNT_VOLUME, &unmount,
		sizeof (unmount), &unmount, sizeof (unmount), &dwResult, NULL);

	if (bResult == FALSE)
	{
		handleWin32Error (hwndDlg);
		return 1;
	}

#ifdef TCMOUNT

	if (unmount.nReturnCode == ERR_SUCCESS
		&& unmount.HiddenVolumeProtectionTriggered
		&& !VolumeNotificationsList.bHidVolDamagePrevReported [nDosDriveNo])
	{
		wchar_t msg[4096];

		VolumeNotificationsList.bHidVolDamagePrevReported [nDosDriveNo] = TRUE;
		swprintf (msg, GetString ("DAMAGE_TO_HIDDEN_VOLUME_PREVENTED"), nDosDriveNo + 'A');
		SetForegroundWindow (hwndDlg);
		MessageBoxW (hwndDlg, msg, lpszTitle, MB_ICONWARNING | MB_SETFOREGROUND | MB_TOPMOST);
	}

#endif	// #ifdef TCMOUNT

	return unmount.nReturnCode;
}


void BroadcastDeviceChange (WPARAM message, int nDosDriveNo, DWORD driveMap)
{
	DEV_BROADCAST_VOLUME dbv;
	DWORD dwResult;
	LONG eventId = 0;
	int i;

	if (message == DBT_DEVICEARRIVAL)
		eventId = SHCNE_DRIVEADD;
	else if (message == DBT_DEVICEREMOVECOMPLETE)
		eventId = SHCNE_DRIVEREMOVED;

	if (driveMap == 0)
		driveMap = (1 << nDosDriveNo);

	if (eventId != 0)
	{
		for (i = 0; i < 26; i++)
		{
			if (driveMap & (1 << i))
			{
				char root[] = {i + 'A', ':', '\\', 0 };
				SHChangeNotify (eventId, SHCNF_PATH, root, NULL);

				if (nCurrentOS == WIN_2000 && RemoteSession)
				{
					char target[32];
					wsprintf (target, "%ls%c", TC_MOUNT_PREFIX, i + 'A');
					root[2] = 0;

					if (message == DBT_DEVICEARRIVAL)
						DefineDosDevice (DDD_RAW_TARGET_PATH, root, target);
					else if (message == DBT_DEVICEREMOVECOMPLETE)
						DefineDosDevice (DDD_RAW_TARGET_PATH| DDD_REMOVE_DEFINITION
						| DDD_EXACT_MATCH_ON_REMOVE, root, target);
				}
			}
		}
	}

	dbv.dbcv_size = sizeof (dbv); 
	dbv.dbcv_devicetype = DBT_DEVTYP_VOLUME; 
	dbv.dbcv_reserved = 0;
	dbv.dbcv_unitmask = driveMap;
	dbv.dbcv_flags = 0; 

	UINT timeOut = 1000;

	// SHChangeNotify() works on Vista, so the Explorer does not require WM_DEVICECHANGE
	if (CurrentOSMajor >= 6)
		timeOut = 100;

	IgnoreWmDeviceChange = TRUE;
	SendMessageTimeout (HWND_BROADCAST, WM_DEVICECHANGE, message, (LPARAM)(&dbv), 0, timeOut, &dwResult);

	// Explorer prior Vista sometimes fails to register a new drive
	if (CurrentOSMajor < 6 && message == DBT_DEVICEARRIVAL)
		SendMessageTimeout (HWND_BROADCAST, WM_DEVICECHANGE, message, (LPARAM)(&dbv), 0, 200, &dwResult);

	IgnoreWmDeviceChange = FALSE;
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
	char root[MAX_PATH];

#ifdef TCMOUNT
	if (mountOptions->PartitionInInactiveSysEncScope)
	{
		if (!CheckSysEncMountWithoutPBA (volumePath, quiet))
			return -1;
	}
#endif

	if (IsMountedVolume (volumePath))
	{
		if (!quiet)
			Error ("VOL_ALREADY_MOUNTED");
		return -1;
	}

	if (!IsDriveAvailable (driveNo))
	{
		if (!quiet)
			Error ("DRIVE_LETTER_UNAVAILABLE");

		return -1;
	}

	// If using cached passwords, check cache status first
	if (password == NULL && IsPasswordCacheEmpty ())
		return 0;

	ZeroMemory (&mount, sizeof (mount));
	mount.bExclusiveAccess = sharedAccess ? FALSE : TRUE;
	mount.UseBackupHeader =  mountOptions->UseBackupHeader;

retry:
	mount.nDosDriveNo = driveNo;
	mount.bCache = cachePassword;

	mount.bPartitionInInactiveSysEncScope = FALSE;

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
	mount.bPreserveTimestamp = mountOptions->PreserveTimestamp;

	mount.bMountManager = TRUE;

	// Windows 2000 mount manager causes problems with remounted volumes
	if (CurrentOSMajor == 5 && CurrentOSMinor == 0)
		mount.bMountManager = FALSE;

	CreateFullVolumePath ((char *) mount.wszVolume, volumePath, &bDevice);

	if (!bDevice)
	{
		// UNC path
		if (volumePath[0] == '\\' && volumePath[1] == '\\')
		{
			_snprintf ((char *)mount.wszVolume, MAX_PATH, "UNC%s", volumePath + 1);
			mount.bUserContext = TRUE;
		}

		if (GetVolumePathName (volumePath, root, sizeof (root) - 1))
		{
			DWORD bps, flags, d;
			if (GetDiskFreeSpace (root, &d, &bps, &d, &d))
				mount.BytesPerSector = bps;

			// Read-only host filesystem
			if (!mount.bMountReadOnly && GetVolumeInformation (root, NULL, 0,  NULL, &d, &flags, NULL, 0))
				mount.bMountReadOnly = (flags & FILE_READ_ONLY_VOLUME) != 0;

			// Network drive
			if (GetDriveType (root) == DRIVE_REMOTE)
				mount.bUserContext = TRUE;
		}
	}

	ToUNICODE ((char *) mount.wszVolume);

	if (mountOptions->PartitionInInactiveSysEncScope)
	{
		if (mount.wszVolume == NULL || swscanf_s ((const wchar_t *) mount.wszVolume,
			WIDE("\\Device\\Harddisk%d\\Partition"),
			&mount.nPartitionInInactiveSysEncScopeDriveNo,
			sizeof(mount.nPartitionInInactiveSysEncScopeDriveNo)) != 1)
		{
			return -1;
		}

		mount.bPartitionInInactiveSysEncScope = TRUE;
	}

	bResult = DeviceIoControl (hDriver, TC_IOCTL_MOUNT_VOLUME, &mount,
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
			{
				IncreaseWrongPwdRetryCount (1);		// We increase the count here only if bReportWrongPassword is TRUE, because "Auto-Mount All Devices" and other callers do it separately

				if (WrongPwdRetryCountOverLimit () 
					&& !mount.UseBackupHeader)
				{
					// Retry using embedded header backup (if any)
					mount.UseBackupHeader = TRUE;
					goto retry;
				}

				handleError (hwndDlg, mount.nReturnCode);
			}

			return 0;
		}

		if (!quiet)
			handleError (hwndDlg, mount.nReturnCode);

		return 0;
	}

	// Mount successful

	if (mount.UseBackupHeader != mountOptions->UseBackupHeader
		&& mount.UseBackupHeader)
	{
		if (bReportWrongPassword && !quiet)
			Warning ("HEADER_DAMAGED_AUTO_USED_HEADER_BAK");
	}

	ResetWrongPwdRetryCount ();

	BroadcastDeviceChange (DBT_DEVICEARRIVAL, driveNo, 0);

	if (mount.bExclusiveAccess == FALSE)
		return 2;

	return 1;
}


BOOL UnmountVolume (HWND hwndDlg, int nDosDriveNo, BOOL forceUnmount)
{
	int result;
	BOOL forced = forceUnmount;
	int dismountMaxRetries = UNMOUNT_MAX_AUTO_RETRIES;

retry:
	BroadcastDeviceChange (DBT_DEVICEREMOVEPENDING, nDosDriveNo, 0);

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
			if (IDYES == AskWarnNoYes ("UNMOUNT_LOCK_FAILED"))
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
	return !DeviceIoControl (hDriver, TC_IOCTL_GET_PASSWORD_CACHE_STATUS, 0, 0, 0, 0, &dw, 0);
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
	DeviceIoControl (hDriver, TC_IOCTL_GET_MOUNTED_VOLUMES, &mlist,
		sizeof (mlist), &mlist, sizeof (mlist), &dwResult,
		NULL);

	for (i=0 ; i<26; i++)
		if (0 == wcscmp ((wchar_t *) mlist.wszVolume[i], (WCHAR *)volume))
			return TRUE;

	return FALSE;
}


int GetMountedVolumeDriveNo (char *volname)
{
	MOUNT_LIST_STRUCT mlist;
	DWORD dwResult;
	int i;
	char volume[TC_MAX_PATH*2+16];

	if (volname == NULL)
		return -1;

	strcpy (volume, volname);

	if (strstr (volname, "\\Device\\") != volname)
		sprintf(volume, "\\??\\%s", volname);
	ToUNICODE (volume);

	memset (&mlist, 0, sizeof (mlist));
	DeviceIoControl (hDriver, TC_IOCTL_GET_MOUNTED_VOLUMES, &mlist,
		sizeof (mlist), &mlist, sizeof (mlist), &dwResult,
		NULL);

	for (i=0 ; i<26; i++)
		if (0 == wcscmp ((wchar_t *) mlist.wszVolume[i], (WCHAR *)volume))
			return i;

	return -1;
}


BOOL IsAdmin (void)
{
	return IsUserAnAdmin ();
}


BOOL IsUacSupported ()
{
	HKEY hkey;
	DWORD value = 1, size = sizeof (DWORD);

	if (nCurrentOS != WIN_VISTA_OR_LATER)
		return FALSE;

	if (RegOpenKeyEx (HKEY_LOCAL_MACHINE, "Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System", 0, KEY_READ, &hkey) == ERROR_SUCCESS)
	{
		if (RegQueryValueEx (hkey, "EnableLUA", 0, 0, (LPBYTE) &value, &size) != ERROR_SUCCESS)
			value = 1;

		RegCloseKey (hkey);
	}

	return value != 0;
}


BOOL ResolveSymbolicLink (PWSTR symLinkName, PWSTR targetName)
{
	BOOL bResult;
	DWORD dwResult;
	RESOLVE_SYMLINK_STRUCT resolve;

	memset (&resolve, 0, sizeof(resolve));
	wcscpy ((PWSTR) &resolve.symLinkName, symLinkName);

	bResult = DeviceIoControl (hDriver, TC_IOCTL_GET_RESOLVED_SYMLINK, &resolve,
		sizeof (resolve), &resolve, sizeof (resolve), &dwResult,
		NULL);

	wcscpy (targetName, (PWSTR) &resolve.targetName);

	return bResult;
}


BOOL GetPartitionInfo (char *deviceName, PPARTITION_INFORMATION rpartInfo)
{
	BOOL bResult;
	DWORD dwResult;
	DISK_PARTITION_INFO_STRUCT dpi;

	memset (&dpi, 0, sizeof(dpi));
	wsprintfW ((PWSTR) &dpi.deviceName, L"%hs", deviceName);

	bResult = DeviceIoControl (hDriver, TC_IOCTL_GET_DRIVE_PARTITION_INFO, &dpi,
		sizeof (dpi), &dpi, sizeof (dpi), &dwResult, NULL);

	memcpy (rpartInfo, &dpi.partInfo, sizeof (PARTITION_INFORMATION));
	return bResult;
}


BOOL GetDriveGeometry (char *deviceName, PDISK_GEOMETRY diskGeometry)
{
	BOOL bResult;
	DWORD dwResult;
	DISK_GEOMETRY_STRUCT dg;

	memset (&dg, 0, sizeof(dg));
	wsprintfW ((PWSTR) &dg.deviceName, L"%hs", deviceName);

	bResult = DeviceIoControl (hDriver, TC_IOCTL_GET_DRIVE_GEOMETRY, &dg,
		sizeof (dg), &dg, sizeof (dg), &dwResult, NULL);

	memcpy (diskGeometry, &dg.diskGeometry, sizeof (DISK_GEOMETRY));
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


HANDLE DismountDrive (char *devName)
{
	DWORD dwResult;
	HANDLE hVolume;
	BOOL bResult = FALSE;
	int attempt = 10;

	hVolume = CreateFile (devName, GENERIC_READ | GENERIC_WRITE,
		FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);

	if (hVolume == INVALID_HANDLE_VALUE)
		return INVALID_HANDLE_VALUE;

	while (!(bResult = DeviceIoControl (hVolume, FSCTL_DISMOUNT_VOLUME, NULL, 0, NULL, 0, &dwResult, NULL)) 
		&& attempt > 0)
	{
		Sleep (UNMOUNT_AUTO_RETRY_DELAY);
		attempt--;
	}

	if (!bResult)
		CloseHandle (hVolume);

	return (bResult ? hVolume : INVALID_HANDLE_VALUE);
}

// Returns TRUE if the file exists (otherwise FALSE).
BOOL FileExists (const char *filePathPtr)
{
	char filePath [TC_MAX_PATH];

	// Strip quotation marks (if any)
	if (filePathPtr [0] == '"')
	{
		strcpy (filePath, filePathPtr + 1);
	}
	else
	{
		strcpy (filePath, filePathPtr);
	}

	// Strip quotation marks (if any)
	if (filePath [strlen (filePath) - 1] == '"')
		filePath [strlen (filePath) - 1] = 0;

    return (_access (filePath, 0) != -1);
}

// Searches the file from its end for the LAST occurrence of the string str.
// The string may contain zeroes, which do NOT terminate the string.
// If the string is found, its offset from the start of the file is returned. 
// If the string isn't found or if any error occurs, -1 is returned.
__int64 FindStringInFile (char *filePath, char* str, int strLen)
{
	int bufSize = 64 * BYTES_PER_KB;
	char *buffer = (char *) malloc (bufSize);
	HANDLE src = NULL;
	DWORD bytesRead;
	BOOL readRetVal;
	__int64 filePos = GetFileSize64 (filePath);
	int bufPos = 0;
	LARGE_INTEGER seekOffset, seekOffsetNew;
	BOOL bExit = FALSE;
	int filePosStep;
	__int64 retVal = -1;

	if (filePos <= 0 
		|| buffer == NULL 
		|| strLen > bufSize
		|| strLen < 1)
		return -1;

	src = CreateFile (filePath, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);

	if (src == INVALID_HANDLE_VALUE)
	{
		free (buffer);
		return -1;
	}

	filePosStep = bufSize - strLen + 1;

	do
	{
		filePos -= filePosStep;

		if (filePos < 0)
		{
			filePos = 0;
			bExit = TRUE;
		}

		seekOffset.QuadPart = filePos;

		if (SetFilePointerEx (src, seekOffset, &seekOffsetNew, FILE_BEGIN) == 0)
			goto fsif_end;

		if ((readRetVal = ReadFile (src, buffer, bufSize, &bytesRead, NULL)) == 0 
			|| bytesRead == 0)
			goto fsif_end;

		bufPos = bytesRead - strLen;

		while (bufPos > 0)
		{
			if (memcmp (buffer + bufPos, str, strLen) == 0)
			{
				// String found
				retVal = filePos + bufPos;
				goto fsif_end;
			}
			bufPos--;
		}

	} while (!bExit);

fsif_end:
	CloseHandle (src);
	free (buffer);

	return retVal;
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

	buffer = (char *) malloc (64 * 1024);
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

// If bAppend is TRUE, the buffer is appended to an existing file. If bAppend is FALSE, any existing file 
// is replaced. If an error occurs, the incomplete file is deleted (provided that bAppend is FALSE).
BOOL SaveBufferToFile (char *inputBuffer, char *destinationFile, DWORD inputLength, BOOL bAppend)
{
	HANDLE dst;
	DWORD bytesWritten;
	BOOL res = TRUE;

	dst = CreateFile (destinationFile,
		GENERIC_WRITE,
		FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, bAppend ? OPEN_EXISTING : CREATE_ALWAYS, 0, NULL);

	if (dst == INVALID_HANDLE_VALUE)
	{
		handleWin32Error (MainDlg);
		return FALSE;
	}

	if (bAppend)
		SetFilePointer (dst, 0, NULL, FILE_END);

	if (!WriteFile (dst, inputBuffer, inputLength, &bytesWritten, NULL)
		|| inputLength != bytesWritten)
	{
		res = FALSE;
	}

	if (!res)
	{
		// If CREATE_ALWAYS is used, ERROR_ALREADY_EXISTS is returned after successful overwrite
		// of an existing file (it's not an error)
		if (! (GetLastError() == ERROR_ALREADY_EXISTS && !bAppend) )	
			handleWin32Error (MainDlg);
	}

	CloseHandle (dst);
	FlushFileBuffers (dst);

	if (!res && !bAppend)
		remove (destinationFile);

	return res;
}


// Proper flush for Windows systems. Returns TRUE if successful.
BOOL TCFlushFile (FILE *f)
{
	HANDLE hf = (HANDLE) _get_osfhandle (_fileno (f));

	fflush (f);

	if (hf == INVALID_HANDLE_VALUE)
		return FALSE;

	return FlushFileBuffers (hf) != 0;
}


// Prints a UTF-16 text (note that this involves a real printer, not a screen).
// textByteLen - length of the text in bytes
// title - printed as part of the page header and used as the filename for a temporary file 
BOOL PrintHardCopyTextUTF16 (wchar_t *text, char *title, int textByteLen)
{
	char cl [MAX_PATH*3] = {"/p \""};
	char path [MAX_PATH * 2] = { 0 };
	char filename [MAX_PATH + 1] = { 0 };

	strcpy (filename, title);
	//strcat (filename, ".txt");

	GetTempPath (sizeof (path), path);

	if (!FileExists (path))
	{
		strcpy (path, GetConfigPath (filename));

		if (strlen(path) < 2)
			return FALSE;
	}
	else
	{
		strcat (path, filename);
	}

	// Write the Unicode signature
	if (!SaveBufferToFile ("\xFF\xFE", path, 2, FALSE))
	{
		remove (path);
		return FALSE;
	}

	// Write the actual text
	if (!SaveBufferToFile ((char *) text, path, textByteLen, TRUE))
	{
		remove (path);
		return FALSE;
	}

	strcat (cl, path);
	strcat (cl, "\"");

	WaitCursor ();
	ShellExecute (NULL, "open", PRINT_TOOL, cl, NULL, SW_HIDE);
	Sleep (6000);
	NormalCursor();

	remove (path);

	return TRUE;
}


BOOL IsNonInstallMode ()
{
	HKEY hkey;
	DWORD dw;

	if (bTravelerModeConfirmed)
		return TRUE;

	if (hDriver != INVALID_HANDLE_VALUE)
	{
		// The driver is running
		if (DeviceIoControl (hDriver, TC_IOCTL_GET_TRAVELER_MODE_STATUS, NULL, 0, NULL, 0, &dw, 0))
		{
			bTravelerModeConfirmed = TRUE;
			return TRUE;
		}
		else
		{
			// This is also returned if we fail to determine the status (it does not mean that traveler mode is disproved).
			return FALSE;	
		}
	}
	else
	{
		// The tests in this block are necessary because this function is in some cases called before DriverAttach().

		HANDLE hDriverTmp = CreateFile (WIN32_ROOT_PREFIX, 0, 0, NULL, OPEN_EXISTING, 0, NULL);

		if (hDriverTmp == INVALID_HANDLE_VALUE)
		{
			// The driver was not found in the system path

			char path[MAX_PATH * 2] = { 0 };

			// We can't use GetConfigPath() here because it would call us back (indirect recursion)
			if (SUCCEEDED(SHGetFolderPath (NULL, CSIDL_APPDATA | CSIDL_FLAG_CREATE, NULL, 0, path)))
			{
				strcat (path, "\\TrueCrypt\\");
				CreateDirectory (path, NULL);
				strcat (path, FILE_SYSTEM_ENCRYPTION_CFG);

				if (FileExists (path))
				{
					// To maintain consistency and safety, if the system encryption config file exits, we cannot
					// allow traveler mode. (This happens e.g. when the pretest fails and the user selects 
					// "Last Known Good Configuration" from the Windows boot menu.)

					// However, if UAC elevation is needed, we have to confirm traveler mode first (after we are elevated, we won't).
					if (!IsAdmin () && IsUacSupported ())
						return TRUE;

					return FALSE;
				}
			}

			// As the driver was not found in the system path, we can predict that we will run in traveler mode
			return TRUE;	
		}
		else
			CloseHandle (hDriverTmp);
	}

	// The following test may be unreliable in some cases (e.g. after the user selects restore "Last Known Good
	// Configuration" from the Windows boot menu).
	if (RegOpenKeyEx (HKEY_LOCAL_MACHINE, "Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\TrueCrypt", 0, KEY_READ, &hkey) == ERROR_SUCCESS)
	{
		RegCloseKey (hkey);
		return FALSE;
	}
	else
		return TRUE;
}


LRESULT SetCheckBox (HWND hwndDlg, int dlgItem, BOOL state)
{
	return SendDlgItemMessage (hwndDlg, dlgItem, BM_SETCHECK, state ? BST_CHECKED : BST_UNCHECKED, 0);
}


BOOL GetCheckBox (HWND hwndDlg, int dlgItem)
{
	return IsButtonChecked (GetDlgItem (hwndDlg, dlgItem));
}


// Adds or removes TrueCrypt.exe to/from the system startup sequence (with appropriate command line arguments)
void ManageStartupSeq (void)
{
	if (!IsNonInstallMode ())
	{
		char regk [64];

		// Split the string in order to prevent some antivirus packages from falsely reporting  
		// TrueCrypt.exe to contain a possible Trojan horse because of this string (heuristic scan).
		sprintf (regk, "%s%s", "Software\\Microsoft\\Windows\\Curren", "tVersion\\Run");

		if (bStartOnLogon)
		{
			char exe[MAX_PATH * 2] = { '"' };

			GetModuleFileName (NULL, exe + 1, sizeof (exe) - 1);

#ifdef VOLFORMAT
			{
				char *tmp = NULL;

				if (tmp = strrchr (exe, '\\'))
					strcpy (++tmp, "TrueCrypt.exe");
			}
#endif
			strcat (exe, "\" /q preferences");

			if (bMountDevicesOnLogon) strcat (exe, " /a devices");
			if (bMountFavoritesOnLogon) strcat (exe, " /a favorites");

			WriteRegistryString (regk, "TrueCrypt", exe);
		}
		else
			DeleteRegistryValue (regk, "TrueCrypt");
	}
}


// Delete the last used Windows file selector path for TrueCrypt from the registry
void CleanLastVisitedMRU (void)
{
	WCHAR exeFilename[MAX_PATH];
	WCHAR *strToMatch;

	WCHAR strTmp[4096];
	char regPath[128];
	char key[64];
	int id, len;

	GetModuleFileNameW (NULL, exeFilename, sizeof (exeFilename) / sizeof(exeFilename[0]));
	strToMatch = wcsrchr (exeFilename, '\\') + 1;

	sprintf (regPath, "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\ComDlg32\\LastVisited%sMRU", nCurrentOS == WIN_VISTA_OR_LATER ? "Pidl" : "");

	for (id = (nCurrentOS == WIN_VISTA_OR_LATER ? 0 : 'a'); id <= (nCurrentOS == WIN_VISTA_OR_LATER ? 1000 : 'z'); id++)
	{
		*strTmp = 0;
		sprintf (key, (nCurrentOS == WIN_VISTA_OR_LATER ? "%d" : "%c"), id);

		if ((len = ReadRegistryBytes (regPath, key, (char *) strTmp, sizeof (strTmp))) > 0)
		{
			if (_wcsicmp (strTmp, strToMatch) == 0) 
			{
				char buf[65536], bufout[sizeof (buf)];

				// Overwrite the entry with zeroes while keeping its original size
				memset (strTmp, 0, len);
				if (!WriteRegistryBytes (regPath, key, (char *) strTmp, len))
					MessageBoxW (NULL, GetString ("CLEAN_WINMRU_FAILED"), lpszTitle, ICON_HAND);

				DeleteRegistryValue (regPath, key);

				// Remove ID from MRUList
				if (nCurrentOS == WIN_VISTA_OR_LATER)
				{
					int *p = (int *)buf;
					int *pout = (int *)bufout;
					int l;

					l = len = ReadRegistryBytes ("Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\ComDlg32\\LastVisitedPidlMRU", "MRUListEx", buf, sizeof (buf));
					while (l > 0)
					{
						l -= sizeof (int);

						if (*p == id)
						{
							p++;
							len -= sizeof (int);
							continue;
						}
						*pout++ = *p++;
					}

					WriteRegistryBytes ("Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\ComDlg32\\LastVisitedPidlMRU", "MRUListEx", bufout, len);
				}
				else
				{
					char *p = buf;
					char *pout = bufout;

					ReadRegistryString ("Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\ComDlg32\\LastVisitedMRU", "MRUList", "", buf, sizeof (buf));
					while (*p)
					{
						if (*p == id)
						{
							p++;
							continue;
						}
						*pout++ = *p++;
					}
					*pout++ = 0;

					WriteRegistryString ("Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\ComDlg32\\LastVisitedMRU", "MRUList", bufout);
				}

				break;
			}
		}
	}
}


#ifndef SETUP
void ClearHistory (HWND hwndDlgItem)
{
	ArrowWaitCursor ();

	ClearCombo (hwndDlgItem);
	DumpCombo (hwndDlgItem, TRUE);

	CleanLastVisitedMRU ();

	NormalCursor ();
}
#endif // #ifndef SETUP


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
	return DeviceIoControl (hDriver, TC_IOCTL_GET_MOUNTED_VOLUMES, list,
		sizeof (*list), list, sizeof (*list), &dwResult,
		NULL);
}


int GetDriverRefCount ()
{
	DWORD dwResult;
	BOOL bResult;
	int refCount;

	bResult = DeviceIoControl (hDriver, TC_IOCTL_GET_DEVICE_REFCOUNT, &refCount, sizeof (refCount), &refCount,
		sizeof (refCount), &dwResult, NULL);

	if (bResult)
		return refCount;
	else
		return -1;
}

// Loads a 32-bit integer from the file at the specified file offset. The saved value is assumed to have been
// processed by mputLong(). The result is stored in *result. Returns TRUE if successful (otherwise FALSE).
BOOL LoadInt32 (char *filePath, unsigned __int32 *result, __int64 fileOffset)
{
	int bufSize = sizeof(__int32);
	unsigned char *buffer = (unsigned char *) malloc (bufSize);
	unsigned char *bufferPtr = buffer;
	HANDLE src = NULL;
	DWORD bytesRead;
	LARGE_INTEGER seekOffset, seekOffsetNew;
	BOOL retVal = FALSE;

	if (buffer == NULL)
		return -1;

	src = CreateFile (filePath, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);

	if (src == INVALID_HANDLE_VALUE)
	{
		free (buffer);
		return FALSE;
	}

	seekOffset.QuadPart = fileOffset;

	if (SetFilePointerEx (src, seekOffset, &seekOffsetNew, FILE_BEGIN) == 0)
		goto fsif_end;

	if (ReadFile (src, buffer, bufSize, &bytesRead, NULL) == 0 
		|| bytesRead != bufSize)
		goto fsif_end;


	retVal = TRUE;

	*result = mgetLong(bufferPtr);

fsif_end:
	CloseHandle (src);
	free (buffer);

	return retVal;
}

// Loads a 16-bit integer from the file at the specified file offset. The saved value is assumed to have been
// processed by mputWord(). The result is stored in *result. Returns TRUE if successful (otherwise FALSE).
BOOL LoadInt16 (char *filePath, int *result, __int64 fileOffset)
{
	int bufSize = sizeof(__int16);
	unsigned char *buffer = (unsigned char *) malloc (bufSize);
	unsigned char *bufferPtr = buffer;
	HANDLE src = NULL;
	DWORD bytesRead;
	LARGE_INTEGER seekOffset, seekOffsetNew;
	BOOL retVal = FALSE;

	if (buffer == NULL)
		return -1;

	src = CreateFile (filePath, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);

	if (src == INVALID_HANDLE_VALUE)
	{
		free (buffer);
		return FALSE;
	}

	seekOffset.QuadPart = fileOffset;

	if (SetFilePointerEx (src, seekOffset, &seekOffsetNew, FILE_BEGIN) == 0)
		goto fsif_end;

	if (ReadFile (src, buffer, bufSize, &bytesRead, NULL) == 0 
		|| bytesRead != bufSize)
		goto fsif_end;


	retVal = TRUE;

	*result = mgetWord(bufferPtr);

fsif_end:
	CloseHandle (src);
	free (buffer);

	return retVal;
}

// Returns NULL if there's any error
char *LoadFile (char *fileName, DWORD *size)
{
	char *buf;
	HANDLE h = CreateFile (fileName, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
	if (h == INVALID_HANDLE_VALUE)
		return NULL;

	*size = GetFileSize (h, NULL);
	buf = (char *) malloc (*size + 1);

	if (buf == NULL)
	{
		CloseHandle (h);
		return NULL;
	}

	ZeroMemory (buf, *size + 1);

	if (!ReadFile (h, buf, *size, size, NULL))
	{
		free (buf);
		buf = NULL;
	}

	CloseHandle (h);
	return buf;
}


// Returns NULL if there's any error.
char *LoadFileBlock (char *fileName, __int64 fileOffset, int count)
{
	char *buf;
	DWORD bytesRead = 0;
	LARGE_INTEGER seekOffset, seekOffsetNew;

	HANDLE h = CreateFile (fileName, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
	if (h == INVALID_HANDLE_VALUE)
		return NULL;

	seekOffset.QuadPart = fileOffset;

	if (SetFilePointerEx (h, seekOffset, &seekOffsetNew, FILE_BEGIN) == 0)
	{
		CloseHandle (h);
		return NULL;
	}

	buf = (char *) malloc (count);

	if (buf == NULL)
	{
		CloseHandle (h);
		return NULL;
	}
 
	ZeroMemory (buf, count);

	if (buf != NULL)
		ReadFile (h, buf, count, &bytesRead, NULL);

	CloseHandle (h);

	if (bytesRead != count)
	{
		free (buf);
		return NULL;
	}

	return buf;
}


// Returns -1 if there is an error, or the size of the file.
__int64 GetFileSize64 (char *path)
{
  	HANDLE h = CreateFile (path, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
	LARGE_INTEGER size;

	if (h == INVALID_HANDLE_VALUE)
		return -1;

	if (GetFileSizeEx (h, &size) == 0)
		return -1;

	CloseHandle (h);

	return size.QuadPart;
}


char *GetModPath (char *path, int maxSize)
{
	GetModuleFileName (NULL, path, maxSize);
	strrchr (path, '\\')[1] = 0;
	return path;
}


char *GetConfigPath (char *fileName)
{
	static char path[MAX_PATH * 2] = { 0 };

	if (IsNonInstallMode ())
	{
		GetModPath (path, sizeof (path));
		strcat (path, fileName);

		return path;
	}

	if (SUCCEEDED(SHGetFolderPath (NULL, CSIDL_APPDATA | CSIDL_FLAG_CREATE, NULL, 0, path)))
	{
		strcat (path, "\\TrueCrypt\\");
		CreateDirectory (path, NULL);
		strcat (path, fileName);
	}
	else
		path[0] = 0;

	return path;
}

// Returns 0 if an error occurs or the drive letter (as an upper-case char) of the system partition (e.g. 'C');
char GetSystemDriveLetter (void)
{
	char systemDir [MAX_PATH];

	if (GetSystemDirectory (systemDir, sizeof (systemDir)))
		return (toupper (systemDir [0]));
	else
		return 0;
}

int Info (char *stringId)
{
	if (Silent) return 0;
	return MessageBoxW (MainDlg, GetString (stringId), lpszTitle, MB_ICONINFORMATION);
}


int InfoDirect (const wchar_t *msg)
{
	if (Silent) return 0;
	return MessageBoxW (MainDlg, msg, lpszTitle, MB_ICONINFORMATION);
}


int Warning (char *stringId)
{
	if (Silent) return 0;
	return MessageBoxW (MainDlg, GetString (stringId), lpszTitle, MB_ICONWARNING);
}


int WarningTopMost (char *stringId)
{
	if (Silent) return 0;
	return MessageBoxW (MainDlg, GetString (stringId), lpszTitle, MB_ICONWARNING | MB_SETFOREGROUND | MB_TOPMOST);
}


int WarningDirect (const wchar_t *warnMsg)
{
	if (Silent) return 0;
	return MessageBoxW (MainDlg, warnMsg, lpszTitle, MB_ICONERROR);
}


int Error (char *stringId)
{
	if (Silent) return 0;
	return MessageBoxW (MainDlg, GetString (stringId), lpszTitle, MB_ICONERROR);
}


int ErrorTopMost (char *stringId)
{
	if (Silent) return 0;
	return MessageBoxW (MainDlg, GetString (stringId), lpszTitle, MB_ICONERROR | MB_SETFOREGROUND | MB_TOPMOST);
}


int ErrorDirect (const wchar_t *errMsg)
{
	if (Silent) return 0;
	return MessageBoxW (MainDlg, errMsg, lpszTitle, MB_ICONERROR);
}


int AskYesNo (char *stringId)
{
	if (Silent) return 0;
	return MessageBoxW (MainDlg, GetString (stringId), lpszTitle, MB_ICONQUESTION | MB_YESNO | MB_DEFBUTTON1);
}


int AskNoYes (char *stringId)
{
	if (Silent) return 0;
	return MessageBoxW (MainDlg, GetString (stringId), lpszTitle, MB_ICONQUESTION | MB_YESNO | MB_DEFBUTTON2);
}


int AskOkCancel (char *stringId)
{
	if (Silent) return 0;
	return MessageBoxW (MainDlg, GetString (stringId), lpszTitle, MB_ICONQUESTION | MB_OKCANCEL | MB_DEFBUTTON1);
}


int AskWarnYesNo (char *stringId)
{
	if (Silent) return 0;
	return MessageBoxW (MainDlg, GetString (stringId), lpszTitle, MB_ICONWARNING | MB_YESNO | MB_DEFBUTTON1);
}


int AskWarnNoYes (char *stringId)
{
	if (Silent) return 0;
	return MessageBoxW (MainDlg, GetString (stringId), lpszTitle, MB_ICONWARNING | MB_YESNO | MB_DEFBUTTON2);
}


int AskWarnNoYesString (wchar_t *string)
{
	if (Silent) return 0;
	return MessageBoxW (MainDlg, string, lpszTitle, MB_ICONWARNING | MB_YESNO | MB_DEFBUTTON2);
}


int AskWarnCancelOk (char *stringId)
{
	if (Silent) return 0;
	return MessageBoxW (MainDlg, GetString (stringId), lpszTitle, MB_ICONWARNING | MB_OKCANCEL | MB_DEFBUTTON2);
}


int AskErrYesNo (char *stringId)
{
	if (Silent) return 0;
	return MessageBoxW (MainDlg, GetString (stringId), lpszTitle, MB_ICONERROR | MB_YESNO | MB_DEFBUTTON1);
}


int AskErrNoYes (char *stringId)
{
	if (Silent) return 0;
	return MessageBoxW (MainDlg, GetString (stringId), lpszTitle, MB_ICONERROR | MB_YESNO | MB_DEFBUTTON2);
}


// The function accepts two input formats:
// Input format 1: {0, "MESSAGE_STRING_ID", "BUTTON_1_STRING_ID", ... "LAST_BUTTON_STRING_ID", 0};
// Input format 2: {L"", L"Message text", L"Button caption 1", ... L"Last button caption", 0};
// The second format is to be used if any of the strings contains format specification (e.g. %s, %d) or
// in any other cases where a string needs to be resolved before calling this function.
// If the returned value is 0, the user closed the dialog window without making a choice. 
// If the user made a choice, the returned value is the ordinal number of the choice (1..MAX_MULTI_CHOICES)
int AskMultiChoice (void *strings[])
{
	return DialogBoxParamW (hInst, 
		MAKEINTRESOURCEW (IDD_MULTI_CHOICE_DLG), MainDlg,
		(DLGPROC) MultiChoiceDialogProc, (LPARAM) &strings[0]);
}


BOOL ConfigWriteBegin ()
{
	DWORD size;
	if (ConfigFileHandle != NULL) 
		return FALSE;

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
		XmlGetAttributeText (xml, "key", key, sizeof (key));
		XmlGetNodeText (xml, value, sizeof (value));

		fprintf (ConfigFileHandle, "\n\t\t<config key=\"%s\">%s</config>", key, value);
		xml++;
	}

	fputs ("\n\t</configuration>", ConfigFileHandle);
	XmlWriteFooter (ConfigFileHandle);

	TCFlushFile (ConfigFileHandle);

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
			XmlGetNodeText (xml, configValue, maxValueSize);
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

	if (r == ERROR_FILE_NOT_FOUND)
	{
		// Try the secondary help file
		r = (int)ShellExecute (NULL, "open", szHelpFile2, NULL, NULL, SW_SHOWNORMAL);

		if (r == ERROR_FILE_NOT_FOUND)
		{
			OpenOnlineHelp ();
			return;
		}
	}

	if (r == SE_ERR_NOASSOC)
	{
		if (AskYesNo ("HELP_READER_ERROR") == IDYES)
			OpenOnlineHelp ();
	}
}


void OpenOnlineHelp ()
{
	Applink ("help", TRUE, "");
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
		kf = (KeyFile *) malloc (sizeof (KeyFile));

		if (XmlGetNodeText (xml, kf->FileName, sizeof (kf->FileName)) != NULL)
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


// Returns TRUE, if the currently running operating system is installed in a hidden volume. If it's not, or if 
// there's an error, returns FALSE.
BOOL IsHiddenOSRunning (void)
{
	static BOOL statusCached = FALSE;
	static BOOL hiddenOSRunning;

	if (!statusCached)
	{
		try
		{
			hiddenOSRunning = BootEncryption (MainDlg).IsHiddenSystemRunning();
		}
		catch (...)
		{
			hiddenOSRunning = FALSE;
		}

		statusCached = TRUE;
	}

	return hiddenOSRunning;
}


BOOL RestartComputer (void)
{
	TOKEN_PRIVILEGES tokenPrivil; 
	HANDLE hTkn; 

	if (!OpenProcessToken (GetCurrentProcess (), TOKEN_QUERY|TOKEN_ADJUST_PRIVILEGES, &hTkn))
	{
		return false; 
	}

	LookupPrivilegeValue (NULL, SE_SHUTDOWN_NAME, &tokenPrivil.Privileges[0].Luid); 
	tokenPrivil.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED; 
	tokenPrivil.PrivilegeCount = 1;    

	AdjustTokenPrivileges (hTkn, false, &tokenPrivil, 0, (PTOKEN_PRIVILEGES) NULL, 0); 
	if (GetLastError() != ERROR_SUCCESS) 
		return false; 

	if (!ExitWindowsEx (EWX_REBOOT | EWX_FORCE, 
		SHTDN_REASON_MAJOR_OTHER | SHTDN_REASON_MINOR_OTHER | SHTDN_REASON_FLAG_PLANNED)) 
		return false; 

	return true;
}


void Applink (char *dest, BOOL bSendOS, char *extraOutput)
{
	char url [MAX_URL_LENGTH];
	char osname [200];

	if (bSendOS)
	{
		/* The type and version of the operating system are (or will be, in future) used to redirect users to website 
		pages that are appropriate in regards to the OS (such as an OS-specific version of the online documentation). */

		OSVERSIONINFOEXA os;

		os.dwOSVersionInfoSize = sizeof (OSVERSIONINFOEXA);

		GetVersionExA ((LPOSVERSIONINFOA) &os);

		strcpy (osname, "&os=");

		switch (nCurrentOS)
		{

		case WIN_2000:
			strcat (osname, "win2000");
			break;

		case WIN_XP:
		case WIN_XP64:
			strcat (osname, "winxp");
			strcat (osname, (os.wSuiteMask & VER_SUITE_PERSONAL) ? "-home" : "-pro");
			break;

		case WIN_SERVER_2003:
			strcat (osname, "win2003");
			break;

		case WIN_VISTA_OR_LATER:
			if (CurrentOSMajor == 6 && CurrentOSMinor == 0)
			{
				if (os.wProductType != VER_NT_SERVER && os.wProductType != VER_NT_DOMAIN_CONTROLLER)
				{
					strcat (osname, "winvista");

					if (os.wSuiteMask & VER_SUITE_PERSONAL)
						strcat (osname, "-home");
					else
					{
						HKEY hkey = 0;
						char str[300] = {0};
						DWORD size = sizeof (str);

						ZeroMemory (str, sizeof (str));
						if (RegOpenKeyEx (HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion",
							0, KEY_QUERY_VALUE, &hkey) == ERROR_SUCCESS
							&& (RegQueryValueEx (hkey, "ProductName", 0, 0, (LPBYTE) &str, &size) == ERROR_SUCCESS))
						{
							if (strstr (str, "Enterprise") != 0)
								strcat (osname, "-enterprise");
							else if (strstr (str, "Business") != 0)
								strcat (osname, "-business");
							else if (strstr (str, "Ultimate") != 0)
								strcat (osname, "-ultimate");
						}
						RegCloseKey (hkey);
					}
				}
				else
				{
					strcat (osname, "win2008");
				}
			}
			else
			{
				sprintf (osname + strlen (osname), "win%d.%d", CurrentOSMajor, CurrentOSMinor);
			}

			if (os.wProductType == VER_NT_SERVER || os.wProductType == VER_NT_DOMAIN_CONTROLLER)
				strcat (osname, "-server");

			break;

		default:
			sprintf (osname + strlen (osname), "win%d.%d", CurrentOSMajor, CurrentOSMinor);
			break;
		}

		if (Is64BitOs())
			strcat (osname, "-x64");

		if (CurrentOSServicePack > 0)
			sprintf (osname + strlen (osname), "-sp%d", CurrentOSServicePack);
	}
	else
		osname[0] = 0;

	ArrowWaitCursor ();

	sprintf (url, TC_APPLINK "%s%s&dest=%s", osname, extraOutput, dest);
	ShellExecute (NULL, "open", url, NULL, NULL, SW_SHOWNORMAL);

	Sleep (200);
	NormalCursor ();
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
	else if (nCurrentOS == WIN_VISTA_OR_LATER)
		Warning ("SYS_ASSIGN_DRIVE_LETTER");

	RegCloseKey (hkey);
}


BOOL CALLBACK CloseTCWindowsEnum (HWND hwnd, LPARAM lParam)
{
	if (GetWindowLongPtr (hwnd, GWLP_USERDATA) == (LONG_PTR) 'TRUE')
	{
		char name[1024] = { 0 };
		GetWindowText (hwnd, name, sizeof (name) - 1);
		if (hwnd != MainDlg && strstr (name, "TrueCrypt"))
		{
			PostMessage (hwnd, TC_APPMSG_CLOSE_BKG_TASK, 0, 0);

			if (DriverVersion < 0x0430)
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


void InconsistencyResolved (char *techInfo)
{
	wchar_t finalMsg[8024];

	wsprintfW (finalMsg, GetString ("INCONSISTENCY_RESOLVED"), techInfo);
	MessageBoxW (MainDlg, finalMsg, lpszTitle, MB_ICONWARNING | MB_SETFOREGROUND | MB_TOPMOST);
}


#ifndef SETUP

int OpenVolume (OpenVolumeContext *context, char *volumePath, Password *password, BOOL write, BOOL preserveTimestamps, BOOL useBackupHeader)
{
	int status;
	int volumeType;
	char szDiskFile[TC_MAX_PATH], szCFDevice[TC_MAX_PATH];
	char szDosDevice[TC_MAX_PATH];
	char buffer[TC_VOLUME_HEADER_EFFECTIVE_SIZE];
	LARGE_INTEGER headerOffset;

	context->VolumeIsOpen = FALSE;
	context->CryptoInfo = NULL;
	context->HostFileHandle = INVALID_HANDLE_VALUE;
	context->TimestampsValid = FALSE;

	CreateFullVolumePath (szDiskFile, volumePath, &context->IsDevice);

	if (context->IsDevice)
	{
		status = FakeDosNameForDevice (szDiskFile, szDosDevice, szCFDevice, FALSE);
		if (status != 0)
			return status;

		preserveTimestamps = FALSE;
	}
	else
		strcpy (szCFDevice, szDiskFile);

	if (preserveTimestamps)
		write = TRUE;

	context->HostFileHandle = CreateFile (szCFDevice, GENERIC_READ | (write ? GENERIC_WRITE : 0), FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);

	if (context->HostFileHandle == INVALID_HANDLE_VALUE)
	{
		status = ERR_OS_ERROR;
		goto error;
	}

	context->VolumeIsOpen = TRUE;

	// Remember the container modification/creation date and time
	if (!context->IsDevice && preserveTimestamps)
	{
		if (GetFileTime (context->HostFileHandle, &context->CreationTime, &context->LastAccessTime, &context->LastWriteTime) == 0)
		{
			context->TimestampsValid = FALSE;
			Warning ("GETFILETIME_FAILED_GENERIC");
		}
		else
			context->TimestampsValid = TRUE;
	}

	// Determine host size
	if (context->IsDevice)
	{
		PARTITION_INFORMATION diskInfo;
		DWORD dwResult;

		if (GetPartitionInfo (volumePath, &diskInfo))
		{
			context->HostSize = diskInfo.PartitionLength.QuadPart;
		}
		else
		{
			DISK_GEOMETRY driveInfo;

			if (!DeviceIoControl (context->HostFileHandle, IOCTL_DISK_GET_DRIVE_GEOMETRY, NULL, 0, &driveInfo, sizeof (driveInfo), &dwResult, NULL))
				goto error;

			context->HostSize = driveInfo.Cylinders.QuadPart * driveInfo.BytesPerSector * driveInfo.SectorsPerTrack * driveInfo.TracksPerCylinder;
		}

		if (context->HostSize == 0)
		{
			status = ERR_VOL_SIZE_WRONG;
			goto error;
		}
	}
	else
	{
		LARGE_INTEGER fileSize;
		if (!GetFileSizeEx (context->HostFileHandle, &fileSize))
		{
			status = ERR_OS_ERROR;
			goto error;
		}

		context->HostSize = fileSize.QuadPart;
	}

	for (volumeType = TC_VOLUME_TYPE_NORMAL; volumeType < TC_VOLUME_TYPE_COUNT; volumeType++)
	{
		// Seek the volume header
		switch (volumeType)
		{
		case TC_VOLUME_TYPE_NORMAL:
			headerOffset.QuadPart = useBackupHeader ? context->HostSize - TC_VOLUME_HEADER_GROUP_SIZE : TC_VOLUME_HEADER_OFFSET;
			break;

		case TC_VOLUME_TYPE_HIDDEN:
			if (TC_HIDDEN_VOLUME_HEADER_OFFSET + TC_VOLUME_HEADER_SIZE > context->HostSize)
				continue;

			headerOffset.QuadPart = useBackupHeader ? context->HostSize - TC_VOLUME_HEADER_SIZE : TC_HIDDEN_VOLUME_HEADER_OFFSET;
			break;

		case TC_VOLUME_TYPE_HIDDEN_LEGACY:
			if (useBackupHeader)
			{
				status = ERR_PASSWORD_WRONG;
				goto error;
			}

			headerOffset.QuadPart = context->HostSize - TC_HIDDEN_VOLUME_HEADER_OFFSET_LEGACY;
			break;
		}

		if (!SetFilePointerEx ((HANDLE) context->HostFileHandle, headerOffset, NULL, FILE_BEGIN))
		{
			status = ERR_OS_ERROR;
			goto error;
		}

		// Read volume header
		DWORD bytesRead;
		if (!ReadFile (context->HostFileHandle, buffer, sizeof (buffer), &bytesRead, NULL))
		{
			status = ERR_OS_ERROR;
			goto error;
		}

		if (bytesRead != sizeof (buffer))
		{
			status = ERR_VOL_SIZE_WRONG;
			goto error;
		}

		// Decrypt volume header
		status = VolumeReadHeader (FALSE, buffer, password, &context->CryptoInfo, NULL);

		if (status == ERR_PASSWORD_WRONG)
			continue;		// Try next volume type

		break;
	}

	if (status == ERR_SUCCESS)
		return status;

error:
	DWORD sysError = GetLastError ();

	CloseVolume (context);

	SetLastError (sysError);
	return status;
}


void CloseVolume (OpenVolumeContext *context)
{
	if (!context->VolumeIsOpen)
		return;

	if (context->HostFileHandle != INVALID_HANDLE_VALUE)
	{
		// Restore the container timestamp (to preserve plausible deniability of possible hidden volume). 
		if (context->TimestampsValid)
		{
			if (!SetFileTime (context->HostFileHandle, &context->CreationTime, &context->LastAccessTime, &context->LastWriteTime))
			{
				handleWin32Error (NULL);
				Warning ("SETFILETIME_FAILED_PW");
			}
		}

		CloseHandle (context->HostFileHandle);
		context->HostFileHandle = INVALID_HANDLE_VALUE;
	}

	if (context->CryptoInfo)
	{
		crypto_close (context->CryptoInfo);
		context->CryptoInfo = NULL;
	}

	context->VolumeIsOpen = FALSE;
}


int ReEncryptVolumeHeader (char *buffer, BOOL bBoot, CRYPTO_INFO *cryptoInfo, Password *password, BOOL wipeMode)
{
	CRYPTO_INFO *newCryptoInfo = NULL;
	
	RandSetHashFunction (cryptoInfo->pkcs5);

	if (Randinit() != ERR_SUCCESS)
		return ERR_PARAMETER_INCORRECT;

	int status = VolumeWriteHeader (bBoot,
		buffer,
		cryptoInfo->ea,
		cryptoInfo->mode,
		password,
		cryptoInfo->pkcs5,
		(char *) cryptoInfo->master_keydata,
		&newCryptoInfo,
		cryptoInfo->VolumeSize.Value,
		cryptoInfo->hiddenVolume ? cryptoInfo->hiddenVolumeSize : 0,
		cryptoInfo->EncryptedAreaStart.Value,
		cryptoInfo->EncryptedAreaLength.Value,
		cryptoInfo->RequiredProgramVersion,
		cryptoInfo->HeaderFlags,
		wipeMode);

	if (newCryptoInfo != NULL)
		crypto_close (newCryptoInfo);

	return status;
}

#endif // !SETUP


BOOL IsPagingFileActive ()
{
	// GlobalMemoryStatusEx() cannot be used to determine if a paging file is active

	char data[65536];
	DWORD size = sizeof (data);
	
	if (ReadLocalMachineRegistryMultiString ("System\\CurrentControlSet\\Control\\Session Manager\\Memory Management", "PagingFiles", data, &size)
		&& size > 6)
		return TRUE;

	for (char drive = 'C'; drive <= 'Z'; ++drive)
	{
		string path = "X:\\pagefile.sys";
		path[0] = drive;

		HANDLE handle = CreateFile (path.c_str(), GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
		
		if (handle != INVALID_HANDLE_VALUE)
			CloseHandle (handle);
		else if (GetLastError() == ERROR_SHARING_VIOLATION)
			return TRUE;
	}

	return FALSE;
}


BOOL DisablePagingFile ()
{
	char empty[] = { 0, 0 };
	return WriteLocalMachineRegistryMultiString ("System\\CurrentControlSet\\Control\\Session Manager\\Memory Management", "PagingFiles", empty, sizeof (empty));
}
