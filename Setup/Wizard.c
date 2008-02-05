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

#include "SelfExtract.h"
#include "Wizard.h"
#include "Dlgcode.h"
#include "Language.h"
#include "Common/Resource.h"
#include "Resource.h"

enum wizard_pages
{
	INTRO_PAGE,
	WIZARD_MODE_PAGE,
	INSTALL_OPTIONS_PAGE,
	INSTALL_PROGRESS_PAGE,
	EXTRACTION_OPTIONS_PAGE,
	EXTRACTION_PROGRESS_PAGE
};

HWND hCurPage = NULL;		/* Handle to current wizard page */
int nCurPageNo = -1;		/* The current wizard page */
char WizardDestInstallPath [TC_MAX_PATH];
char WizardDestExtractPath [TC_MAX_PATH];
char SelfFile [TC_MAX_PATH];

HBITMAP hbmWizardBitmapRescaled = NULL;

BOOL bExtractOnly = FALSE;
BOOL bLicenseAccepted = FALSE;
BOOL bOpenContainingFolder = TRUE;
BOOL bExtractionSuccessful = FALSE;
BOOL bStartInstall = FALSE;
BOOL bStartExtraction = FALSE;
BOOL bInProgress = FALSE;

int nPbar = 0;			/* Control ID of progress bar */

void localcleanup (void)
{
	/* Delete buffered bitmaps (if any) */
	if (hbmWizardBitmapRescaled != NULL)
	{
		DeleteObject ((HGDIOBJ) hbmWizardBitmapRescaled);
		hbmWizardBitmapRescaled = NULL;
	}

	/* Cleanup common code resources */
	cleanup ();
}

static void InitWizardDestInstallPath (void)
{

	if (strlen (WizardDestInstallPath) < 2)
	{
		strcpy (WizardDestInstallPath, InstallationPath);
		if (WizardDestInstallPath [strlen (WizardDestInstallPath) - 1] != '\\')
		{
			strcat (WizardDestInstallPath, "\\");
		}
	}
}

void LoadPage (HWND hwndDlg, int nPageNo)
{
	RECT rD, rW;

	if (hCurPage != NULL)
	{
		DestroyWindow (hCurPage);
	}

	GetWindowRect (GetDlgItem (hwndDlg, IDC_POS_BOX), &rW);

	nCurPageNo = nPageNo;

	switch (nPageNo)
	{
	case INTRO_PAGE:
		hCurPage = CreateDialogW (hInst, MAKEINTRESOURCEW (IDD_INTRO_PAGE_DLG), hwndDlg,
					 (DLGPROC) PageDialogProc);
		break;

	case WIZARD_MODE_PAGE:
		hCurPage = CreateDialogW (hInst, MAKEINTRESOURCEW (IDD_WIZARD_MODE_PAGE_DLG), hwndDlg,
					 (DLGPROC) PageDialogProc);
		break;

	case INSTALL_OPTIONS_PAGE:
		hCurPage = CreateDialogW (hInst, MAKEINTRESOURCEW (IDD_INSTALL_OPTIONS_PAGE_DLG), hwndDlg,
					 (DLGPROC) PageDialogProc);
		break;

	case INSTALL_PROGRESS_PAGE:
		hCurPage = CreateDialogW (hInst, MAKEINTRESOURCEW (IDD_PROGRESS_PAGE_DLG), hwndDlg,
					 (DLGPROC) PageDialogProc);
		break;

	case EXTRACTION_OPTIONS_PAGE:
		hCurPage = CreateDialogW (hInst, MAKEINTRESOURCEW (IDD_EXTRACTION_OPTIONS_PAGE_DLG), hwndDlg,
					 (DLGPROC) PageDialogProc);
		break;

	case EXTRACTION_PROGRESS_PAGE:
		hCurPage = CreateDialogW (hInst, MAKEINTRESOURCEW (IDD_PROGRESS_PAGE_DLG), hwndDlg,
					 (DLGPROC) PageDialogProc);
		break;
	}

	rD.left = 15;
	rD.top = 45;
	rD.right = 0;
	rD.bottom = 0;
	MapDialogRect (hwndDlg, &rD);

	if (hCurPage != NULL)
	{
		MoveWindow (hCurPage, rD.left, rD.top, rW.right - rW.left, rW.bottom - rW.top, TRUE);
		ShowWindow (hCurPage, SW_SHOWNORMAL);
	}

	/* Refresh the graphics (white background of some texts, etc.) */
	RefreshUIGFX ();
}


/* Except in response to the WM_INITDIALOG message, the dialog box procedure
   should return nonzero if it processes the message, and zero if it does
   not. - see DialogProc */
BOOL CALLBACK PageDialogProc (HWND hwndDlg, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
	static char PageDebugId[128];
	WORD lw = LOWORD (wParam);
	WORD hw = HIWORD (wParam);

	hCurPage = hwndDlg;

	switch (uMsg)
	{
	case WM_INITDIALOG:
		LocalizeDialog (hwndDlg, "IDD_INSTL_DLG");

		sprintf (PageDebugId, "SETUP_WIZARD_PAGE_%d", nCurPageNo);
		LastDialogId = PageDebugId;

		switch (nCurPageNo)
		{
		case INTRO_PAGE:
			{
				char *licenseText = NULL;

				licenseText = GetLegalNotices ();
				if (licenseText != NULL)
				{
					SetWindowText (GetDlgItem (hwndDlg, IDC_LICENSE_TEXT), licenseText);
					free (licenseText);
				}
				else
				{
					Error("CANNOT_DISPLAY_LICENSE");
					PostMessage (MainDlg, WM_CLOSE, 0, 0);
				}

				/* Some of the following texts cannot be localized by third parties for legal reasons. */

				CheckButton (GetDlgItem (hwndDlg, bLicenseAccepted ? IDC_AGREE : IDC_DISAGREE));

				SetWindowTextW (GetDlgItem (GetParent (hwndDlg), IDC_BOX_TITLE), L"License Agreement");
				SetWindowTextW (GetDlgItem (GetParent (hwndDlg), IDC_BOX_INFO), L"You must accept this license agreement before you can use, extract, or install TrueCrypt.");
				SetWindowTextW (GetDlgItem (hwndDlg, IDC_BOX_HELP), L"IMPORTANT: By selecting the first option below and clicking Accept, you accept and agree to be bound by these license terms. Click the 'arrow down' icon to see the rest of the license.");
				//SendMessage (GetDlgItem (hwndDlg, IDC_BOX_HELP), WM_SETFONT, (WPARAM) hUserBoldFont, (LPARAM) TRUE);

				SetWindowTextW (GetDlgItem (hwndDlg, IDC_AGREE), L"I a&ccept and agree to be bound by all of the terms of the license agreement");
				SetWindowTextW (GetDlgItem (hwndDlg, IDC_DISAGREE), L"I &do not accept the terms of the license agreement");

				//SendMessage (GetDlgItem (hwndDlg, IDC_AGREE), WM_SETFONT, (WPARAM) hUserBoldFont, (LPARAM) TRUE);
				//SendMessage (GetDlgItem (hwndDlg, IDC_DISAGREE), WM_SETFONT, (WPARAM) hUserBoldFont, (LPARAM) TRUE);

				EnableWindow (GetDlgItem (hwndDlg, IDC_AGREE), TRUE);
				EnableWindow (GetDlgItem (hwndDlg, IDC_DISAGREE), TRUE);

				SetWindowTextW (GetDlgItem (GetParent (hwndDlg), IDC_NEXT), L"&Accept");	// Cannot be localized by third parties for legal reasons.
				SetWindowTextW (GetDlgItem (GetParent (hwndDlg), IDC_PREV), GetString ("PREV"));
				SetWindowTextW (GetDlgItem (GetParent (hwndDlg), IDCANCEL), GetString ("CANCEL"));

				EnableWindow (GetDlgItem (GetParent (hwndDlg), IDC_NEXT), bLicenseAccepted);
				EnableWindow (GetDlgItem (GetParent (hwndDlg), IDC_PREV), FALSE);
				EnableWindow (GetDlgItem (GetParent (hwndDlg), IDHELP), bLicenseAccepted);
			}
			return 1;

		case WIZARD_MODE_PAGE:

			if (bRepairMode)
			{
				SetWindowTextW (GetDlgItem (hwndDlg, IDC_WIZARD_MODE_INSTALL), GetString ("REPAIR_REINSTALL"));
				bExtractOnly = FALSE;
			}

			SetWindowTextW (GetDlgItem (GetParent (hwndDlg), IDC_BOX_TITLE), GetString ("SETUP_MODE_TITLE"));
			SetWindowTextW (GetDlgItem (GetParent (hwndDlg), IDC_BOX_INFO), GetString ("SETUP_MODE_INFO"));

			SendMessage (GetDlgItem (hwndDlg, IDC_WIZARD_MODE_INSTALL), WM_SETFONT, (WPARAM) hUserBoldFont, (LPARAM) TRUE);
			SendMessage (GetDlgItem (hwndDlg, IDC_WIZARD_MODE_EXTRACT_ONLY), WM_SETFONT, (WPARAM) hUserBoldFont, (LPARAM) TRUE);

			CheckButton (GetDlgItem (hwndDlg, bExtractOnly ? IDC_WIZARD_MODE_EXTRACT_ONLY : IDC_WIZARD_MODE_INSTALL));

			SetWindowTextW (GetDlgItem (hwndDlg, IDC_BOX_HELP), GetString ("SETUP_MODE_HELP_EXTRACT"));

			if (!bRepairMode)
				SetWindowTextW (GetDlgItem (hwndDlg, IDC_BOX_HELP2), GetString ("SETUP_MODE_HELP_INSTALL"));

			EnableWindow (GetDlgItem (hwndDlg, IDC_WIZARD_MODE_EXTRACT_ONLY), !bRepairMode);
			EnableWindow (GetDlgItem (hwndDlg, IDC_BOX_HELP), !bRepairMode);
			EnableWindow (GetDlgItem (hwndDlg, IDC_WIZARD_MODE_INSTALL), TRUE);

			SetWindowTextW (GetDlgItem (GetParent (hwndDlg), IDC_NEXT), GetString ("NEXT"));
			SetWindowTextW (GetDlgItem (GetParent (hwndDlg), IDC_PREV), GetString ("PREV"));
			SetWindowTextW (GetDlgItem (GetParent (hwndDlg), IDCANCEL), GetString ("CANCEL"));
			EnableWindow (GetDlgItem (GetParent (hwndDlg), IDC_NEXT), TRUE);
			EnableWindow (GetDlgItem (GetParent (hwndDlg), IDC_PREV), TRUE);

			return 1;

		case EXTRACTION_OPTIONS_PAGE:

			if (strlen(WizardDestExtractPath) < 2)
			{ 
				strcpy (WizardDestExtractPath, SetupFilesDir);
				strncat (WizardDestExtractPath, "TrueCrypt\\", sizeof (WizardDestExtractPath) - strlen (WizardDestExtractPath) - 1);
			}

			SendMessage (GetDlgItem (hwndDlg, IDC_DESTINATION), EM_LIMITTEXT, TC_MAX_PATH - 1, 0);

			SetDlgItemText (hwndDlg, IDC_DESTINATION, WizardDestExtractPath);

			SetCheckBox (hwndDlg, IDC_OPEN_CONTAINING_FOLDER, bOpenContainingFolder);

			SetWindowTextW (GetDlgItem (GetParent (hwndDlg), IDC_BOX_TITLE), GetString ("EXTRACTION_OPTIONS_TITLE"));
			SetWindowTextW (GetDlgItem (GetParent (hwndDlg), IDC_BOX_INFO), GetString ("EXTRACTION_OPTIONS_INFO"));
			SetWindowTextW (GetDlgItem (hwndDlg, IDC_BOX_HELP), GetString ("AUTO_FOLDER_CREATION"));

			SetWindowTextW (GetDlgItem (GetParent (hwndDlg), IDC_NEXT), GetString ("EXTRACT"));
			SetWindowTextW (GetDlgItem (GetParent (hwndDlg), IDC_PREV), GetString ("PREV"));
			EnableWindow (GetDlgItem (GetParent (hwndDlg), IDC_PREV), TRUE);
			EnableWindow (GetDlgItem (GetParent (hwndDlg), IDC_NEXT), TRUE);
			EnableWindow (GetDlgItem (GetParent (hwndDlg), IDCANCEL), TRUE);

			return 1;

		case EXTRACTION_PROGRESS_PAGE:

			SetWindowTextW (GetDlgItem (GetParent (hwndDlg), IDC_BOX_TITLE), GetString ("EXTRACTING_VERB"));
			SetWindowTextW (GetDlgItem (GetParent (hwndDlg), IDC_BOX_INFO), GetString ("EXTRACTION_PROGRESS_INFO"));
			SetWindowTextW (GetDlgItem (GetParent (hwndDlg), IDC_NEXT), GetString ("NEXT"));

			if (bStartExtraction)
			{
				/* Start extraction */

				LastDialogId = "EXTRACTION_IN_PROGRESS";

				WaitCursor ();

				EnableWindow (GetDlgItem (GetParent (hwndDlg), IDC_PREV), FALSE);
				EnableWindow (GetDlgItem (GetParent (hwndDlg), IDC_NEXT), FALSE);
				EnableWindow (GetDlgItem (GetParent (hwndDlg), IDHELP), FALSE);
				EnableWindow (GetDlgItem (GetParent (hwndDlg), IDCANCEL), FALSE);

				if (WizardDestExtractPath [strlen(WizardDestExtractPath)-1] != '\\')
					strcat (WizardDestExtractPath, "\\");

				strcpy (DestExtractPath, WizardDestExtractPath);

				InitProgressBar ();

				bInProgress = TRUE;
				bStartExtraction = FALSE;

				_beginthread (ExtractAllFilesThread, 16384, (void *) hwndDlg);
			}
			else
			{
				NormalCursor ();

				EnableWindow (GetDlgItem (GetParent (hwndDlg), IDC_PREV), TRUE);
				EnableWindow (GetDlgItem (GetParent (hwndDlg), IDC_NEXT), TRUE);
				EnableWindow (GetDlgItem (GetParent (hwndDlg), IDHELP), TRUE);
				EnableWindow (GetDlgItem (GetParent (hwndDlg), IDCANCEL), TRUE);
			}

			return 1;

		case INSTALL_OPTIONS_PAGE:

			SetWindowTextW (GetDlgItem (GetParent (hwndDlg), IDC_BOX_TITLE), GetString ("SETUP_OPTIONS_TITLE"));
			SetWindowTextW (GetDlgItem (GetParent (hwndDlg), IDC_BOX_INFO), GetString ("SETUP_OPTIONS_INFO"));
			SetWindowTextW (GetDlgItem (hwndDlg, IDC_BOX_HELP), GetString ("AUTO_FOLDER_CREATION"));

			InitWizardDestInstallPath ();

			SendMessage (GetDlgItem (hwndDlg, IDC_DESTINATION), EM_LIMITTEXT, TC_MAX_PATH - 1, 0);

			SetDlgItemText (hwndDlg, IDC_DESTINATION, WizardDestInstallPath);

			// System Restore
			SetCheckBox (hwndDlg, IDC_SYSTEM_RESTORE, bSystemRestore);
			if (SystemRestoreDll == 0)
			{
				SetCheckBox (hwndDlg, IDC_SYSTEM_RESTORE, FALSE);
				EnableWindow (GetDlgItem (hwndDlg, IDC_SYSTEM_RESTORE), FALSE);
			}

			SetCheckBox (hwndDlg, IDC_ALL_USERS, bForAllUsers);
			SetCheckBox (hwndDlg, IDC_FILE_TYPE, bRegisterFileExt);
			SetCheckBox (hwndDlg, IDC_PROG_GROUP, bAddToStartMenu);
			SetCheckBox (hwndDlg, IDC_DESKTOP_ICON, bDesktopIcon);

			SetWindowTextW (GetDlgItem (GetParent (hwndDlg), IDC_NEXT), GetString ("INSTALL"));
			SetWindowTextW (GetDlgItem (GetParent (hwndDlg), IDC_PREV), GetString ("PREV"));

			EnableWindow (GetDlgItem (GetParent (hwndDlg), IDHELP), TRUE);
			EnableWindow (GetDlgItem (GetParent (hwndDlg), IDC_PREV), TRUE);
			EnableWindow (GetDlgItem (GetParent (hwndDlg), IDC_NEXT), TRUE);
			EnableWindow (GetDlgItem (GetParent (hwndDlg), IDCANCEL), TRUE);

			return 1;

		case INSTALL_PROGRESS_PAGE:

			SetWindowTextW (GetDlgItem (GetParent (hwndDlg), IDC_BOX_TITLE), GetString ("SETUP_PROGRESS_TITLE"));
			SetWindowTextW (GetDlgItem (GetParent (hwndDlg), IDC_BOX_INFO), GetString ("SETUP_PROGRESS_INFO"));
			SetWindowTextW (GetDlgItem (GetParent (hwndDlg), IDC_NEXT), GetString ("NEXT"));
			SetWindowTextW (GetDlgItem (GetParent (hwndDlg), IDC_PREV), GetString ("PREV"));

			if (bStartInstall)
			{
				/* Start install */

				LastDialogId = "INSTALL_IN_PROGRESS";

				SetWindowTextW (GetDlgItem (GetParent (hwndDlg), IDC_NEXT), GetString ("NEXT"));

				EnableWindow (GetDlgItem (GetParent (hwndDlg), IDC_PREV), FALSE);
				EnableWindow (GetDlgItem (GetParent (hwndDlg), IDC_NEXT), FALSE);
				EnableWindow (GetDlgItem (GetParent (hwndDlg), IDHELP), FALSE);
				EnableWindow (GetDlgItem (GetParent (hwndDlg), IDCANCEL), FALSE);

				InitProgressBar ();

				if (WizardDestInstallPath [strlen(WizardDestInstallPath)-1] != '\\')
					strcat (WizardDestInstallPath, "\\");

				strcpy (InstallationPath, WizardDestInstallPath);

				WaitCursor ();

				bInProgress = TRUE;
				bStartInstall = FALSE;

				_beginthread (DoInstall, 16384, (void *) hwndDlg);
			}
			else
			{
				NormalCursor ();

				EnableWindow (GetDlgItem (GetParent (hwndDlg), IDC_PREV), TRUE);
				EnableWindow (GetDlgItem (GetParent (hwndDlg), IDC_NEXT), TRUE);
				EnableWindow (GetDlgItem (GetParent (hwndDlg), IDHELP), TRUE);
				EnableWindow (GetDlgItem (GetParent (hwndDlg), IDCANCEL), TRUE);

			}

			return 1;

		}
		return 0;

	case WM_HELP:
		if (bLicenseAccepted)
			OpenPageHelp (GetParent (hwndDlg), nCurPageNo);

		return 1;

	case TC_APPMSG_LOAD_LICENSE:
		{
			char *licenseText = NULL;
			licenseText = GetLegalNotices ();
			if (licenseText != NULL)
			{
				SetWindowText (GetDlgItem (hwndDlg, IDC_LICENSE_TEXT), licenseText);
				free (licenseText);
			}
			else
			{
				Error("CANNOT_DISPLAY_LICENSE");
				PostMessage (MainDlg, WM_CLOSE, 0, 0);
			}
		}
		return 1;


	case WM_COMMAND:

		if (lw == IDC_DISAGREE && nCurPageNo == INTRO_PAGE)
		{
			EnableWindow (GetDlgItem (GetParent (hwndDlg), IDC_NEXT), FALSE);
			return 1;
		}

		if (lw == IDC_AGREE && nCurPageNo == INTRO_PAGE)
		{
			EnableWindow (GetDlgItem (GetParent (hwndDlg), IDC_NEXT), TRUE);
			return 1;
		}

		if (lw == IDC_WIZARD_MODE_EXTRACT_ONLY && nCurPageNo == WIZARD_MODE_PAGE)
		{
			bExtractOnly = TRUE;
			return 1;
		}

		if (lw == IDC_WIZARD_MODE_INSTALL && nCurPageNo == WIZARD_MODE_PAGE)
		{
			bExtractOnly = FALSE;
			return 1;
		}

		if ( nCurPageNo == EXTRACTION_OPTIONS_PAGE && hw == EN_CHANGE )
		{
			EnableWindow (GetDlgItem (MainDlg, IDC_NEXT), (GetWindowTextLength (GetDlgItem (hCurPage, IDC_DESTINATION)) > 1));
			return 1;
		}

		if ( nCurPageNo == INSTALL_OPTIONS_PAGE && hw == EN_CHANGE )
		{
			EnableWindow (GetDlgItem (MainDlg, IDC_NEXT), (GetWindowTextLength (GetDlgItem (hCurPage, IDC_DESTINATION)) > 1));
			return 1;
		}

		if (nCurPageNo == INTRO_PAGE && lw == IDC_LICENSE_TEXT && HIWORD (wParam) == EN_UPDATE)
		{
			// License is read-only
			SendMessage (hwndDlg, TC_APPMSG_LOAD_LICENSE, 0, 0);
			return 1;
		}

		if ( nCurPageNo == EXTRACTION_OPTIONS_PAGE )
		{
			switch (lw)
			{
			case IDC_BROWSE:
				if (BrowseDirectories (hwndDlg, "SELECT_DEST_DIR", WizardDestExtractPath))
				{
					if (WizardDestExtractPath [strlen(WizardDestExtractPath)-1] != '\\')
					{
						strcat (WizardDestExtractPath, "\\");
					}
					SetDlgItemText (hwndDlg, IDC_DESTINATION, WizardDestExtractPath);
				}
				return 1;

			case IDC_OPEN_CONTAINING_FOLDER:
				bOpenContainingFolder = IsButtonChecked (GetDlgItem (hCurPage, IDC_SYSTEM_RESTORE));
				return 1;
			}
		}

		if ( nCurPageNo == INSTALL_OPTIONS_PAGE )
		{
			switch (lw)
			{
			case IDC_BROWSE:
				if (BrowseDirectories (hwndDlg, "SELECT_DEST_DIR", WizardDestInstallPath))
				{
					if (WizardDestInstallPath [strlen(WizardDestInstallPath)-1] != '\\')
					{
						strcat (WizardDestInstallPath, "\\");
					}
					SetDlgItemText (hwndDlg, IDC_DESTINATION, WizardDestInstallPath);
				}
				return 1;

			case IDC_SYSTEM_RESTORE:
				bSystemRestore = IsButtonChecked (GetDlgItem (hCurPage, IDC_SYSTEM_RESTORE));
				return 1;

			case IDC_ALL_USERS:
				bForAllUsers = IsButtonChecked (GetDlgItem (hCurPage, IDC_ALL_USERS));
				return 1;

			case IDC_FILE_TYPE:
				bRegisterFileExt = IsButtonChecked (GetDlgItem (hCurPage, IDC_FILE_TYPE));
				return 1;

			case IDC_PROG_GROUP:
				bAddToStartMenu = IsButtonChecked (GetDlgItem (hCurPage, IDC_PROG_GROUP));
				return 1;

			case IDC_DESKTOP_ICON:
				bDesktopIcon = IsButtonChecked (GetDlgItem (hCurPage, IDC_DESKTOP_ICON));
				return 1;

			}
		}

		return 0;
	}

	return 0;
}

void InitProgressBar (void)
{
	HWND hProgressBar = GetDlgItem (hCurPage, nPbar);
	SendMessage (hProgressBar, PBM_SETRANGE32, 0, 100);
	SendMessage (hProgressBar, PBM_SETSTEP, 1, 0);
	InvalidateRect (hProgressBar, NULL, TRUE);
}

// Must always return TRUE
BOOL UpdateProgressBarProc (int nPercent)
{
	HWND hProgressBar = GetDlgItem (hCurPage, nPbar);
	SendMessage (hProgressBar, PBM_SETPOS, (int) (100.0 * nPercent / 100), 0);
	InvalidateRect (hProgressBar, NULL, TRUE);
	ShowWindow(hProgressBar, SW_HIDE);
	ShowWindow(hProgressBar, SW_SHOW);
	// Prevent the IDC_LOG_WINDOW item from partially disappearing at higher DPIs
	ShowWindow(GetDlgItem (hCurPage, IDC_LOG_WINDOW), SW_HIDE);
	ShowWindow(GetDlgItem (hCurPage, IDC_LOG_WINDOW), SW_SHOW);
	RefreshUIGFX();
	return TRUE;
}

void RefreshUIGFX (void)
{
	InvalidateRect (GetDlgItem (MainDlg, IDC_SETUP_WIZARD_BKG), NULL, TRUE);
	InvalidateRect (GetDlgItem (MainDlg, IDC_BOX_TITLE), NULL, TRUE);
	InvalidateRect (GetDlgItem (MainDlg, IDC_BOX_INFO), NULL, TRUE);
	InvalidateRect (GetDlgItem (MainDlg, IDC_BITMAP_SETUP_WIZARD), NULL, TRUE);
	InvalidateRect (GetDlgItem (MainDlg, IDC_HR), NULL, TRUE);
	// Prevent these items from disappearing at higher DPIs
	ShowWindow(GetDlgItem(MainDlg, IDC_HR), SW_HIDE);
	ShowWindow(GetDlgItem(MainDlg, IDC_HR), SW_SHOW);
	ShowWindow(GetDlgItem(MainDlg, IDC_HR_BOTTOM), SW_HIDE);
	ShowWindow(GetDlgItem(MainDlg, IDC_HR_BOTTOM), SW_SHOW);
	ShowWindow(GetDlgItem(MainDlg, IDC_BOX_INFO), SW_HIDE);
	ShowWindow(GetDlgItem(MainDlg, IDC_BOX_INFO), SW_SHOW);
	ShowWindow(GetDlgItem(MainDlg, IDC_BOX_TITLE), SW_HIDE);
	ShowWindow(GetDlgItem(MainDlg, IDC_BOX_TITLE), SW_SHOW);
}


/* Except in response to the WM_INITDIALOG message, the dialog box procedure
   should return nonzero if it processes the message, and zero if it does
   not. - see DialogProc */
BOOL CALLBACK MainDialogProc (HWND hwndDlg, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
	WORD lw = LOWORD (wParam);

	if (lParam);		/* Remove unused parameter warning */

	switch (uMsg)
	{
	case WM_INITDIALOG:
		{
			RECT rec;

			GetModuleFileName (NULL, SelfFile, sizeof (SelfFile));

			MainDlg = hwndDlg;
			InitDialog (hwndDlg);
			LocalizeDialog (hwndDlg, "IDD_INSTL_DLG");
			
			// Resize the bitmap if the user has a non-default DPI 
			if (ScreenDPI != USER_DEFAULT_SCREEN_DPI)
			{
				hbmWizardBitmapRescaled = RenderBitmap (MAKEINTRESOURCE (IDB_SETUP_WIZARD),
					GetDlgItem (hwndDlg, IDC_BITMAP_SETUP_WIZARD),
					0, 0, 0, 0, FALSE, TRUE);
			}

			// Gfx area background (must not keep aspect ratio; must retain Windows-imposed distortion)
			GetClientRect (GetDlgItem (hwndDlg, IDC_SETUP_WIZARD_GFX_AREA), &rec);
			SetWindowPos (GetDlgItem (hwndDlg, IDC_SETUP_WIZARD_BKG), HWND_TOP, 0, 0, rec.right, rec.bottom, SWP_NOMOVE);

			nPbar = IDC_PROGRESS_BAR;

			SendMessage (GetDlgItem (hwndDlg, IDC_BOX_TITLE), WM_SETFONT, (WPARAM) hUserBoldFont, (LPARAM) TRUE);

			SetWindowTextW (hwndDlg, lpszTitle);

			if (bDevm)
			{
				InitWizardDestInstallPath ();
				bSystemRestore = FALSE;
				bRegisterFileExt = FALSE;
				bAddToStartMenu = FALSE;
				bDesktopIcon = TRUE;
				bLicenseAccepted = TRUE;
				bStartInstall = TRUE;
				LoadPage (hwndDlg, INSTALL_PROGRESS_PAGE);
			}
			else
				LoadPage (hwndDlg, INTRO_PAGE);
		}
		return 0;

	case WM_SYSCOMMAND:
		if (lw == IDC_ABOUT)
		{
			if (bLicenseAccepted)
				DialogBoxW (hInst, MAKEINTRESOURCEW (IDD_ABOUT_DLG), hwndDlg, (DLGPROC) AboutDlgProc);

			return 1;
		}
		return 0;

	case WM_HELP:
		if (bLicenseAccepted)
			OpenPageHelp (hwndDlg, nCurPageNo);

		return 1;

	case WM_COMMAND:
		if (lw == IDHELP)
		{
			if (bLicenseAccepted)
				OpenPageHelp (hwndDlg, nCurPageNo);

			return 1;
		}
		if (lw == IDCANCEL)
		{
			PostMessage (hwndDlg, WM_CLOSE, 0, 0);
			return 1;
		}
		if (lw == IDC_NEXT)
		{
			if (nCurPageNo == INTRO_PAGE)
			{
				if (!IsButtonChecked (GetDlgItem (hCurPage, IDC_AGREE)))
				{
					bLicenseAccepted = FALSE;
					return 1;
				}
				bLicenseAccepted = TRUE;
				EnableWindow (GetDlgItem (hwndDlg, IDHELP), TRUE);
			}

			else if (nCurPageNo == WIZARD_MODE_PAGE)
			{
				if (bExtractOnly = IsButtonChecked (GetDlgItem (hCurPage, IDC_WIZARD_MODE_EXTRACT_ONLY)))
				{
					nCurPageNo = EXTRACTION_OPTIONS_PAGE - 1;
				}
			}

			else if (nCurPageNo == EXTRACTION_OPTIONS_PAGE)
			{
				GetWindowText (GetDlgItem (hCurPage, IDC_DESTINATION), WizardDestExtractPath, sizeof (WizardDestExtractPath));
				bStartExtraction = TRUE;
			}
			
			else if (nCurPageNo == INSTALL_OPTIONS_PAGE)
			{
				GetWindowText (GetDlgItem (hCurPage, IDC_DESTINATION), WizardDestInstallPath, sizeof (WizardDestInstallPath));
				bStartInstall = TRUE;
			}

			else if (nCurPageNo == INSTALL_PROGRESS_PAGE)
			{
				PostMessage (hwndDlg, WM_CLOSE, 0, 0);
				return 1;
			}

			else if (nCurPageNo == EXTRACTION_PROGRESS_PAGE)
			{
				PostMessage (hwndDlg, WM_CLOSE, 0, 0);
				return 1;
			}

			LoadPage (hwndDlg, ++nCurPageNo);

			return 1;
		}

		if (lw == IDC_PREV)
		{
			if (nCurPageNo == WIZARD_MODE_PAGE)
			{
				bExtractOnly = IsButtonChecked (GetDlgItem (hCurPage, IDC_WIZARD_MODE_EXTRACT_ONLY));
			}

			else if (nCurPageNo == EXTRACTION_OPTIONS_PAGE)
			{
				GetWindowText (GetDlgItem (hCurPage, IDC_DESTINATION), WizardDestExtractPath, sizeof (WizardDestExtractPath));
				nCurPageNo = WIZARD_MODE_PAGE + 1;
			}

			else if (nCurPageNo == INSTALL_OPTIONS_PAGE)
			{
				GetWindowText (GetDlgItem (hCurPage, IDC_DESTINATION), WizardDestInstallPath, sizeof (WizardDestInstallPath));
			}

			LoadPage (hwndDlg, --nCurPageNo);

			return 1;
		}

		return 0;

	case WM_CTLCOLORSTATIC:

		/* This maintains the white background under the transparent-backround texts */

		SetBkMode ((HDC) wParam, TRANSPARENT);
		return ((LONG) (HBRUSH) (GetStockObject (NULL_BRUSH)));

	case WM_ERASEBKGND:
		return 0;

	case TC_APPMSG_INSTALL_SUCCESS:
		
		/* Installation completed successfully */
		
		bInProgress = FALSE;

		NormalCursor ();

		SetWindowTextW (GetDlgItem (hwndDlg, IDC_NEXT), GetString ("FINALIZE"));
		EnableWindow (GetDlgItem (hwndDlg, IDC_PREV), FALSE);
		EnableWindow (GetDlgItem (hwndDlg, IDC_NEXT), TRUE);
		EnableWindow (GetDlgItem (hwndDlg, IDHELP), FALSE);
		EnableWindow (GetDlgItem (hwndDlg, IDCANCEL), FALSE);

		SetWindowTextW (GetDlgItem (hwndDlg, IDC_BOX_TITLE), GetString ("SETUP_FINISHED_TITLE"));
		SetWindowTextW (GetDlgItem (hwndDlg, IDC_BOX_INFO), GetString ("SETUP_FINISHED_INFO"));

		RefreshUIGFX ();
		return 1;

	case TC_APPMSG_INSTALL_FAILURE:
		
		/* Extraction failed */
		
		bInProgress = FALSE;

		NormalCursor ();

		nCurPageNo = INSTALL_OPTIONS_PAGE;
		LoadPage (hwndDlg, nCurPageNo);
		return 1;

	case TC_APPMSG_EXTRACTION_SUCCESS:
		
		/* Extraction completed successfully */

		InvalidateRect (GetDlgItem (MainDlg, IDD_INSTL_DLG), NULL, TRUE);

		bInProgress = FALSE;
		bExtractionSuccessful = TRUE;

		NormalCursor ();

		StatusMessage (hCurPage, "EXTRACTION_FINISHED_INFO");

		SetWindowTextW (GetDlgItem (hwndDlg, IDC_NEXT), GetString ("FINALIZE"));
		EnableWindow (GetDlgItem (hwndDlg, IDC_PREV), FALSE);
		EnableWindow (GetDlgItem (hwndDlg, IDC_NEXT), TRUE);
		EnableWindow (GetDlgItem (hwndDlg, IDHELP), FALSE);
		EnableWindow (GetDlgItem (hwndDlg, IDCANCEL), FALSE);

		SetWindowTextW (GetDlgItem (hwndDlg, IDC_BOX_TITLE), GetString ("EXTRACTION_FINISHED_TITLE"));
		SetWindowTextW (GetDlgItem (hwndDlg, IDC_BOX_INFO), GetString ("EXTRACTION_FINISHED_INFO"));

		RefreshUIGFX ();
		UpdateProgressBarProc(100);

		Info ("EXTRACTION_FINISHED_INFO");

		return 1;

	case TC_APPMSG_EXTRACTION_FAILURE:
		
		/* Extraction failed */
		
		bInProgress = FALSE;

		NormalCursor ();

		StatusMessage (hCurPage, "EXTRACTION_FAILED");

		UpdateProgressBarProc(0);

		Error ("EXTRACTION_FAILED");

		nCurPageNo = EXTRACTION_OPTIONS_PAGE;
		LoadPage (hwndDlg, nCurPageNo);
		return 1;

	case WM_CLOSE:
		if (bInProgress)
		{
			NormalCursor();
			if (AskNoYes("CONFIRM_EXIT_UNIVERSAL") == IDNO)
			{
				return 1;
			}
			WaitCursor ();
		}

		localcleanup();

		if (bOpenContainingFolder && bExtractOnly && bExtractionSuccessful)
			ShellExecute (NULL, "open", WizardDestExtractPath, NULL, NULL, SW_SHOWNORMAL);

		EndDialog (hwndDlg, IDCANCEL);
		return 1;
	}

	return 0;
}


