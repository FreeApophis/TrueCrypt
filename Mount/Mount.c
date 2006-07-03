/* Legal Notice: The source code contained in this file has been derived from
   the source code of Encryption for the Masses 2.02a, which is Copyright (c)
   1998-99 Paul Le Roux and which is covered by the 'License Agreement for
   Encryption for the Masses'. Modifications and additions to that source code
   contained in this file are Copyright (c) 2004-2006 TrueCrypt Foundation and
   Copyright (c) 2004 TrueCrypt Team, and are covered by TrueCrypt License 2.1
   the full text of which is contained in the file License.txt included in
   TrueCrypt binary and source code distribution archives.  */

#include "Tcdefs.h"
#include <time.h>
#include <math.h>
#include <dbt.h>
#include <windowsx.h>
#include "Apidrvr.h"
#include "Cmdline.h"
#include "Crypto.h"
#include "Dlgcode.h"
#include "Combo.h"
#include "Hotkeys.h"
#include "Keyfiles.h"
#include "Language.h"
#include "Mount.h"
#include "Pkcs5.h"
#include "Registry.h"
#include "Resource.h"
#include "Password.h"
#include "Xml.h"
#include "../Common/Dictionary.h"
#include "../Common/Common.h"
#include "../Common/Resource.h"

BOOL bExplore = FALSE;				/* Display explorer window after mount */
BOOL bBeep = FALSE;					/* Donot beep after mount */
char szFileName[TC_MAX_PATH+1];		/* Volume to mount */
char szDriveLetter[3];				/* Drive Letter to mount */
char commandLineDrive = 0;
BOOL bCacheInDriver = FALSE;		/* Cache any passwords we see */
BOOL bHistoryCmdLine = FALSE;		/* History control is always disabled */
BOOL bCloseDismountedWindows=TRUE;	/* Close all open explorer windows of dismounted volume */
BOOL bWipeCacheOnExit = FALSE;		/* Wipe password from chace on exit */
BOOL bWipeCacheOnAutoDismount = TRUE;
BOOL bStartOnLogon = FALSE;
BOOL bMountDevicesOnLogon = FALSE;
BOOL bMountFavoritesOnLogon = FALSE;
BOOL bEnableBkgTask = FALSE;
BOOL bCloseBkgTaskWhenNoVolumes = FALSE;
BOOL bDismountOnLogOff = TRUE;
BOOL bDismountOnScreenSaver = TRUE;
BOOL bDismountOnPowerSaving = FALSE;
BOOL bForceAutoDismount = TRUE;
BOOL bForceMount = FALSE;			/* Mount volume even if host file/device already in use */
BOOL bForceUnmount = FALSE;			/* Unmount volume even if it cannot be locked */
BOOL bWipe = FALSE;					/* Wipe driver passwords */
BOOL bAuto = FALSE;					/* Do everything without user input */
BOOL bAutoMountDevices = FALSE;		/* Auto-mount devices */
BOOL bAutoMountFavorites = FALSE;
BOOL bPlaySoundOnHotkeyMountDismount = TRUE;
BOOL bDisplayMsgBoxOnHotkeyDismount = FALSE;

BOOL Quit = FALSE;					/* Exit after processing command line */
BOOL UsePreferences = TRUE;

int MaxVolumeIdleTime = -120;
int nCurrentShowType = 0;			/* current display mode, mount, unmount etc */
int nSelectedDriveIndex = -1;		/* Item number of selected drive */

int cmdUnmountDrive = 0;			/* Volume drive letter to unmount (-1 = all) */
Password VolumePassword;			/* Password used for mounting volumes */
Password CmdVolumePassword;			/* Password passed from command line */
BOOL CmdVolumePasswordValid;
MountOptions mountOptions;
MountOptions defaultMountOptions;
KeyFile *FirstCmdKeyFile;

static KeyFilesDlgParam				hidVolProtKeyFilesParam;

static MOUNT_LIST_STRUCT			LastKnownMountList;
static VOLUME_NOTIFICATIONS_LIST	VolumeNotificationsList;	
static DWORD						LastKnownLogicalDrives;

static HANDLE TaskBarIconMutex = NULL;
static BOOL MainWindowHidden = FALSE;
static int pwdChangeDlgMode	= PCDM_CHANGE_PASSWORD;
static int NoCmdLineArgs;
static BOOL CmdLineVolumeSpecified;

void
localcleanup (void)
{
	// Wipe command line
	char *c = GetCommandLineA ();
	wchar_t *wc = GetCommandLineW ();
	burn(c, strlen (c));
	burn(wc, wcslen (wc) * sizeof (wchar_t));

	/* Cleanup common code resources */
	cleanup ();
}

void
RefreshMainDlg (HWND hwndDlg)
{
	int drive = (char) (HIWORD (GetSelectedLong (GetDlgItem (hwndDlg, IDC_DRIVELIST))));

	MoveEditToCombo (GetDlgItem (hwndDlg, IDC_VOLUME), bHistory);
	LoadDriveLetters (GetDlgItem (hwndDlg, IDC_DRIVELIST), drive);
	EnableDisableButtons (hwndDlg);
}

void
EndMainDlg (HWND hwndDlg)
{
	MoveEditToCombo (GetDlgItem (hwndDlg, IDC_VOLUME), bHistory);
	
	if (UsePreferences) 
		SaveSettings (hwndDlg);

	if (bWipeCacheOnExit)
	{
		DWORD dwResult;
		DeviceIoControl (hDriver, WIPE_CACHE, NULL, 0, NULL, 0, &dwResult, NULL);
	}

	if (!bHistory)
	{
		SetWindowText (GetDlgItem (hwndDlg, IDC_VOLUME), "");
		ClearCombo (GetDlgItem (hwndDlg, IDC_VOLUME));
	}

	if (TaskBarIconMutex != NULL)
	{
		MainWindowHidden = TRUE;
		ShowWindow (hwndDlg, SW_HIDE);
	}
	else
	{
		TaskBarIconRemove (hwndDlg);
		EndDialog (hwndDlg, 0);
	}
}

static void InitMainDialog (HWND hwndDlg)
{
	MENUITEMINFOW info;
	char *popupTexts[] = {"MENU_FILE", "MENU_VOLUMES", "MENU_KEYFILES", "MENU_TOOLS", "MENU_SETTINGS", "MENU_HELP", "MENU_WEBSITE", 0};
	wchar_t *str;
	int i;

	/* Call the common dialog init code */
	InitDialog (hwndDlg);
	LocalizeDialog (hwndDlg, NULL);

	DragAcceptFiles (hwndDlg, TRUE);

	SendMessage (GetDlgItem (hwndDlg, IDC_VOLUME), CB_LIMITTEXT, TC_MAX_PATH, 0);
	SetWindowTextW (hwndDlg, lpszTitle);

	// Help file name
	InitHelpFileName();

	// Localize menu strings
	for (i = 40001; str = (wchar_t *)GetDictionaryValueByInt (i); i++)
	{
		info.cbSize = sizeof (info);
		info.fMask = MIIM_TYPE;
		info.fType = MFT_STRING;
		info.dwTypeData = str;
		info.cch = wcslen (str);

		SetMenuItemInfoW (GetMenu (hwndDlg), i, FALSE,  &info); 
	}

	for (i = 0; popupTexts[i] != 0; i++)
	{
		str = GetString (popupTexts[i]);

		info.cbSize = sizeof (info);
		info.fMask = MIIM_TYPE;

		if (memcmp (popupTexts[i], "MENU_WEBSITE", 6) == 0)
			info.fType = MFT_STRING | MFT_RIGHTJUSTIFY;
		else
			info.fType = MFT_STRING;

		info.dwTypeData = str;
		info.cch = wcslen (str);

		SetMenuItemInfoW (GetMenu (hwndDlg), i, TRUE,  &info); 
	}

	BuildTree (GetDlgItem (hwndDlg, IDC_DRIVELIST));

	if (*szDriveLetter != 0)
	{
		SelectItem (GetDlgItem (hwndDlg, IDC_DRIVELIST), *szDriveLetter);

		if(nSelectedDriveIndex > SendMessage (GetDlgItem (hwndDlg, IDC_DRIVELIST), LVM_GETITEMCOUNT, 0, 0)/2) 
			SendMessage(GetDlgItem (hwndDlg, IDC_DRIVELIST), LVM_SCROLL, 0, 1000);
	}

	SendMessage (GetDlgItem (hwndDlg, IDC_NO_HISTORY), BM_SETCHECK, bHistory ? BST_UNCHECKED : BST_CHECKED, 0);
	EnableDisableButtons (hwndDlg);
}

void
EnableDisableButtons (HWND hwndDlg)
{
	HWND hOKButton = GetDlgItem (hwndDlg, IDOK);
	WORD x;

	x = LOWORD (GetSelectedLong (GetDlgItem (hwndDlg, IDC_DRIVELIST)));

	EnableMenuItem (GetMenu (hwndDlg), IDM_MOUNT_VOLUME, MF_ENABLED);
	EnableMenuItem (GetMenu (hwndDlg), IDM_MOUNT_VOLUME_OPTIONS, MF_ENABLED);
	EnableMenuItem (GetMenu (hwndDlg), IDM_BACKUP_VOL_HEADER, MF_ENABLED);
	EnableMenuItem (GetMenu (hwndDlg), IDM_RESTORE_VOL_HEADER, MF_ENABLED);
	EnableMenuItem (GetMenu (hwndDlg), IDM_CHANGE_PASSWORD, MF_ENABLED);
	EnableWindow (hOKButton, TRUE);

	if (x == VFREE)
	{
		SetWindowTextW (hOKButton, GetString ("MOUNT_BUTTON"));

		EnableMenuItem (GetMenu (hwndDlg), IDM_UNMOUNT_VOLUME, MF_GRAYED);
	}

	if (x == VMOUNTED)
	{
		SetWindowTextW (hOKButton, GetString ("UNMOUNT_BUTTON"));
		EnableWindow (hOKButton, TRUE);
		EnableMenuItem (GetMenu (hwndDlg), IDM_UNMOUNT_VOLUME, MF_ENABLED);

		EnableWindow (GetDlgItem (hwndDlg, IDC_VOLUME_PROPERTIES), TRUE);
		EnableMenuItem (GetMenu (hwndDlg), IDM_VOLUME_PROPERTIES, MF_ENABLED);
	}
	else
	{
		SetWindowTextW (hOKButton, GetString ("MOUNT_BUTTON"));
		EnableWindow (GetDlgItem (hwndDlg, IDC_VOLUME_PROPERTIES), FALSE);
		EnableMenuItem (GetMenu (hwndDlg), IDM_VOLUME_PROPERTIES, MF_GRAYED);
	}

	EnableWindow (GetDlgItem (hwndDlg, IDC_WIPE_CACHE), !IsPasswordCacheEmpty());
	EnableMenuItem (GetMenu (hwndDlg), IDM_WIPE_CACHE, IsPasswordCacheEmpty() ? MF_GRAYED:MF_ENABLED);
	EnableMenuItem (GetMenu (hwndDlg), IDM_CLEAR_HISTORY, IsComboEmpty (GetDlgItem (hwndDlg, IDC_VOLUME)) ? MF_GRAYED:MF_ENABLED);
}

BOOL VolumeSelected (HWND hwndDlg)
{
	return (GetWindowTextLength (GetDlgItem (hwndDlg, IDC_VOLUME)) > 0);
}

void
LoadSettings (HWND hwndDlg)
{
	// Options
	bExplore =						ConfigReadInt ("OpenExplorerWindowAfterMount", FALSE);
	bCloseDismountedWindows =		ConfigReadInt ("CloseExplorerWindowsOnDismount", TRUE);

	bHistory =						ConfigReadInt ("SaveVolumeHistory", FALSE);

	bCacheInDriver =				ConfigReadInt ("CachePasswords", FALSE);
	bWipeCacheOnExit =				ConfigReadInt ("WipePasswordCacheOnExit", FALSE);
	bWipeCacheOnAutoDismount =		ConfigReadInt ("WipeCacheOnAutoDismount", TRUE);

	bStartOnLogon =					ConfigReadInt ("StartOnLogon", FALSE);
	bMountDevicesOnLogon =			ConfigReadInt ("MountDevicesOnLogon", FALSE);
	bMountFavoritesOnLogon =		ConfigReadInt ("MountFavoritesOnLogon", FALSE);

	bEnableBkgTask =				ConfigReadInt ("EnableBackgroundTask", TRUE);
	bCloseBkgTaskWhenNoVolumes =	ConfigReadInt ("CloseBackgroundTaskOnNoVolumes", FALSE);

	bDismountOnLogOff =				ConfigReadInt ("DismountOnLogOff", TRUE);
	bDismountOnPowerSaving =		ConfigReadInt ("DismountOnPowerSaving", FALSE);
	bDismountOnScreenSaver =		ConfigReadInt ("DismountOnScreenSaver", FALSE);
	bForceAutoDismount =			ConfigReadInt ("ForceAutoDismount", TRUE);
	MaxVolumeIdleTime =				ConfigReadInt ("MaxVolumeIdleTime", -120);

	defaultKeyFilesParam.EnableKeyFiles = ConfigReadInt ("UseKeyfiles", FALSE);

	bPreserveTimestamp = defaultMountOptions.PreserveTimestamp = ConfigReadInt ("PreserveTimestamps", TRUE);
	defaultMountOptions.Removable =	ConfigReadInt ("MountVolumesRemovable", FALSE);
	defaultMountOptions.ReadOnly =	ConfigReadInt ("MountVolumesReadOnly", FALSE);
	defaultMountOptions.ProtectHiddenVolume = FALSE;

	mountOptions = defaultMountOptions;

	// Drive letter - command line arg overrides registry
	if (szDriveLetter[0] == 0)
		ConfigReadString ("LastSelectedDrive", "", szDriveLetter, sizeof (szDriveLetter));

	// Hotkeys
	bPlaySoundOnHotkeyMountDismount									= ConfigReadInt ("PlaySoundOnHotkeyMountDismount", TRUE);
	bDisplayMsgBoxOnHotkeyDismount									= ConfigReadInt ("DisplayMsgBoxOnHotkeyDismount", FALSE);
	Hotkeys [HK_AUTOMOUNT_DEVICES].vKeyModifiers					= ConfigReadInt ("HotkeyModAutoMountDevices", 0);
	Hotkeys [HK_AUTOMOUNT_DEVICES].vKeyCode							= ConfigReadInt ("HotkeyCodeAutoMountDevices", 0);
	Hotkeys [HK_DISMOUNT_ALL].vKeyModifiers							= ConfigReadInt ("HotkeyModDismountAll", 0);
	Hotkeys [HK_DISMOUNT_ALL].vKeyCode								= ConfigReadInt ("HotkeyCodeDismountAll", 0);
	Hotkeys [HK_FORCE_DISMOUNT_ALL_AND_WIPE].vKeyModifiers			= ConfigReadInt ("HotkeyModForceDismountAllWipe", 0);
	Hotkeys [HK_FORCE_DISMOUNT_ALL_AND_WIPE].vKeyCode				= ConfigReadInt ("HotkeyCodeForceDismountAllWipe", 0);
	Hotkeys [HK_FORCE_DISMOUNT_ALL_AND_WIPE_AND_EXIT].vKeyModifiers	= ConfigReadInt ("HotkeyModForceDismountAllWipeExit", 0);
	Hotkeys [HK_FORCE_DISMOUNT_ALL_AND_WIPE_AND_EXIT].vKeyCode		= ConfigReadInt ("HotkeyCodeForceDismountAllWipeExit", 0);
	Hotkeys [HK_MOUNT_FAVORITE_VOLUMES].vKeyModifiers				= ConfigReadInt ("HotkeyModMountFavoriteVolumes", 0);
	Hotkeys [HK_MOUNT_FAVORITE_VOLUMES].vKeyCode					= ConfigReadInt ("HotkeyCodeMountFavoriteVolumes", 0);
	Hotkeys [HK_SHOW_HIDE_MAIN_WINDOW].vKeyModifiers				= ConfigReadInt ("HotkeyModShowHideMainWindow", 0);
	Hotkeys [HK_SHOW_HIDE_MAIN_WINDOW].vKeyCode						= ConfigReadInt ("HotkeyCodeShowHideMainWindow", 0);
	RegisterAllHotkeys (hwndDlg, Hotkeys);

	// History
	if (bHistoryCmdLine != TRUE)
	{
		LoadCombo (GetDlgItem (hwndDlg, IDC_VOLUME));
		if (CmdLineVolumeSpecified)
			SetWindowText (GetDlgItem (hwndDlg, IDC_VOLUME), szFileName);
	}
}

void
SaveSettings (HWND hwndDlg)
{
	char szTmp[32] = {0};
	LPARAM lLetter;

	// Options
	ConfigWriteBegin ();

	ConfigWriteInt ("OpenExplorerWindowAfterMount",		bExplore);
	ConfigWriteInt ("CloseExplorerWindowsOnDismount",	bCloseDismountedWindows);
	ConfigWriteInt ("SaveVolumeHistory",				!IsButtonChecked (GetDlgItem (hwndDlg, IDC_NO_HISTORY)));

	ConfigWriteInt ("CachePasswords",					bCacheInDriver);
	ConfigWriteInt ("WipePasswordCacheOnExit",			bWipeCacheOnExit);
	ConfigWriteInt ("WipeCacheOnAutoDismount",			bWipeCacheOnAutoDismount);

	ConfigWriteInt ("StartOnLogon",						bStartOnLogon);
	ConfigWriteInt ("MountDevicesOnLogon",				bMountDevicesOnLogon);
	ConfigWriteInt ("MountFavoritesOnLogon",			bMountFavoritesOnLogon);

	ConfigWriteInt ("MountVolumesReadOnly",				defaultMountOptions.ReadOnly);
	ConfigWriteInt ("MountVolumesRemovable",			defaultMountOptions.Removable);
	ConfigWriteInt ("PreserveTimestamps",				defaultMountOptions.PreserveTimestamp);

	ConfigWriteInt ("EnableBackgroundTask",				bEnableBkgTask);
	ConfigWriteInt ("CloseBackgroundTaskOnNoVolumes",	bCloseBkgTaskWhenNoVolumes);

	ConfigWriteInt ("DismountOnLogOff",					bDismountOnLogOff);
	ConfigWriteInt ("DismountOnPowerSaving",			bDismountOnPowerSaving);
	ConfigWriteInt ("DismountOnScreenSaver",			bDismountOnScreenSaver);
	ConfigWriteInt ("ForceAutoDismount",				bForceAutoDismount);
	ConfigWriteInt ("MaxVolumeIdleTime",				MaxVolumeIdleTime);

	ConfigWriteInt ("UseKeyfiles",						defaultKeyFilesParam.EnableKeyFiles);

	// Drive Letter
	lLetter = GetSelectedLong (GetDlgItem (hwndDlg, IDC_DRIVELIST));
	if (LOWORD (lLetter) != 0xffff)
		sprintf (szTmp, "%c:", (char) HIWORD (lLetter));
	ConfigWriteString ("LastSelectedDrive", szTmp);

	// Hotkeys
	ConfigWriteInt ("HotkeyModAutoMountDevices",				Hotkeys[HK_AUTOMOUNT_DEVICES].vKeyModifiers);
	ConfigWriteInt ("HotkeyCodeAutoMountDevices",				Hotkeys[HK_AUTOMOUNT_DEVICES].vKeyCode);
	ConfigWriteInt ("HotkeyModDismountAll",						Hotkeys[HK_DISMOUNT_ALL].vKeyModifiers);
	ConfigWriteInt ("HotkeyCodeDismountAll",					Hotkeys[HK_DISMOUNT_ALL].vKeyCode);
	ConfigWriteInt ("HotkeyModForceDismountAllWipe",			Hotkeys[HK_FORCE_DISMOUNT_ALL_AND_WIPE].vKeyModifiers);
	ConfigWriteInt ("HotkeyCodeForceDismountAllWipe",			Hotkeys[HK_FORCE_DISMOUNT_ALL_AND_WIPE].vKeyCode);
	ConfigWriteInt ("HotkeyModForceDismountAllWipeExit",		Hotkeys[HK_FORCE_DISMOUNT_ALL_AND_WIPE_AND_EXIT].vKeyModifiers);
	ConfigWriteInt ("HotkeyCodeForceDismountAllWipeExit",		Hotkeys[HK_FORCE_DISMOUNT_ALL_AND_WIPE_AND_EXIT].vKeyCode);
	ConfigWriteInt ("HotkeyModMountFavoriteVolumes",			Hotkeys[HK_MOUNT_FAVORITE_VOLUMES].vKeyModifiers);
	ConfigWriteInt ("HotkeyCodeMountFavoriteVolumes",			Hotkeys[HK_MOUNT_FAVORITE_VOLUMES].vKeyCode);
	ConfigWriteInt ("HotkeyModShowHideMainWindow",				Hotkeys[HK_SHOW_HIDE_MAIN_WINDOW].vKeyModifiers);
	ConfigWriteInt ("HotkeyCodeShowHideMainWindow",				Hotkeys[HK_SHOW_HIDE_MAIN_WINDOW].vKeyCode);
	ConfigWriteInt ("PlaySoundOnHotkeyMountDismount",			bPlaySoundOnHotkeyMountDismount);
	ConfigWriteInt ("DisplayMsgBoxOnHotkeyDismount",			bDisplayMsgBoxOnHotkeyDismount);

	// Language
	if (GetPreferredLangId () != NULL)
		ConfigWriteString ("Language", GetPreferredLangId ());

	ConfigWriteEnd ();

	// History
	DumpCombo (GetDlgItem (hwndDlg, IDC_VOLUME), IsButtonChecked (GetDlgItem (hwndDlg, IDC_NO_HISTORY)));
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

	ZeroMemory (&driver, sizeof (driver));
	bResult = DeviceIoControl (hDriver, MOUNT_LIST, &driver,
		sizeof (driver), &driver, sizeof (driver), &dwResult,
		NULL);
	memcpy (&LastKnownMountList, &driver, sizeof (driver));

	if (bResult == FALSE)
	{
		handleWin32Error (hTree);
		driver.ulMountedDrives = 0;
	}

	LastKnownLogicalDrives = dwUsedDrives = GetLogicalDrives ();
	if (dwUsedDrives == 0)
			Warning ("DRIVELETTERS");

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
			if (ListView_GetItem (hTree, &tmp))
				curDrive = HIWORD(tmp.lParam);
		}

		if ( driver.ulMountedDrives & (1 << i) )
		{
			char szTmp[1024];
			wchar_t szTmpW[1024];
			wchar_t *ws;

			memset(&listItem, 0, sizeof(listItem));

			listItem.mask = LVIF_TEXT | LVIF_IMAGE | LVIF_PARAM;
			listItem.iImage = 1;
			listItem.iItem = item++;  

			if(drive > 0 && drive != curDrive)
				continue;

			ToSBCS ((void *) driver.wszVolume[i]);

			if (memcmp (driver.wszVolume[i], "\\Device", 7) == 0)
				sprintf (szTmp, "%s", ((char *) driver.wszVolume[i]));
			else
				sprintf (szTmp, "%s", ((char *) driver.wszVolume[i]) + 4);

			listItem.pszText = szDriveLetters[i];
			listItem.lParam = MAKELONG (VMOUNTED, i + 'A');
			
			if(drive == 0) 
				ListView_InsertItem (hTree, &listItem);
			else
				ListView_SetItem (hTree, &listItem);

			listItem.mask=LVIF_TEXT;   
			listItem.pszText = szTmp;

			listItem.iSubItem = 1;
			ListView_SetItem (hTree, &listItem);

			GetSizeString (driver.diskLength[i], szTmpW);
			ListSubItemSetW (hTree, listItem.iItem, 2, szTmpW);

			EAGetName (szTmp, driver.ea[i]);
			listItem.iSubItem = 3;
			ListView_SetItem (hTree, &listItem);

			switch (driver.volumeType[i])
			{
			case PROP_VOL_TYPE_NORMAL:
				ws = GetString ("NORMAL");
				break;
			case PROP_VOL_TYPE_HIDDEN:
				ws = GetString ("HIDDEN");
				break;
			case PROP_VOL_TYPE_OUTER:
				ws = GetString ("OUTER");		// Normal/outer volume (hidden volume protected)
				break;
			case PROP_VOL_TYPE_OUTER_VOL_WRITE_PREVENTED:
				ws = GetString ("OUTER_VOL_WRITE_PREVENTED");	// Normal/outer volume (hidden volume protected AND write denied)
				break;
			default:
				ws = L"?";
			}
			ListSubItemSetW (hTree, listItem.iItem, 4, ws);

			if (driver.volumeType[i] == PROP_VOL_TYPE_OUTER_VOL_WRITE_PREVENTED)	// Normal/outer volume (hidden volume protected AND write denied)
			{				
				if (!VolumeNotificationsList.bHidVolDamagePrevReported[i])
				{
					wchar_t szTmp[1024];

					VolumeNotificationsList.bHidVolDamagePrevReported[i] = TRUE;
					wsprintfW (szTmp, GetString ("DAMAGE_TO_HIDDEN_VOLUME_PREVENTED"), i+'A');
					SetForegroundWindow (GetParent(hTree));
					MessageBoxW (GetParent(hTree), szTmp, lpszTitle, MB_ICONWARNING);
				}
			}
			else
			{
				VolumeNotificationsList.bHidVolDamagePrevReported[i] = FALSE;
			}
		}
		else
		{
			VolumeNotificationsList.bHidVolDamagePrevReported[i] = FALSE;

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
				ListView_SetItem (hTree, &listItem);
				listItem.iSubItem = 2;
				ListView_SetItem (hTree, &listItem);
				listItem.iSubItem = 3;
				ListView_SetItem (hTree, &listItem);
				listItem.iSubItem = 4;
				ListView_SetItem (hTree, &listItem);

			}
		}
	}
}


static void PasswordChangeEnable (HWND hwndDlg, int button, int passwordId, BOOL keyFilesEnabled,
								  int newPasswordId, int newVerifyId, BOOL newKeyFilesEnabled)
{
	char password[MAX_PASSWORD + 1];
	char newPassword[MAX_PASSWORD + 1];
	char newVerify[MAX_PASSWORD + 1];
	BOOL bEnable = TRUE;

	GetWindowText (GetDlgItem (hwndDlg, passwordId), password, sizeof (password));

	if (pwdChangeDlgMode == PCDM_CHANGE_PKCS5_PRF)
		newKeyFilesEnabled = keyFilesEnabled;

	switch (pwdChangeDlgMode)
	{
	case PCDM_REMOVE_ALL_KEYFILES_FROM_VOL:
	case PCDM_ADD_REMOVE_VOL_KEYFILES:
	case PCDM_CHANGE_PKCS5_PRF:
		memcpy (newPassword, password, sizeof (newPassword));
		memcpy (newVerify, password, sizeof (newVerify));
		break;

	default:
		GetWindowText (GetDlgItem (hwndDlg, newPasswordId), newPassword, sizeof (newPassword));
		GetWindowText (GetDlgItem (hwndDlg, newVerifyId), newVerify, sizeof (newVerify));
	}

	if (!keyFilesEnabled && strlen (password) < MIN_PASSWORD)
		bEnable = FALSE;
	else if (strcmp (newPassword, newVerify) != 0)
		bEnable = FALSE;
	else if (!newKeyFilesEnabled && strlen (newPassword) < MIN_PASSWORD)
		bEnable = FALSE;

	burn (password, sizeof (password));
	burn (newPassword, sizeof (newPassword));
	burn (newVerify, sizeof (newVerify));

	EnableWindow (GetDlgItem (hwndDlg, button), bEnable);
}


/* Except in response to the WM_INITDIALOG message, the dialog box procedure
   should return nonzero if it processes the message, and zero if it does
   not. - see DialogProc */
BOOL WINAPI
PasswordChangeDlgProc (HWND hwndDlg, UINT msg, WPARAM wParam, LPARAM lParam)
{
	static KeyFilesDlgParam newKeyFilesParam;

	WORD lw = LOWORD (wParam);
	WORD hw = HIWORD (wParam);

	if (lParam);		/* remove warning */
	if (hw);			/* remove warning */

	switch (msg)
	{
	case WM_INITDIALOG:
		{
			LPARAM nIndex;
			HWND hComboBox = GetDlgItem (hwndDlg, IDC_PKCS5_PRF_ID);
			int i;

			ZeroMemory (&newKeyFilesParam, sizeof (newKeyFilesParam));

			SetWindowTextW (hwndDlg, GetString ("IDD_PASSWORDCHANGE_DLG"));
			LocalizeDialog (hwndDlg, "IDD_PASSWORDCHANGE_DLG");

			SendMessage (GetDlgItem (hwndDlg, IDC_OLD_PASSWORD), EM_LIMITTEXT, MAX_PASSWORD, 0);
			SendMessage (GetDlgItem (hwndDlg, IDC_PASSWORD), EM_LIMITTEXT, MAX_PASSWORD, 0);
			SendMessage (GetDlgItem (hwndDlg, IDC_VERIFY), EM_LIMITTEXT, MAX_PASSWORD, 0);
			EnableWindow (GetDlgItem (hwndDlg, IDOK), FALSE);

			SetCheckBox (hwndDlg, IDC_ENABLE_KEYFILES, KeyFilesEnable);
			EnableWindow (GetDlgItem (hwndDlg, IDC_KEYFILES), KeyFilesEnable);
			EnableWindow (GetDlgItem (hwndDlg, IDC_NEW_KEYFILES), FALSE);

			SendMessage (hComboBox, CB_RESETCONTENT, 0, 0);

			nIndex = SendMessageW (hComboBox, CB_ADDSTRING, 0, (LPARAM) GetString ("UNCHANGED"));
			SendMessage (hComboBox, CB_SETITEMDATA, nIndex, (LPARAM) 0);

			for (i = 1; i <= LAST_PRF_ID; i++)
			{
				nIndex = SendMessage (hComboBox, CB_ADDSTRING, 0, (LPARAM) get_pkcs5_prf_name(i));
				SendMessage (hComboBox, CB_SETITEMDATA, nIndex, (LPARAM) i);
			}

			SendMessage (hComboBox, CB_SETCURSEL, 0, 0);

			switch (pwdChangeDlgMode)
			{
			case PCDM_CHANGE_PKCS5_PRF:
				SetWindowTextW (hwndDlg, GetString ("IDD_PCDM_CHANGE_PKCS5_PRF"));
				LocalizeDialog (hwndDlg, "IDD_PCDM_CHANGE_PKCS5_PRF");
				EnableWindow (GetDlgItem (hwndDlg, IDC_PASSWORD), FALSE);
				EnableWindow (GetDlgItem (hwndDlg, IDC_VERIFY), FALSE);
				EnableWindow (GetDlgItem (hwndDlg, IDC_ENABLE_NEW_KEYFILES), FALSE);
				EnableWindow (GetDlgItem (hwndDlg, IDC_SHOW_PASSWORD_CHPWD_NEW), FALSE);
				EnableWindow (GetDlgItem (hwndDlg, IDC_NEW_KEYFILES), FALSE);
				EnableWindow (GetDlgItem (hwndDlg, IDT_NEW_PASSWORD), FALSE);
				EnableWindow (GetDlgItem (hwndDlg, IDT_CONFIRM_PASSWORD), FALSE);
				break;

			case PCDM_ADD_REMOVE_VOL_KEYFILES:
				SetWindowTextW (hwndDlg, GetString ("IDD_PCDM_ADD_REMOVE_VOL_KEYFILES"));
				LocalizeDialog (hwndDlg, "IDD_PCDM_ADD_REMOVE_VOL_KEYFILES");
				newKeyFilesParam.EnableKeyFiles = TRUE;
				EnableWindow (GetDlgItem (hwndDlg, IDC_PASSWORD), FALSE);
				EnableWindow (GetDlgItem (hwndDlg, IDC_VERIFY), FALSE);
				EnableWindow (GetDlgItem (hwndDlg, IDC_SHOW_PASSWORD_CHPWD_NEW), FALSE);
				EnableWindow (GetDlgItem (hwndDlg, IDT_NEW_PASSWORD), FALSE);
				EnableWindow (GetDlgItem (hwndDlg, IDT_CONFIRM_PASSWORD), FALSE);
				break;

			case PCDM_REMOVE_ALL_KEYFILES_FROM_VOL:
				newKeyFilesParam.EnableKeyFiles = FALSE;
				SetWindowTextW (hwndDlg, GetString ("IDD_PCDM_REMOVE_ALL_KEYFILES_FROM_VOL"));
				LocalizeDialog (hwndDlg, "IDD_PCDM_REMOVE_ALL_KEYFILES_FROM_VOL");
				KeyFilesEnable = TRUE;
				SetCheckBox (hwndDlg, IDC_ENABLE_KEYFILES, TRUE);
				EnableWindow (GetDlgItem (hwndDlg, IDC_KEYFILES), TRUE);
				EnableWindow (GetDlgItem (hwndDlg, IDC_ENABLE_KEYFILES), TRUE);
				EnableWindow (GetDlgItem (hwndDlg, IDC_PASSWORD), FALSE);
				EnableWindow (GetDlgItem (hwndDlg, IDC_VERIFY), FALSE);
				EnableWindow (GetDlgItem (hwndDlg, IDC_ENABLE_NEW_KEYFILES), FALSE);
				EnableWindow (GetDlgItem (hwndDlg, IDC_SHOW_PASSWORD_CHPWD_NEW), FALSE);
				EnableWindow (GetDlgItem (hwndDlg, IDC_NEW_KEYFILES), FALSE);
				EnableWindow (GetDlgItem (hwndDlg, IDT_NEW_PASSWORD), FALSE);
				EnableWindow (GetDlgItem (hwndDlg, IDT_CONFIRM_PASSWORD), FALSE);
				EnableWindow (GetDlgItem (hwndDlg, IDT_PKCS5_PRF), FALSE);
				EnableWindow (GetDlgItem (hwndDlg, IDC_PKCS5_PRF_ID), FALSE);
				break;

			case PCDM_CHANGE_PASSWORD:
			default:
				// NOP
				break;
			};

			CheckCapsLock (hwndDlg, FALSE);

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
			RestoreDefaultKeyFilesParam ();

			EndDialog (hwndDlg, IDCANCEL);
			return 1;
		}

		if (hw == EN_CHANGE)
		{
			PasswordChangeEnable (hwndDlg, IDOK,
				IDC_OLD_PASSWORD,
				KeyFilesEnable && FirstKeyFile != NULL,
				IDC_PASSWORD, IDC_VERIFY, 
				newKeyFilesParam.EnableKeyFiles && newKeyFilesParam.FirstKeyFile != NULL);		

			return 1;
		}

		if (lw == IDC_KEYFILES)
		{
			KeyFilesDlgParam param;
			param.EnableKeyFiles = KeyFilesEnable;
			param.FirstKeyFile = FirstKeyFile;

			if (IDOK == DialogBoxParamW (hInst,
				MAKEINTRESOURCEW (IDD_KEYFILES), hwndDlg,
				(DLGPROC) KeyFilesDlgProc, (LPARAM) &param))
			{
				KeyFilesEnable = param.EnableKeyFiles;
				FirstKeyFile = param.FirstKeyFile;
			
				SetCheckBox (hwndDlg, IDC_ENABLE_KEYFILES, KeyFilesEnable);
				EnableWindow (GetDlgItem (hwndDlg, IDC_KEYFILES), KeyFilesEnable);
			}

			PasswordChangeEnable (hwndDlg, IDOK,
				IDC_OLD_PASSWORD,
				KeyFilesEnable && FirstKeyFile != NULL,
				IDC_PASSWORD, IDC_VERIFY, 
				newKeyFilesParam.EnableKeyFiles && newKeyFilesParam.FirstKeyFile != NULL);		

			return 1;
		}

		
		if (lw == IDC_NEW_KEYFILES)
		{
			if (IDOK == DialogBoxParamW (hInst,
				MAKEINTRESOURCEW (IDD_KEYFILES), hwndDlg,
				(DLGPROC) KeyFilesDlgProc, (LPARAM) &newKeyFilesParam))
			{
				SetCheckBox (hwndDlg, IDC_ENABLE_NEW_KEYFILES, newKeyFilesParam.EnableKeyFiles);
				EnableWindow (GetDlgItem (hwndDlg, IDC_NEW_KEYFILES), newKeyFilesParam.EnableKeyFiles);

				VerifyPasswordAndUpdate (hwndDlg, GetDlgItem (hwndDlg, IDOK), GetDlgItem (hwndDlg, IDC_PASSWORD),
					GetDlgItem (hwndDlg, IDC_VERIFY), NULL, NULL,
					newKeyFilesParam.EnableKeyFiles && newKeyFilesParam.FirstKeyFile != NULL);		
			}

			PasswordChangeEnable (hwndDlg, IDOK,
				IDC_OLD_PASSWORD,
				KeyFilesEnable && FirstKeyFile != NULL,
				IDC_PASSWORD, IDC_VERIFY, 
				newKeyFilesParam.EnableKeyFiles && newKeyFilesParam.FirstKeyFile != NULL);		

			return 1;
		}

		if (lw == IDC_ENABLE_KEYFILES)
		{
			KeyFilesEnable = GetCheckBox (hwndDlg, IDC_ENABLE_KEYFILES);
			EnableWindow (GetDlgItem (hwndDlg, IDC_KEYFILES), KeyFilesEnable);

			PasswordChangeEnable (hwndDlg, IDOK,
				IDC_OLD_PASSWORD,
				KeyFilesEnable && FirstKeyFile != NULL,
				IDC_PASSWORD, IDC_VERIFY, 
				newKeyFilesParam.EnableKeyFiles && newKeyFilesParam.FirstKeyFile != NULL);		

			return 1;
		}

		if (lw == IDC_ENABLE_NEW_KEYFILES)
		{
			newKeyFilesParam.EnableKeyFiles = GetCheckBox (hwndDlg, IDC_ENABLE_NEW_KEYFILES);
			EnableWindow (GetDlgItem (hwndDlg, IDC_NEW_KEYFILES), newKeyFilesParam.EnableKeyFiles);

			PasswordChangeEnable (hwndDlg, IDOK,
				IDC_OLD_PASSWORD,
				KeyFilesEnable && FirstKeyFile != NULL,
				IDC_PASSWORD, IDC_VERIFY, 
				newKeyFilesParam.EnableKeyFiles && newKeyFilesParam.FirstKeyFile != NULL);		

			return 1;
		}

		if (lw == IDC_SHOW_PASSWORD_CHPWD_ORI)
		{
			SendMessage (GetDlgItem (hwndDlg, IDC_OLD_PASSWORD),
						EM_SETPASSWORDCHAR,
						GetCheckBox (hwndDlg, IDC_SHOW_PASSWORD_CHPWD_ORI) ? 0 : '*',
						0);
			InvalidateRect (GetDlgItem (hwndDlg, IDC_OLD_PASSWORD), NULL, TRUE);
			return 1;
		}

		if (lw == IDC_SHOW_PASSWORD_CHPWD_NEW)
		{
			SendMessage (GetDlgItem (hwndDlg, IDC_PASSWORD),
						EM_SETPASSWORDCHAR,
						GetCheckBox (hwndDlg, IDC_SHOW_PASSWORD_CHPWD_NEW) ? 0 : '*',
						0);
			SendMessage (GetDlgItem (hwndDlg, IDC_VERIFY),
						EM_SETPASSWORDCHAR,
						GetCheckBox (hwndDlg, IDC_SHOW_PASSWORD_CHPWD_NEW) ? 0 : '*',
						0);
			InvalidateRect (GetDlgItem (hwndDlg, IDC_PASSWORD), NULL, TRUE);
			InvalidateRect (GetDlgItem (hwndDlg, IDC_VERIFY), NULL, TRUE);
			return 1;
		}

		if (lw == IDOK)
		{
			HWND hParent = GetParent (hwndDlg);
			Password oldPassword;
			Password newPassword;
			int nStatus;
			int pkcs5 = SendMessage (GetDlgItem (hwndDlg, IDC_PKCS5_PRF_ID), CB_GETITEMDATA, 
					SendMessage (GetDlgItem (hwndDlg, IDC_PKCS5_PRF_ID), CB_GETCURSEL, 0, 0), 0);

			if (!CheckPasswordCharEncoding (GetDlgItem (hwndDlg, IDC_PASSWORD), NULL))
			{
				Error ("UNSUPPORTED_CHARS_IN_PWD");
				return 1;
			}

			if (pwdChangeDlgMode == PCDM_CHANGE_PKCS5_PRF)
			{
				newKeyFilesParam.EnableKeyFiles = KeyFilesEnable;
			}
			else if (!(newKeyFilesParam.EnableKeyFiles && newKeyFilesParam.FirstKeyFile != NULL)
				&& pwdChangeDlgMode == PCDM_CHANGE_PASSWORD)
			{
				if (!CheckPasswordLength (hwndDlg, GetDlgItem (hwndDlg, IDC_PASSWORD)))
					return 1;
			}

			GetWindowText (GetDlgItem (hParent, IDC_VOLUME), szFileName, sizeof (szFileName));

			GetWindowText (GetDlgItem (hwndDlg, IDC_OLD_PASSWORD), oldPassword.Text, sizeof (oldPassword.Text));
			oldPassword.Length = strlen (oldPassword.Text);

			switch (pwdChangeDlgMode)
			{
			case PCDM_REMOVE_ALL_KEYFILES_FROM_VOL:
			case PCDM_ADD_REMOVE_VOL_KEYFILES:
			case PCDM_CHANGE_PKCS5_PRF:
				memcpy (newPassword.Text, oldPassword.Text, sizeof (newPassword.Text));
				newPassword.Length = strlen (oldPassword.Text);
				break;

			default:
				GetWindowText (GetDlgItem (hwndDlg, IDC_PASSWORD), newPassword.Text, sizeof (newPassword.Text));
				newPassword.Length = strlen (newPassword.Text);
			}

			if (KeyFilesEnable)
				KeyFilesApply (&oldPassword, FirstKeyFile, bPreserveTimestamp);

			if (newKeyFilesParam.EnableKeyFiles)
				KeyFilesApply (&newPassword,
				pwdChangeDlgMode==PCDM_CHANGE_PKCS5_PRF ? FirstKeyFile : newKeyFilesParam.FirstKeyFile,
				bPreserveTimestamp);

			nStatus = ChangePwd (szFileName, &oldPassword, &newPassword, pkcs5, hwndDlg);

			burn (&oldPassword, sizeof (oldPassword));
			burn (&newPassword, sizeof (newPassword));

			if (nStatus != 0)
			{
				if (nStatus != -1)
					handleError (hwndDlg, nStatus);
			}
			else
			{
				// Attempt to wipe passwords stored in the input field buffers
				char tmp[MAX_PASSWORD+1];
				memset (tmp, 'X', MAX_PASSWORD);
				tmp[MAX_PASSWORD] = 0;
				SetWindowText (GetDlgItem (hwndDlg, IDC_PASSWORD), tmp);	
				SetWindowText (GetDlgItem (hwndDlg, IDC_OLD_PASSWORD), tmp);	
				SetWindowText (GetDlgItem (hwndDlg, IDC_VERIFY), tmp);	

				KeyFileRemoveAll (&newKeyFilesParam.FirstKeyFile);
				RestoreDefaultKeyFilesParam ();

				EndDialog (hwndDlg, IDOK);
			}
			return 1;
		}
		return 0;
	}

	return 0;
}

static char PasswordDlgVolume[MAX_PATH];

/* Except in response to the WM_INITDIALOG message, the dialog box procedure
   should return nonzero if it processes the message, and zero if it does
   not. - see DialogProc */
BOOL WINAPI
PasswordDlgProc (HWND hwndDlg, UINT msg, WPARAM wParam, LPARAM lParam)
{
	WORD lw = LOWORD (wParam);
	static Password *szXPwd;	

	switch (msg)
	{
	case WM_INITDIALOG:
		{
			szXPwd = (Password *) lParam;
			LocalizeDialog (hwndDlg, "IDD_PASSWORD_DLG");
			DragAcceptFiles (hwndDlg, TRUE);

			if (strlen (PasswordDlgVolume) > 0)
			{
				wchar_t s[1024];
				wsprintfW (s, GetString ("ENTER_PASSWORD_FOR"), PasswordDlgVolume);
				SetWindowTextW (hwndDlg, s);
			}

			SendMessage (GetDlgItem (hwndDlg, IDC_PASSWORD), EM_LIMITTEXT, MAX_PASSWORD, 0);
			SendMessage (GetDlgItem (hwndDlg, IDC_CACHE), BM_SETCHECK, bCacheInDriver ? BST_CHECKED:BST_UNCHECKED, 0);

			SetCheckBox (hwndDlg, IDC_KEYFILES_ENABLE, KeyFilesEnable);
			EnableWindow (GetDlgItem (hwndDlg, IDC_KEY_FILES), KeyFilesEnable);

			SetForegroundWindow (hwndDlg);
			return 1;
		}

	case WM_COMMAND:

		if (lw == IDC_MOUNT_OPTIONS)
		{
			DialogBoxParamW (hInst, 
				MAKEINTRESOURCEW (IDD_MOUNT_OPTIONS), hwndDlg,
				(DLGPROC) MountOptionsDlgProc, (LPARAM) &mountOptions);
			return 1;
		}

		if (lw == IDC_SHOW_PASSWORD)
		{
			SendMessage (GetDlgItem (hwndDlg, IDC_PASSWORD),
						EM_SETPASSWORDCHAR,
						GetCheckBox (hwndDlg, IDC_SHOW_PASSWORD) ? 0 : '*',
						0);
			InvalidateRect (GetDlgItem (hwndDlg, IDC_PASSWORD), NULL, TRUE);
			return 1;
		}

		if (lw == IDC_KEY_FILES)
		{
			KeyFilesDlgParam param;
			param.EnableKeyFiles = KeyFilesEnable;
			param.FirstKeyFile = FirstKeyFile;

			if (IDOK == DialogBoxParamW (hInst,
				MAKEINTRESOURCEW (IDD_KEYFILES), hwndDlg,
				(DLGPROC) KeyFilesDlgProc, (LPARAM) &param))
			{
				KeyFilesEnable = param.EnableKeyFiles;
				FirstKeyFile = param.FirstKeyFile;

				SetCheckBox (hwndDlg, IDC_KEYFILES_ENABLE, KeyFilesEnable);
				EnableWindow (GetDlgItem (hwndDlg, IDC_KEY_FILES), KeyFilesEnable);
			}

			return 1;
		}

		if (lw == IDC_KEYFILES_ENABLE)
		{
			KeyFilesEnable = GetCheckBox (hwndDlg, IDC_KEYFILES_ENABLE);
			EnableWindow (GetDlgItem (hwndDlg, IDC_KEY_FILES), KeyFilesEnable);

			return 1;
		}

		if (lw == IDCANCEL || lw == IDOK)
		{
			char tmp[MAX_PASSWORD+1];
			
			if (lw == IDOK)
			{
				if (mountOptions.ProtectHiddenVolume && hidVolProtKeyFilesParam.EnableKeyFiles)
					KeyFilesApply (&mountOptions.ProtectedHidVolPassword, hidVolProtKeyFilesParam.FirstKeyFile,
					bPreserveTimestamp);

				GetWindowText (GetDlgItem (hwndDlg, IDC_PASSWORD), szXPwd->Text, MAX_PASSWORD + 1);
				szXPwd->Length = strlen (szXPwd->Text);

				bCacheInDriver = IsButtonChecked (GetDlgItem (hwndDlg, IDC_CACHE));	 
			}

			// Attempt to wipe password stored in the input field buffer
			memset (tmp, 'X', MAX_PASSWORD);
			tmp[MAX_PASSWORD] = 0;
			SetWindowText (GetDlgItem (hwndDlg, IDC_PASSWORD), tmp);	
			SetWindowText (GetDlgItem (hwndDlg, IDC_PASSWORD_PROT_HIDVOL), tmp);	

			if (hidVolProtKeyFilesParam.FirstKeyFile != NULL)
			{
				KeyFileRemoveAll (&hidVolProtKeyFilesParam.FirstKeyFile);
				hidVolProtKeyFilesParam.EnableKeyFiles = FALSE;
			}

			EndDialog (hwndDlg, lw);
			return 1;
		}
		return 0;

	case WM_DROPFILES:
		{
			HDROP hdrop = (HDROP) wParam;
			int i = 0, count = DragQueryFile (hdrop, -1, NULL, 0);

			while (count-- > 0)
			{
				KeyFile *kf = malloc (sizeof (KeyFile));
				DragQueryFile (hdrop, i++, kf->FileName, sizeof (kf->FileName));
				FirstKeyFile = KeyFileAdd (FirstKeyFile, kf);
				KeyFilesEnable = TRUE;
			}

			SetCheckBox (hwndDlg, IDC_KEYFILES_ENABLE, KeyFilesEnable);
			EnableWindow (GetDlgItem (hwndDlg, IDC_KEY_FILES), KeyFilesEnable);

			DragFinish (hdrop);
		}
		return 1;
	}

	return 0;
}

static void PreferencesDlgEnableButtons (HWND hwndDlg)
{
	BOOL icon = IsButtonChecked (GetDlgItem (hwndDlg, IDC_PREF_BKG_TASK_ENABLE));
	BOOL idle = IsButtonChecked (GetDlgItem (hwndDlg, IDC_PREF_DISMOUNT_INACTIVE));
	BOOL logon = IsButtonChecked (GetDlgItem (hwndDlg, IDC_PREF_LOGON_START));
	BOOL installed = !IsNonInstallMode();

	EnableWindow (GetDlgItem (hwndDlg, IDC_CLOSE_BKG_TASK_WHEN_NOVOL), icon && installed);
	EnableWindow (GetDlgItem (hwndDlg, IDT_LOGON), installed);
	EnableWindow (GetDlgItem (hwndDlg, IDC_PREF_LOGON_START), installed);
	EnableWindow (GetDlgItem (hwndDlg, IDC_PREF_LOGON_MOUNT_DEVICES), installed && logon);
	EnableWindow (GetDlgItem (hwndDlg, IDC_PREF_LOGON_MOUNT_FAVORITES), installed && logon);
	EnableWindow (GetDlgItem (hwndDlg, IDT_AUTO_DISMOUNT), icon);
	EnableWindow (GetDlgItem (hwndDlg, IDT_AUTO_DISMOUNT_ON), icon);
	EnableWindow (GetDlgItem (hwndDlg, IDT_MINUTES), icon);
	EnableWindow (GetDlgItem (hwndDlg, IDC_PREF_DISMOUNT_LOGOFF), icon);
	EnableWindow (GetDlgItem (hwndDlg, IDC_PREF_DISMOUNT_POWERSAVING), icon);
	EnableWindow (GetDlgItem (hwndDlg, IDC_PREF_DISMOUNT_SCREENSAVER), icon);
	EnableWindow (GetDlgItem (hwndDlg, IDC_PREF_DISMOUNT_INACTIVE), icon);
	EnableWindow (GetDlgItem (hwndDlg, IDC_PREF_DISMOUNT_INACTIVE_TIME), icon && idle);
	EnableWindow (GetDlgItem (hwndDlg, IDC_PREF_FORCE_AUTO_DISMOUNT), icon);
	EnableWindow (GetDlgItem (hwndDlg, IDC_PREF_WIPE_CACHE_ON_AUTODISMOUNT), icon);
}

BOOL WINAPI
PreferencesDlgProc (HWND hwndDlg, UINT msg, WPARAM wParam, LPARAM lParam)
{
	WORD lw = LOWORD (wParam);

	switch (msg)
	{
	case WM_INITDIALOG:
		{
			LocalizeDialog (hwndDlg, "IDD_PREFERENCES_DLG");
		
			SendMessage (GetDlgItem (hwndDlg, IDC_PREF_OPEN_EXPLORER), BM_SETCHECK, 
						bExplore ? BST_CHECKED:BST_UNCHECKED, 0);

			SendMessage (GetDlgItem (hwndDlg, IDC_PREF_CLOSE_DISMOUNTED_WINDOWS), BM_SETCHECK, 
						bCloseDismountedWindows ? BST_CHECKED:BST_UNCHECKED, 0);
			
			SendMessage (GetDlgItem (hwndDlg, IDC_PRESERVE_TIMESTAMPS), BM_SETCHECK, 
						defaultMountOptions.PreserveTimestamp ? BST_CHECKED:BST_UNCHECKED, 0);

			SendMessage (GetDlgItem (hwndDlg, IDC_PREF_WIPE_CACHE_ON_EXIT), BM_SETCHECK, 
						bWipeCacheOnExit ? BST_CHECKED:BST_UNCHECKED, 0);

			SendMessage (GetDlgItem (hwndDlg, IDC_PREF_WIPE_CACHE_ON_AUTODISMOUNT), BM_SETCHECK, 
						bWipeCacheOnAutoDismount ? BST_CHECKED:BST_UNCHECKED, 0);

			SendMessage (GetDlgItem (hwndDlg, IDC_PREF_CACHE_PASSWORDS), BM_SETCHECK, 
						bCacheInDriver ? BST_CHECKED:BST_UNCHECKED, 0);
			
			SendMessage (GetDlgItem (hwndDlg, IDC_PREF_MOUNT_READONLY), BM_SETCHECK, 
						defaultMountOptions.ReadOnly ? BST_CHECKED:BST_UNCHECKED, 0);

			SendMessage (GetDlgItem (hwndDlg, IDC_PREF_MOUNT_REMOVABLE), BM_SETCHECK, 
						defaultMountOptions.Removable ? BST_CHECKED:BST_UNCHECKED, 0);

			SendMessage (GetDlgItem (hwndDlg, IDC_PREF_LOGON_START), BM_SETCHECK, 
						bStartOnLogon ? BST_CHECKED:BST_UNCHECKED, 0);

			SendMessage (GetDlgItem (hwndDlg, IDC_PREF_LOGON_MOUNT_DEVICES), BM_SETCHECK, 
						bMountDevicesOnLogon ? BST_CHECKED:BST_UNCHECKED, 0);

			SendMessage (GetDlgItem (hwndDlg, IDC_PREF_LOGON_MOUNT_FAVORITES), BM_SETCHECK, 
						bMountFavoritesOnLogon ? BST_CHECKED:BST_UNCHECKED, 0);

			SendMessage (GetDlgItem (hwndDlg, IDC_PREF_BKG_TASK_ENABLE), BM_SETCHECK, 
						bEnableBkgTask ? BST_CHECKED:BST_UNCHECKED, 0);

			SendMessage (GetDlgItem (hwndDlg, IDC_CLOSE_BKG_TASK_WHEN_NOVOL), BM_SETCHECK, 
						bCloseBkgTaskWhenNoVolumes || IsNonInstallMode() ? BST_CHECKED:BST_UNCHECKED, 0);
			
			SendMessage (GetDlgItem (hwndDlg, IDC_PREF_DISMOUNT_LOGOFF), BM_SETCHECK, 
						bDismountOnLogOff ? BST_CHECKED:BST_UNCHECKED, 0);

			SendMessage (GetDlgItem (hwndDlg, IDC_PREF_DISMOUNT_POWERSAVING), BM_SETCHECK, 
						bDismountOnPowerSaving ? BST_CHECKED:BST_UNCHECKED, 0);

			SendMessage (GetDlgItem (hwndDlg, IDC_PREF_DISMOUNT_SCREENSAVER), BM_SETCHECK, 
						bDismountOnScreenSaver ? BST_CHECKED:BST_UNCHECKED, 0);
			
			SendMessage (GetDlgItem (hwndDlg, IDC_PREF_FORCE_AUTO_DISMOUNT), BM_SETCHECK, 
						bForceAutoDismount ? BST_CHECKED:BST_UNCHECKED, 0);

			SendMessage (GetDlgItem (hwndDlg, IDC_PREF_DISMOUNT_INACTIVE), BM_SETCHECK, 
						MaxVolumeIdleTime > 0 ? BST_CHECKED:BST_UNCHECKED, 0);

			SetDlgItemInt (hwndDlg, IDC_PREF_DISMOUNT_INACTIVE_TIME, abs (MaxVolumeIdleTime), FALSE);

			PreferencesDlgEnableButtons (hwndDlg);
			return 1;
		}

	case WM_COMMAND:

		if (lw == IDC_PRESERVE_TIMESTAMPS && !IsButtonChecked (GetDlgItem (hwndDlg, IDC_PRESERVE_TIMESTAMPS)))
		{
			if (AskWarnNoYes ("CONFIRM_TIMESTAMP_UPDATING") == IDNO)
				SetCheckBox (hwndDlg, IDC_PRESERVE_TIMESTAMPS, TRUE);
		}

		if (lw == IDC_PREF_BKG_TASK_ENABLE && !IsButtonChecked (GetDlgItem (hwndDlg, IDC_PREF_BKG_TASK_ENABLE)))
		{
			if (AskWarnNoYes ("CONFIRM_BACKGROUND_TASK_DISABLED") == IDNO)
				SetCheckBox (hwndDlg, IDC_PREF_BKG_TASK_ENABLE, TRUE);
		}

		// Forced dismount disabled warning
		if (lw == IDC_PREF_DISMOUNT_INACTIVE
			|| lw == IDC_PREF_DISMOUNT_POWERSAVING
			|| lw == IDC_PREF_DISMOUNT_SCREENSAVER
			|| lw == IDC_PREF_FORCE_AUTO_DISMOUNT)
		{
			BOOL i = IsButtonChecked (GetDlgItem (hwndDlg, IDC_PREF_DISMOUNT_INACTIVE));
			BOOL p = IsButtonChecked (GetDlgItem (hwndDlg, IDC_PREF_DISMOUNT_POWERSAVING));
			BOOL s = IsButtonChecked (GetDlgItem (hwndDlg, IDC_PREF_DISMOUNT_SCREENSAVER));
			BOOL q = IsButtonChecked (GetDlgItem (hwndDlg, IDC_PREF_FORCE_AUTO_DISMOUNT));

			if (!q)
			{
				if (lw == IDC_PREF_FORCE_AUTO_DISMOUNT && (i || p || s))
				{
					if (AskWarnNoYes ("CONFIRM_NO_FORCED_AUTODISMOUNT") == IDNO)
						SetCheckBox (hwndDlg, IDC_PREF_FORCE_AUTO_DISMOUNT, TRUE);
				}
				else if ((lw == IDC_PREF_DISMOUNT_INACTIVE && i
					|| lw == IDC_PREF_DISMOUNT_POWERSAVING && p
					|| lw == IDC_PREF_DISMOUNT_SCREENSAVER && s))
					Warning ("WARN_PREF_AUTO_DISMOUNT");
			}

		}

		if (lw == IDCANCEL)
		{
			EndDialog (hwndDlg, lw);
			return 1;
		}

		if (lw == IDOK)
		{
			bExplore						= IsButtonChecked (GetDlgItem (hwndDlg, IDC_PREF_OPEN_EXPLORER));	 
			bCloseDismountedWindows			= IsButtonChecked (GetDlgItem (hwndDlg, IDC_PREF_CLOSE_DISMOUNTED_WINDOWS));	 
			bPreserveTimestamp = defaultMountOptions.PreserveTimestamp = IsButtonChecked (GetDlgItem (hwndDlg, IDC_PRESERVE_TIMESTAMPS));	 
			bWipeCacheOnExit				= IsButtonChecked (GetDlgItem (hwndDlg, IDC_PREF_WIPE_CACHE_ON_EXIT));
			bWipeCacheOnAutoDismount		= IsButtonChecked (GetDlgItem (hwndDlg, IDC_PREF_WIPE_CACHE_ON_AUTODISMOUNT));
			bCacheInDriver					= IsButtonChecked (GetDlgItem (hwndDlg, IDC_PREF_CACHE_PASSWORDS));	 
			defaultMountOptions.ReadOnly	= IsButtonChecked (GetDlgItem (hwndDlg, IDC_PREF_MOUNT_READONLY));
			defaultMountOptions.Removable	= IsButtonChecked (GetDlgItem (hwndDlg, IDC_PREF_MOUNT_REMOVABLE));
			bEnableBkgTask				= IsButtonChecked (GetDlgItem (hwndDlg, IDC_PREF_BKG_TASK_ENABLE));
			bCloseBkgTaskWhenNoVolumes	= IsNonInstallMode() ? bCloseBkgTaskWhenNoVolumes : IsButtonChecked (GetDlgItem (hwndDlg, IDC_CLOSE_BKG_TASK_WHEN_NOVOL));
			bDismountOnLogOff				= IsButtonChecked (GetDlgItem (hwndDlg, IDC_PREF_DISMOUNT_LOGOFF));
			bDismountOnPowerSaving			= IsButtonChecked (GetDlgItem (hwndDlg, IDC_PREF_DISMOUNT_POWERSAVING));
			bDismountOnScreenSaver			= IsButtonChecked (GetDlgItem (hwndDlg, IDC_PREF_DISMOUNT_SCREENSAVER));
			bForceAutoDismount				= IsButtonChecked (GetDlgItem (hwndDlg, IDC_PREF_FORCE_AUTO_DISMOUNT));
			MaxVolumeIdleTime				= GetDlgItemInt (hwndDlg, IDC_PREF_DISMOUNT_INACTIVE_TIME, NULL, FALSE)
												* (IsButtonChecked (GetDlgItem (hwndDlg, IDC_PREF_DISMOUNT_INACTIVE)) ? 1 : -1);
			bStartOnLogon					= IsButtonChecked (GetDlgItem (hwndDlg, IDC_PREF_LOGON_START));	 
			bMountDevicesOnLogon			= IsButtonChecked (GetDlgItem (hwndDlg, IDC_PREF_LOGON_MOUNT_DEVICES));	 
			bMountFavoritesOnLogon			= IsButtonChecked (GetDlgItem (hwndDlg, IDC_PREF_LOGON_MOUNT_FAVORITES));	 

			if (!IsNonInstallMode ())
			{
				char regk [64];

				// Split the string in order to prevent some antivirus packages from falsely reporting  
				// TrueCrypt.exe to contain a possible Trojan horse because of this string (heuristic scan).
				sprintf (regk, "%s%s", "Software\\Microsoft\\Windows\\Curren", "tVersion\\Run");

				if (bStartOnLogon)
				{
					char exe[MAX_PATH * 2] = { '"' };
					GetModuleFileName (NULL, exe + 1, sizeof (exe));
					strcat (exe, "\" /q preferences");
					
					if (bMountDevicesOnLogon) strcat (exe, " /a devices");
					if (bMountFavoritesOnLogon) strcat (exe, " /a favorites");

					WriteRegistryString (regk, "TrueCrypt", exe);
				}
				else
					DeleteRegistryValue (regk, "TrueCrypt");
			}

			SaveSettings (hwndDlg);

			EndDialog (hwndDlg, lw);
			return 1;
		}

		if (lw == IDC_PREFS_HOTKEY_SETTINGS)
		{
			DialogBoxParam (hInst, 
				MAKEINTRESOURCE (IDD_HOTKEYS_DLG), hwndDlg,
				(DLGPROC) HotkeysDlgProc, (LPARAM) 0);
			return 1;

		}

		if (lw == IDC_PREFS_KEYFILE_SETTINGS)
		{
			KeyfileDefaultsDlg (hwndDlg);
			return 1;
		}

		if (HIWORD (wParam) == BN_CLICKED)
		{
			PreferencesDlgEnableButtons (hwndDlg);
			return 1;
		}

		return 0;
	}

	return 0;
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
			BOOL protect;
			
			mountOptions = (MountOptions *) lParam;

			LocalizeDialog (hwndDlg, "IDD_MOUNT_OPTIONS");
		
			SendDlgItemMessage (hwndDlg, IDC_MOUNT_READONLY, BM_SETCHECK,
				mountOptions->ReadOnly ? BST_CHECKED : BST_UNCHECKED, 0);
			SendDlgItemMessage (hwndDlg, IDC_MOUNT_REMOVABLE, BM_SETCHECK,
				mountOptions->Removable ? BST_CHECKED : BST_UNCHECKED, 0);
			SendDlgItemMessage (hwndDlg, IDC_PROTECT_HIDDEN_VOL, BM_SETCHECK,
				mountOptions->ProtectHiddenVolume ? BST_CHECKED : BST_UNCHECKED, 0);

			protect = IsButtonChecked (GetDlgItem (hwndDlg, IDC_PROTECT_HIDDEN_VOL));

			EnableWindow (GetDlgItem (hwndDlg, IDC_PROTECT_HIDDEN_VOL), !IsButtonChecked (GetDlgItem (hwndDlg, IDC_MOUNT_READONLY)));
			EnableWindow (GetDlgItem (hwndDlg, IDT_HIDDEN_VOL_PROTECTION), !IsButtonChecked (GetDlgItem (hwndDlg, IDC_MOUNT_READONLY)));
			EnableWindow (GetDlgItem (hwndDlg, IDC_PASSWORD_PROT_HIDVOL), protect);
			EnableWindow (GetDlgItem (hwndDlg, IDC_SHOW_PASSWORD_MO), protect);
			EnableWindow (GetDlgItem (hwndDlg, IDT_HIDDEN_PROT_PASSWD), protect);
			EnableWindow (GetDlgItem (hwndDlg, IDC_KEYFILES_HIDVOL_PROT), protect && hidVolProtKeyFilesParam.EnableKeyFiles);
			EnableWindow (GetDlgItem (hwndDlg, IDC_KEYFILES_ENABLE_HIDVOL_PROT), protect);

			SetCheckBox (hwndDlg, IDC_KEYFILES_ENABLE_HIDVOL_PROT, hidVolProtKeyFilesParam.EnableKeyFiles);

			SendDlgItemMessage (hwndDlg, IDC_PASSWORD_PROT_HIDVOL, EM_LIMITTEXT, MAX_PASSWORD, 0);

			if (mountOptions->ProtectedHidVolPassword.Length > 0)
				SetWindowText (GetDlgItem (hwndDlg, IDC_PASSWORD_PROT_HIDVOL), mountOptions->ProtectedHidVolPassword.Text);	

			return 1;
		}

	case WM_COMMAND:

		if (lw == IDC_KEYFILES_HIDVOL_PROT)
		{
			if (IDOK == DialogBoxParamW (hInst,
				MAKEINTRESOURCEW (IDD_KEYFILES), hwndDlg,
				(DLGPROC) KeyFilesDlgProc, (LPARAM) &hidVolProtKeyFilesParam))
			{
				SetCheckBox (hwndDlg, IDC_KEYFILES_ENABLE_HIDVOL_PROT, hidVolProtKeyFilesParam.EnableKeyFiles);
				EnableWindow (GetDlgItem (hwndDlg, IDC_KEYFILES_HIDVOL_PROT), hidVolProtKeyFilesParam.EnableKeyFiles);
			}
		}

		if (lw == IDC_KEYFILES_ENABLE_HIDVOL_PROT)
		{
			hidVolProtKeyFilesParam.EnableKeyFiles = GetCheckBox (hwndDlg, IDC_KEYFILES_ENABLE_HIDVOL_PROT);
			EnableWindow (GetDlgItem (hwndDlg, IDC_KEYFILES_HIDVOL_PROT), hidVolProtKeyFilesParam.EnableKeyFiles);

			return 0;
		}

		if (lw == IDC_SHOW_PASSWORD_MO)
		{
			SendMessage (GetDlgItem (hwndDlg, IDC_PASSWORD_PROT_HIDVOL),
						EM_SETPASSWORDCHAR,
						GetCheckBox (hwndDlg, IDC_SHOW_PASSWORD_MO) ? 0 : '*',
						0);
			InvalidateRect (GetDlgItem (hwndDlg, IDC_PASSWORD_PROT_HIDVOL), NULL, TRUE);
			return 1;
		}

		if (lw == IDCANCEL)
		{
			char tmp[MAX_PASSWORD+1];

			// Cleanup
			memset (tmp, 'X', MAX_PASSWORD);
			tmp[MAX_PASSWORD] = 0;
			SetWindowText (GetDlgItem (hwndDlg, IDC_PASSWORD_PROT_HIDVOL), tmp);	

			EndDialog (hwndDlg, lw);
			return 1;
		}

		if (lw == IDOK)
		{
			char tmp[MAX_PASSWORD+1];
			
			mountOptions->ReadOnly = IsButtonChecked (GetDlgItem (hwndDlg, IDC_MOUNT_READONLY));
			mountOptions->Removable = IsButtonChecked (GetDlgItem (hwndDlg, IDC_MOUNT_REMOVABLE));
			mountOptions->ProtectHiddenVolume = IsButtonChecked (GetDlgItem (hwndDlg, IDC_PROTECT_HIDDEN_VOL));

			if (mountOptions->ProtectHiddenVolume)
			{
				GetWindowText (GetDlgItem (hwndDlg, IDC_PASSWORD_PROT_HIDVOL),
					mountOptions->ProtectedHidVolPassword.Text,
					sizeof (mountOptions->ProtectedHidVolPassword.Text));

				mountOptions->ProtectedHidVolPassword.Length = strlen (mountOptions->ProtectedHidVolPassword.Text);
			}

			// Cleanup
			memset (tmp, 'X', MAX_PASSWORD);
			tmp[MAX_PASSWORD] = 0;
			SetWindowText (GetDlgItem (hwndDlg, IDC_PASSWORD_PROT_HIDVOL), tmp);	

			if (mountOptions->ProtectHiddenVolume && !bEnableBkgTask)
				if (AskWarnYesNo ("HIDVOL_PROT_BKG_TASK_WARNING") == IDYES)
					bEnableBkgTask = TRUE;

			EndDialog (hwndDlg, lw);
			return 1;
		}

		if (lw == IDC_MOUNT_READONLY || lw == IDC_PROTECT_HIDDEN_VOL)
		{
			BOOL protect;

			if (lw == IDC_MOUNT_READONLY)
			{
				SendDlgItemMessage (hwndDlg, IDC_PROTECT_HIDDEN_VOL, BM_SETCHECK, BST_UNCHECKED, 0);
				EnableWindow (GetDlgItem (hwndDlg, IDC_PROTECT_HIDDEN_VOL), !IsButtonChecked (GetDlgItem (hwndDlg, IDC_MOUNT_READONLY)));
				EnableWindow (GetDlgItem (hwndDlg, IDT_HIDDEN_VOL_PROTECTION), !IsButtonChecked (GetDlgItem (hwndDlg, IDC_MOUNT_READONLY)));
			}

			protect = IsButtonChecked (GetDlgItem (hwndDlg, IDC_PROTECT_HIDDEN_VOL));

			EnableWindow (GetDlgItem (hwndDlg, IDC_PASSWORD_PROT_HIDVOL), protect);
			EnableWindow (GetDlgItem (hwndDlg, IDT_HIDDEN_PROT_PASSWD), protect);
			EnableWindow (GetDlgItem (hwndDlg, IDC_SHOW_PASSWORD_MO), protect);
			EnableWindow (GetDlgItem (hwndDlg, IDC_KEYFILES_HIDVOL_PROT), protect && hidVolProtKeyFilesParam.EnableKeyFiles);
			EnableWindow (GetDlgItem (hwndDlg, IDC_KEYFILES_ENABLE_HIDVOL_PROT), protect);

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
	int i = 0;

	switch (msg)
	{
	case WM_INITDIALOG:
		{
			VOLUME_PROPERTIES_STRUCT prop;
			DWORD dwResult;
			BOOL bResult;	

			LVCOLUMNW lvCol;
			HWND list = GetDlgItem (hwndDlg, IDC_VOLUME_PROPERTIES_LIST);
			char szTmp[1024];
			wchar_t sw[1024];
			wchar_t *s;

			LocalizeDialog (hwndDlg, "IDD_VOLUME_PROPERTIES");

			SendMessage (list,LVM_SETEXTENDEDLISTVIEWSTYLE, 0,
				LVS_EX_FULLROWSELECT
				|LVS_EX_HEADERDRAGDROP
				|LVS_EX_LABELTIP
				); 

			memset (&lvCol,0,sizeof(lvCol));               
			lvCol.mask = LVCF_TEXT|LVCF_WIDTH|LVCF_SUBITEM|LVCF_FMT;  
			lvCol.pszText = GetString ("VALUE");                           
			lvCol.cx = 202;
			lvCol.fmt = LVCFMT_LEFT ;
			SendMessage (list,LVM_INSERTCOLUMNW,0,(LPARAM)&lvCol);

			lvCol.pszText = GetString ("PROPERTY");  
			lvCol.cx = 177;           
			lvCol.fmt = LVCFMT_LEFT;
			SendMessage (list,LVM_INSERTCOLUMNW,0,(LPARAM)&lvCol);
	
			memset (&prop, 0, sizeof(prop));
			prop.driveNo = HIWORD (GetSelectedLong (GetDlgItem (GetParent(hwndDlg), IDC_DRIVELIST))) - 'A';

			bResult = DeviceIoControl (hDriver, VOLUME_PROPERTIES, &prop,
				sizeof (prop), &prop, sizeof (prop), &dwResult,
				NULL);
	
			// Location
			ListItemAddW (list, i, GetString ("LOCATION"));
			ListSubItemSetW (list, i++, 1, prop.wszVolume[1] != L'?' ? prop.wszVolume : prop.wszVolume + 4);

			// Size
			ListItemAddW (list, i, GetString ("SIZE"));
			swprintf (sw, L"%I64u %s", prop.diskLength, GetString ("BYTES"));
			ListSubItemSetW (list, i++, 1, sw);

			// Type
			ListItemAddW (list, i, GetString ("TYPE"));
			ListSubItemSetW (list, i++, 1, 
				prop.hiddenVolume ? GetString ("HIDDEN") : 
				(prop.hiddenVolProtection != HIDVOL_PROT_STATUS_NONE ? GetString ("OUTER") : GetString ("NORMAL")));
			
			// Write protection
			ListItemAddW (list, i, GetString ("READ_ONLY"));

			if (prop.readOnly || prop.hiddenVolProtection == HIDVOL_PROT_STATUS_ACTION_TAKEN)
				s = GetString ("UISTR_YES");
			else
				s = GetString ("UISTR_NO");

			ListSubItemSetW (list, i++, 1, s);

			// Hidden Volume Protection
			ListItemAddW (list, i, GetString ("HIDDEN_VOL_PROTECTION"));
			if (prop.hiddenVolume)
				s = GetString ("N_A_UISTR");
			else if (prop.hiddenVolProtection == HIDVOL_PROT_STATUS_NONE)
				s = GetString ("UISTR_NO");
			else if (prop.hiddenVolProtection == HIDVOL_PROT_STATUS_ACTIVE)
				s = GetString ("UISTR_YES");
			else if (prop.hiddenVolProtection == HIDVOL_PROT_STATUS_ACTION_TAKEN)
				s = GetString ("HID_VOL_DAMAGE_PREVENTED");

			ListSubItemSetW (list, i++, 1, s);

			// Encryption algorithm
			ListItemAddW (list, i, GetString ("ENCRYPTION_ALGORITHM"));
			EAGetName (szTmp, prop.ea);
			ListSubItemSet (list, i++, 1, szTmp);

			// Key size
			{
				char name[128];
				int size = EAGetKeySize (prop.ea);	
				EAGetName (name, prop.ea);

				if (strcmp (name, "Triple DES") == 0)
					size -= 3; // Compensate for parity bytes

				ListItemAddW (list, i, GetString ("KEY_SIZE"));
				wsprintfW (sw, L"%d %s", size * 8, GetString ("BITS"));
				ListSubItemSetW (list, i++, 1, sw);
			}

			// Block size
			ListItemAddW (list, i, GetString ("BLOCK_SIZE"));
			if (EAGetFirstMode (prop.ea) == INNER_CBC)
			{
				// Cascaded ciphers with non-equal block sizes  (deprecated/legacy)
				wchar_t tmpstr[64];
				int i = EAGetLastCipher(prop.ea);

				swprintf (sw, L"%d", CipherGetBlockSize(i)*8);
				
				while (i = EAGetPreviousCipher(prop.ea, i))
				{
					swprintf (tmpstr, L"/%d", CipherGetBlockSize(i)*8);
					wcscat (sw, tmpstr);
				}
				wcscat (sw, L" ");
			}
			else
			{
				swprintf (sw, L"%d ", CipherGetBlockSize (EAGetFirstCipher(prop.ea))*8);
			}
			wcscat (sw, GetString ("BITS"));
			ListSubItemSetW (list, i++, 1, sw);

			// Mode
			ListItemAddW (list, i, GetString ("MODE_OF_OPERATION"));
			ListSubItemSet (list, i++, 1, EAGetModeName (prop.ea, prop.mode, TRUE));

			// PRF
			ListItemAddW (list, i, GetString ("PKCS5_PRF"));
			ListSubItemSet (list, i++, 1, get_pkcs5_prf_name (prop.pkcs5));

			// PCKS iterations
			ListItemAddW (list, i, GetString ("PKCS5_ITERATIONS"));
			sprintf (szTmp, "%d", prop.pkcs5Iterations);
			ListSubItemSet (list, i++, 1, szTmp);

			{
				FILETIME ft, curFt;
				SYSTEMTIME st;
				wchar_t date[128];
				memset (date, 0, sizeof (date));

				// Volume date
				ListItemAddW (list, i, GetString ("VOLUME_CREATE_DATE"));
				*(unsigned __int64 *)(&ft) = prop.volumeCreationTime;
				FileTimeToSystemTime (&ft, &st);
				GetDateFormatW (LOCALE_USER_DEFAULT, 0, &st, 0, sw, sizeof (sw)/2);
				swprintf (date, L"%s ", sw);
				GetTimeFormatW (LOCALE_USER_DEFAULT, 0, &st, 0, sw, sizeof (sw)/2);
				wcscat (date, sw);
				ListSubItemSetW (list, i++, 1, date);

				// Header date
				ListItemAddW (list, i, GetString ("VOLUME_HEADER_DATE"));
				*(unsigned __int64 *)(&ft) = prop.headerCreationTime;
				FileTimeToSystemTime (&ft, &st);
				GetDateFormatW (LOCALE_USER_DEFAULT, 0, &st, 0, sw, sizeof (sw)/2);
				swprintf (date, L"%s ", sw);
				GetTimeFormatW (LOCALE_USER_DEFAULT, 0, &st, 0, sw, sizeof (sw)/2);
				wcscat (date, sw);

				GetLocalTime (&st);
				SystemTimeToFileTime (&st, &curFt);
				swprintf (date + wcslen (date),  GetString ("VOLUME_HEADER_DAYS")
					, (*(__int64 *)&curFt - *(__int64 *)&ft)/1000000000000);
				ListSubItemSetW (list, i++, 1, date);
			}

			// Total data read
			ListItemAddW (list, i, GetString ("TOTAL_DATA_READ"));
			GetSizeString (prop.totalBytesRead, sw);
			ListSubItemSetW (list, i++, 1, sw);

			// Total data written
			ListItemAddW (list, i, GetString ("TOTAL_DATA_WRITTEN"));
			GetSizeString (prop.totalBytesWritten, sw);
			ListSubItemSetW (list, i++, 1, sw);

			return 1;
		}

	case WM_COMMAND:
		if (lw == IDOK)
		{
			EndDialog (hwndDlg, lw);
			return 1;
		}
		return 0;

	case WM_CLOSE:
		EndDialog (hwndDlg, lw);
		return 1;
	}

	return 0;
}


BOOL WINAPI
TravellerDlgProc (HWND hwndDlg, UINT msg, WPARAM wParam, LPARAM lParam)
{
	WORD lw = LOWORD (wParam);

	switch (msg)
	{
	case WM_INITDIALOG:
		{
			int i, index;
			char drive[] = { 0, ':', 0 };

			LocalizeDialog (hwndDlg, "IDD_TRAVELLER_DLG");

			SendDlgItemMessage (hwndDlg, IDC_COPY_WIZARD, BM_SETCHECK, 
						BST_CHECKED, 0);

			SendDlgItemMessage (hwndDlg, IDC_TRAVEL_OPEN_EXPLORER, BM_SETCHECK, 
						BST_CHECKED, 0);

			SendDlgItemMessage (hwndDlg, IDC_AUTORUN_DISABLE, BM_SETCHECK, 
						BST_CHECKED, 0);

			SendDlgItemMessage (hwndDlg, IDC_DRIVELIST, CB_RESETCONTENT, 0, 0);

			index = SendDlgItemMessageW (hwndDlg, IDC_DRIVELIST, CB_ADDSTRING, 0, (LPARAM) GetString ("FIRST_AVAILABLE"));
			SendDlgItemMessage (hwndDlg, IDC_DRIVELIST, CB_SETITEMDATA, index, (LPARAM) 0);

			for (i = 'A'; i <= 'Z'; i++)
			{
				drive[0] = i;
				index = SendDlgItemMessage (hwndDlg, IDC_DRIVELIST, CB_ADDSTRING, 0, (LPARAM) drive);
				SendDlgItemMessage (hwndDlg, IDC_DRIVELIST, CB_SETITEMDATA, index, (LPARAM) i);
			}
		
			SendDlgItemMessage (hwndDlg, IDC_DRIVELIST, CB_SETCURSEL, 0, 0);

			return 1;
		}


	case WM_COMMAND:

		if (HIWORD (wParam) == BN_CLICKED
			&& (lw == IDC_AUTORUN_DISABLE || lw == IDC_AUTORUN_MOUNT || lw == IDC_AUTORUN_START ))
		{
			BOOL enabled = !IsButtonChecked (GetDlgItem (hwndDlg, IDC_AUTORUN_DISABLE));
			
			EnableWindow (GetDlgItem (hwndDlg, IDC_BROWSE_FILES), enabled);
			EnableWindow (GetDlgItem (hwndDlg, IDC_VOLUME_NAME), enabled);
			EnableWindow (GetDlgItem (hwndDlg, IDC_TRAVEL_OPEN_EXPLORER), enabled);
			EnableWindow (GetDlgItem (hwndDlg, IDC_TRAV_CACHE_PASSWORDS), enabled);
			EnableWindow (GetDlgItem (hwndDlg, IDC_MOUNT_READONLY), enabled);
			EnableWindow (GetDlgItem (hwndDlg, IDC_DRIVELIST), enabled);
			EnableWindow (GetDlgItem (hwndDlg, IDT_TRAVELLER_MOUNT), enabled);
			EnableWindow (GetDlgItem (hwndDlg, IDT_MOUNT_LETTER), enabled);
			EnableWindow (GetDlgItem (hwndDlg, IDT_MOUNT_SETTINGS), enabled);

			return 1;
		}

		if (lw == IDC_BROWSE_FILES)
		{
			char volName[MAX_PATH] = { 0 };

			if (BrowseFiles (hwndDlg, "OPEN_TITLE", volName, bHistory, FALSE))
				SetDlgItemText (hwndDlg, IDC_VOLUME_NAME, strchr (volName, '\\') + 1);

			return 1;
		}

		if (lw == IDC_BROWSE_DIRS)
		{
			char dstPath[MAX_PATH * 2];
			GetDlgItemText (hwndDlg, IDC_DIRECTORY, dstPath, sizeof dstPath);

			if (BrowseDirectories (hwndDlg, "SELECT_DEST_DIR", dstPath))
				SetDlgItemText (hwndDlg, IDC_DIRECTORY, dstPath);

			return 1;
		}

		if (lw == IDCANCEL)
		{
			EndDialog (hwndDlg, lw);
			return 1;
		}

		if (lw == IDC_CREATE)
		{
			BOOL copyWizard, bExplore, bCacheInDriver, bAutoRun, bAutoMount, bMountReadOnly;
			char dstDir[MAX_PATH];
			char srcPath[MAX_PATH * 2];
			char dstPath[MAX_PATH * 2];
			char appDir[MAX_PATH];
			char sysDir[MAX_PATH];
			char volName[MAX_PATH];
			int drive;

			GetDlgItemText (hwndDlg, IDC_DIRECTORY, dstDir, sizeof dstDir);
			volName[0] = 0;
			GetDlgItemText (hwndDlg, IDC_VOLUME_NAME, volName + 1, sizeof volName);
			
			drive = SendDlgItemMessage (hwndDlg, IDC_DRIVELIST, CB_GETCURSEL, 0, 0);
			drive = SendDlgItemMessage (hwndDlg, IDC_DRIVELIST, CB_GETITEMDATA, drive, 0);

			copyWizard = IsButtonChecked (GetDlgItem (hwndDlg, IDC_COPY_WIZARD));
			bExplore = IsButtonChecked (GetDlgItem (hwndDlg, IDC_TRAVEL_OPEN_EXPLORER));
			bCacheInDriver = IsButtonChecked (GetDlgItem (hwndDlg, IDC_TRAV_CACHE_PASSWORDS));
			bMountReadOnly = IsButtonChecked (GetDlgItem (hwndDlg, IDC_MOUNT_READONLY));
			bAutoRun = !IsButtonChecked (GetDlgItem (hwndDlg, IDC_AUTORUN_DISABLE));
			bAutoMount = IsButtonChecked (GetDlgItem (hwndDlg, IDC_AUTORUN_MOUNT));

			if (dstDir[0] == 0)
			{
				SetFocus (GetDlgItem (hwndDlg, IDC_DIRECTORY));
				MessageBoxW (hwndDlg, GetString ("NO_PATH_SELECTED"), lpszTitle, MB_ICONEXCLAMATION);
				return 1;
			}

			
			if (bAutoMount && volName[1] == 0)
			{
				SetFocus (GetDlgItem (hwndDlg, IDC_VOLUME_NAME));
				MessageBoxW (hwndDlg, GetString ("NO_FILE_SELECTED"), lpszTitle, MB_ICONEXCLAMATION);
				return 1;
			}

			if (volName[1] != 0)
			{
				volName[0] = '"';
				strcat (volName, "\"");
			}

			EnableWindow (GetDlgItem (hwndDlg, IDOK), FALSE);
			EnableWindow (GetDlgItem (hwndDlg, IDCANCEL), FALSE);

			GetModuleFileName (NULL, appDir, sizeof (appDir));
			strrchr (appDir, '\\')[0] = 0;

			ArrowWaitCursor();
			GetSystemDirectory (sysDir, sizeof (sysDir));

			sprintf (dstPath, "%s\\TrueCrypt", dstDir);
			CreateDirectory (dstPath, NULL);

			// Main app
			sprintf (srcPath, "%s\\TrueCrypt.exe", appDir);
			sprintf (dstPath, "%s\\TrueCrypt\\TrueCrypt.exe", dstDir);
			if (!TCCopyFile (srcPath, dstPath))
			{
				handleWin32Error (hwndDlg);
				goto stop;
			}

			// Wizard
			if (copyWizard)
			{
				sprintf (srcPath, "%s\\TrueCrypt Format.exe", appDir);
				sprintf (dstPath, "%s\\TrueCrypt\\TrueCrypt Format.exe", dstDir);
				if (!TCCopyFile (srcPath, dstPath))
				{
					handleWin32Error (hwndDlg);
					goto stop;
				}
			}

			// Driver
			sprintf (srcPath, "%s\\truecrypt.sys", appDir);
			sprintf (dstPath, "%s\\TrueCrypt\\truecrypt.sys", dstDir);
			if (!TCCopyFile (srcPath, dstPath))
			{
				handleWin32Error (hwndDlg);
				goto stop;
			}

			// Driver x64
			sprintf (srcPath, "%s\\truecrypt-x64.sys", appDir);
			sprintf (dstPath, "%s\\TrueCrypt\\truecrypt-x64.sys", dstDir);
			if (!TCCopyFile (srcPath, dstPath))
			{
				handleWin32Error (hwndDlg);
				goto stop;
			}

			// AutoRun
			if (bAutoRun)
			{
				FILE *af;
				char autoMount[100];
				char openApp[100];
				char driveLetter[] = { ' ', '/', 'l', drive, 0 };

				sprintf (dstPath, "%s\\autorun.inf", dstDir);
				af = fopen (dstPath, "w");

				if (af == NULL)
				{
					MessageBoxW (hwndDlg, GetString ("CANT_CREATE_AUTORUN"), lpszTitle, MB_ICONERROR);
					goto stop;
				}

				fprintf (af, "[autorun]\n");

				sprintf (autoMount, "TrueCrypt\\TrueCrypt.exe /q /a%s%s%s%s /m rm /v %s",
					drive > 0 ? driveLetter : "",
					bExplore ? " /e" : "",
					bCacheInDriver ? " /cy" : "",
					bMountReadOnly ? " /m ro" : "",
					volName);

				sprintf (openApp, "TrueCrypt\\TrueCrypt.exe%s%s%s%s /m rm%s%s",
					drive > 0 ? driveLetter : "",
					bExplore ? " /e" : "",
					bCacheInDriver ? " /cy" : "",
					bMountReadOnly ? " /m ro" : "",
					volName[0] != 0 ? " /v " : "",
					volName[0] != 0 ? volName : "");

				fprintf (af, "open=%s\n", 
					bAutoMount ? autoMount : openApp);

				fprintf (af, "shell=%s\n", 
					bAutoMount ? "mount" : "open");

				fprintf (af, "action=%s\n", 
					bAutoMount ? "Mount TrueCrypt Volume" : "Start TrueCrypt");

				fprintf (af, "shell\\open\\command=%s\nshell\\open=TrueCrypt Start\n", openApp);
				
				if (volName[0] != 0)
					fprintf (af, "shell\\mount\\command=%s\nshell\\mount=TrueCrypt Mount\n", autoMount);

				fprintf (af, "shell\\dismount\\command=TrueCrypt\\TrueCrypt.exe /q /d\nshell\\dismount=TrueCrypt Dismount All\n");

				fclose (af);
			}
			MessageBoxW (hwndDlg, GetString ("TRAVELLER_DISK_CREATED"), lpszTitle, MB_ICONINFORMATION);

stop:
			NormalCursor ();
			EnableWindow (GetDlgItem (hwndDlg, IDOK), TRUE);
			EnableWindow (GetDlgItem (hwndDlg, IDCANCEL), TRUE);

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
	LVCOLUMNW lvCol;

	ListView_DeleteColumn (hTree,0);
	ListView_DeleteColumn (hTree,0);
	ListView_DeleteColumn (hTree,0);
	ListView_DeleteColumn (hTree,0);
	ListView_DeleteColumn (hTree,0);
	ListView_DeleteColumn (hTree,0);

	SendMessage(hTree,LVM_SETEXTENDEDLISTVIEWSTYLE,0,
		LVS_EX_FULLROWSELECT
		|LVS_EX_HEADERDRAGDROP 
		); 

	memset(&lvCol,0,sizeof(lvCol)); 

	lvCol.mask = LVCF_TEXT|LVCF_WIDTH|LVCF_SUBITEM|LVCF_FMT;  
	lvCol.pszText = GetString ("DRIVE");                           
	lvCol.cx = 37;
	lvCol.fmt = LVCFMT_COL_HAS_IMAGES|LVCFMT_LEFT ;
	SendMessage (hTree,LVM_INSERTCOLUMNW,0,(LPARAM)&lvCol);

	lvCol.pszText = GetString ("VOLUME");  
	lvCol.cx = 258;           
	lvCol.fmt = LVCFMT_LEFT;
	SendMessage (hTree,LVM_INSERTCOLUMNW,1,(LPARAM)&lvCol);

	lvCol.pszText = GetString ("SIZE");  
	lvCol.cx = 55;
	lvCol.fmt = LVCFMT_RIGHT;
	SendMessage (hTree,LVM_INSERTCOLUMNW,2,(LPARAM)&lvCol);

	lvCol.pszText = GetString ("ENCRYPTION_ALGORITHM");  
	lvCol.cx = 117;
	lvCol.fmt = LVCFMT_LEFT;
	SendMessage (hTree,LVM_INSERTCOLUMNW,3,(LPARAM)&lvCol);

	lvCol.pszText = GetString ("TYPE");  
	lvCol.cx = 52;
	lvCol.fmt = LVCFMT_LEFT;
	SendMessage (hTree,LVM_INSERTCOLUMNW,4,(LPARAM)&lvCol);

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

	if (nSelectedDriveIndex >= 0)
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

static int AskUserPassword (HWND hwndDlg, Password *password)
{
	int result;

	result = DialogBoxParamW (hInst, 
		MAKEINTRESOURCEW (IDD_PASSWORD_DLG), hwndDlg,
		(DLGPROC) PasswordDlgProc, (LPARAM) password);

	if (result != IDOK)
	{
		password->Length = 0;
		burn (&mountOptions.ProtectedHidVolPassword, sizeof (mountOptions.ProtectedHidVolPassword));
	}

	return result == IDOK;
}

// GUI actions

static BOOL Mount (HWND hwndDlg, int nDosDriveNo, char *szFileName)
{
	BOOL status = FALSE;
	char fileName[MAX_PATH];
	int mounted = 0;
	if (nDosDriveNo == 0)
		nDosDriveNo = HIWORD (GetSelectedLong (GetDlgItem (hwndDlg, IDC_DRIVELIST))) - 'A';

	VolumePassword.Length = 0;

	if (szFileName == NULL)
	{
		GetWindowText (GetDlgItem (hwndDlg, IDC_VOLUME), fileName, sizeof (fileName));
		szFileName = fileName;
	}

	if (strlen(szFileName) == 0)
	{
		status = FALSE;
		goto ret;
	}

	if (IsMountedVolume (szFileName))
	{
		Warning ("ALREADY_MOUNTED");
		status = FALSE;
		goto ret;
	}

	// First try cached passwords and if they fail ask user for a new one
	ArrowWaitCursor ();

	mounted = MountVolume (hwndDlg, nDosDriveNo, szFileName, NULL, bCacheInDriver, bForceMount, &mountOptions, FALSE, FALSE);
	
	// If keyfiles are enabled, test empty password first
	if (!mounted && KeyFilesEnable)
	{
		KeyFilesApply (&VolumePassword, FirstKeyFile, bPreserveTimestamp);
		mounted = MountVolume (hwndDlg, nDosDriveNo, szFileName, &VolumePassword, bCacheInDriver, bForceMount, &mountOptions, FALSE, FALSE);
	}

	NormalCursor ();

	while (mounted == 0)
	{
		if (CmdVolumePassword.Length > 0)
		{
			VolumePassword = CmdVolumePassword;
		}
		else if (!Silent)
		{
			strcpy (PasswordDlgVolume, szFileName);
			if (!AskUserPassword (hwndDlg, &VolumePassword))
				goto ret;
		}
		
		ArrowWaitCursor ();

		if (KeyFilesEnable)
			KeyFilesApply (&VolumePassword, FirstKeyFile, bPreserveTimestamp);

		mounted = MountVolume (hwndDlg, nDosDriveNo, szFileName, &VolumePassword, bCacheInDriver, bForceMount, &mountOptions, FALSE, TRUE);
		NormalCursor ();

		if (mounted > 0 && !KeyFilesEnable && !CheckPasswordCharEncoding (NULL, &VolumePassword))
			Warning ("UNSUPPORTED_CHARS_IN_PWD_RECOM");

		burn (&VolumePassword, sizeof (VolumePassword));
		burn (&mountOptions.ProtectedHidVolPassword, sizeof (mountOptions.ProtectedHidVolPassword));

		if (CmdVolumePassword.Length > 0 || Silent)
			break;
	}

	if (mounted > 0)
	{
		status = TRUE;

		if (bBeep)
			MessageBeep (-1);

		RefreshMainDlg(hwndDlg);

		if (bExplore)
		{	
			ArrowWaitCursor();
			OpenVolumeExplorerWindow (nDosDriveNo);
			NormalCursor();
		}

		if (mountOptions.ProtectHiddenVolume)
			Info ("HIDVOL_PROT_WARN_AFTER_MOUNT");
	}

ret:
	burn (&VolumePassword, sizeof (VolumePassword));
	burn (&mountOptions.ProtectedHidVolPassword, sizeof (mountOptions.ProtectedHidVolPassword));
	RestoreDefaultKeyFilesParam ();
	return status;
}


static BOOL Dismount (HWND hwndDlg, int nDosDriveNo)
{
	BOOL status = FALSE;
	ArrowWaitCursor ();

	if (nDosDriveNo == 0)
		nDosDriveNo = (char) (HIWORD (GetSelectedLong (GetDlgItem (hwndDlg, IDC_DRIVELIST))) - 'A');

	if (bCloseDismountedWindows)
	{
		CloseVolumeExplorerWindows (hwndDlg, nDosDriveNo);
	}

	if (UnmountVolume (hwndDlg, nDosDriveNo, bForceUnmount))
	{
		status = TRUE;

		if (bBeep)
			MessageBeep (-1);
		RefreshMainDlg (hwndDlg);

		if (nCurrentOS == WIN_2000 && RemoteSession && !IsAdmin ())
			LoadDriveLetters (GetDlgItem (hwndDlg, IDC_DRIVELIST), 0);
	}

	NormalCursor ();
	return status;
}

static BOOL DismountAll (HWND hwndDlg, BOOL forceUnmount, BOOL interact, int dismountMaxRetries, int dismountAutoRetryDelay)
{
	BOOL status = TRUE;
	MOUNT_LIST_STRUCT mountList;
	DWORD dwResult;
	UNMOUNT_STRUCT unmount;
	BOOL bResult;
	unsigned __int32 prevMountedDrives = 0;
	int i;

retry:
	ArrowWaitCursor();

	DeviceIoControl (hDriver, MOUNT_LIST, &mountList, sizeof (mountList), &mountList, sizeof (mountList), &dwResult, NULL);

	if (mountList.ulMountedDrives == 0)
	{
		NormalCursor();
		return TRUE;
	}

	prevMountedDrives = mountList.ulMountedDrives;

	for (i = 0; i < 26; i++)
	{
		if (mountList.ulMountedDrives & (1 << i))
		{
			if (bCloseDismountedWindows)
				CloseVolumeExplorerWindows (hwndDlg, i);
		}
	}

	unmount.nDosDriveNo = 0;
	unmount.ignoreOpenFiles = forceUnmount;

	do
	{
		bResult = DeviceIoControl (hDriver, UNMOUNT_ALL, &unmount,
			sizeof (unmount), &unmount, sizeof (unmount), &dwResult, NULL);

		if (bResult == FALSE)
		{
			NormalCursor();
			handleWin32Error (hwndDlg);
			return FALSE;
		}

		if (unmount.nReturnCode == ERR_FILES_OPEN)
			Sleep (dismountAutoRetryDelay);
		else
			break;

	} while (--dismountMaxRetries > 0);

	memset (&mountList, 0, sizeof (mountList));
	DeviceIoControl (hDriver, MOUNT_LIST, &mountList, sizeof (mountList), &mountList, sizeof (mountList), &dwResult, NULL);
	BroadcastDeviceChange (DBT_DEVICEREMOVECOMPLETE, 0, prevMountedDrives & ~mountList.ulMountedDrives);

	RefreshMainDlg (hwndDlg);

	if (nCurrentOS == WIN_2000 && RemoteSession && !IsAdmin ())
		LoadDriveLetters (GetDlgItem (hwndDlg, IDC_DRIVELIST), 0);

	NormalCursor();

	if (unmount.nReturnCode != 0)
	{
		if (forceUnmount)
			status = FALSE;

		if (unmount.nReturnCode == ERR_FILES_OPEN)
		{
			if (interact && IDYES == AskWarnNoYes ("UNMOUNTALL_LOCK_FAILED"))
			{
				forceUnmount = TRUE;
				goto retry;
			}

			return FALSE;
		}
		
		if (interact)
			MessageBoxW (hwndDlg, GetString ("UNMOUNT_FAILED"), lpszTitle, MB_ICONERROR);
	}
	else
	{
		if (bBeep)
			MessageBeep (-1);
	}

	return status;
}

static BOOL MountAllDevices (HWND hwndDlg, BOOL bPasswordPrompt)
{
	HWND driveList = GetDlgItem (hwndDlg, IDC_DRIVELIST);
	int i, n, selDrive = ListView_GetSelectionMark (driveList);
	BOOL shared = FALSE, status = FALSE;
	int mountedVolCount = 0;

	VolumePassword.Length = 0;
	mountOptions = defaultMountOptions;

	if (selDrive == -1) selDrive = 0;

	do
	{
		if (!CmdVolumePasswordValid && bPasswordPrompt)
		{
			PasswordDlgVolume[0] = '\0';
			if (!AskUserPassword (hwndDlg, &VolumePassword))
				goto ret;
		}
		else if (CmdVolumePasswordValid)
		{
			bPasswordPrompt = FALSE;
			VolumePassword = CmdVolumePassword;
		}

		ArrowWaitCursor();

		if (FirstCmdKeyFile)
			KeyFilesApply (&VolumePassword, FirstCmdKeyFile, bPreserveTimestamp);
		else if (KeyFilesEnable)
			KeyFilesApply (&VolumePassword, FirstKeyFile, bPreserveTimestamp);

		for (i = 0; i < 64; i++)
		{
			// Include partition 0 (whole disk)
			for (n = 0; n <= 32; n++)
			{
				char szFileName[TC_MAX_PATH];
				OPEN_TEST_STRUCT driver;
				BOOL mounted;

				sprintf (szFileName, "\\Device\\Harddisk%d\\Partition%d", i, n);

				mounted = IsMountedVolume (szFileName);

				// Skip other partitions of the disk if partition0 (whole disk) is mounted
				if (n == 0 && mounted)
					break;

				if (!mounted && OpenDevice (szFileName, &driver))
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
					if ((mounted = MountVolume (hwndDlg, nDosDriveNo, szFileName, &VolumePassword, bCacheInDriver, bForceMount, &mountOptions, TRUE, FALSE)) > 0
						|| (mounted = MountVolume (hwndDlg, nDosDriveNo, szFileName, NULL, bCacheInDriver, bForceMount, &mountOptions, TRUE, FALSE)) > 0)
					{
						if (mounted == 2)
							shared = TRUE;

						LoadDriveLetters (driveList, (HIWORD (GetItemLong (GetDlgItem (hwndDlg, IDC_DRIVELIST), selDrive))));
						selDrive++;

						if (bExplore)
						{	
							ArrowWaitCursor();
							OpenVolumeExplorerWindow (nDosDriveNo);
							NormalCursor();
						}

						if (bBeep)
							MessageBeep (-1);

						status = TRUE;

						mountedVolCount++;

						// Skip other partitions of the disk if partition0 (whole disk) has been mounted
						if (n == 0)
							break;
					}
				}
				else if (n == 0)
					break;
			}
		}

		burn (&VolumePassword, sizeof (VolumePassword));

		if (mountedVolCount < 1 && !Silent)
		{
			WCHAR szTmp[1024];

			wsprintfW (szTmp, GetString (KeyFilesEnable || FirstCmdKeyFile ? "PASSWORD_OR_KEYFILE_WRONG_AUTOMOUNT" : "PASSWORD_WRONG_AUTOMOUNT"));
			if (CheckCapsLock (hwndDlg, TRUE))
				wcscat (szTmp, GetString ("PASSWORD_WRONG_CAPSLOCK_ON"));

			MessageBoxW (hwndDlg, szTmp, lpszTitle, MB_ICONWARNING);
		}

		burn (&mountOptions.ProtectedHidVolPassword, sizeof (mountOptions.ProtectedHidVolPassword));
	} while (bPasswordPrompt && mountedVolCount < 1);

	/* One or more volumes successfully mounted */

	if (shared)
		Warning ("DEVICE_IN_USE_INFO");

	if (mountOptions.ProtectHiddenVolume)
	{
		if (mountedVolCount > 1)
			Info ("HIDVOL_PROT_WARN_AFTER_MOUNT_PLURAL");
		else if (mountedVolCount == 1)
			Info ("HIDVOL_PROT_WARN_AFTER_MOUNT");
	}

	if (!KeyFilesEnable
		&& !FirstCmdKeyFile
		&& mountedVolCount > 0
		&& !CheckPasswordCharEncoding (NULL, &VolumePassword))
			Warning ("UNSUPPORTED_CHARS_IN_PWD_RECOM");

ret:
	burn (&VolumePassword, sizeof (VolumePassword));
	burn (&mountOptions.ProtectedHidVolPassword, sizeof (mountOptions.ProtectedHidVolPassword));
	RestoreDefaultKeyFilesParam ();
	EnableDisableButtons (hwndDlg);
	NormalCursor();

	return status;
}

static void ChangePassword (HWND hwndDlg)
{
	int result;
	
	GetWindowText (GetDlgItem (hwndDlg, IDC_VOLUME), szFileName, sizeof (szFileName));
	if (IsMountedVolume (szFileName))
	{
		Warning (pwdChangeDlgMode == PCDM_CHANGE_PKCS5_PRF ? "MOUNTED_NO_PKCS5_PRF_CHANGE" : "MOUNTED_NOPWCHANGE");
		return;
	}

	result = DialogBoxW (hInst, MAKEINTRESOURCEW (IDD_PASSWORDCHANGE_DLG), hwndDlg,
		(DLGPROC) PasswordChangeDlgProc);

	if (result == IDOK)
	{
		HWND tmp = GetDlgItem (hwndDlg, IDC_PASSWORD);

		switch (pwdChangeDlgMode)
		{
		case PCDM_CHANGE_PKCS5_PRF:
			Info ("PKCS5_PRF_CHANGED");
			break;

		case PCDM_ADD_REMOVE_VOL_KEYFILES:
		case PCDM_REMOVE_ALL_KEYFILES_FROM_VOL:
			Info ("KEYFILE_CHANGED");
			break;

		case PCDM_CHANGE_PASSWORD:
		default:
			Info ("PASSWORD_CHANGED");
		}
		SetFocus (tmp);
	}
}

static void SelectContainer (HWND hwndDlg)
{
	if (BrowseFiles (hwndDlg, "OPEN_VOL_TITLE", szFileName, bHistory, FALSE) == FALSE)
		return;

	AddComboItem (GetDlgItem (hwndDlg, IDC_VOLUME), szFileName, bHistory);
	EnableDisableButtons (hwndDlg);
	SetFocus (GetDlgItem (hwndDlg, IDC_DRIVELIST));
}

static void SelectPartition (HWND hwndDlg)
{
	int nResult = DialogBoxParamW (hInst, MAKEINTRESOURCEW (IDD_RAWDEVICES_DLG), hwndDlg,
		(DLGPROC) RawDevicesDlgProc, (LPARAM) & szFileName[0]);
	if (nResult == IDOK)
	{
		AddComboItem (GetDlgItem (hwndDlg, IDC_VOLUME), szFileName, bHistory);
		EnableDisableButtons (hwndDlg);
		SetFocus (GetDlgItem (hwndDlg, IDC_DRIVELIST));
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

		Info ("WIPE_CACHE");
	}
}

static void Benchmark (HWND hwndDlg)
{
	DialogBoxParamW (hInst, MAKEINTRESOURCEW (IDD_BENCHMARK_DLG), hwndDlg,
		(DLGPROC) BenchmarkDlgProc, (LPARAM) NULL);
}


static BOOL CheckMountList ()
{
	MOUNT_LIST_STRUCT current;
	GetMountList (&current);

	if (LastKnownLogicalDrives != GetLogicalDrives()
		|| memcmp (&LastKnownMountList, &current, sizeof (current)) != 0)
	{
		LastKnownMountList = current;

		ArrowWaitCursor ();
		LoadDriveLetters (GetDlgItem (MainDlg, IDC_DRIVELIST), 0);

		if (nSelectedDriveIndex >= 0)
		{
			SelectItem (GetDlgItem (MainDlg, IDC_DRIVELIST),
				(char) HIWORD (GetItemLong (GetDlgItem (MainDlg, IDC_DRIVELIST), nSelectedDriveIndex)));
		}

		NormalCursor ();
		return FALSE;
	}

	return TRUE;
}


/* Except in response to the WM_INITDIALOG message, the dialog box procedure
   should return nonzero if it processes the message, and zero if it does
   not. - see DialogProc */
BOOL CALLBACK
MainDialogProc (HWND hwndDlg, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
	WORD lw = LOWORD (wParam);
	WORD hw = HIWORD (wParam);
	DWORD mPos;

	if (lParam);		/* remove warning */

	switch (uMsg)
	{
	case WM_HOTKEY:

		HandleHotKey (hwndDlg, wParam);
		return 1;

	case WM_INITDIALOG:
		{
			int exitCode = 0;
			MainDlg = hwndDlg;

			// Set critical default options in case UsePreferences is false
			bPreserveTimestamp = defaultMountOptions.PreserveTimestamp = TRUE;

			ExtractCommandLine (hwndDlg, (char *) lParam);

			if (UsePreferences)
			{
				// General preferences
				LoadSettings (hwndDlg);

				// Keyfiles
				LoadDefaultKeyFilesParam ();
				RestoreDefaultKeyFilesParam ();
			}

			InitMainDialog (hwndDlg);

			// Wipe cache
			if (bWipe)
				WipeCache (hwndDlg);

			// Automount
			if (bAuto || (Quit && szFileName[0] != 0))
			{
				// No drive letter specified on command line
				if (commandLineDrive == 0)
					szDriveLetter[0] = GetFirstAvailableDrive () + 'A';

				if (bAutoMountDevices)
				{
					defaultMountOptions = mountOptions;
					if (FirstCmdKeyFile)
					{
						KeyFilesEnable = defaultKeyFilesParam.EnableKeyFiles = TRUE;
						FirstKeyFile = KeyFileCloneAll (FirstCmdKeyFile);
						defaultKeyFilesParam.FirstKeyFile = KeyFileCloneAll (FirstCmdKeyFile);
					}

					if (!MountAllDevices (hwndDlg, !Silent))
						exitCode = 1;
				}

				if (bAutoMountFavorites)
				{
					defaultMountOptions = mountOptions;
					if (FirstCmdKeyFile)
					{
						KeyFilesEnable = defaultKeyFilesParam.EnableKeyFiles = TRUE;
						FirstKeyFile = KeyFileCloneAll (FirstCmdKeyFile);
						defaultKeyFilesParam.FirstKeyFile = KeyFileCloneAll (FirstCmdKeyFile);
					}

					if (!MountFavoriteVolumes ())
						exitCode = 1;
				}

				if (szFileName[0] != 0 && !IsMountedVolume (szFileName))
				{
					BOOL mounted;

					// Cached password
					mounted = MountVolume (hwndDlg, szDriveLetter[0] - 'A', szFileName, NULL, bCacheInDriver, bForceMount, &mountOptions, Silent, FALSE);

					// Command line password or keyfiles
					if (!mounted && (CmdVolumePassword.Length != 0 || FirstCmdKeyFile))
					{
						BOOL reportBadPasswd = CmdVolumePassword.Length > 0;

						if (FirstCmdKeyFile)
							KeyFilesApply (&CmdVolumePassword, FirstCmdKeyFile, bPreserveTimestamp);

						mounted = MountVolume (hwndDlg, szDriveLetter[0] - 'A',
							szFileName, &CmdVolumePassword, bCacheInDriver, bForceMount,
							&mountOptions, Silent, reportBadPasswd);

						burn (&CmdVolumePassword, sizeof (CmdVolumePassword));
					}

					if (FirstCmdKeyFile)
					{
						FirstKeyFile = FirstCmdKeyFile;
						KeyFilesEnable = TRUE;
					}

					// Ask user for password
					while (!mounted && !Silent)
					{
						VolumePassword.Length = 0;

						strcpy (PasswordDlgVolume, szFileName);
						if (!AskUserPassword (hwndDlg, &VolumePassword))
							break;

						ArrowWaitCursor ();

						if (KeyFilesEnable && FirstKeyFile)
							KeyFilesApply (&VolumePassword, FirstKeyFile, bPreserveTimestamp);

						mounted = MountVolume (hwndDlg, szDriveLetter[0] - 'A', szFileName, &VolumePassword, bCacheInDriver, bForceMount, &mountOptions, FALSE, TRUE);

						burn (&VolumePassword, sizeof (VolumePassword));
						burn (&mountOptions.ProtectedHidVolPassword, sizeof (mountOptions.ProtectedHidVolPassword));

						NormalCursor ();
					}

					if (UsePreferences)
						RestoreDefaultKeyFilesParam ();

					if (mounted > 0)
					{
						if (bBeep) MessageBeep (-1);
						if (bExplore) OpenVolumeExplorerWindow (szDriveLetter[0] - 'A');
						RefreshMainDlg(hwndDlg);
					}
					else
						exitCode = 1;
				}
				else if (bExplore)
					OpenVolumeExplorerWindow (szDriveLetter[0] - 'A');
				else if (szFileName[0] != 0 && IsMountedVolume (szFileName))
					Warning ("ALREADY_MOUNTED");
					
				if (!Quit)
					RefreshMainDlg(hwndDlg);
			}

			// Wipe command line password
			if (CmdVolumePassword.Length != 0)
			{
				burn (&CmdVolumePassword, sizeof (CmdVolumePassword));
				CmdVolumePassword.Length = 0;
			}

			// Wipe command line keyfiles
			if (FirstCmdKeyFile)
			{
				if (defaultKeyFilesParam.FirstKeyFile)
					KeyFileRemoveAll (&defaultKeyFilesParam.FirstKeyFile);

				defaultKeyFilesParam.EnableKeyFiles = FALSE;

				if (!Quit)
				{
					LoadSettings (hwndDlg);
					LoadDefaultKeyFilesParam ();
					RestoreDefaultKeyFilesParam ();
				}
			}

			// Dismount
			if (cmdUnmountDrive > 0)
			{
				if (!Dismount (hwndDlg, (char)toupper(szDriveLetter[0]) - 'A'))
					exitCode = 1;
			}
			else if (cmdUnmountDrive == -1)
			{
				if (!DismountAll (hwndDlg, bForceUnmount, !Silent, UNMOUNT_MAX_AUTO_RETRIES, UNMOUNT_AUTO_RETRY_DELAY))
					exitCode = 1;
			}

			// TaskBar icon
			if (bEnableBkgTask)
			{
				TaskBarIconAdd (hwndDlg);
				if (Quit && TaskBarIconMutex != NULL)
					MainWindowHidden = TRUE;
			}

			// Quit
			if (Quit && TaskBarIconMutex == NULL)
				exit (exitCode);

			// No command line arguments or only /volume => bring active instance
			// to foreground if available
			if (NoCmdLineArgs == 0 || (CmdLineVolumeSpecified && NoCmdLineArgs <= 2))
			{
				HWND h = hwndDlg;
				EnumWindows (FindTCWindowEnum, (LPARAM) &h);

				if (h != hwndDlg)
				{
					if (CmdLineVolumeSpecified)
					{
						COPYDATASTRUCT cd;
						memcpy (&cd.dwData, WM_COPY_SET_VOLUME_NAME, 4);
						cd.lpData = szFileName;
						cd.cbData = strlen (szFileName) + 1;

						SendMessage (h, WM_COPYDATA, (WPARAM)hwndDlg, (LPARAM)&cd);
					}

					SendMessage (h, WM_APP + APP_MESSAGE_SHOW_WINDOW, 0, 0);

					ShowWindow (h, SW_SHOW);
					SetForegroundWindow (h);
					exit (0);
				}
			}

			Silent = FALSE;

			GetMountList (&LastKnownMountList);
			SetTimer (hwndDlg, 1, MAIN_TIMER_INTERVAL, NULL);

			SetFocus (GetDlgItem (hwndDlg, IDC_DRIVELIST));
		}
		return 0;

	case WM_WINDOWPOSCHANGING:
		if (MainWindowHidden)
		{
			PWINDOWPOS wp = (PWINDOWPOS)lParam;
			wp->flags &= ~SWP_SHOWWINDOW;
			return 0;
		}
		return 1;

	case WM_SYSCOMMAND:
		if (lw == IDC_ABOUT)
		{
			DialogBoxW (hInst, MAKEINTRESOURCEW (IDD_ABOUT_DLG), hwndDlg, (DLGPROC) AboutDlgProc);
			return 1;
		}
		return 0;

	case WM_HELP:
		OpenPageHelp (hwndDlg, 0);
		return 1;

	case WM_ENDSESSION:
		if (TaskBarIconMutex != NULL)
		{
			if (bDismountOnLogOff)
			{
				// Auto-dismount when user logs off
				DWORD dwResult;

				if (bWipeCacheOnAutoDismount)
					DeviceIoControl (hDriver, WIPE_CACHE, NULL, 0, NULL, 0, &dwResult, NULL);

				if (!DismountAll (hwndDlg, FALSE, FALSE, 5, 1000))
				{
					if (bForceAutoDismount)
						DismountAll (hwndDlg, TRUE, FALSE, 1, 0);
					else
						DismountAll (hwndDlg, FALSE, TRUE, 1, 0);
				}
			}

			TaskBarIconRemove (hwndDlg);
		}
		return 0;

	case WM_POWERBROADCAST:
		if (wParam == PBT_APMSUSPEND
			&& TaskBarIconMutex != NULL && bDismountOnPowerSaving)
		{
			// Auto-dismount when entering power-saving mode
			DWORD dwResult;
			DismountAll (hwndDlg, bForceAutoDismount, TRUE, UNMOUNT_MAX_AUTO_RETRIES, UNMOUNT_AUTO_RETRY_DELAY);
			
			if (bWipeCacheOnAutoDismount)
				DeviceIoControl (hDriver, WIPE_CACHE, NULL, 0, NULL, 0, &dwResult, NULL);
		}
		return 0;

	case WM_TIMER:
		{
			MainWindowHidden = !IsWindowVisible (hwndDlg);

			// Check mount list and update GUI if needed
			CheckMountList ();

			// Cache status
			if (IsPasswordCacheEmpty() == IsWindowEnabled (GetDlgItem (hwndDlg, IDC_WIPE_CACHE)))
				EnableWindow (GetDlgItem (hwndDlg, IDC_WIPE_CACHE), !IsPasswordCacheEmpty());

			if (TaskBarIconMutex != NULL)
			{
				// Idle auto-dismount
				if (MaxVolumeIdleTime > 0)
					DismountIdleVolumes ();

				// Screen saver auto-dismount
				if (bDismountOnScreenSaver)
				{
					static BOOL previousState = FALSE;
					BOOL running = FALSE;
					SystemParametersInfo (SPI_GETSCREENSAVERRUNNING, 0, &running, 0);

					if (running && !previousState)
					{
						DWORD dwResult;
						previousState = TRUE;
						DismountAll (hwndDlg, bForceAutoDismount, FALSE, UNMOUNT_MAX_AUTO_RETRIES, UNMOUNT_AUTO_RETRY_DELAY);

						if (bWipeCacheOnAutoDismount)
							DeviceIoControl (hDriver, WIPE_CACHE, NULL, 0, NULL, 0, &dwResult, NULL);
					}
					else
					{
						previousState = running;
					}
				}
			}

			// Exit background process in non-install mode or if no volume mounted
			// and no other instance active
			if (LastKnownMountList.ulMountedDrives == 0
				&& !IsWindowVisible (hwndDlg)
#ifndef _DEBUG
				&& (bCloseBkgTaskWhenNoVolumes || IsNonInstallMode ()) 
#endif
				&& GetDriverRefCount () < 2)
			{
				TaskBarIconRemove (hwndDlg);
				EndMainDlg (hwndDlg);
			}

			return 1;
		}

	case WM_APP + MSG_TASKBAR_ICON:
		{
			switch (lParam)
			{
			case WM_LBUTTONDOWN:
				SetForegroundWindow (hwndDlg);
				MainWindowHidden = FALSE;
				ShowWindow (hwndDlg, SW_SHOW);
				break;

			case WM_RBUTTONDOWN:
				{
					POINT pos;
					HMENU popup = CreatePopupMenu ();
					int sel, i, n;
					
					MainWindowHidden = !IsWindowVisible (hwndDlg);
					if (MainWindowHidden)
					{
						AppendMenuW (popup, MF_STRING, IDM_SHOW_HIDE, GetString ("SHOW_TC"));
						AppendMenu (popup, MF_SEPARATOR, 0, NULL);
					}
					else if (bEnableBkgTask
						&& (!(LastKnownMountList.ulMountedDrives == 0
						&& (bCloseBkgTaskWhenNoVolumes || IsNonInstallMode ()) 
						&& GetDriverRefCount () < 2)))
					{
						AppendMenuW (popup, MF_STRING, IDM_SHOW_HIDE, GetString ("HIDE_TC"));
						AppendMenu (popup, MF_SEPARATOR, 0, NULL);
					}
					AppendMenuW (popup, MF_STRING, IDM_MOUNT_FAVORITE_VOLUMES, GetString ("IDM_MOUNT_FAVORITE_VOLUMES"));
					AppendMenuW (popup, MF_STRING, IDM_UNMOUNTALL, GetString ("IDM_UNMOUNTALL"));
					AppendMenu (popup, MF_SEPARATOR, 0, NULL);

					for (n = 0; n < 2; n++)
					{
						for (i = 0; i < 26; i++)
						{
							if (LastKnownMountList.ulMountedDrives & (1 << i))
							{
								wchar_t s[1024];
								wchar_t *vol = LastKnownMountList.wszVolume[i];

								if (wcsstr (vol, L"\\??\\")) vol += 4;

								wsprintfW (s, L"%s %c: (%s)",
									GetString (n==0 ? "OPEN" : "DISMOUNT"),
									i + L'A', 
									vol);
								AppendMenuW (popup, MF_STRING, n*26 + 9000 + i, s);
							}
						}
						if (LastKnownMountList.ulMountedDrives != 0)
							AppendMenu (popup, MF_SEPARATOR, 0, NULL);
					}

					AppendMenuW (popup, MF_STRING, IDM_HELP, GetString ("MENU_HELP"));
					AppendMenuW (popup, MF_STRING, IDM_HOMEPAGE, GetString ("HOMEPAGE"));
					AppendMenuW (popup, MF_STRING, IDM_PREFERENCES, GetString ("IDM_PREFERENCES"));
					AppendMenuW (popup, MF_STRING, IDM_ABOUT, GetString ("IDM_ABOUT"));
					AppendMenu (popup, MF_SEPARATOR, 0, NULL);
					AppendMenuW (popup, MF_STRING, IDM_EXIT, GetString ("IDM_EXIT"));

					GetCursorPos (&pos);

					SetForegroundWindow(hwndDlg);

					sel = TrackPopupMenu (popup,
						TPM_RETURNCMD | TPM_LEFTALIGN | TPM_BOTTOMALIGN | TPM_RIGHTBUTTON,
						pos.x,
						pos.y,
						0,
						hwndDlg,
						NULL);

					if (sel >= 9000 && sel < 9026)
					{
						OpenVolumeExplorerWindow (sel - 9000);
					}
					else if (sel >= 9026 && sel < 9052)
					{
						if (CheckMountList ())
							Dismount (hwndDlg, sel - 9026);
					}
					else if (sel == IDM_SHOW_HIDE)
					{
						MainWindowHidden = !MainWindowHidden;
						ShowWindow (hwndDlg, !MainWindowHidden ? SW_SHOW : SW_HIDE);
					}
					else if (sel == IDM_EXIT)
					{
						if (LastKnownMountList.ulMountedDrives == 0
							|| AskWarnNoYes ("CONFIRM_EXIT") == IDYES)
						{
							// Close all other TC windows
							EnumWindows (CloseTCWindowsEnum, 0);

							TaskBarIconRemove (hwndDlg);
							SendMessage (hwndDlg, WM_COMMAND, sel, 0);
						}
					}
					else
					{
						SendMessage (hwndDlg, WM_COMMAND, sel, 0);
					}

					PostMessage(hwndDlg, WM_NULL, 0, 0);
					DestroyMenu (popup);
				}
			}
			return 1;
		}

	case WM_NOTIFY:

		if(wParam == IDC_DRIVELIST)
		{
			/* Single click within drive list */
			if (((LPNMHDR) lParam)->code == LVN_ITEMCHANGED && (((LPNMLISTVIEW) lParam)->uNewState & LVIS_FOCUSED ))
			{
				nSelectedDriveIndex = ((LPNMLISTVIEW) lParam)->iItem;
				EnableDisableButtons (hwndDlg);
				return 1;
			}

			/* Double click within drive list */
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
					if (GetAsyncKeyState (VK_CONTROL) < 0)
					{
						if (IDCANCEL == DialogBoxParamW (hInst, 
							MAKEINTRESOURCEW (IDD_MOUNT_OPTIONS), hwndDlg,
							(DLGPROC) MountOptionsDlgProc, (LPARAM) &mountOptions))
							return 1;

						if (mountOptions.ProtectHiddenVolume && hidVolProtKeyFilesParam.EnableKeyFiles)
							KeyFilesApply (&mountOptions.ProtectedHidVolPassword, hidVolProtKeyFilesParam.FirstKeyFile, bPreserveTimestamp);
					}

					if (CheckMountList ())
						Mount (hwndDlg, 0, 0);
				}
				return 1;
			}

			/* Right click and drag&drop operations */
			switch(((NM_LISTVIEW *) lParam)->hdr.code)
			{
			case NM_RCLICK:
			case LVN_BEGINRDRAG:
				/* If the mouse was moving while the right mouse button is pressed, popup menu would
				not open, because drag&drop operation would be initiated. Therefore, we're handling
				RMB drag-and-drop operations as well. */
				{

					/* Drive list context menu */

					int menuItem;
					HMENU popup = CreatePopupMenu ();

					SetFocus (GetDlgItem (hwndDlg, IDC_DRIVELIST));

					if (LOWORD (GetSelectedLong (GetDlgItem (hwndDlg, IDC_DRIVELIST))) == VFREE)
					{
						// No mounted volume at this drive letter
						AppendMenuW (popup, MF_STRING, IDM_MOUNT_VOLUME, GetString ("IDM_MOUNT_VOLUME"));
					}
					else
					{
						// There's a mounted volume at this drive letter
						AppendMenuW (popup, MF_STRING, IDM_UNMOUNT_VOLUME, GetString ("DISMOUNT"));
						AppendMenuW (popup, MF_STRING, IDPM_OPEN_VOLUME, GetString ("OPEN"));
						AppendMenu (popup, MF_SEPARATOR, 0, NULL);
						AppendMenuW (popup, MF_STRING, IDPM_CHECK_FILESYS, GetString ("IDPM_CHECK_FILESYS"));
						AppendMenuW (popup, MF_STRING, IDPM_REPAIR_FILESYS, GetString ("IDPM_REPAIR_FILESYS"));
						AppendMenu (popup, MF_SEPARATOR, 0, NULL);
						AppendMenuW (popup, MF_STRING, IDM_VOLUME_PROPERTIES, GetString ("IDPM_PROPERTIES"));
					}

					mPos=GetMessagePos();

					menuItem = TrackPopupMenu (popup,
						TPM_RETURNCMD | TPM_LEFTBUTTON,
						GET_X_LPARAM(mPos),
						GET_Y_LPARAM(mPos),
						0,
						hwndDlg,
						NULL);

					DestroyMenu (popup);

					switch (menuItem)
					{
					case IDPM_CHECK_FILESYS:
					case IDPM_REPAIR_FILESYS:
						{
							LPARAM lLetter = GetSelectedLong (GetDlgItem (hwndDlg, IDC_DRIVELIST));

							if (LOWORD (lLetter) != 0xffff)
							{
								wchar_t msg[1024], param[1024];
								char szTmp[32] = {0};

								sprintf (szTmp, "%c:", (char) HIWORD (lLetter));
								
								wsprintfW (msg, 
									GetString (menuItem == IDPM_REPAIR_FILESYS ? "REPAIRING_FS" : "CHECKING_FS")
									, szTmp);

								wsprintfW (param, 
									menuItem == IDPM_REPAIR_FILESYS ? 
										L"/C echo %s && (chkdsk %hs /F /X || set X=0) && pause"
										: L"/C echo %s && (chkdsk %hs || set X=0) && pause",
									msg,
									szTmp);

								ShellExecuteW (NULL, L"open", L"cmd.exe", param, NULL, SW_SHOW);
							}
						}
						break;

					case IDM_UNMOUNT_VOLUME:
						if (CheckMountList ())
							Dismount (hwndDlg, 0);
						break;

					case IDPM_OPEN_VOLUME:
						{
							int state = GetItemLong(GetDlgItem (hwndDlg, IDC_DRIVELIST), ((LPNMITEMACTIVATE)lParam)->iItem );
							nSelectedDriveIndex = ((LPNMITEMACTIVATE)lParam)->iItem;

							ArrowWaitCursor ();
							OpenVolumeExplorerWindow (HIWORD(state) - 'A');
							NormalCursor ();
						}
						break;

					case IDM_VOLUME_PROPERTIES:
						DialogBoxParamW (hInst, 
							MAKEINTRESOURCEW (IDD_VOLUME_PROPERTIES), hwndDlg,
							(DLGPROC) VolumePropertiesDlgProc, (LPARAM) 0);
						break;

					case IDM_MOUNT_VOLUME:
						if (!VolumeSelected(hwndDlg))
						{
							Warning ("NO_VOLUME_SELECTED");
						}
						else
						{
							mountOptions = defaultMountOptions;

							if (CheckMountList ())
								Mount (hwndDlg, 0, 0);
						}
						break;
					}
					return 1;
				}
			}
		}
		return 0;

	case WM_ERASEBKGND:
		return 0;

	case WM_COMMAND:

		if (lw == IDCANCEL || lw == IDC_EXIT || lw == IDM_EXIT)
		{
			EndMainDlg (hwndDlg);
			return 1;
		}

		if (lw == IDHELP || lw == IDM_HELP)
		{
			OpenPageHelp (hwndDlg, 0);
			return 1;
		}

		if (lw == IDM_ABOUT || lw == IDB_LOGO)
		{
			DialogBoxW (hInst, MAKEINTRESOURCEW (IDD_ABOUT_DLG), hwndDlg, (DLGPROC) AboutDlgProc);
			return 1;
		}

		if (lw == IDOK && LOWORD (GetSelectedLong (GetDlgItem (hwndDlg, IDC_DRIVELIST))) == VMOUNTED
			|| lw == IDM_UNMOUNT_VOLUME)
		{
			if (lw == IDM_UNMOUNT_VOLUME && LOWORD (GetSelectedLong (GetDlgItem (hwndDlg, IDC_DRIVELIST))) != VMOUNTED)
			{
				Warning ("SELECT_A_MOUNTED_VOLUME");
				return 1;
			}

			if (CheckMountList ())
				Dismount (hwndDlg, 0);
			return 1;
		}

		if ((lw == IDOK || lw == IDM_MOUNT_VOLUME || lw == IDM_MOUNT_VOLUME_OPTIONS || lw == IDC_MOUNTALL || lw == IDM_MOUNTALL) 
			&& LOWORD (GetSelectedLong (GetDlgItem (hwndDlg, IDC_DRIVELIST))) == 0xffff)
		{
			MessageBoxW (hwndDlg, GetString ("SELECT_FREE_DRIVE"), L"TrueCrypt", MB_ICONEXCLAMATION);
			return 1;
		}

		if ((lw == IDOK || lw == IDM_MOUNT_VOLUME || lw == IDM_MOUNT_VOLUME_OPTIONS))
		{
			if (!VolumeSelected(hwndDlg))
			{
				Warning ("NO_VOLUME_SELECTED");
			}
			else if (LOWORD (GetSelectedLong (GetDlgItem (hwndDlg, IDC_DRIVELIST))) == VFREE)
			{
				mountOptions = defaultMountOptions;

				if (lw == IDM_MOUNT_VOLUME_OPTIONS || GetAsyncKeyState (VK_CONTROL) < 0)
				{
					if (IDCANCEL == DialogBoxParamW (hInst, 
						MAKEINTRESOURCEW (IDD_MOUNT_OPTIONS), hwndDlg,
						(DLGPROC) MountOptionsDlgProc, (LPARAM) &mountOptions))
						return 1;

					if (mountOptions.ProtectHiddenVolume && hidVolProtKeyFilesParam.EnableKeyFiles)
						KeyFilesApply (&mountOptions.ProtectedHidVolPassword, hidVolProtKeyFilesParam.FirstKeyFile, bPreserveTimestamp);
				}

				if (CheckMountList ())
					Mount (hwndDlg, 0, 0);
			}
			return 1;
		}

		if (lw == IDC_UNMOUNTALL || lw == IDM_UNMOUNTALL)
		{
			DismountAll (hwndDlg, bForceUnmount, TRUE, UNMOUNT_MAX_AUTO_RETRIES, UNMOUNT_AUTO_RETRY_DELAY);
			return 1;
		}

		if (lw == IDC_MOUNTALL || lw == IDM_MOUNTALL)
		{
			// If Shift key is down and the password cache isn't empty, bypass password prompt
			MountAllDevices (hwndDlg, !(GetAsyncKeyState (VK_SHIFT) < 0 && !IsPasswordCacheEmpty()));
			return 1;
		}
		
		if (lw == IDC_SELECT_FILE || lw == IDM_SELECT_FILE)
		{
			SelectContainer (hwndDlg);
			return 1;
		}

		if (lw == IDC_SELECT_DEVICE || lw == IDM_SELECT_DEVICE)
		{
			SelectPartition (hwndDlg);
			return 1;
		}

		if (lw == IDC_VOLUME_TOOLS)
		{
			int menuItem;
			char volPath[TC_MAX_PATH];		/* Volume to mount */
			HMENU popup = CreatePopupMenu ();
			RECT rect;

			AppendMenuW (popup, MF_STRING, IDM_CHANGE_PASSWORD, GetString ("IDM_CHANGE_PASSWORD"));
			AppendMenuW (popup, MF_STRING, IDM_CHANGE_HEADER_KEY_DERIV_ALGO, GetString ("IDM_CHANGE_HEADER_KEY_DERIV_ALGO"));
			AppendMenu (popup, MF_SEPARATOR, 0, NULL);
			AppendMenuW (popup, MF_STRING, IDM_BACKUP_VOL_HEADER, GetString ("IDM_BACKUP_VOL_HEADER"));
			AppendMenuW (popup, MF_STRING, IDM_RESTORE_VOL_HEADER, GetString ("IDM_RESTORE_VOL_HEADER"));

			GetWindowRect (GetDlgItem (hwndDlg, IDC_VOLUME_TOOLS), &rect);

			menuItem = TrackPopupMenu (popup,
				TPM_RETURNCMD | TPM_LEFTBUTTON,
				rect.left + 2,
				rect.top + 2,
				0,
				hwndDlg,
				NULL);

			DestroyMenu (popup);

			switch (menuItem)
			{
			case IDM_CHANGE_PASSWORD:
				if (!VolumeSelected(hwndDlg))
				{
					Warning ("NO_VOLUME_SELECTED");
				}
				else
				{
					pwdChangeDlgMode = PCDM_CHANGE_PASSWORD;
					ChangePassword (hwndDlg);
				}
				break;

			case IDM_CHANGE_HEADER_KEY_DERIV_ALGO:
				if (!VolumeSelected(hwndDlg))
				{
					Warning ("NO_VOLUME_SELECTED");
				}
				else
				{
					pwdChangeDlgMode = PCDM_CHANGE_PKCS5_PRF;
					ChangePassword (hwndDlg);
				}
				break;

			case IDM_BACKUP_VOL_HEADER:
				if (!VolumeSelected(hwndDlg))
				{
					Warning ("NO_VOLUME_SELECTED");
				}
				else
				{
					GetWindowText (GetDlgItem (hwndDlg, IDC_VOLUME), volPath, sizeof (volPath));

					if (BackupVolumeHeader (hwndDlg, TRUE, volPath) != 0)
						handleWin32Error (hwndDlg);
				}
				break;

			case IDM_RESTORE_VOL_HEADER:
				if (!VolumeSelected(hwndDlg))
				{
					Warning ("NO_VOLUME_SELECTED");
				}
				else
				{
					GetWindowText (GetDlgItem (hwndDlg, IDC_VOLUME), volPath, sizeof (volPath));

					if (RestoreVolumeHeader (hwndDlg, volPath) != 0)
						handleWin32Error (hwndDlg);
				}
				break;
			}
			return 1;
		}

		if (lw == IDM_CHANGE_PASSWORD)
		{
			if (!VolumeSelected(hwndDlg))
			{
				Warning ("NO_VOLUME_SELECTED");
			}
			else
			{
				pwdChangeDlgMode = PCDM_CHANGE_PASSWORD;
				ChangePassword (hwndDlg);
			}
			return 1;
		}

		if (lw == IDM_CHANGE_HEADER_KEY_DERIV_ALGO)
		{
			if (!VolumeSelected(hwndDlg))
			{
				Warning ("NO_VOLUME_SELECTED");
			}
			else
			{
				pwdChangeDlgMode = PCDM_CHANGE_PKCS5_PRF;
				ChangePassword (hwndDlg);
			}
			return 1;
		}

		if (lw == IDC_WIPE_CACHE || lw == IDM_WIPE_CACHE)
		{
			WipeCache (hwndDlg);
			return 1;
		}

		if (lw == IDM_CLEAR_HISTORY)
		{
			ClearCombo (GetDlgItem (hwndDlg, IDC_VOLUME));
			DumpCombo (GetDlgItem (hwndDlg, IDC_VOLUME), TRUE);
			EnableDisableButtons (hwndDlg);
			return 1;
		}

		if (lw == IDC_CREATE_VOLUME || lw == IDM_CREATE_VOLUME || lw == IDM_VOLUME_WIZARD)
		{
			char t[TC_MAX_PATH];
			char *tmp;
			FILE *fhTemp;

			GetModuleFileName (NULL, t, sizeof (t));

			tmp = strrchr (t, '\\');
			if (tmp)
			{
				STARTUPINFO si;
				PROCESS_INFORMATION pi;
				ZeroMemory (&si, sizeof (si));

				strcpy (++tmp, "TrueCrypt Format.exe");

				if ((fhTemp = fopen(t, "r")) == NULL)
					Error ("VOL_CREATION_WIZARD_NOT_FOUND");
				else
					fclose (fhTemp);

				if (!CreateProcess (t, NULL, NULL, NULL, FALSE, NORMAL_PRIORITY_CLASS, NULL, NULL, &si, &pi))
				{
					handleWin32Error (hwndDlg);
				}
				else
				{
					CloseHandle (pi.hProcess);
					CloseHandle (pi.hThread);
				}
			}
			return 1;
		}

		if (lw == IDM_ADD_REMOVE_VOL_KEYFILES)
		{
			if (!VolumeSelected(hwndDlg))
			{
				Warning ("NO_VOLUME_SELECTED");
			}
			else
			{
				pwdChangeDlgMode = PCDM_ADD_REMOVE_VOL_KEYFILES;
				ChangePassword (hwndDlg);
			}
			return 1;
		}

		if (lw == IDM_REMOVE_ALL_KEYFILES_FROM_VOL)
		{
			if (!VolumeSelected(hwndDlg))
			{
				Warning ("NO_VOLUME_SELECTED");
			}
			else
			{		
				pwdChangeDlgMode = PCDM_REMOVE_ALL_KEYFILES_FROM_VOL;
				ChangePassword (hwndDlg);
			}
			return 1;
		}

		if (lw == IDM_GENERATE_KEYFILE || lw == IDM_KEYFILE_GENERATOR)
		{
			DialogBoxParamW (hInst, 
				MAKEINTRESOURCEW (IDD_KEYFILE_GENERATOR), hwndDlg,
				(DLGPROC) KeyfileGeneratorDlgProc, (LPARAM) 0);

				return 1;
		}

		if (lw == IDM_LICENSE)
		{
			//char t[TC_MAX_PATH];
			//char *tmp;

			//GetModuleFileName (NULL, t, sizeof (t));
			//tmp = strrchr (t, '\\');
			//if (tmp)
			//{
			//	strcpy (++tmp, "License.txt");
			//	ShellExecute (NULL, "open", t, NULL, NULL, SW_SHOWNORMAL);
			//}
			DialogBoxW (hInst, MAKEINTRESOURCEW (IDD_LEGAL_NOTICES_DLG), hwndDlg, (DLGPROC) LegalNoticesDlgProc);
			return 1;
		}
	
		if (lw == IDM_WEBSITE || lw == IDM_HOMEPAGE)
		{
			char tmpstr [256];

			sprintf (tmpstr, "http://www.truecrypt.org/applink.php?version=%s", VERSION_STRING);
			ShellExecute (NULL, "open", (LPCTSTR) tmpstr, NULL, NULL, SW_SHOWNORMAL);
			return 1;
		}
		else if (lw == IDM_FORUMS)
		{
			char tmpstr [256];

			sprintf (tmpstr, "http://www.truecrypt.org/applink.php?version=%s&dest=forum", VERSION_STRING);
			ShellExecute (NULL, "open", (LPCTSTR) tmpstr, NULL, NULL, SW_SHOWNORMAL);
			return 1;
		}
		else if (lw == IDM_ONLINE_TUTORIAL)
		{
			char tmpstr [256];

			sprintf (tmpstr, "http://www.truecrypt.org/applink.php?version=%s&dest=tutorial", VERSION_STRING);
			ShellExecute (NULL, "open", (LPCTSTR) tmpstr, NULL, NULL, SW_SHOWNORMAL);
			return 1;
		}
		else if (lw == IDM_ONLINE_HELP)
		{
			OpenOnlineHelp ();
			return 1;
		}
		else if (lw == IDM_FAQ)
		{
			char tmpstr [256];

			sprintf (tmpstr, "http://www.truecrypt.org/applink.php?version=%s&dest=faq", VERSION_STRING);
			ShellExecute (NULL, "open", (LPCTSTR) tmpstr, NULL, NULL, SW_SHOWNORMAL);
			return 1;
		}
		else if (lw == IDM_TC_DOWNLOADS)
		{
			char tmpstr [256];

			sprintf (tmpstr, "http://www.truecrypt.org/applink.php?version=%s&dest=downloads", VERSION_STRING);
			ShellExecute (NULL, "open", (LPCTSTR) tmpstr, NULL, NULL, SW_SHOWNORMAL);
			return 1;
		}
		else if (lw == IDM_NEWS)
		{
			char tmpstr [256];

			sprintf (tmpstr, "http://www.truecrypt.org/applink.php?version=%s&dest=news", VERSION_STRING);
			ShellExecute (NULL, "open", (LPCTSTR) tmpstr, NULL, NULL, SW_SHOWNORMAL);
			return 1;
		}
		else if (lw == IDM_VERSION_HISTORY)
		{
			char tmpstr [256];

			sprintf (tmpstr, "http://www.truecrypt.org/applink.php?version=%s&dest=history", VERSION_STRING);
			ShellExecute (NULL, "open", (LPCTSTR) tmpstr, NULL, NULL, SW_SHOWNORMAL);
			return 1;
		}
		else if (lw == IDM_BUGREPORT)
		{
			char tmpstr [256];

			sprintf (tmpstr, "http://www.truecrypt.org/applink.php?version=%s&dest=bugreport", VERSION_STRING);
			ShellExecute (NULL, "open", (LPCTSTR) tmpstr, NULL, NULL, SW_SHOWNORMAL);
			return 1;
		}
		else if (lw == IDM_CONTACT)
		{
			char tmpstr [256];

			sprintf (tmpstr, "http://www.truecrypt.org/applink.php?version=%s&dest=contact", VERSION_STRING);
			ShellExecute (NULL, "open", (LPCTSTR) tmpstr, NULL, NULL, SW_SHOWNORMAL);
			return 1;
		}

		if (lw == IDM_PREFERENCES)
		{
			if (IDOK == DialogBoxParamW (hInst, 
				MAKEINTRESOURCEW (IDD_PREFERENCES_DLG), hwndDlg,
				(DLGPROC) PreferencesDlgProc, (LPARAM) 0))
			{
				if (bEnableBkgTask)
					TaskBarIconAdd (hwndDlg);
				else
					TaskBarIconRemove (hwndDlg);
			}
			return 1;
		}

		if (lw == IDM_HOTKEY_SETTINGS)
		{
			DialogBoxParamW (hInst, 
				MAKEINTRESOURCEW (IDD_HOTKEYS_DLG), hwndDlg,
				(DLGPROC) HotkeysDlgProc, (LPARAM) 0);
			return 1;
		}

		if (lw == IDM_DEFAULT_KEYFILES || lw == IDM_SET_DEFAULT_KEYFILES)
		{
			KeyfileDefaultsDlg (hwndDlg);
			return 1;
		}

		if (lw == IDM_BENCHMARK)
		{
			Benchmark (hwndDlg);
			return 1;
		}

		if (lw == IDM_TRAVELLER)
		{
			DialogBoxParamW (hInst, 
				MAKEINTRESOURCEW (IDD_TRAVELLER_DLG), hwndDlg,
				(DLGPROC) TravellerDlgProc, (LPARAM) 0);
			return 1;
		}

		if (lw == IDM_BACKUP_VOL_HEADER)
		{
			if (!VolumeSelected(hwndDlg))
			{
				Warning ("NO_VOLUME_SELECTED");
			}
			else
			{
				char volPath[TC_MAX_PATH];		/* Volume to mount */

				GetWindowText (GetDlgItem (hwndDlg, IDC_VOLUME), volPath, sizeof (volPath));

				if (BackupVolumeHeader (hwndDlg, TRUE, volPath) != 0)
					handleWin32Error (hwndDlg);
			}
			return 1;
		}

		if (lw == IDM_RESTORE_VOL_HEADER)
		{
			if (!VolumeSelected(hwndDlg))
			{
				Warning ("NO_VOLUME_SELECTED");
			}
			else
			{
				char volPath[TC_MAX_PATH];		/* Volume to mount */

				GetWindowText (GetDlgItem (hwndDlg, IDC_VOLUME), volPath, sizeof (volPath));

				if (RestoreVolumeHeader (hwndDlg, volPath) != 0)
					handleWin32Error (hwndDlg);
			}
			return 1;
		}

		if (lw == IDM_LANGUAGE)
		{
			BOOL p;
			if (DialogBoxParamW (hInst, MAKEINTRESOURCEW (IDD_LANGUAGE), hwndDlg,
				(DLGPROC) LanguageDlgProc, (LPARAM) 0) == IDOK)
			{
				LoadLanguageFile ();
				SaveSettings (hwndDlg);

				p = LocalizationActive;
				LocalizationActive = TRUE;
				InitMainDialog (hwndDlg);
				InvalidateRect (hwndDlg, NULL, FALSE);
				LocalizationActive = p;
				DrawMenuBar (hwndDlg);
			}
			return 1;
		}

		if (lw == IDM_TEST_VECTORS)
		{
			DialogBoxParamW (hInst, MAKEINTRESOURCEW (IDD_CIPHER_TEST_DLG), hwndDlg, (DLGPROC) CipherTestDialogProc, (LPARAM) 1);

			return 1;
		}

		if (lw == IDM_REFRESH_DRIVE_LETTERS)
		{
			DWORD driveMap = GetLogicalDrives ();
			
			ArrowWaitCursor ();

			if (!(nCurrentOS == WIN_2000 && RemoteSession))
			{
				BroadcastDeviceChange (DBT_DEVICEREMOVECOMPLETE, 0, ~driveMap);
				Sleep (100);
				BroadcastDeviceChange (DBT_DEVICEARRIVAL, 0, driveMap);
			}

			LoadDriveLetters (GetDlgItem (hwndDlg, IDC_DRIVELIST), 0);

			if (nSelectedDriveIndex >= 0)
			{
				SelectItem (GetDlgItem (hwndDlg, IDC_DRIVELIST),
					(char) HIWORD (GetItemLong (GetDlgItem (hwndDlg, IDC_DRIVELIST), nSelectedDriveIndex)));
			}

			NormalCursor ();
			return 1;
		}

		if (lw == IDM_MOUNT_FAVORITE_VOLUMES)
		{
			MountFavoriteVolumes ();
			return 1;
		}

		if (lw == IDM_SAVE_FAVORITE_VOLUMES)
		{
			SaveFavoriteVolumes ();
			return 1;
		}

		if (lw == IDC_VOLUME_PROPERTIES || lw == IDM_VOLUME_PROPERTIES)
		{
			DialogBoxParamW (hInst, 
				MAKEINTRESOURCEW (IDD_VOLUME_PROPERTIES), hwndDlg,
				(DLGPROC) VolumePropertiesDlgProc, (LPARAM) 0);
			return 1;
		}

		if (lw == IDC_VOLUME && hw == CBN_EDITCHANGE)
		{
			EnableDisableButtons (hwndDlg);
			return 1;
		}

		if (lw == IDC_VOLUME && hw == CBN_SELCHANGE)
		{
			UpdateComboOrder (GetDlgItem (hwndDlg, IDC_VOLUME));
			MoveEditToCombo ((HWND) lParam, bHistory);
			PostMessage (hwndDlg, WM_APP + APP_MESSAGE_ENABLE_DISABLE, 0, 0);
			return 1;
		}

		if (lw == IDC_NO_HISTORY)
		{
			bHistory = !IsButtonChecked (GetDlgItem (hwndDlg, IDC_NO_HISTORY));
			return 1;
		}

		return 0;

	case WM_DROPFILES:
		{
			HDROP hdrop = (HDROP) wParam;
			DragQueryFile (hdrop, 0, szFileName, sizeof szFileName);
			DragFinish (hdrop);

			AddComboItem (GetDlgItem (hwndDlg, IDC_VOLUME), szFileName, bHistory);
			EnableDisableButtons (hwndDlg);
			SetFocus (GetDlgItem (hwndDlg, IDC_DRIVELIST));
		}
		return 1;

	case WM_APP + APP_MESSAGE_ENABLE_DISABLE:
		EnableDisableButtons (hwndDlg);
		return 1;

	case WM_APP + APP_MESSAGE_SHOW_WINDOW:
		ShowWindow (hwndDlg, SW_SHOW);
		MainWindowHidden = FALSE;
		return 1;

	case WM_COPYDATA:
		{
			PCOPYDATASTRUCT cd = (PCOPYDATASTRUCT)lParam;
			if (memcmp (&cd->dwData, WM_COPY_SET_VOLUME_NAME, 4) == 0)
			{
				if (cd->cbData > 0)
					AddComboItem (GetDlgItem (hwndDlg, IDC_VOLUME), (char *)cd->lpData, bHistory);

				EnableDisableButtons (hwndDlg);
				SetFocus (GetDlgItem (hwndDlg, IDC_DRIVELIST));
			}
		}
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
	char tmpPath[MAX_PATH * 2];

	/* Defaults */
	mountOptions.PreserveTimestamp = TRUE;

	/* Extract command line arguments */
	NoCmdLineArgs = nNoCommandLineArgs = Win32CommandLine (lpszCommandLine, &lpszCommandLineArgs);
	if (nNoCommandLineArgs > 0)
	{
		int i;

		for (i = 0; i < nNoCommandLineArgs; i++)
		{
			argument args[]=
			{
				{"/auto", "/a"},
				{"/beep", "/b"},
				{"/cache", "/c"},
				{"/dismount", "/d"},
				{"/explore", "/e"},
				{"/force", "/f"},
				{"/help", "/?"},
				{"/history", "/h"},
				{"/keyfile", "/k"},
				{"/letter", "/l"},
				{"/mountoption", "/m"},
				{"/password", "/p"},
				{"/quit", "/q"},
				{"/silent", "/s"},
				{"/volume", "/v"},
				{"/wipecache", "/w"}
			};

			argumentspec as;

			int nArgPos;
			int x;

			as.args = args;
			as.arg_cnt = sizeof(args)/ sizeof(args[0]);
			
			x = GetArgumentID (&as, lpszCommandLineArgs[i], &nArgPos);

			switch (x)
			{
			case 'a':
				{
					char szTmp[32];
					bAuto = TRUE;

					if (HAS_ARGUMENT == GetArgumentValue (lpszCommandLineArgs,
						nArgPos, &i, nNoCommandLineArgs, szTmp, sizeof (szTmp)))
					{
						if (!_stricmp (szTmp, "devices"))
							bAutoMountDevices = TRUE;
						else if (!_stricmp (szTmp, "favorites"))
							bAutoMountFavorites = TRUE;
					}
				}
				break;

			case 'b':
				bBeep = TRUE;
				break;

			case 'c':
				{
					char szTmp[8];
					bCacheInDriver = TRUE;

					GetArgumentValue (lpszCommandLineArgs, nArgPos, &i, nNoCommandLineArgs,
						     szTmp, sizeof (szTmp));

					if (!_stricmp(szTmp,"n") || !_stricmp(szTmp,"no"))
						bCacheInDriver = FALSE;
				}
				break;

			case 'd':

				if (HAS_ARGUMENT == GetArgumentValue (lpszCommandLineArgs, nArgPos, &i, nNoCommandLineArgs,
				     szDriveLetter, sizeof (szDriveLetter)))
					cmdUnmountDrive = toupper(szDriveLetter[0]) - 'A';
				else 
					cmdUnmountDrive = -1;

				break;

			case 'e':
				bExplore = TRUE;
				break;

			case 'f':
				bForceMount = TRUE;
				bForceUnmount = TRUE;
				break;

			case 'k':
				if (HAS_ARGUMENT == GetArgumentValue (lpszCommandLineArgs, nArgPos, &i,
					nNoCommandLineArgs, tmpPath, sizeof (tmpPath)))
				{
					KeyFile *kf;
					RelativePath2Absolute (tmpPath);
					kf = malloc (sizeof (KeyFile));
					strncpy (kf->FileName, tmpPath, sizeof (kf->FileName));
					FirstCmdKeyFile = KeyFileAdd (FirstCmdKeyFile, kf);
				}
				break;

			case 'l':
				GetArgumentValue (lpszCommandLineArgs, nArgPos, &i, nNoCommandLineArgs,
					szDriveLetter, sizeof (szDriveLetter));
				commandLineDrive = *szDriveLetter = (char) toupper (*szDriveLetter);
				break;

			case 'h':
				{
					char szTmp[8];
					bHistory = bHistoryCmdLine = TRUE;

					GetArgumentValue (lpszCommandLineArgs, nArgPos, &i, nNoCommandLineArgs,
						     szTmp, sizeof (szTmp));

					if (!_stricmp(szTmp,"n") || !_stricmp(szTmp,"no"))
						bHistory = FALSE;
				}
				break;

			case 'm':
				{
					char szTmp[16];
					if (HAS_ARGUMENT == GetArgumentValue (lpszCommandLineArgs,
						nArgPos, &i, nNoCommandLineArgs, szTmp, sizeof (szTmp)))
					{
						if (!_stricmp (szTmp, "ro") || !_stricmp (szTmp, "readonly"))
							mountOptions.ReadOnly = TRUE;

						if (!_stricmp (szTmp, "rm") || !_stricmp (szTmp, "removable"))
							mountOptions.Removable = TRUE;

						if (!_stricmp (szTmp, "ts") || !_stricmp (szTmp, "timestamp"))
							mountOptions.PreserveTimestamp = FALSE;

						if (!_stricmp (szTmp, "system"))
							mountOptions.SystemVolume = TRUE;

						if (!_stricmp (szTmp, "persistent"))
							mountOptions.PersistentVolume = TRUE;
					}
				}
				break;

			case 'p':
				GetArgumentValue (lpszCommandLineArgs, nArgPos, &i, nNoCommandLineArgs,
						     CmdVolumePassword.Text, sizeof (CmdVolumePassword.Text));
				CmdVolumePassword.Length = strlen (CmdVolumePassword.Text);
				CmdVolumePasswordValid = TRUE;
				break;

			case 'v':
				if (HAS_ARGUMENT == GetArgumentValue (lpszCommandLineArgs, nArgPos, &i,
								      nNoCommandLineArgs, szFileName, sizeof (szFileName)))
				{
					RelativePath2Absolute (szFileName);
					AddComboItem (GetDlgItem (hwndDlg, IDC_VOLUME), szFileName, bHistory);
					CmdLineVolumeSpecified = TRUE;
				}
				break;

			case 'q':
				{
					char szTmp[32];
					Quit = TRUE;
					UsePreferences = FALSE;

					if (HAS_ARGUMENT == GetArgumentValue (lpszCommandLineArgs,
						nArgPos, &i, nNoCommandLineArgs, szTmp, sizeof (szTmp)))
					{
						if (!_stricmp (szTmp, "preferences"))
							UsePreferences = TRUE;
					}

				}
				break;

			case 's':
				Silent = TRUE;
				break;

			case 'w':
				bWipe = TRUE;
				break;

			case '?':
				DialogBoxParamW (hInst, MAKEINTRESOURCEW (IDD_COMMANDHELP_DLG), hwndDlg, (DLGPROC)
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

					if (nNoCommandLineArgs == 1)
						CmdLineVolumeSpecified = TRUE;
					AddComboItem (GetDlgItem (hwndDlg, IDC_VOLUME), szFileName, bHistory);
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

	/* Call InitApp to initialize the common code */
	InitApp (hInstance);

	RegisterRedTick(hInstance);

	/* Allocate, dup, then store away the application title */
	lpszTitle = L"TrueCrypt";

	status = DriverAttach ();
	if (status != 0)
	{
		if (status == ERR_OS_ERROR)
			handleWin32Error (NULL);
		else
			handleError (NULL, status);

		AbortProcess ("NODRIVER");
	}

	VirtualLock (&VolumePassword, sizeof (VolumePassword));
	VirtualLock (&CmdVolumePassword, sizeof (CmdVolumePassword));
	VirtualLock (&mountOptions, sizeof (mountOptions));
	VirtualLock (&defaultMountOptions, sizeof (defaultMountOptions));

	/* Create the main dialog box */
	DialogBoxParamW (hInstance, MAKEINTRESOURCEW (IDD_MOUNT_DLG), NULL, (DLGPROC) MainDialogProc,
			(LPARAM) lpszCommandLine);

	/* Terminate */
	return 0;
}


BOOL TaskBarIconAdd (HWND hwnd) 
{ 
    BOOL res; 
    NOTIFYICONDATAW tnid; 
 
	// Only one icon may be created
	if (TaskBarIconMutex != NULL) return TRUE;

	TaskBarIconMutex = CreateMutex (NULL, TRUE, "TrueCryptTaskBarIcon");
	if (TaskBarIconMutex == NULL || GetLastError () == ERROR_ALREADY_EXISTS)
	{
		TaskBarIconMutex = NULL;
		return FALSE;
	}

    tnid.cbSize = sizeof (NOTIFYICONDATAW); 
    tnid.hWnd = hwnd; 
    tnid.uID = IDI_TRUECRYPT_ICON; 
    tnid.uFlags = NIF_MESSAGE | NIF_ICON | NIF_TIP; 
    tnid.uCallbackMessage = WM_APP + MSG_TASKBAR_ICON; 
	tnid.hIcon = LoadImage (hInst, MAKEINTRESOURCE (IDI_TRUECRYPT_ICON), IMAGE_ICON, 16, 16,
		nCurrentOS != WIN_2000 ? LR_DEFAULTCOLOR : LR_VGACOLOR); // Windows 2000 cannot display more than 16 fixed colors in notification tray
        
	wcscpy (tnid.szTip, L"TrueCrypt");
	
	res = Shell_NotifyIconW (NIM_ADD, &tnid); 
 
    if (tnid.hIcon) 
        DestroyIcon (tnid.hIcon); 
 
    return res; 
}


BOOL TaskBarIconRemove (HWND hwnd) 
{ 
	if (TaskBarIconMutex != NULL)
	{
		NOTIFYICONDATA tnid; 
		BOOL res;

		ZeroMemory (&tnid, sizeof (tnid));
		tnid.cbSize = sizeof(NOTIFYICONDATA); 
		tnid.hWnd = hwnd; 
		tnid.uID = IDI_TRUECRYPT_ICON; 

		res = Shell_NotifyIcon (NIM_DELETE, &tnid);
		if (TaskBarIconMutex)
		{
			CloseHandle (TaskBarIconMutex);
			TaskBarIconMutex = NULL;
		}
		return res;
	}
	else
		return FALSE;
}


void DismountIdleVolumes ()
{
	static int secCounter;
	static int InactivityTime[26];
	static unsigned __int64 LastRead[26], LastWritten[26];
	static int LastId[26];

	VOLUME_PROPERTIES_STRUCT prop;
	DWORD dwResult;
	BOOL bResult;
	int i;

	if (++secCounter % 60 != 0) return;

	for (i = 0; i < 26; i++)
	{
		if (LastKnownMountList.ulMountedDrives & (1 << i))
		{
			memset (&prop, 0, sizeof(prop));
			prop.driveNo = i;

			bResult = DeviceIoControl (hDriver, VOLUME_PROPERTIES, &prop,
				sizeof (prop), &prop, sizeof (prop), &dwResult, NULL);

			if (bResult)
			{
				if (LastRead[i] == prop.totalBytesRead 
					&& LastWritten[i] == prop.totalBytesWritten
					&& LastId[i] == prop.uniqueId)
				{
					if (++InactivityTime[i] >= MaxVolumeIdleTime)
					{
						if (bCloseDismountedWindows && CloseVolumeExplorerWindows (MainDlg, i))
							Sleep (250);

						if (DriverUnmountVolume (MainDlg, i, bForceAutoDismount) == 0)
						{
							InactivityTime[i] = 0;
							BroadcastDeviceChange (DBT_DEVICEREMOVECOMPLETE, i, 0);

							if (bWipeCacheOnAutoDismount)
								DeviceIoControl (hDriver, WIPE_CACHE, NULL, 0, NULL, 0, &dwResult, NULL);
						}
					}
				}
				else
				{
					InactivityTime[i] = 0;
					LastRead[i] = prop.totalBytesRead;
					LastWritten[i] = prop.totalBytesWritten;
					LastId[i] = prop.uniqueId;
				}
			}
		}
	}
}


BOOL MountFavoriteVolumes ()
{
	BOOL status = TRUE;
	DWORD size;
	char *favorites = LoadFile (GetConfigPath (FILE_FAVORITE_VOLUMES), &size);
	char *xml = favorites;
	char mountPoint[MAX_PATH], volume[MAX_PATH];

	if (xml == NULL) return FALSE;

	while (xml = XmlFindElement (xml, "volume"))
	{
		int drive;
		XmlAttribute (xml, "mountpoint", mountPoint, sizeof (mountPoint));
		XmlNodeText (xml, volume, sizeof (volume));
		drive = toupper (mountPoint[0]) - 'A';

		if ((LastKnownMountList.ulMountedDrives & (1 << drive)) == 0)
		{
			if (!Mount (MainDlg, drive, volume))
				status = FALSE;
			LoadDriveLetters (GetDlgItem (MainDlg, IDC_DRIVELIST), 0);
		}

		xml++;
	}

	free (favorites);
	return status;
}


void SaveFavoriteVolumes ()
{
	if (AskNoYes("CONFIRM_SAVE_FAVORITE_VOL") == IDYES)
	{
		FILE *f;
		int i, cnt = 0;

		f = fopen (GetConfigPath (FILE_FAVORITE_VOLUMES), "w");
		if (f == NULL)
		{
			handleWin32Error (MainDlg);
			return;
		}

		XmlWriteHeader (f);
		fputs ("\n\t<favorites>", f);

		for (i = 0; i < 26; i++)
		{
			if (LastKnownMountList.ulMountedDrives & (1 << i))
			{
				fwprintf (f, L"\n\t\t<volume mountpoint=\"%hc:\\\">%s</volume>", i + 'A', 
					&LastKnownMountList.wszVolume[i][(LastKnownMountList.wszVolume[i][1] == L'?') ? 4 : 0]);
				cnt++;
			}
		}

		fputs ("\n\t</favorites>", f);
		XmlWriteFooter (f);
		fclose (f);

		if (cnt == 0)
			remove (GetConfigPath (FILE_FAVORITE_VOLUMES));		// No volumes to save as favorite

		Info ("FAVORITE_VOLUMES_SAVED");
	}
}


static void SaveDefaultKeyFilesParam (void)
{
	if (defaultKeyFilesParam.FirstKeyFile == NULL)
	{
		/* No keyfiles selected */ 
		remove (GetConfigPath (FILE_DEFAULT_KEYFILES));
	}
	else
	{
		FILE *f;
		KeyFile *kf = FirstKeyFile;

		f = fopen (GetConfigPath (FILE_DEFAULT_KEYFILES), "w");
		if (f == NULL)
		{
			handleWin32Error (MainDlg);
			return;
		}

		XmlWriteHeader (f);

		fputs ("\n\t<defaultkeyfiles>", f);

		while (kf != NULL)
		{
			fwprintf (f, L"\n\t\t<keyfile>%hs</keyfile>", kf->FileName); 
			kf = kf->Next;
		}

		fputs ("\n\t</defaultkeyfiles>", f); 

		XmlWriteFooter (f);

		fclose (f);
		return;
	}
}


static void KeyfileDefaultsDlg (HWND hwndDlg)
{
	KeyFilesDlgParam param;

	param.EnableKeyFiles = defaultKeyFilesParam.EnableKeyFiles;
	param.FirstKeyFile = defaultKeyFilesParam.FirstKeyFile;

	if (DialogBoxParamW (hInst,
		MAKEINTRESOURCEW (IDD_KEYFILES), hwndDlg,
		(DLGPROC) KeyFilesDlgProc, (LPARAM) &param) == IDOK)
	{
		if (!param.EnableKeyFiles || AskYesNo("CONFIRM_SAVE_DEFAULT_KEYFILES") == IDYES)
		{
			KeyFileRemoveAll (&defaultKeyFilesParam.FirstKeyFile);
			defaultKeyFilesParam.EnableKeyFiles = param.EnableKeyFiles;
			defaultKeyFilesParam.FirstKeyFile = param.FirstKeyFile;

			RestoreDefaultKeyFilesParam ();
			SaveDefaultKeyFilesParam ();
		}
	}
}


static void HandleHotKey (HWND hwndDlg, WPARAM wParam)
{
	DWORD dwResult;
	BOOL success = TRUE;

	switch (wParam)
	{
	case HK_AUTOMOUNT_DEVICES:
		MountAllDevices (hwndDlg, TRUE);

		if (bPlaySoundOnHotkeyMountDismount)
			MessageBeep(-1);

		break;

	case HK_DISMOUNT_ALL:
		DismountAll (hwndDlg, FALSE, TRUE, UNMOUNT_MAX_AUTO_RETRIES, UNMOUNT_AUTO_RETRY_DELAY);

		if (bPlaySoundOnHotkeyMountDismount)
			MessageBeep(-1);

		if (bDisplayMsgBoxOnHotkeyDismount)
			Info ("DISMOUNT_ALL_ATTEMPT_COMPLETED");

		break;

	case HK_FORCE_DISMOUNT_ALL_AND_WIPE:
		success = DismountAll (hwndDlg, TRUE, FALSE, UNMOUNT_MAX_AUTO_RETRIES, UNMOUNT_AUTO_RETRY_DELAY);
		success &= DeviceIoControl (hDriver, WIPE_CACHE, NULL, 0, NULL, 0, &dwResult, NULL);
		if (success)
		{
			if (bPlaySoundOnHotkeyMountDismount)
				MessageBeep(-1);

			if (bDisplayMsgBoxOnHotkeyDismount)
				Info ("VOLUMES_DISMOUNTED_CACHE_WIPED");
		}
		break;

	case HK_FORCE_DISMOUNT_ALL_AND_WIPE_AND_EXIT:
		success = DismountAll (hwndDlg, TRUE, FALSE, UNMOUNT_MAX_AUTO_RETRIES, UNMOUNT_AUTO_RETRY_DELAY);
		success &= DeviceIoControl (hDriver, WIPE_CACHE, NULL, 0, NULL, 0, &dwResult, NULL);
		if (success)
		{
			if (bPlaySoundOnHotkeyMountDismount)
				MessageBeep(-1);

			if (bDisplayMsgBoxOnHotkeyDismount)
				Info ("VOLUMES_DISMOUNTED_CACHE_WIPED");
		}
		TaskBarIconRemove (hwndDlg);
		EndMainDlg (hwndDlg);
		break;

	case HK_MOUNT_FAVORITE_VOLUMES:
		MountFavoriteVolumes ();

		if (bPlaySoundOnHotkeyMountDismount)
			MessageBeep(-1);

		break;

	case HK_SHOW_HIDE_MAIN_WINDOW:
		MainWindowHidden = !IsWindowVisible (hwndDlg);
		MainWindowHidden = !MainWindowHidden;
		
		if (!MainWindowHidden)
				SetForegroundWindow (hwndDlg);
		ShowWindow (hwndDlg, !MainWindowHidden ? SW_SHOW : SW_HIDE);
		break;
	}
}