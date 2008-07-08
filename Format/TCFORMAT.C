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

#include <stdlib.h>
#include <limits.h>
#include <time.h>
#include <errno.h>
#include <io.h>
#include <sys/stat.h>
#include <shlobj.h>

#include "Crypto.h"
#include "Apidrvr.h"
#include "Dlgcode.h"
#include "Language.h"
#include "Combo.h"
#include "Registry.h"
#include "Boot/Windows/BootDefs.h"
#include "Common/Common.h"
#include "Common/BootEncryption.h"
#include "Common/Dictionary.h"
#include "Common/Endian.h"
#include "Common/resource.h"
#include "Random.h"
#include "Fat.h"
#include "Resource.h"
#include "TcFormat.h"
#include "Format.h"
#include "FormatCom.h"
#include "Password.h"
#include "Progress.h"
#include "Tests.h"
#include "Cmdline.h"
#include "Volumes.h"
#include "Wipe.h"
#include "Xml.h"

using namespace TrueCrypt;

enum wizard_pages
{
	INTRO_PAGE,
		SYSENC_TYPE_PAGE,
				SYSENC_HIDDEN_OS_REQ_CHECK_PAGE,
		SYSENC_SPAN_PAGE,
		SYSENC_PRE_DRIVE_ANALYSIS_PAGE,
		SYSENC_DRIVE_ANALYSIS_PAGE,
		SYSENC_MULTI_BOOT_MODE_PAGE,
		SYSENC_MULTI_BOOT_SYS_EQ_BOOT_PAGE,
		SYSENC_MULTI_BOOT_NBR_SYS_DRIVES_PAGE,
		SYSENC_MULTI_BOOT_ADJACENT_SYS_PAGE,
		SYSENC_MULTI_BOOT_NONWIN_BOOT_LOADER_PAGE,
		SYSENC_MULTI_BOOT_OUTCOME_PAGE,
	VOLUME_TYPE_PAGE,
			HIDDEN_VOL_WIZARD_MODE_PAGE,
	FILE_PAGE,
			HIDDEN_VOL_HOST_PRE_CIPHER_PAGE,
			HIDDEN_VOL_PRE_CIPHER_PAGE,
	CIPHER_PAGE,
	SIZE_PAGE,
			HIDDEN_VOL_HOST_PASSWORD_PAGE,
	PASSWORD_PAGE,
	FILESYS_PAGE,
		SYSENC_COLLECTING_RANDOM_DATA_PAGE,
		SYSENC_KEYS_GEN_PAGE,
		SYSENC_RESCUE_DISK_CREATION_PAGE,
		SYSENC_RESCUE_DISK_BURN_PAGE,
		SYSENC_RESCUE_DISK_VERIFIED_PAGE,
		SYSENC_WIPE_MODE_PAGE,
		SYSENC_PRETEST_INFO_PAGE,
		SYSENC_PRETEST_RESULT_PAGE,
		SYSENC_ENCRYPTION_PAGE,
	FORMAT_PAGE,
	FORMAT_FINISHED_PAGE
};

enum timer_ids
{
	TIMER_ID_RANDVIEW = 0xff,
	TIMER_ID_SYSENC_PROGRESS,
	TIMER_ID_SYSENC_DRIVE_ANALYSIS_PROGRESS,
	TIMER_ID_KEYB_LAYOUT_GUARD
};

#define TIMER_INTERVAL_RANDVIEW							30	// Refresh interval for Random pool display
#define TIMER_INTERVAL_SYSENC_PROGRESS					30
#define TIMER_INTERVAL_SYSENC_DRIVE_ANALYSIS_PROGRESS	100
#define TIMER_INTERVAL_KEYB_LAYOUT_GUARD				10

enum sys_encryption_cmd_line_switches
{
	SYSENC_COMMAND_NONE = 0,
	SYSENC_COMMAND_RESUME,
	SYSENC_COMMAND_STARTUP_SEQ_RESUME,
	SYSENC_COMMAND_ENCRYPT,
	SYSENC_COMMAND_DECRYPT,
	SYSENC_COMMAND_CREATE_HIDDEN_OS,
	SYSENC_COMMAND_CREATE_HIDDEN_OS_ELEV
};

typedef struct 
{
	int NumberOfSysDrives;			// Number of drives that contain an operating system. -1: unknown, 1: one, 2: two or more
	int MultipleSystemsOnDrive;		// Multiple systems are installed on the drive where the currently running system resides.  -1: unknown, 0: no, 1: yes
	int BootLoaderLocation;			// Boot loader (boot manager) installed in: 1: MBR/1st cylinder, 0: partition/bootsector: -1: unknown
	int BootLoaderBrand;			// -1: unknown, 0: Microsoft Windows, 1: any non-Windows boot manager/loader
	int SystemOnBootDrive;			// If the currently running operating system is installed on the boot drive. -1: unknown, 0: no, 1: yes
} SYSENC_MULTIBOOT_CFG;

#define SYSENC_PAUSE_RETRY_INTERVAL		100
#define SYSENC_PAUSE_RETRIES			200

// Expected duration of system drive analysis, in ms 
#define SYSENC_DRIVE_ANALYSIS_ETA		(4*60000)

BootEncryption			*BootEncObj = NULL;
BootEncryptionStatus	BootEncStatus;

HWND hCurPage = NULL;		/* Handle to current wizard page */
int nCurPageNo = -1;		/* The current wizard page */
int nLastPageNo = -1;
volatile int WizardMode = DEFAULT_VOL_CREATION_WIZARD_MODE; /* IMPORTANT: Never change this value directly -- always use ChangeWizardMode() instead. */
volatile BOOL bHiddenOS = FALSE;		/* If TRUE, we are performing or (or supposed to perform) actions relating to an operating system installed in a hidden volume (i.e., encrypting a decoy OS partition or creating the outer/hidden volume for the hidden OS). To determine or set the phase of the process, call ChangeHiddenOSCreationPhase() and DetermineHiddenOSCreationPhase()) */
BOOL bDirectSysEncMode = FALSE;
BOOL bDirectSysEncModeCommand = SYSENC_COMMAND_NONE;
BOOL DirectDeviceEncMode = FALSE;
int nNeedToStoreFilesOver4GB = 0;		/* Whether the user wants to be able to store files larger than 4GB on the volume: -1 = Undecided or error, 0 = No, 1 = Yes */
int nVolumeEA = 1;			/* Default encryption algorithm */
BOOL bSystemEncryptionInProgress = FALSE;		/* TRUE when encrypting/decrypting the system partition/drive (FALSE when paused). */
BOOL bWholeSysDrive = FALSE;	/* Whether to encrypt the entire system drive or just the system partition. */
static BOOL bSystemEncryptionStatusChanged = FALSE;   /* TRUE if this instance changed the value of SystemEncryptionStatus (it's set to FALSE each time the system encryption settings are saved to the config file). This value is to be treated as protected -- only the wizard can change this value (others may only read it). */
volatile BOOL bSysEncDriveAnalysisInProgress = FALSE;
volatile BOOL bSysEncDriveAnalysisTimeOutOccurred = FALSE;
int SysEncDetectHiddenSectors = -1;		/* Whether the user wants us to detect and encrypt the Host Protect Area (if any): -1 = Undecided or error, 0 = No, 1 = Yes */
int SysEncDriveAnalysisStart;
BOOL bDontVerifyRescueDisk = FALSE;
BOOL bFirstSysEncResumeDone = FALSE;
int nMultiBoot = 0;			/* The number of operating systems installed on the computer, according to the user. 0: undetermined, 1: one, 2: two or more */
volatile BOOL bHiddenVol = FALSE;	/* If true, we are (or will be) creating a hidden volume. */
volatile BOOL bHiddenVolHost = FALSE;	/* If true, we are (or will be) creating the host volume (called "outer") for a hidden volume. */
volatile BOOL bHiddenVolDirect = FALSE;	/* If true, the wizard omits creating a host volume in the course of the process of hidden volume creation. */
volatile BOOL bHiddenVolFinished = FALSE;
int hiddenVolHostDriveNo = -1;	/* Drive letter for the volume intended to host a hidden volume. */
BOOL bRemovableHostDevice = FALSE;	/* TRUE when creating a device/partition-hosted volume on a removable device. State undefined when creating file-hosted volumes. */
int realClusterSize;		/* Parameter used when determining the maximum possible size of a hidden volume. */
int hash_algo = DEFAULT_HASH_ALGORITHM;	/* Which PRF to use in header key derivation (PKCS #5) and in the RNG. */
unsigned __int64 nUIVolumeSize = 0;		/* The volume size. Important: This value is not in bytes. It has to be multiplied by nMultiplier. Do not use this value when actually creating the volume (it may chop off 512 bytes, if it is not a multiple of 1024 bytes). */
unsigned __int64 nVolumeSize = 0;		/* The volume size, in bytes. */
unsigned __int64 nHiddenVolHostSize = 0;	/* Size of the hidden volume host, in bytes */
__int64 nMaximumHiddenVolSize = 0;		/* Maximum possible size of the hidden volume, in bytes */
__int64 nbrFreeClusters = 0;
int nMultiplier = 1024*1024;		/* Size selection multiplier. */
char szFileName[TC_MAX_PATH+1];	/* The file selected by the user */
char szDiskFile[TC_MAX_PATH+1];	/* Fully qualified name derived from szFileName */
char szRescueDiskISO[TC_MAX_PATH+1];	/* The filename and path to the Rescue Disk ISO file to be burned (for boot encryption) */

volatile BOOL bThreadCancel = FALSE;	/* TRUE if the user cancels the volume formatting */
volatile BOOL bThreadRunning = FALSE;	/* Is the thread running */

volatile BOOL bConfirmQuit = FALSE;		/* If TRUE, the user is asked to confirm exit when he clicks the X icon, Exit, etc. */
volatile BOOL bConfirmQuitSysEncPretest = FALSE;

BOOL bDevice = FALSE;		/* Is this a partition volume ? */

BOOL showKeys = TRUE;
volatile HWND hMasterKey = NULL;		/* Text box showing hex dump of the master key */
volatile HWND hHeaderKey = NULL;		/* Text box showing hex dump of the header key */
volatile HWND hRandPool = NULL;		/* Text box showing hex dump of the random pool */
volatile HWND hRandPoolSys = NULL;	/* Text box showing hex dump of the random pool for system encryption */
volatile HWND hPasswordInputField = NULL;	/* Password input field */
volatile HWND hVerifyPasswordInputField = NULL;		/* Verify-password input field */

HBITMAP hbmWizardBitmapRescaled = NULL;

char OrigKeyboardLayout [8+1] = "00000409";
BOOL bKeyboardLayoutChanged = FALSE;		/* TRUE if the keyboard layout was changed to the standard US keyboard layout (from any other layout). */ 
BOOL bKeybLayoutAltKeyWarningShown = FALSE;	/* TRUE if the user has been informed that it is not possible to type characters by pressing keys while the right Alt key is held down. */ 

BOOL bWarnDeviceFormatAdvanced = TRUE;
BOOL bWarnOuterVolSuitableFileSys = TRUE;

Password volumePassword;			/* User password */
char szVerify[MAX_PASSWORD + 1];	/* Tmp password buffer */
char szRawPassword[MAX_PASSWORD + 1];	/* Password before keyfile was applied to it */

BOOL bHistoryCmdLine = FALSE; /* History control is always disabled */
BOOL ComServerMode = FALSE;

int nPbar = 0;			/* Control ID of progress bar:- for format code */

char HeaderKeyGUIView [KEY_GUI_VIEW_SIZE];
char MasterKeyGUIView [KEY_GUI_VIEW_SIZE];

#define RANDPOOL_DISPLAY_COLUMNS	15
#define RANDPOOL_DISPLAY_ROWS		8
#define RANDPOOL_DISPLAY_BYTE_PORTION	(RANDPOOL_DISPLAY_COLUMNS * RANDPOOL_DISPLAY_ROWS)
#define RANDPOOL_DISPLAY_SIZE	(RANDPOOL_DISPLAY_BYTE_PORTION * 3 + RANDPOOL_DISPLAY_ROWS + 2)
unsigned char randPool [RANDPOOL_DISPLAY_BYTE_PORTION];
unsigned char lastRandPool [RANDPOOL_DISPLAY_BYTE_PORTION];
unsigned char outRandPoolDispBuffer [RANDPOOL_DISPLAY_SIZE];
BOOL bDisplayPoolContents = TRUE;

volatile BOOL bSparseFileSwitch = FALSE;
volatile BOOL quickFormat = FALSE;	/* WARNING: Meaning of this variable depends on bSparseFileSwitch. If bSparseFileSwitch is TRUE, this variable represents the sparse file flag. */
volatile int fileSystem = FILESYS_NONE;	
volatile int clusterSize = 0;

SYSENC_MULTIBOOT_CFG	SysEncMultiBootCfg;
wchar_t SysEncMultiBootCfgOutcome [4096] = {'N','/','A',0};

static BOOL ElevateWholeWizardProcess (string arguments)
{
	char modPath[MAX_PATH];

	if (IsAdmin())
		return TRUE;

	if (!IsUacSupported())
		return IsAdmin();

	GetModuleFileName (NULL, modPath, sizeof (modPath));

	if ((int)ShellExecute (MainDlg, "runas", modPath, (string("/q UAC ") + arguments).c_str(), NULL, SW_SHOWNORMAL) > 32)
	{				
		exit (0);
	}
	else
	{
		Error ("UAC_INIT_ERROR");
		return FALSE;
	}
}

static void WipePasswordsAndKeyfiles (void)
{
	char tmp[MAX_PASSWORD+1];

	// Attempt to wipe passwords stored in the input field buffers
	memset (tmp, 'X', MAX_PASSWORD);
	tmp [MAX_PASSWORD] = 0;
	SetWindowText (hPasswordInputField, tmp);
	SetWindowText (hVerifyPasswordInputField, tmp);

	burn (&szVerify[0], sizeof (szVerify));
	burn (&volumePassword, sizeof (volumePassword));
	burn (&szRawPassword[0], sizeof (szRawPassword));

	SetWindowText (hPasswordInputField, "");
	SetWindowText (hVerifyPasswordInputField, "");

	KeyFileRemoveAll (&FirstKeyFile);
	KeyFileRemoveAll (&defaultKeyFilesParam.FirstKeyFile);
}

static void localcleanup (void)
{
	char tmp[RANDPOOL_DISPLAY_SIZE+1];

	if (WizardMode == WIZARD_MODE_SYS_DEVICE
		&& InstanceHasSysEncMutex ())
	{
		try
		{
			BootEncStatus = BootEncObj->GetStatus();

			if (BootEncStatus.SetupInProgress)
			{
				BootEncObj->AbortSetup ();
			}
		}
		catch (...)
		{
			// NOP
		}
	}

	WipePasswordsAndKeyfiles ();

	Randfree ();

	burn (HeaderKeyGUIView, sizeof(HeaderKeyGUIView));
	burn (MasterKeyGUIView, sizeof(MasterKeyGUIView));
	burn (randPool, sizeof(randPool));
	burn (lastRandPool, sizeof(lastRandPool));
	burn (outRandPoolDispBuffer, sizeof(outRandPoolDispBuffer));
	burn (szFileName, sizeof(szFileName));
	burn (szDiskFile, sizeof(szDiskFile));

	// Attempt to wipe the GUI fields showing portions of randpool, of the master and header keys
	memset (tmp, 'X', sizeof(tmp));
	tmp [sizeof(tmp)-1] = 0;
	SetWindowText (hRandPool, tmp);
	SetWindowText (hRandPoolSys, tmp);
	SetWindowText (hMasterKey, tmp);
	SetWindowText (hHeaderKey, tmp);

	UnregisterRedTick (hInst);

	/* Delete buffered bitmaps (if any) */
	if (hbmWizardBitmapRescaled != NULL)
	{
		DeleteObject ((HGDIOBJ) hbmWizardBitmapRescaled);
		hbmWizardBitmapRescaled = NULL;
	}

	/* Cleanup common code resources */
	cleanup ();

	if (BootEncObj != NULL)
	{
		delete BootEncObj;
		BootEncObj = NULL;
	}
}

static BOOL CALLBACK BroadcastSysEncCfgUpdateCallb (HWND hwnd, LPARAM lParam)
{
	if (GetWindowLongPtr (hwnd, GWLP_USERDATA) == (LONG_PTR) 'TRUE')
	{
		char name[1024] = { 0 };
		GetWindowText (hwnd, name, sizeof (name) - 1);
		if (hwnd != MainDlg && strstr (name, "TrueCrypt"))
		{
			PostMessage (hwnd, TC_APPMSG_SYSENC_CONFIG_UPDATE, 0, 0);
		}
	}
	return TRUE;
}

static BOOL BroadcastSysEncCfgUpdate (void)
{
	BOOL bSuccess = FALSE;
	EnumWindows (BroadcastSysEncCfgUpdateCallb, (LPARAM) &bSuccess);
	return bSuccess;
}

// IMPORTANT: This function may be called only by Format (other modules can only _read_ the system encryption config).
// Returns TRUE if successful (otherwise FALSE)
static BOOL SaveSysEncSettings (HWND hwndDlg)
{
	FILE *f;

	if (!bSystemEncryptionStatusChanged)
		return TRUE;

	if (hwndDlg == NULL && MainDlg != NULL)
		hwndDlg = MainDlg;

	if (!CreateSysEncMutex ())
		return FALSE;		// Only one instance that has the mutex can modify the system encryption settings

	if (SystemEncryptionStatus == SYSENC_STATUS_NONE)
	{
		if (remove (GetConfigPath (FILE_SYSTEM_ENCRYPTION_CFG)) != 0)
		{
			Error ("CANNOT_SAVE_SYS_ENCRYPTION_SETTINGS");
			return FALSE;
		}

		bSystemEncryptionStatusChanged = FALSE;
		BroadcastSysEncCfgUpdate ();
		return TRUE;
	}

	f = fopen (GetConfigPath (FILE_SYSTEM_ENCRYPTION_CFG), "w");
	if (f == NULL)
	{
		Error ("CANNOT_SAVE_SYS_ENCRYPTION_SETTINGS");
		handleWin32Error (hwndDlg);
		return FALSE;
	}

	if (XmlWriteHeader (f) < 0

	|| fputs ("\n\t<sysencryption>", f) < 0

	|| fprintf (f, "\n\t\t<config key=\"SystemEncryptionStatus\">%d</config>", SystemEncryptionStatus) < 0

	|| fprintf (f, "\n\t\t<config key=\"WipeMode\">%d</config>", (int) nWipeMode) < 0

	|| fputs ("\n\t</sysencryption>", f) < 0

	|| XmlWriteFooter (f) < 0)
	{
		handleWin32Error (hwndDlg);
		fclose (f);
		Error ("CANNOT_SAVE_SYS_ENCRYPTION_SETTINGS");
		return FALSE;
	}

	TCFlushFile (f);

	fclose (f);

	bSystemEncryptionStatusChanged = FALSE;
	BroadcastSysEncCfgUpdate ();

	return TRUE;
}

// WARNING: This function may take a long time to finish
static unsigned int DetermineHiddenOSCreationPhase (void)
{
	unsigned int phase = TC_HIDDEN_OS_CREATION_PHASE_NONE;

	try
	{
		phase = BootEncObj->GetHiddenOSCreationPhase();
	}
	catch (Exception &e)
	{
		e.Show (MainDlg);
		AbortProcess("ERR_GETTING_SYSTEM_ENCRYPTION_STATUS");
	}

	return phase;
}

// IMPORTANT: This function may be called only by Format (other modules can only _read_ the status).
// Returns TRUE if successful (otherwise FALSE)
static BOOL ChangeHiddenOSCreationPhase (int newPhase) 
{
	if (!CreateSysEncMutex ())
	{
		Error ("SYSTEM_ENCRYPTION_IN_PROGRESS_ELSEWHERE");
		return FALSE;
	}

	try
	{
		BootEncObj->SetHiddenOSCreationPhase (newPhase);
	}
	catch (Exception &e)
	{
		e.Show (MainDlg);
		return FALSE;
	}

	//// The contents of the following items might be inappropriate after a change of the phase
	//szFileName[0] = 0;
	//szDiskFile[0] = 0;
	//nUIVolumeSize = 0;
	//nVolumeSize = 0;

	return TRUE;
}

// IMPORTANT: This function may be called only by Format (other modules can only _read_ the system encryption status).
// Returns TRUE if successful (otherwise FALSE)
static BOOL ChangeSystemEncryptionStatus (int newStatus)
{
	if (!CreateSysEncMutex ())
	{
		Error ("SYSTEM_ENCRYPTION_IN_PROGRESS_ELSEWHERE");
		return FALSE;		// Only one instance that has the mutex can modify the system encryption settings
	}

	SystemEncryptionStatus = newStatus;
	bSystemEncryptionStatusChanged = TRUE;

	if (newStatus == SYSENC_STATUS_NONE && !IsHiddenOSRunning())
	{
		if (DetermineHiddenOSCreationPhase() != TC_HIDDEN_OS_CREATION_PHASE_NONE
			&& !ChangeHiddenOSCreationPhase (TC_HIDDEN_OS_CREATION_PHASE_NONE))
			return FALSE;
	}

	if (!SaveSysEncSettings (MainDlg))
	{
		return FALSE;
	}

	return TRUE;
}

// If the return code of this function is ignored and newWizardMode == WIZARD_MODE_SYS_DEVICE, then this function
// may be called only after CreateSysEncMutex() returns TRUE. It returns TRUE if successful (otherwise FALSE).
static BOOL ChangeWizardMode (int newWizardMode)
{
	if (WizardMode != newWizardMode)	
	{
		if (WizardMode == WIZARD_MODE_SYS_DEVICE || newWizardMode == WIZARD_MODE_SYS_DEVICE)
		{
			if (newWizardMode == WIZARD_MODE_SYS_DEVICE)
			{
				if (!CreateSysEncMutex ())
				{
					Error ("SYSTEM_ENCRYPTION_IN_PROGRESS_ELSEWHERE");
					return FALSE;
				}
			}

			// If the previous mode was different, the password may have been typed using a different
			// keyboard layout (which might confuse the user and cause other problems if system encryption
			// was or will be involved).
			WipePasswordsAndKeyfiles();	
		}

		if (newWizardMode == WIZARD_MODE_NONSYS_DEVICE && !IsAdmin() && IsUacSupported())
		{
			if (!ElevateWholeWizardProcess ("/e"))
				return FALSE;
		}

		// The contents of the following items may be inappropriate after a change of mode
		szFileName[0] = 0;
		szDiskFile[0] = 0;
		nUIVolumeSize = 0;
		nVolumeSize = 0;

		WizardMode = newWizardMode;
	}

	bDevice = (WizardMode != WIZARD_MODE_FILE_CONTAINER);

	if (newWizardMode != WIZARD_MODE_SYS_DEVICE 
		&& !bHiddenOS)
	{
		CloseSysEncMutex ();	
	}

	return TRUE;
}

// Determines whether the wizard directly affects system encryption in any way.
// Note, for example, that when the user enters a password for a hidden volume that is to host a hidden OS,
// WizardMode is NOT set to WIZARD_MODE_SYS_DEVICE. The keyboard layout, however, has to be US. That's why 
// this function has to be called instead of checking the value of WizardMode.
static BOOL SysEncInEffect (void)
{
	return (WizardMode == WIZARD_MODE_SYS_DEVICE
		|| CreatingHiddenSysVol());
}

static BOOL CreatingHiddenSysVol (void)
{
	return (bHiddenOS 
		&& bHiddenVol && !bHiddenVolHost);
}

static void LoadSettings (HWND hwndDlg)
{
	LoadSysEncSettings (hwndDlg);

	defaultKeyFilesParam.EnableKeyFiles = FALSE;

	bStartOnLogon =	ConfigReadInt ("StartOnLogon", FALSE);

	HiddenSectorDetectionStatus = ConfigReadInt ("HiddenSectorDetectionStatus", 0);

	bHistory = ConfigReadInt ("SaveVolumeHistory", FALSE);

	if (hwndDlg != NULL)
	{
		LoadCombo (GetDlgItem (hwndDlg, IDC_COMBO_BOX));
		return;
	}

	if (bHistoryCmdLine)
		return;
}

static void SaveSettings (HWND hwndDlg)
{
	WaitCursor ();

	if (hwndDlg != NULL)
		DumpCombo (GetDlgItem (hwndDlg, IDC_COMBO_BOX), !bHistory);

	ConfigWriteBegin ();

	ConfigWriteInt ("StartOnLogon",	bStartOnLogon);

	ConfigWriteInt ("HiddenSectorDetectionStatus", HiddenSectorDetectionStatus);

	ConfigWriteInt ("SaveVolumeHistory", bHistory);

	if (GetPreferredLangId () != NULL)
		ConfigWriteString ("Language", GetPreferredLangId ());

	ConfigWriteEnd ();

	NormalCursor ();
}

// WARNING: This function does NOT cause immediate application exit (use e,g. return 1 after calling it
// from a DialogProc function).
static void EndMainDlg (HWND hwndDlg)
{
	if (nCurPageNo == FILE_PAGE)
	{
		if (IsWindow(GetDlgItem(hCurPage, IDC_NO_HISTORY)))
			bHistory = !IsButtonChecked (GetDlgItem (hCurPage, IDC_NO_HISTORY));

		MoveEditToCombo (GetDlgItem (hCurPage, IDC_COMBO_BOX), bHistory);
		SaveSettings (hCurPage);
	}
	else 
	{
		SaveSettings (NULL);
	}

	SaveSysEncSettings (hwndDlg);

	if (!bHistory)
		CleanLastVisitedMRU ();

	EndDialog (hwndDlg, 0);
}

// Returns TRUE if system encryption or decryption had been or is in progress and has not been completed
static BOOL SysEncryptionOrDecryptionRequired (void)
{
	/* If you update this function, revise SysEncryptionOrDecryptionRequired() in Mount.c as well. */

	static BootEncryptionStatus locBootEncStatus;

	try
	{
		locBootEncStatus = BootEncObj->GetStatus();
	}
	catch (Exception &e)
	{
		e.Show (MainDlg);
	}

	return (SystemEncryptionStatus == SYSENC_STATUS_ENCRYPTING
		|| SystemEncryptionStatus == SYSENC_STATUS_DECRYPTING
		|| 
		(
			locBootEncStatus.DriveMounted 
			&& 
			(
				locBootEncStatus.ConfiguredEncryptedAreaStart != locBootEncStatus.EncryptedAreaStart
				|| locBootEncStatus.ConfiguredEncryptedAreaEnd != locBootEncStatus.EncryptedAreaEnd
			)
		)
	);
}

// Returns TRUE if the system partition/drive is completely encrypted
static BOOL SysDriveOrPartitionFullyEncrypted (BOOL bSilent)
{
	/* If you update this function, revise SysDriveOrPartitionFullyEncrypted() in Mount.c as well. */

	static BootEncryptionStatus locBootEncStatus;

	try
	{
		locBootEncStatus = BootEncObj->GetStatus();
	}
	catch (Exception &e)
	{
		if (!bSilent)
			e.Show (MainDlg);
	}

	return (!locBootEncStatus.SetupInProgress
		&& locBootEncStatus.ConfiguredEncryptedAreaEnd != 0
		&& locBootEncStatus.ConfiguredEncryptedAreaEnd != -1
		&& locBootEncStatus.ConfiguredEncryptedAreaStart == locBootEncStatus.EncryptedAreaStart
		&& locBootEncStatus.ConfiguredEncryptedAreaEnd == locBootEncStatus.EncryptedAreaEnd);
}

// Adds or removes the wizard to/from the system startup sequence
static void ManageStartupSeqWiz (BOOL bRemove, const char *arg)
{
	char regk [64];

	// Split the string in order to prevent some antivirus packages from falsely reporting  
	// TrueCrypt Format.exe to contain a possible Trojan horse because of this string (heuristic scan).
	sprintf (regk, "%s%s", "Software\\Microsoft\\Windows\\Curren", "tVersion\\Run");

	if (!bRemove)
	{
		char exe[MAX_PATH * 2] = { '"' };
		GetModuleFileName (NULL, exe + 1, sizeof (exe) - 1);

		if (strlen (arg) > 0)
		{
			strcat (exe, "\" ");
			strcat (exe, arg);
		}

		WriteRegistryString (regk, "TrueCrypt Format", exe);
	}
	else
		DeleteRegistryValue (regk, "TrueCrypt Format");
}

// This functions is to be used when the wizard mode needs to be changed to WIZARD_MODE_SYS_DEVICE.
// If the function fails to switch the mode, it returns FALSE (otherwise TRUE).
BOOL SwitchWizardToSysEncMode (void)
{
	WaitCursor ();

	try
	{
		BootEncStatus = BootEncObj->GetStatus();
		bWholeSysDrive = BootEncObj->SystemPartitionCoversWholeDrive();
	}
	catch (Exception &e)
	{
		e.Show (MainDlg);
		Error ("ERR_GETTING_SYSTEM_ENCRYPTION_STATUS");
		NormalCursor ();
		return FALSE;
	}

	// From now on, we should be the only instance of the TC wizard allowed to deal with system encryption
	if (!CreateSysEncMutex ())
	{
		Warning ("SYSTEM_ENCRYPTION_IN_PROGRESS_ELSEWHERE");
		NormalCursor ();
		return FALSE;
	}

	// User-mode app may have crashed and its mutex may have gotten lost, so we need to check the driver status too
	if (BootEncStatus.SetupInProgress)
	{
		if (AskWarnYesNo ("SYSTEM_ENCRYPTION_RESUME_PROMPT") == IDYES)
		{
			if (SystemEncryptionStatus != SYSENC_STATUS_ENCRYPTING
				&& SystemEncryptionStatus != SYSENC_STATUS_DECRYPTING)
			{
				// The config file with status was lost or not written correctly
				if (!ResolveUnknownSysEncDirection ())
				{
					CloseSysEncMutex ();	
					NormalCursor ();
					return FALSE;
				}
			}

			bDirectSysEncMode = TRUE;
			ChangeWizardMode (WIZARD_MODE_SYS_DEVICE);
			LoadPage (MainDlg, SYSENC_ENCRYPTION_PAGE);
			NormalCursor ();
			return TRUE;
		}
		else
		{
			CloseSysEncMutex ();	
			Error ("SYS_ENCRYPTION_OR_DECRYPTION_IN_PROGRESS");
			NormalCursor ();
			return FALSE;
		}
	}

	if (BootEncStatus.DriveMounted
		|| BootEncStatus.DriveEncrypted
		|| SysEncryptionOrDecryptionRequired ())
	{

		if (!SysDriveOrPartitionFullyEncrypted (FALSE)
			&& AskWarnYesNo ("SYSTEM_ENCRYPTION_RESUME_PROMPT") == IDYES)
		{
			if (SystemEncryptionStatus == SYSENC_STATUS_NONE)
			{
				// If the config file with status was lost or not written correctly, we
				// don't know whether to encrypt or decrypt (but we know that encryption or
				// decryption is required). Ask the user to select encryption, decryption, 
				// or cancel
				if (!ResolveUnknownSysEncDirection ())
				{
					CloseSysEncMutex ();	
					NormalCursor ();
					return FALSE;
				}
			}

			bDirectSysEncMode = TRUE;
			ChangeWizardMode (WIZARD_MODE_SYS_DEVICE);
			LoadPage (MainDlg, SYSENC_ENCRYPTION_PAGE);
			NormalCursor ();
			return TRUE;
		}
		else
		{
			CloseSysEncMutex ();	
			Error ("SETUP_FAILED_BOOT_DRIVE_ENCRYPTED");
			NormalCursor ();
			return FALSE;
		}
	}
	else
	{
		// Check compliance with requirements for boot encryption

		if (!IsAdmin())
		{
			if (!IsUacSupported())
			{
				Warning ("ADMIN_PRIVILEGES_WARN_DEVICES");
			}
		}

		try
		{
			BootEncObj->CheckRequirements ();
		}
		catch (Exception &e)
		{
			CloseSysEncMutex ();	
			e.Show (MainDlg);
			NormalCursor ();
			return FALSE;
		}

		if (!ChangeWizardMode (WIZARD_MODE_SYS_DEVICE))
		{
			NormalCursor ();
			return FALSE;
		}

		if (bSysDriveSelected || bSysPartitionSelected)
		{
			// The user selected the non-sys-device wizard mode but then selected a system device

			bWholeSysDrive = (bSysDriveSelected && !bSysPartitionSelected);

			bSysDriveSelected = FALSE;
			bSysPartitionSelected = FALSE;

			try
			{
				if (!bHiddenVol)
				{
					if (bWholeSysDrive && !BootEncObj->SystemPartitionCoversWholeDrive())
					{
						if (nCurrentOS != WIN_VISTA_OR_LATER)
						{
							if (BootEncObj->SystemDriveContainsExtendedPartition())
							{
								bWholeSysDrive = FALSE;

								Error ("WDE_UNSUPPORTED_FOR_EXTENDED_PARTITIONS");

								if (AskYesNo ("ASK_ENCRYPT_PARTITION_INSTEAD_OF_DRIVE") == IDNO)
								{
									ChangeWizardMode (WIZARD_MODE_NONSYS_DEVICE);
									return FALSE;
								}
							}
							else
								Warning ("WDE_EXTENDED_PARTITIONS_WARNING");
						}
					}
					else if (BootEncObj->SystemPartitionCoversWholeDrive() 
						&& !bWholeSysDrive)
						bWholeSysDrive = (AskYesNo ("WHOLE_SYC_DEVICE_RECOM") == IDYES);
				}

			}
			catch (Exception &e)
			{
				e.Show (MainDlg);
				return FALSE;
			}

			if (!bHiddenVol)
			{
				// Skip SYSENC_SPAN_PAGE and SYSENC_TYPE_PAGE as the user already made the choice
				LoadPage (MainDlg, bWholeSysDrive ? SYSENC_PRE_DRIVE_ANALYSIS_PAGE : SYSENC_MULTI_BOOT_MODE_PAGE);	
			}
			else
			{
				// The user selected the non-sys-device wizard mode but then selected a system device.
				// In addition, he selected the hidden volume mode.

				if (bWholeSysDrive)
					Warning ("HIDDEN_OS_PRECLUDES_SINGLE_KEY_WDE");

				bWholeSysDrive = FALSE;

				LoadPage (MainDlg, SYSENC_TYPE_PAGE);
			}
		}
		else
			LoadPage (MainDlg, SYSENC_TYPE_PAGE);

		NormalCursor ();
		return TRUE;
	}

	CloseSysEncMutex ();	
	NormalCursor ();
	return FALSE;
}

void SwitchWizardToFileContainerMode (void)
{
	ChangeWizardMode (WIZARD_MODE_FILE_CONTAINER);

	LoadPage (MainDlg, FILE_PAGE);

	NormalCursor ();
}

void SwitchWizardToNonSysDeviceMode (void)
{
	ChangeWizardMode (WIZARD_MODE_NONSYS_DEVICE);

	LoadPage (MainDlg, VOLUME_TYPE_PAGE);

	NormalCursor ();
}

BOOL SwitchWizardToHiddenOSMode (void)
{
	if (SwitchWizardToSysEncMode())
	{
		if (nCurPageNo != SYSENC_ENCRYPTION_PAGE)	// If the user did not manually choose to resume encryption or decryption of the system partition/drive
		{
			bHiddenOS = TRUE;
			bHiddenVol = TRUE;
			bHiddenVolHost = TRUE;
			bHiddenVolDirect = FALSE;
			bWholeSysDrive = FALSE;

			if (bDirectSysEncModeCommand == SYSENC_COMMAND_CREATE_HIDDEN_OS_ELEV)
			{
				// Some of the requirements for hidden OS should have already been checked by the wizard process
				// that launched us (in order to elevate), but we must recheck them. Otherwise, an advanced user 
				// could bypass the checks by using the undocumented CLI switch. Moreover, some requirements
				// can be checked only at this point (when we are elevated).
				try
				{
					BootEncObj->CheckRequirementsHiddenOS ();

					if (BootEncObj->IsPagingFileActive ())
					{
						AbortProcess ("DISABLE_SWAP_FILE_BEFORE_CREATING_HIDDEN_OS");
					}
				}
				catch (Exception &e)
				{
					e.Show (MainDlg);
					return FALSE;
				}

				LoadPage (MainDlg, SYSENC_MULTI_BOOT_MODE_PAGE);
			}
			else
				LoadPage (MainDlg, SYSENC_HIDDEN_OS_REQ_CHECK_PAGE);

			NormalCursor ();
		}
		else
			return TRUE;
	}
	else
		return FALSE;

	return TRUE;
}

// Use this function e.g. if the config file with the system encryption settings was lost or not written
// correctly, and we don't know whether to encrypt or decrypt (but we know that encryption or decryption
// is required). Returns FALSE if failed or cancelled.
static BOOL ResolveUnknownSysEncDirection (void)
{
	if (CreateSysEncMutex ())
	{
		if (SystemEncryptionStatus != SYSENC_STATUS_ENCRYPTING
			&& SystemEncryptionStatus != SYSENC_STATUS_DECRYPTING)
		{
			try
			{
				BootEncStatus = BootEncObj->GetStatus();
			}
			catch (Exception &e)
			{
				e.Show (MainDlg);
				Error ("ERR_GETTING_SYSTEM_ENCRYPTION_STATUS");
				return FALSE;
			}

			if (BootEncStatus.SetupInProgress)
			{
				return ChangeSystemEncryptionStatus (
					(BootEncStatus.SetupMode != SetupDecryption) ? SYSENC_STATUS_ENCRYPTING : SYSENC_STATUS_DECRYPTING);
			}
			else
			{
				// Ask the user to select encryption, decryption, or cancel

				char *tmpStr[] = {0,
					!BootEncStatus.DriveEncrypted ? "CHOOSE_ENCRYPT_OR_DECRYPT_FINALIZE_DECRYPT_NOTE" : "CHOOSE_ENCRYPT_OR_DECRYPT",
					"ENCRYPT",
					"DECRYPT",
					"IDCANCEL",
					0};

				switch (AskMultiChoice ((void **) tmpStr))
				{
				case 1:
					return ChangeSystemEncryptionStatus (SYSENC_STATUS_ENCRYPTING);
				case 2:
					return ChangeSystemEncryptionStatus (SYSENC_STATUS_DECRYPTING);
				default:
					return FALSE;
				}
			}
		}
		else
			return TRUE;
	}
	else
	{
		Error ("SYSTEM_ENCRYPTION_IN_PROGRESS_ELSEWHERE");
		return FALSE;
	}
}

// This function should be used to resolve inconsistencies that might lead to a deadlock (inability to encrypt or
// decrypt the system partition/drive and to uninstall TrueCrypt). The function removes the system encryption key 
// data ("volume header"), the TrueCrypt boot loader, restores the original system loader (if available),
// unregisters the boot driver, etc. Note that if the system partition/drive is encrypted, it will start decrypting
// it in the background (therefore, it should be used when the system partition/drive is not encrypted, ideally).
// Exceptions are handled and errors are reported within the function. Returns TRUE if successful.
static BOOL ForceRemoveSysEnc (void)
{
	if (CreateSysEncMutex ())	// If no other instance is currently taking care of system encryption
	{
		BootEncryptionStatus locBootEncStatus;

		try
		{
			locBootEncStatus = BootEncObj->GetStatus();

			if (locBootEncStatus.SetupInProgress)
				BootEncObj->AbortSetupWait ();

			locBootEncStatus = BootEncObj->GetStatus();

			if (locBootEncStatus.DriveMounted)
			{
				// Remove the header
				BootEncObj->StartDecryption ();			
				locBootEncStatus = BootEncObj->GetStatus();

				while (locBootEncStatus.SetupInProgress)
				{
					Sleep (100);
					locBootEncStatus = BootEncObj->GetStatus();
				}

				BootEncObj->CheckEncryptionSetupResult ();
			}

			Sleep (50);
		}
		catch (Exception &e)
		{
			e.Show (MainDlg);
			return FALSE;
		}

		try
		{
			locBootEncStatus = BootEncObj->GetStatus();

			if (!locBootEncStatus.DriveMounted)
				BootEncObj->Deinstall ();
		}
		catch (Exception &e)
		{
			e.Show (MainDlg);
			return FALSE;
		}

		return TRUE;
	}
	else
		return FALSE;
}

// Returns 0 if there's an error.
__int64 GetSystemPartitionSize (void)
{
	try
	{
		return BootEncObj->GetSystemDriveConfiguration().SystemPartition.Info.PartitionLength.QuadPart;
	}
	catch (Exception &e)
	{
		e.Show (MainDlg);
		return 0;
	}
}

void ComboSelChangeEA (HWND hwndDlg)
{
	LPARAM nIndex = SendMessage (GetDlgItem (hwndDlg, IDC_COMBO_BOX), CB_GETCURSEL, 0, 0);

	if (nIndex == CB_ERR)
	{
		SetWindowText (GetDlgItem (hwndDlg, IDC_BOX_HELP), "");
	}
	else
	{
		char name[100];
		wchar_t auxLine[4096];
		wchar_t hyperLink[256] = { 0 };
		char cipherIDs[5];
		int i, cnt = 0;

		nIndex = SendMessage (GetDlgItem (hwndDlg, IDC_COMBO_BOX), CB_GETITEMDATA, nIndex, 0);
		EAGetName (name, nIndex);

		if (strcmp (name, "AES") == 0)
		{
			swprintf_s (hyperLink, sizeof(hyperLink) / 2, GetString ("MORE_INFO_ABOUT"), name);

			SetWindowTextW (GetDlgItem (hwndDlg, IDC_BOX_HELP), GetString ("AES_HELP"));
		}
		else if (strcmp (name, "Serpent") == 0)
		{
			swprintf_s (hyperLink, sizeof(hyperLink) / 2, GetString ("MORE_INFO_ABOUT"), name);
				
			SetWindowTextW (GetDlgItem (hwndDlg, IDC_BOX_HELP), GetString ("SERPENT_HELP"));
		}
		else if (strcmp (name, "Twofish") == 0)
		{
			swprintf_s (hyperLink, sizeof(hyperLink) / 2, GetString ("MORE_INFO_ABOUT"), name);

			SetWindowTextW (GetDlgItem (hwndDlg, IDC_BOX_HELP), GetString ("TWOFISH_HELP"));
		}
		else if (EAGetCipherCount (nIndex) > 1)
		{
			// Cascade
			cipherIDs[cnt++] = i = EAGetLastCipher(nIndex);
			while (i = EAGetPreviousCipher(nIndex, i))
			{
				cipherIDs[cnt] = i;
				cnt++; 
			}

			switch (cnt)	// Number of ciphers in the cascade
			{
			case 2:
				swprintf (auxLine, GetString ("TWO_LAYER_CASCADE_HELP"), 
					CipherGetName (cipherIDs[1]),
					CipherGetKeySize (cipherIDs[1])*8,
					CipherGetName (cipherIDs[0]),
					CipherGetKeySize (cipherIDs[0])*8);
				break;

			case 3:
				swprintf (auxLine, GetString ("THREE_LAYER_CASCADE_HELP"), 
					CipherGetName (cipherIDs[2]),
					CipherGetKeySize (cipherIDs[2])*8,
					CipherGetName (cipherIDs[1]),
					CipherGetKeySize (cipherIDs[1])*8,
					CipherGetName (cipherIDs[0]),
					CipherGetKeySize (cipherIDs[0])*8);
				break;
			}

			wcscpy_s (hyperLink, sizeof(hyperLink) / 2, GetString ("IDC_LINK_MORE_INFO_ABOUT_CIPHER"));

			SetWindowTextW (GetDlgItem (hwndDlg, IDC_BOX_HELP), auxLine);
		}
		else
		{
			// No info available for this encryption algorithm
			SetWindowTextW (GetDlgItem (hwndDlg, IDC_BOX_HELP), L"");
		}


		// Update hyperlink
		SetWindowTextW (GetDlgItem (hwndDlg, IDC_LINK_MORE_INFO_ABOUT_CIPHER), hyperLink);
		AccommodateTextField (hwndDlg, IDC_LINK_MORE_INFO_ABOUT_CIPHER, FALSE);
	}
}

static void VerifySizeAndUpdate (HWND hwndDlg, BOOL bUpdate)
{
	BOOL bEnable = TRUE;
	char szTmp[50];
	__int64 lTmp;
	size_t i;
	static unsigned __int64 nLastVolumeSize = 0;

	GetWindowText (GetDlgItem (hwndDlg, IDC_SIZEBOX), szTmp, sizeof (szTmp));

	for (i = 0; i < strlen (szTmp); i++)
	{
		if (szTmp[i] >= '0' && szTmp[i] <= '9')
			continue;
		else
		{
			bEnable = FALSE;
			break;
		}
	}

	if (IsButtonChecked (GetDlgItem (hwndDlg, IDC_KB)))
		nMultiplier = BYTES_PER_KB;
	else
		nMultiplier = BYTES_PER_MB;

	if (bDevice && !(bHiddenVol && !bHiddenVolHost))	// If raw device but not a hidden volume
	{
		lTmp = nVolumeSize;
		i = 1;
	}
	else
	{
		i = nMultiplier;
		lTmp = _atoi64 (szTmp);
	}

	if (bEnable)
	{
		if (lTmp * i < (bHiddenVolHost ? TC_MIN_HIDDEN_VOLUME_HOST_SIZE : (bHiddenVol ? TC_MIN_HIDDEN_VOLUME_SIZE : TC_MIN_VOLUME_SIZE)))
			bEnable = FALSE;

		if (!bHiddenVolHost && bHiddenVol)
		{
			if (lTmp * i > nMaximumHiddenVolSize)
				bEnable = FALSE;
		}
		else
		{
			if (lTmp * i > (bHiddenVolHost ? TC_MAX_HIDDEN_VOLUME_HOST_SIZE : TC_MAX_VOLUME_SIZE))
				bEnable = FALSE;
		}

		if (lTmp * i % SECTOR_SIZE != 0)
			bEnable = FALSE;
	}

	if (bUpdate)
	{
		nUIVolumeSize = lTmp;

		if (!bDevice || (bHiddenVol && !bHiddenVolHost))	// Update only if it's not a raw device or if it's a hidden volume
			nVolumeSize = i * lTmp;
	}

	EnableWindow (GetDlgItem (GetParent (hwndDlg), IDC_NEXT), bEnable);

	if (nVolumeSize != nLastVolumeSize)
	{
		// Change of volume size may make some file systems allowed or disallowed, so the default filesystem must
		// be reselected.
		fileSystem = FILESYS_NONE;	
		nLastVolumeSize = nVolumeSize;
	}
}

static void UpdateWizardModeControls (HWND hwndDlg, int setWizardMode)
{
	SendMessage (GetDlgItem (hwndDlg, IDC_FILE_CONTAINER),
		BM_SETCHECK,
		setWizardMode == WIZARD_MODE_FILE_CONTAINER ? BST_CHECKED : BST_UNCHECKED,
		0);

	SendMessage (GetDlgItem (hwndDlg, IDC_NONSYS_DEVICE),
		BM_SETCHECK,
		setWizardMode == WIZARD_MODE_NONSYS_DEVICE ? BST_CHECKED : BST_UNCHECKED,
		0);

	SendMessage (GetDlgItem (hwndDlg, IDC_SYS_DEVICE),
		BM_SETCHECK,
		setWizardMode == WIZARD_MODE_SYS_DEVICE ? BST_CHECKED : BST_UNCHECKED,
		0);
}

static int GetSelectedWizardMode (HWND hwndDlg)
{
	if (IsButtonChecked (GetDlgItem (hwndDlg, IDC_FILE_CONTAINER)))
		return WIZARD_MODE_FILE_CONTAINER;

	if (IsButtonChecked (GetDlgItem (hwndDlg, IDC_NONSYS_DEVICE)))
		return WIZARD_MODE_NONSYS_DEVICE;

	if (IsButtonChecked (GetDlgItem (hwndDlg, IDC_SYS_DEVICE)))
		return WIZARD_MODE_SYS_DEVICE;

	return DEFAULT_VOL_CREATION_WIZARD_MODE;
}

static void RefreshMultiBootControls (HWND hwndDlg)
{
	SendMessage (GetDlgItem (hwndDlg, IDC_SINGLE_BOOT),
		BM_SETCHECK,
		nMultiBoot == 1 ? BST_CHECKED : BST_UNCHECKED,
		0);

	SendMessage (GetDlgItem (hwndDlg, IDC_MULTI_BOOT),
		BM_SETCHECK,
		nMultiBoot > 1 ? BST_CHECKED : BST_UNCHECKED,
		0);
}

// -1 = Undecided or error, 0 = No, 1 = Yes
static int Get2RadButtonPageAnswer (void)
{
	if (IsButtonChecked (GetDlgItem (hCurPage, IDC_CHOICE1)))
		return 1;

	if (IsButtonChecked (GetDlgItem (hCurPage, IDC_CHOICE2)))
		return 0;

	return -1;
}

// 0 = No, 1 = Yes
static void Update2RadButtonPage (int answer)
{
	SendMessage (GetDlgItem (hCurPage, IDC_CHOICE1),
		BM_SETCHECK,
		answer == 1 ? BST_CHECKED : BST_UNCHECKED,
		0);

	SendMessage (GetDlgItem (hCurPage, IDC_CHOICE2),
		BM_SETCHECK,
		answer == 0 ? BST_CHECKED : BST_UNCHECKED,
		0);
}

// -1 = Undecided, 0 = No, 1 = Yes
static void Init2RadButtonPageYesNo (int answer)
{
	SetWindowTextW (GetDlgItem (hCurPage, IDC_CHOICE1), GetString ("UISTR_YES"));
	SetWindowTextW (GetDlgItem (hCurPage, IDC_CHOICE2), GetString ("UISTR_NO"));

	SetWindowTextW (GetDlgItem (MainDlg, IDC_NEXT), GetString ("NEXT"));
	SetWindowTextW (GetDlgItem (MainDlg, IDC_PREV), GetString ("PREV"));
	SetWindowTextW (GetDlgItem (MainDlg, IDCANCEL), GetString ("CANCEL"));

	EnableWindow (GetDlgItem (MainDlg, IDC_NEXT), answer >= 0);
	EnableWindow (GetDlgItem (MainDlg, IDC_PREV), TRUE);

	Update2RadButtonPage (answer);
}

static void UpdateSysEncProgressBar (void)
{
	BootEncryptionStatus locBootEncStatus;
	static BOOL lastTransformWaitingForIdle = FALSE;

	try
	{
		locBootEncStatus = BootEncObj->GetStatus();
	}
	catch (...)
	{
		return;
	}

	if (locBootEncStatus.EncryptedAreaEnd == -1 
		|| locBootEncStatus.EncryptedAreaStart == -1)
	{
		UpdateProgressBarProc (0);
	}
	else
	{
		UpdateProgressBarProc ((locBootEncStatus.EncryptedAreaEnd - locBootEncStatus.EncryptedAreaStart + 1) / SECTOR_SIZE);

		if (locBootEncStatus.SetupInProgress)
		{
			wchar_t tmpStr[100];

			// Status

			if (locBootEncStatus.TransformWaitingForIdle)
				wcscpy (tmpStr, GetString ("PROGRESS_STATUS_WAITING"));
			else
				wcscpy (tmpStr, GetString (SystemEncryptionStatus == SYSENC_STATUS_DECRYPTING ? "PROGRESS_STATUS_DECRYPTING" : "PROGRESS_STATUS_ENCRYPTING"));

			wcscat (tmpStr, L" ");

			SetWindowTextW (GetDlgItem (hCurPage, IDC_WRITESPEED), tmpStr);

			// Remainining time 

			if (locBootEncStatus.TransformWaitingForIdle)
			{
				// The estimate cannot be computed correctly when speed is zero
				SetWindowTextW (GetDlgItem (hCurPage, IDC_TIMEREMAIN), GetString ("N_A_UISTR"));
			}

			if (locBootEncStatus.TransformWaitingForIdle != lastTransformWaitingForIdle)
			{
				if (lastTransformWaitingForIdle)
				{
					// Estimate of remaining time and other values may have been heavily distorted as the speed
					// was zero. Therefore, we're going to reinitialize the progress bar and all related variables.
					InitSysEncProgressBar ();
				}
				lastTransformWaitingForIdle = locBootEncStatus.TransformWaitingForIdle;
			}
		}
	}
}

static void InitSysEncProgressBar (void)
{
	BootEncryptionStatus locBootEncStatus;

	try
	{
		locBootEncStatus = BootEncObj->GetStatus();
	}
	catch (...)
	{
		return;
	}

	if (locBootEncStatus.ConfiguredEncryptedAreaEnd == -1 
		|| locBootEncStatus.ConfiguredEncryptedAreaStart == -1)
		return;

	InitProgressBar ((locBootEncStatus.ConfiguredEncryptedAreaEnd 
		- locBootEncStatus.ConfiguredEncryptedAreaStart + 1) / SECTOR_SIZE,
		(locBootEncStatus.EncryptedAreaEnd == locBootEncStatus.EncryptedAreaStart || locBootEncStatus.EncryptedAreaEnd == -1) ?
		0 :	locBootEncStatus.EncryptedAreaEnd - locBootEncStatus.EncryptedAreaStart + 1,
		SystemEncryptionStatus == SYSENC_STATUS_DECRYPTING,
		TRUE,
		TRUE,
		TRUE);
}

static void UpdateSysEncControls (void)
{
	BootEncryptionStatus locBootEncStatus;

	try
	{
		locBootEncStatus = BootEncObj->GetStatus();
	}
	catch (...)
	{
		return;
	}

	EnableWindow (GetDlgItem (hCurPage, IDC_WIPE_MODE), 
		!locBootEncStatus.SetupInProgress 
		&& SystemEncryptionStatus == SYSENC_STATUS_ENCRYPTING
		&& !bHiddenOS);

	SetWindowTextW (GetDlgItem (hCurPage, IDC_PAUSE),
		GetString (locBootEncStatus.SetupInProgress ? "IDC_PAUSE" : "RESUME"));

	EnableWindow (GetDlgItem (MainDlg, IDC_NEXT), !locBootEncStatus.SetupInProgress && !bFirstSysEncResumeDone);

	if (!locBootEncStatus.SetupInProgress)
	{
		wchar_t tmpStr[100];

		wcscpy (tmpStr, GetString ((SysDriveOrPartitionFullyEncrypted (TRUE) || !locBootEncStatus.DriveMounted) ?
			"PROGRESS_STATUS_FINISHED" : "PROGRESS_STATUS_PAUSED"));
		wcscat (tmpStr, L" ");

		// Status
		SetWindowTextW (GetDlgItem (hCurPage, IDC_WRITESPEED), tmpStr);

		if (SysDriveOrPartitionFullyEncrypted (TRUE) || SystemEncryptionStatus == SYSENC_STATUS_NONE)
		{
			wcscpy (tmpStr, GetString ("PROCESSED_PORTION_100_PERCENT"));
			wcscat (tmpStr, L" ");

			SetWindowTextW (GetDlgItem (hCurPage, IDC_BYTESWRITTEN), tmpStr);
		}

		SetWindowText (GetDlgItem (hCurPage, IDC_TIMEREMAIN), " ");
	}
}

static void SysEncPause (void)
{
	BootEncryptionStatus locBootEncStatus;

	if (CreateSysEncMutex ())
	{
		EnableWindow (GetDlgItem (hCurPage, IDC_PAUSE), FALSE);

		try
		{
			locBootEncStatus = BootEncObj->GetStatus();
		}
		catch (Exception &e)
		{
			e.Show (MainDlg);
			Error ("ERR_GETTING_SYSTEM_ENCRYPTION_STATUS");
			EnableWindow (GetDlgItem (hCurPage, IDC_PAUSE), TRUE);
			return;
		}

		if (!locBootEncStatus.SetupInProgress)
		{
			EnableWindow (GetDlgItem (hCurPage, IDC_PAUSE), TRUE);
			return;
		}

		WaitCursor ();

		try
		{
			int attempts = SYSENC_PAUSE_RETRIES;

			BootEncObj->AbortSetup ();

			locBootEncStatus = BootEncObj->GetStatus();

			while (locBootEncStatus.SetupInProgress && attempts > 0)
			{
				Sleep (SYSENC_PAUSE_RETRY_INTERVAL);
				attempts--;
				locBootEncStatus = BootEncObj->GetStatus();
			}

			if (!locBootEncStatus.SetupInProgress)
				BootEncObj->CheckEncryptionSetupResult ();

		}
		catch (Exception &e)
		{
			e.Show (MainDlg);
		}

		NormalCursor ();

		if (locBootEncStatus.SetupInProgress)
		{
			SetTimer (MainDlg, TIMER_ID_SYSENC_PROGRESS, TIMER_INTERVAL_SYSENC_PROGRESS, NULL);
			EnableWindow (GetDlgItem (hCurPage, IDC_PAUSE), TRUE);
			Error ("FAILED_TO_INTERRUPT_SYSTEM_ENCRYPTION");
			return;
		}
		
		UpdateSysEncControls ();
		EnableWindow (GetDlgItem (hCurPage, IDC_PAUSE), TRUE);
	}
	else
		Error ("SYSTEM_ENCRYPTION_IN_PROGRESS_ELSEWHERE");
}


static void SysEncResume (void)
{
	BootEncryptionStatus locBootEncStatus;

	if (CreateSysEncMutex ())
	{
		EnableWindow (GetDlgItem (hCurPage, IDC_PAUSE), FALSE);

		try
		{
			locBootEncStatus = BootEncObj->GetStatus();
		}
		catch (Exception &e)
		{
			e.Show (MainDlg);
			Error ("ERR_GETTING_SYSTEM_ENCRYPTION_STATUS");
			EnableWindow (GetDlgItem (hCurPage, IDC_PAUSE), TRUE);
			return;
		}

		if (locBootEncStatus.SetupInProgress)
		{
			bSystemEncryptionInProgress = TRUE;
			UpdateSysEncControls ();
			SetTimer (MainDlg, TIMER_ID_SYSENC_PROGRESS, TIMER_INTERVAL_SYSENC_PROGRESS, NULL);
			EnableWindow (GetDlgItem (hCurPage, IDC_PAUSE), TRUE);
			return;
		}

		bSystemEncryptionInProgress = FALSE;
		WaitCursor ();

		try
		{
			switch (SystemEncryptionStatus)
			{
			case SYSENC_STATUS_ENCRYPTING:

				BootEncObj->StartEncryption (nWipeMode);	
				break;

			case SYSENC_STATUS_DECRYPTING:

				if (locBootEncStatus.DriveMounted)	// If the drive is not encrypted we will just deinstall
					BootEncObj->StartDecryption ();	

				break;
			}

			bSystemEncryptionInProgress = TRUE;
		}
		catch (Exception &e)
		{
			e.Show (MainDlg);
		}

		NormalCursor ();

		if (!bSystemEncryptionInProgress)
		{
			EnableWindow (GetDlgItem (hCurPage, IDC_PAUSE), TRUE);
			Error ("FAILED_TO_RESUME_SYSTEM_ENCRYPTION");
			return;
		}

		bFirstSysEncResumeDone = TRUE;
		InitSysEncProgressBar ();
		UpdateSysEncProgressBar ();
		UpdateSysEncControls ();
		EnableWindow (GetDlgItem (hCurPage, IDC_PAUSE), TRUE);
		SetTimer (MainDlg, TIMER_ID_SYSENC_PROGRESS, TIMER_INTERVAL_SYSENC_PROGRESS, NULL);
	}
	else
		Error ("SYSTEM_ENCRYPTION_IN_PROGRESS_ELSEWHERE");
}


BOOL RegisterBootDriver (void)
{
	try
	{
		BootEncObj->RegisterBootDriver();
	}
	catch (Exception &e)
	{
		e.Show (NULL);
		return FALSE;
	}

	return TRUE;
}


static BOOL GetDevicePathForHiddenOS (void)
{
	BOOL tmpbDevice = FALSE;

	try
	{
		strncpy (szFileName, BootEncObj->GetPartitionForHiddenOS().DevicePath.c_str(), sizeof(szFileName));

		CreateFullVolumePath (szDiskFile, szFileName, &tmpbDevice);
	}
	catch (Exception &e)
	{
		e.Show (MainDlg);
		return FALSE;
	}

	return (szFileName[0] != 0 
		&& szDiskFile[0] != 0 
		&& tmpbDevice);
}


// Returns TRUE if there is unallocated space greater than 64 MB (max possible slack space size) between the 
// boot partition and the first partition behind it. If there's none or if an error occurs, returns FALSE.
static BOOL CheckGapBetweenSysAndHiddenOS (void)
{
	try
	{
		SystemDriveConfiguration sysDriveCfg = BootEncObj->GetSystemDriveConfiguration();

		return (sysDriveCfg.SystemPartition.Info.StartingOffset.QuadPart 
			+ sysDriveCfg.SystemPartition.Info.PartitionLength.QuadPart
			+ 64 * BYTES_PER_MB
			+ 128 * BYTES_PER_KB
			<= BootEncObj->GetPartitionForHiddenOS().Info.StartingOffset.QuadPart);
	}
	catch (Exception &e)
	{
		e.Show (MainDlg);
	}

	return FALSE;
}


void DisplayRandPool (HWND hPoolDisplay, BOOL bShow)
{		
	unsigned char tmp[4];
	unsigned char tmpByte;
	int col, row;
	static BOOL bRandPoolDispAscii = FALSE;

	if (!bShow)
	{
		SetWindowText (hPoolDisplay, "");
		return;
	}

	RandpeekBytes (randPool, sizeof (randPool));

	if (memcmp (lastRandPool, randPool, sizeof(lastRandPool)) != 0)
	{
		outRandPoolDispBuffer[0] = 0;

		for (row = 0; row < RANDPOOL_DISPLAY_ROWS; row++)
		{
			for (col = 0; col < RANDPOOL_DISPLAY_COLUMNS; col++)
			{
				tmpByte = randPool[row * RANDPOOL_DISPLAY_COLUMNS + col];

				sprintf ((char *) tmp, bRandPoolDispAscii ? ((tmpByte >= 32 && tmpByte < 255 && tmpByte != '&') ? " %c " : " . ") : "%02X ", tmpByte);
				strcat ((char *) outRandPoolDispBuffer, (char *) tmp);
			}
			strcat ((char *) outRandPoolDispBuffer, "\n");
		}
		SetWindowText (hPoolDisplay, (char *) outRandPoolDispBuffer);

		memcpy (lastRandPool, randPool, sizeof(lastRandPool));
	}
}

static void __cdecl sysEncDriveAnalysisThread (void *hwndDlgArg)
{
	// Mark the detection process as 'in progress'
	HiddenSectorDetectionStatus = 1;
	SaveSettings (NULL);
	BroadcastSysEncCfgUpdate ();

	try
	{
		BootEncObj->ProbeRealSystemDriveSize ();
		bSysEncDriveAnalysisTimeOutOccurred = FALSE;
	}
	catch (TimeOut &)
	{
		bSysEncDriveAnalysisTimeOutOccurred = TRUE;
	}
	catch (Exception &e)
	{
		e.Show (NULL);
		EndMainDlg (MainDlg);
		exit(0);
	}

	// Mark the detection process as successful
	HiddenSectorDetectionStatus = 0;
	SaveSettings (NULL);
	BroadcastSysEncCfgUpdate ();

	// This artificial delay prevents user confusion on systems where the analysis ends almost instantly
	Sleep (3000);

	bSysEncDriveAnalysisInProgress = FALSE;
}

static void __cdecl formatThreadFunction (void *hwndDlgArg)
{
	int nStatus;
	DWORD dwWin32FormatError;
	BOOL bHidden;
	HWND hwndDlg = (HWND) hwndDlgArg;
	volatile FORMAT_VOL_PARAMETERS *volParams = (FORMAT_VOL_PARAMETERS *) malloc (sizeof(FORMAT_VOL_PARAMETERS));

	if (volParams == NULL)
		AbortProcess ("ERR_MEM_ALLOC");

	VirtualLock ((LPVOID) volParams, sizeof(FORMAT_VOL_PARAMETERS));

	// Check administrator privileges
	if (!IsAdmin () && !IsUacSupported ())
	{
		if (fileSystem == FILESYS_NTFS)
		{
			if (MessageBoxW (hwndDlg, GetString ("ADMIN_PRIVILEGES_WARN_NTFS"), lpszTitle, MB_OKCANCEL|MB_ICONWARNING|MB_DEFBUTTON2) == IDCANCEL)
				goto cancel;
		}
		if (bDevice)
		{
			if (MessageBoxW (hwndDlg, GetString ("ADMIN_PRIVILEGES_WARN_DEVICES"), lpszTitle, MB_OKCANCEL|MB_ICONWARNING|MB_DEFBUTTON2) == IDCANCEL)
				goto cancel;
		}
	}

	if (bDevice == FALSE)
	{
		int x = _access (szDiskFile, 06);
		if (x == 0 || errno != ENOENT)
		{
			wchar_t szTmp[512];

			if (! ((bHiddenVol && !bHiddenVolHost) && errno != EACCES))	// Only ask ask for permission to overwrite an existing volume if we're not creating a hidden volume
			{
				_snwprintf (szTmp, sizeof szTmp / 2,
					GetString (errno == EACCES ? "READONLYPROMPT" : "OVERWRITEPROMPT"),
					szDiskFile);

				x = MessageBoxW (hwndDlg, szTmp, lpszTitle, YES_NO|MB_ICONWARNING|MB_DEFBUTTON2);

				if (x != IDYES)
					goto cancel;
			}
		}

		if (_access (szDiskFile, 06) != 0)
		{
			if (errno == EACCES)
			{
				if (_chmod (szDiskFile, _S_IREAD | _S_IWRITE) != 0)
				{
					MessageBoxW (hwndDlg, GetString ("ACCESSMODEFAIL"), lpszTitle, ICON_HAND);
					goto cancel;
				}
			}
		}

	}
	else
	{
		int x;
		wchar_t szTmp[4096];
		int driveNo;
		WCHAR deviceName[MAX_PATH];

		strcpy ((char *)deviceName, szFileName);
		ToUNICODE ((char *)deviceName);

		driveNo = GetDiskDeviceDriveLetter (deviceName);

		if (!(bHiddenVol && !bHiddenVolHost))	// Do not ask for permission to overwrite an existing volume if we're creating a hidden volume within it
		{
			wchar_t drive[128];
			wchar_t *type;

			if (strstr (szFileName, "Partition"))
				type = GetString ( strstr (szFileName, "Partition0") == NULL ? "PARTITION_UPPER_CASE" : "DEVICE_UPPER_CASE");
			else
				type = GetString ("DEVICE_UPPER_CASE");

			if (driveNo != -1)
			{
				wchar_t name[128];

				if (!GetDriveLabel (driveNo, name, sizeof (name)))
					name[0] = 0;

				swprintf_s (drive, sizeof (drive)/2, name[0] ? L" (%hc: '%s')" : L" (%hc:%s)", 'A' + driveNo, name[0] ? name : L"");
			}
			else
				drive[0] = 0;

			if (bHiddenOS && bHiddenVolHost)
				swprintf (szTmp, GetString ("OVERWRITEPROMPT_DEVICE_HIDDEN_OS_PARTITION"), szFileName, drive);
			else
				swprintf (szTmp, GetString ("OVERWRITEPROMPT_DEVICE"), type, szFileName, drive);


			x = MessageBoxW (hwndDlg, szTmp, lpszTitle, YES_NO|MB_ICONWARNING|MB_DEFBUTTON2);
			if (x != IDYES)
				goto cancel;
		}
	}

	bHidden = bHiddenVol && !bHiddenVolHost;

	volParams->bDevice = bDevice;
	volParams->hiddenVol = bHidden;
	volParams->volumePath = szDiskFile;
	volParams->size = nVolumeSize;
	volParams->hiddenVolHostSize = nHiddenVolHostSize;
	volParams->ea = nVolumeEA;
	volParams->pkcs5 = hash_algo;
	volParams->headerFlags = CreatingHiddenSysVol() ? TC_HEADER_FLAG_ENCRYPTED_SYSTEM : 0;
	volParams->fileSystem = fileSystem;
	volParams->clusterSize = clusterSize;
	volParams->sparseFileSwitch = bSparseFileSwitch;
	volParams->quickFormat = quickFormat;
	volParams->realClusterSize = &realClusterSize;
	volParams->password = &volumePassword;
	volParams->hwndDlg = hwndDlg;

	InitProgressBar (GetVolumeDataAreaSize (bHidden, nVolumeSize) / SECTOR_SIZE, 0, FALSE, FALSE, FALSE, TRUE);

	nStatus = FormatVolume (volParams);

	if (nStatus == ERR_OUTOFMEMORY)
	{
		AbortProcess ("OUTOFMEMORY");
	}

	dwWin32FormatError = GetLastError ();

	if (bHiddenVolHost && !bThreadCancel && nStatus == 0)
	{
		/* Auto mount the newly created hidden volume host */
		switch (MountHiddenVolHost (hwndDlg, szDiskFile, &hiddenVolHostDriveNo, &volumePassword, FALSE))
		{
		case ERR_NO_FREE_DRIVES:
			MessageBoxW (hwndDlg, GetString ("NO_FREE_DRIVE_FOR_OUTER_VOL"), lpszTitle, ICON_HAND);
			bThreadCancel = TRUE;
			break;
		case ERR_VOL_MOUNT_FAILED:
		case ERR_PASSWORD_WRONG:
			MessageBoxW (hwndDlg, GetString ("CANT_MOUNT_OUTER_VOL"), lpszTitle, ICON_HAND);
			bThreadCancel = TRUE;
			break;
		}
	}

	SetLastError (dwWin32FormatError);

	if (bThreadCancel)
	{
		if (!bDevice && !(bHiddenVol && !bHiddenVolHost))	// If we're not creating a hidden volume and if it's a file container
		{
			remove (szDiskFile);		// Delete the container
		}

		goto cancel;
	}

	if (nStatus != 0)
	{
		wchar_t szMsg[1024];

		handleError (hwndDlg, nStatus);

		if (!(bHiddenVolHost && hiddenVolHostDriveNo < 0))  // If the error was not that the hidden volume host could not be mounted (this error has already been reported to the user)
		{
			swprintf (szMsg, GetString ("CREATE_FAILED"), szDiskFile);
			MessageBoxW (hwndDlg, szMsg, lpszTitle, ICON_HAND);
		}

		if (!bDevice && !(bHiddenVol && !bHiddenVolHost))	// If we're not creating a hidden volume and if it's a file container
		{
			remove (szDiskFile);		// Delete the container
		}

		goto cancel;
	}
	else
	{
		/* Volume successfully created */

		RestoreDefaultKeyFilesParam ();

		if (bDevice)
		{
			// Handle assigned drive letter (if any)

			WCHAR deviceName[MAX_PATH];
			int driveLetter = -1;

			strcpy ((char *)deviceName, szDiskFile);
			ToUNICODE ((char *)deviceName);
			driveLetter = GetDiskDeviceDriveLetter (deviceName);

			if (!bHiddenVolHost
				&& !bHiddenOS
				&& driveLetter > 1)		// If a drive letter is assigned to the device, but not A: or B:
			{
				char rootPath[] = { driveLetter + 'A', ':', '\\', 0 };
				wchar_t szTmp[8192];

				swprintf (szTmp, GetString ("AFTER_FORMAT_DRIVE_LETTER_WARN"), rootPath[0], rootPath[0], rootPath[0], rootPath[0]);
				MessageBoxW (hwndDlg, szTmp, lpszTitle, MB_ICONWARNING);
			}
		}

		if (!bHiddenVolHost)
		{
			if (bHiddenVol)
			{
				bHiddenVolFinished = TRUE;

				if (!bHiddenOS)
					Warning ("HIDVOL_FORMAT_FINISHED_HELP");
			}
			else 
			{
				Info("FORMAT_FINISHED_INFO");

				if (bSparseFileSwitch && quickFormat)
					Warning("SPARSE_FILE_SIZE_NOTE");
			}
		}
		else
		{
			/* We've just created an outer volume (to host a hidden volume within) */

			bHiddenVolHost = FALSE; 
			bHiddenVolFinished = FALSE;
			nHiddenVolHostSize = nVolumeSize;

			// Clear the outer volume password
			memset(&szVerify[0], 0, sizeof (szVerify));
			memset(&szRawPassword[0], 0, sizeof (szRawPassword));

			MessageBeep (MB_OK);
		}

		SetTimer (hwndDlg, TIMER_ID_RANDVIEW, TIMER_INTERVAL_RANDVIEW, NULL);

		PostMessage (hwndDlg, TC_APPMSG_FORMAT_FINISHED, 0, 0);
		bThreadRunning = FALSE;

		if (volParams != NULL)
		{
			burn ((LPVOID) volParams, sizeof(FORMAT_VOL_PARAMETERS));
			VirtualUnlock ((LPVOID) volParams, sizeof(FORMAT_VOL_PARAMETERS));
			free ((LPVOID) volParams);
			volParams = NULL;
		}

		LastDialogId = "FORMAT_FINISHED";
		_endthread ();
	}

cancel:
	LastDialogId = "FORMAT_CANCELED";

	SetTimer (hwndDlg, TIMER_ID_RANDVIEW, TIMER_INTERVAL_RANDVIEW, NULL);

	PostMessage (hwndDlg, TC_APPMSG_FORMAT_THREAD_ENDED, 0, 0);
	bThreadRunning = FALSE;

	if (bHiddenVolHost && hiddenVolHostDriveNo < -1 && !bThreadCancel)	// If hidden volume host could not be mounted
		AbortProcessSilent ();

	if (volParams != NULL)
	{
		burn ((LPVOID) volParams, sizeof(FORMAT_VOL_PARAMETERS));
		VirtualUnlock ((LPVOID) volParams, sizeof(FORMAT_VOL_PARAMETERS));
		free ((LPVOID) volParams);
		volParams = NULL;
	}

	_endthread ();
}

static void LoadPage (HWND hwndDlg, int nPageNo)
{
	RECT rD, rW;

	nLastPageNo = nCurPageNo;

	if (hCurPage != NULL)
	{
		// WARNING: nCurPageNo must be set to a non-existent ID here before wiping the password fields below in
		// this function, etc. Otherwise, such actions (SetWindowText) would invoke the EN_CHANGE handlers, which 
		// would, if keyfiles were applied, e.g. use strlen() on a buffer full of random data, in most cases 
		// not null-terminated.
		nCurPageNo = -1;


		// Place here any actions that need to be performed at the latest possible time when leaving a wizard page
		// (i.e. right before "destroying" the page). Also, code that needs to be executed both on IDC_NEXT and
		// on IDC_PREV can be placed here so as to avoid code doubling. 

		switch (nLastPageNo)
		{
		case PASSWORD_PAGE:
			{
				char tmp[MAX_PASSWORD+1];

				// Attempt to wipe passwords stored in the input field buffers. This is performed here (and 
				// not in the IDC_PREV or IDC_NEXT sections) in order to prevent certain race conditions
				// when keyfiles are used.
				memset (tmp, 'X', MAX_PASSWORD);
				tmp [MAX_PASSWORD] = 0;
				SetWindowText (hPasswordInputField, tmp);
				SetWindowText (hVerifyPasswordInputField, tmp);
			}
			break;
		}

		DestroyWindow (hCurPage);
		hCurPage = NULL;
	}

	// This prevents the mouse pointer from remaining as the "hand" cursor when the user presses Enter
	// while hovering over a hyperlink.
	bHyperLinkBeingTracked = FALSE;
	NormalCursor();

	GetWindowRect (GetDlgItem (hwndDlg, IDC_POS_BOX), &rW);


	nCurPageNo = nPageNo;


	switch (nPageNo)
	{
	case INTRO_PAGE:
		hCurPage = CreateDialogW (hInst, MAKEINTRESOURCEW (IDD_INTRO_PAGE_DLG), hwndDlg,
					 (DLGPROC) PageDialogProc);
		break;

	case SYSENC_TYPE_PAGE:
		hCurPage = CreateDialogW (hInst, MAKEINTRESOURCEW (IDD_SYSENC_TYPE_PAGE_DLG), hwndDlg,
					 (DLGPROC) PageDialogProc);
		break;

	case SYSENC_HIDDEN_OS_REQ_CHECK_PAGE:
		hCurPage = CreateDialogW (hInst, MAKEINTRESOURCEW (IDD_SYSENC_HIDDEN_OS_REQ_CHECK_PAGE_DLG), hwndDlg,
					 (DLGPROC) PageDialogProc);
		break;

	case SYSENC_SPAN_PAGE:
		hCurPage = CreateDialogW (hInst, MAKEINTRESOURCEW (IDD_SYSENC_SPAN_PAGE_DLG), hwndDlg,
					 (DLGPROC) PageDialogProc);
		break;

	case SYSENC_PRE_DRIVE_ANALYSIS_PAGE:
		hCurPage = CreateDialogW (hInst, MAKEINTRESOURCEW (IDD_UNIVERSAL_DUAL_CHOICE_PAGE_DLG), hwndDlg,
					 (DLGPROC) PageDialogProc);
		break;

	case SYSENC_DRIVE_ANALYSIS_PAGE:
		hCurPage = CreateDialogW (hInst, MAKEINTRESOURCEW (IDD_SYSENC_DRIVE_ANALYSIS_PAGE_DLG), hwndDlg,
					 (DLGPROC) PageDialogProc);
		break;

	case SYSENC_MULTI_BOOT_MODE_PAGE:
		hCurPage = CreateDialogW (hInst, MAKEINTRESOURCEW (IDD_SYSENC_MULTI_BOOT_MODE_PAGE_DLG), hwndDlg,
					 (DLGPROC) PageDialogProc);
		break;

	case SYSENC_MULTI_BOOT_SYS_EQ_BOOT_PAGE:
	case SYSENC_MULTI_BOOT_NBR_SYS_DRIVES_PAGE:
	case SYSENC_MULTI_BOOT_ADJACENT_SYS_PAGE:
	case SYSENC_MULTI_BOOT_NONWIN_BOOT_LOADER_PAGE:
		hCurPage = CreateDialogW (hInst, MAKEINTRESOURCEW (IDD_UNIVERSAL_DUAL_CHOICE_PAGE_DLG), hwndDlg,
					 (DLGPROC) PageDialogProc);
		break;

	case SYSENC_MULTI_BOOT_OUTCOME_PAGE:
		hCurPage = CreateDialogW (hInst, MAKEINTRESOURCEW (IDD_INFO_PAGE_DLG), hwndDlg,
					 (DLGPROC) PageDialogProc);
		break;

	case VOLUME_TYPE_PAGE:
		hCurPage = CreateDialogW (hInst, MAKEINTRESOURCEW (IDD_VOLUME_TYPE_PAGE_DLG), hwndDlg,
					 (DLGPROC) PageDialogProc);
		break;

	case HIDDEN_VOL_WIZARD_MODE_PAGE:
		hCurPage = CreateDialogW (hInst, MAKEINTRESOURCEW (IDD_HIDDEN_VOL_WIZARD_MODE_PAGE_DLG), hwndDlg,
					 (DLGPROC) PageDialogProc);
		break;

	case FILE_PAGE:
		hCurPage = CreateDialogW (hInst, MAKEINTRESOURCEW (IDD_FILE_PAGE_DLG), hwndDlg,
					 (DLGPROC) PageDialogProc);

		EnableWindow (GetDlgItem(hCurPage, IDC_NO_HISTORY), !bHistoryCmdLine);

		EnableWindow (GetDlgItem (hwndDlg, IDC_NEXT), 
			GetWindowTextLength (GetDlgItem (hCurPage, IDC_COMBO_BOX)) > 0);

		break;

	case HIDDEN_VOL_HOST_PRE_CIPHER_PAGE:
		hCurPage = CreateDialogW (hInst, MAKEINTRESOURCEW (IDD_INFO_PAGE_DLG), hwndDlg,
					 (DLGPROC) PageDialogProc);
		break;
	case HIDDEN_VOL_PRE_CIPHER_PAGE:
		hCurPage = CreateDialogW (hInst, MAKEINTRESOURCEW (IDD_INFO_PAGE_DLG), hwndDlg,
					 (DLGPROC) PageDialogProc);
		break;
	case CIPHER_PAGE:
		hCurPage = CreateDialogW (hInst, MAKEINTRESOURCEW (IDD_CIPHER_PAGE_DLG), hwndDlg,
					 (DLGPROC) PageDialogProc);
		break;
	case SIZE_PAGE:
		hCurPage = CreateDialogW (hInst, MAKEINTRESOURCEW (IDD_SIZE_PAGE_DLG), hwndDlg,
					 (DLGPROC) PageDialogProc);
		break;
	case HIDDEN_VOL_HOST_PASSWORD_PAGE:
		hCurPage = CreateDialogW (hInst, MAKEINTRESOURCEW (IDD_HIDVOL_HOST_PASSWORD_PAGE_DLG), hwndDlg,
					 (DLGPROC) PageDialogProc);
		break;
	case PASSWORD_PAGE:
		hCurPage = CreateDialogW (hInst, MAKEINTRESOURCEW (IDD_PASSWORD_PAGE_DLG), hwndDlg,
					 (DLGPROC) PageDialogProc);
		break;
	case FILESYS_PAGE:
		hCurPage = CreateDialogW (hInst, MAKEINTRESOURCEW (IDD_UNIVERSAL_DUAL_CHOICE_PAGE_DLG), hwndDlg,
					 (DLGPROC) PageDialogProc);
		break;
	case SYSENC_COLLECTING_RANDOM_DATA_PAGE:
		hCurPage = CreateDialogW (hInst, MAKEINTRESOURCEW (IDD_SYSENC_COLLECTING_RANDOM_DATA_DLG), hwndDlg,
					 (DLGPROC) PageDialogProc);
		break;
	case SYSENC_KEYS_GEN_PAGE:
		hCurPage = CreateDialogW (hInst, MAKEINTRESOURCEW (IDD_SYSENC_KEYS_GEN_PAGE_DLG), hwndDlg,
					 (DLGPROC) PageDialogProc);
		break;
	case SYSENC_RESCUE_DISK_CREATION_PAGE:
		hCurPage = CreateDialogW (hInst, MAKEINTRESOURCEW (IDD_SYSENC_RESCUE_DISK_CREATION_DLG), hwndDlg,
					 (DLGPROC) PageDialogProc);
		break;
	case SYSENC_RESCUE_DISK_BURN_PAGE:
		hCurPage = CreateDialogW (hInst, MAKEINTRESOURCEW (IDD_SYSENC_RESCUE_DISK_BURN_PAGE_DLG), hwndDlg,
			(DLGPROC) PageDialogProc);
		break;
	case SYSENC_RESCUE_DISK_VERIFIED_PAGE:
		hCurPage = CreateDialogW (hInst, MAKEINTRESOURCEW (IDD_INFO_PAGE_DLG), hwndDlg,
					 (DLGPROC) PageDialogProc);
		break;
	case SYSENC_WIPE_MODE_PAGE:
		hCurPage = CreateDialogW (hInst, MAKEINTRESOURCEW (IDD_SYSENC_WIPE_MODE_PAGE_DLG), hwndDlg,
			(DLGPROC) PageDialogProc);
		break;
	case SYSENC_PRETEST_INFO_PAGE:
		hCurPage = CreateDialogW (hInst, MAKEINTRESOURCEW (IDD_INFO_PAGE_DLG), hwndDlg,
					 (DLGPROC) PageDialogProc);
		break;
	case SYSENC_PRETEST_RESULT_PAGE:
		hCurPage = CreateDialogW (hInst, MAKEINTRESOURCEW (IDD_INFO_PAGE_DLG), hwndDlg,
					 (DLGPROC) PageDialogProc);
		break;
	case SYSENC_ENCRYPTION_PAGE:
		hCurPage = CreateDialogW (hInst, MAKEINTRESOURCEW (IDD_SYSENC_ENCRYPTION_PAGE_DLG), hwndDlg,
					 (DLGPROC) PageDialogProc);
		break;
	case FORMAT_PAGE:
		hCurPage = CreateDialogW (hInst, MAKEINTRESOURCEW (IDD_FORMAT_PAGE_DLG), hwndDlg,
					 (DLGPROC) PageDialogProc);
		break;
	case FORMAT_FINISHED_PAGE:
		hCurPage = CreateDialogW (hInst, MAKEINTRESOURCEW ((bHiddenVol && !bHiddenVolHost && !bHiddenVolFinished) ? IDD_HIDVOL_HOST_FILL_PAGE_DLG : IDD_INFO_PAGE_DLG), hwndDlg,
					 (DLGPROC) PageDialogProc);
		break;
	}

	rD.left = 162;
	rD.top = 25;
	rD.right = 0;
	rD.bottom = 0;
	MapDialogRect (hwndDlg, &rD);

	if (hCurPage != NULL)
	{
		MoveWindow (hCurPage, rD.left, rD.top, rW.right - rW.left, rW.bottom - rW.top, TRUE);
		ShowWindow (hCurPage, SW_SHOWNORMAL);

		// Place here any message boxes that need to be displayed as soon as a new page is displayed. This 
		// ensures that the page is fully rendered (otherwise it would remain blank, until the message box
		// is closed).
		switch (nPageNo)
		{
		case PASSWORD_PAGE:

			CheckCapsLock (hwndDlg, FALSE);

			if (CreatingHiddenSysVol())
				Warning ("PASSWORD_HIDDEN_OS_NOTE");

			break;
		}
	}
}


int PrintFreeSpace (HWND hwndTextBox, char *lpszDrive, PLARGE_INTEGER lDiskFree)
{
	char *nResourceString;
	int nMultiplier;
	wchar_t szTmp2[256];

	if (lDiskFree->QuadPart < BYTES_PER_KB)
		nMultiplier = 1;
	else if (lDiskFree->QuadPart < BYTES_PER_MB)
		nMultiplier = BYTES_PER_KB;
	else
		nMultiplier = BYTES_PER_MB;

	if (nMultiplier == 1)
	{
		if (bHiddenVol && !bHiddenVolHost)	// If it's a hidden volume
			nResourceString = "MAX_HIDVOL_SIZE_BYTES";
		else if (bDevice)
			nResourceString = "DEVICE_FREE_BYTES";
		else
			nResourceString = "DISK_FREE_BYTES";
	}
	else if (nMultiplier == BYTES_PER_KB)
	{
		if (bHiddenVol && !bHiddenVolHost)	// If it's a hidden volume
			nResourceString = "MAX_HIDVOL_SIZE_KB";
		else if (bDevice)
			nResourceString = "DEVICE_FREE_KB";
		else
			nResourceString = "DISK_FREE_KB";
	}
	else 
	{
		if (bHiddenVol && !bHiddenVolHost)	// If it's a hidden volume
			nResourceString = "MAX_HIDVOL_SIZE_MB";
		else if (bDevice)
			nResourceString = "DEVICE_FREE_MB";
		else
			nResourceString = "DISK_FREE_MB";
	}
 
	if (bHiddenVol && !bHiddenVolHost)	// If it's a hidden volume
	{
		_snwprintf (szTmp2, sizeof szTmp2 / 2, GetString (nResourceString), ((double) lDiskFree->QuadPart) / nMultiplier);
		SetWindowTextW (GetDlgItem (hwndTextBox, IDC_SIZEBOX), szTmp2);
	}
	else
		_snwprintf (szTmp2, sizeof szTmp2 / 2, GetString (nResourceString), lpszDrive, ((double) lDiskFree->QuadPart) / nMultiplier);

	SetWindowTextW (hwndTextBox, szTmp2);

	if (lDiskFree->QuadPart % (__int64) BYTES_PER_MB != 0)
		nMultiplier = BYTES_PER_KB;

	return nMultiplier;
}

void DisplaySizingErrorText (HWND hwndTextBox)
{
	wchar_t szTmp[1024];

	if (translateWin32Error (szTmp, sizeof (szTmp) / sizeof(szTmp[0])))
	{
		wchar_t szTmp2[1024];
		wsprintfW (szTmp2, L"%s\n%s", GetString ("CANNOT_CALC_SPACE"), szTmp);
		SetWindowTextW (hwndTextBox, szTmp2);
	}
	else
	{
		SetWindowText (hwndTextBox, "");
	}
}

void EnableDisableFileNext (HWND hComboBox, HWND hMainButton)
{
	LPARAM nIndex = SendMessage (hComboBox, CB_GETCURSEL, 0, 0);
	if (bHistory && nIndex == CB_ERR)
	{
		EnableWindow (hMainButton, FALSE);
		SetFocus (hComboBox);
	}
	else
	{
		EnableWindow (hMainButton, TRUE);
		SetFocus (hMainButton);
	}
}

// Returns TRUE if the file is a sparse file. If it's not a sparse file or in case of any error, returns FALSE.
BOOL IsSparseFile (HWND hwndDlg)
{
	HANDLE hFile;
	BY_HANDLE_FILE_INFORMATION bhFileInfo;

	FILETIME ftLastAccessTime;
	BOOL bTimeStampValid = FALSE;

	BOOL retCode = FALSE;

	hFile = CreateFile (szFileName, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);

	if (hFile == INVALID_HANDLE_VALUE)
	{
		MessageBoxW (hwndDlg, GetString ("CANT_ACCESS_VOL"), lpszTitle, ICON_HAND);
		return FALSE;
	}

	if (bPreserveTimestamp)
	{
		/* Remember the container timestamp (used to reset file date and time of file-hosted
		   containers to preserve plausible deniability of hidden volumes)  */
		if (GetFileTime (hFile, NULL, &ftLastAccessTime, NULL) == 0)
		{
			bTimeStampValid = FALSE;
			MessageBoxW (hwndDlg, GetString ("GETFILETIME_FAILED_IMPLANT"), lpszTitle, MB_OK | MB_ICONEXCLAMATION);
		}
		else
			bTimeStampValid = TRUE;
	}

	bhFileInfo.dwFileAttributes = 0;

	GetFileInformationByHandle(hFile, &bhFileInfo);

	retCode = bhFileInfo.dwFileAttributes & FILE_ATTRIBUTE_SPARSE_FILE;

	if (bTimeStampValid)
	{
		// Restore the container timestamp (to preserve plausible deniability). 
		if (SetFileTime (hFile, NULL, &ftLastAccessTime, NULL) == 0)
			MessageBoxW (hwndDlg, GetString ("SETFILETIME_FAILED_PREP_IMPLANT"), lpszTitle, MB_OK | MB_ICONEXCLAMATION);
	}
	CloseHandle (hFile);
	return retCode;
}


// Note: GetFileVolSize is not to be used for devices (only for file-hosted volumes)
BOOL GetFileVolSize (HWND hwndDlg, unsigned __int64 *size)
{
	LARGE_INTEGER fileSize;
	HANDLE hFile;

	FILETIME ftLastAccessTime;
	BOOL bTimeStampValid = FALSE;

	hFile = CreateFile (szFileName, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);

	if (hFile == INVALID_HANDLE_VALUE)
	{
		MessageBoxW (hwndDlg, GetString ("CANT_ACCESS_VOL"), lpszTitle, ICON_HAND);
		return FALSE;
	}

	if (bPreserveTimestamp)
	{
		/* Remember the container timestamp (used to reset file date and time of file-hosted
		   containers to preserve plausible deniability of hidden volumes)  */
		if (GetFileTime (hFile, NULL, &ftLastAccessTime, NULL) == 0)
		{
			bTimeStampValid = FALSE;
			MessageBoxW (hwndDlg, GetString ("GETFILETIME_FAILED_IMPLANT"), lpszTitle, MB_OK | MB_ICONEXCLAMATION);
		}
		else
			bTimeStampValid = TRUE;
	}

	if (GetFileSizeEx(hFile, &fileSize) == 0)
	{
		MessageBoxW (hwndDlg, GetString ("CANT_GET_VOLSIZE"), lpszTitle, ICON_HAND);
		if (bTimeStampValid)
		{
			// Restore the container timestamp (to preserve plausible deniability). 
			if (SetFileTime (hFile, NULL, &ftLastAccessTime, NULL) == 0)
				MessageBoxW (hwndDlg, GetString ("SETFILETIME_FAILED_PREP_IMPLANT"), lpszTitle, MB_OK | MB_ICONEXCLAMATION);
		}
		CloseHandle (hFile);
		return FALSE;
	}

	if (bTimeStampValid)
	{
		// Restore the container timestamp (to preserve plausible deniability). 
		if (SetFileTime (hFile, NULL, &ftLastAccessTime, NULL) == 0)
			MessageBoxW (hwndDlg, GetString ("SETFILETIME_FAILED_PREP_IMPLANT"), lpszTitle, MB_OK | MB_ICONEXCLAMATION);
	}
	CloseHandle (hFile);
	*size = fileSize.QuadPart;
	return TRUE;
}


BOOL
QueryFreeSpace (HWND hwndDlg, HWND hwndTextBox, BOOL display)
{
	if (bHiddenVol && !bHiddenVolHost)	// If it's a hidden volume
	{
		LARGE_INTEGER lDiskFree;
		char szTmp[TC_MAX_PATH];

		lDiskFree.QuadPart = nMaximumHiddenVolSize;

		if (display)
			PrintFreeSpace (hwndTextBox, szTmp, &lDiskFree);

		return TRUE;
	}
	else if (bDevice == FALSE)
	{
		char root[TC_MAX_PATH];
		ULARGE_INTEGER free;

		if (!GetVolumePathName (szFileName, root, sizeof (root)))
		{
			handleWin32Error (hwndDlg);
			return FALSE;
		}

		if (!GetDiskFreeSpaceEx (root, &free, 0, 0))
		{
			if (display)
				DisplaySizingErrorText (hwndTextBox);

			return FALSE;
		}
		else
		{
			LARGE_INTEGER lDiskFree;
			lDiskFree.QuadPart = free.QuadPart;

			if (display)
				PrintFreeSpace (hwndTextBox, root, &lDiskFree);

			return TRUE;
		}
	}
	else
	{
		DISK_GEOMETRY driveInfo;
		PARTITION_INFORMATION diskInfo;
		BOOL piValid = FALSE;
		BOOL gValid = FALSE;

		// Query partition size
		piValid = GetPartitionInfo (szDiskFile, &diskInfo);
		gValid = GetDriveGeometry (szDiskFile, &driveInfo);

		if (!piValid && !gValid)
		{
			if (display)
				DisplaySizingErrorText (hwndTextBox);

			return FALSE;
		}

		if (gValid && driveInfo.BytesPerSector != 512)
		{
			Error ("LARGE_SECTOR_UNSUPPORTED");
			return FALSE;
		}

		if (piValid)
		{
			nVolumeSize = diskInfo.PartitionLength.QuadPart;

			if(display)
				nMultiplier = PrintFreeSpace (hwndTextBox, szDiskFile, &diskInfo.PartitionLength);

			nUIVolumeSize = diskInfo.PartitionLength.QuadPart / nMultiplier;

			if (nVolumeSize == 0)
			{
				if (display)
					SetWindowTextW (hwndTextBox, GetString ("EXT_PARTITION"));

				return FALSE;
			}
		}
		else
		{
			LARGE_INTEGER lDiskFree;

			// Drive geometry info is used only when GetPartitionInfo() fails
			lDiskFree.QuadPart = driveInfo.Cylinders.QuadPart * driveInfo.BytesPerSector *
				driveInfo.SectorsPerTrack * driveInfo.TracksPerCylinder;

			nVolumeSize = lDiskFree.QuadPart;

			if (display)
				nMultiplier = PrintFreeSpace (hwndTextBox, szDiskFile, &lDiskFree);

			nUIVolumeSize = lDiskFree.QuadPart / nMultiplier;
		}

		return TRUE;
	}
}


// Returns TRUE if it makes sense to ask the user whether he wants to store files larger than 4GB in the volume.
static BOOL FileSize4GBLimitQuestionNeeded (void)
{
	uint64 dataAreaSize = GetVolumeDataAreaSize (bHiddenVol && !bHiddenVolHost, nVolumeSize);

	return (dataAreaSize > 4 * BYTES_PER_GB + TC_MIN_FAT_FS_SIZE
		&& dataAreaSize <= TC_MAX_FAT_FS_SIZE);
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
		LocalizeDialog (hwndDlg, "IDD_VOL_CREATION_WIZARD_DLG");

		sprintf (PageDebugId, "FORMAT_PAGE_%d", nCurPageNo);
		LastDialogId = PageDebugId;

		switch (nCurPageNo)
		{
		case INTRO_PAGE:

			SendMessage (GetDlgItem (hwndDlg, IDC_FILE_CONTAINER), WM_SETFONT, (WPARAM) hUserBoldFont, (LPARAM) TRUE);
			SendMessage (GetDlgItem (hwndDlg, IDC_NONSYS_DEVICE), WM_SETFONT, (WPARAM) hUserBoldFont, (LPARAM) TRUE);
			SendMessage (GetDlgItem (hwndDlg, IDC_SYS_DEVICE), WM_SETFONT, (WPARAM) hUserBoldFont, (LPARAM) TRUE);

			SetWindowTextW (GetDlgItem (GetParent (hwndDlg), IDC_BOX_TITLE), GetString ("INTRO_TITLE"));

			ToHyperlink (hwndDlg, IDC_MORE_INFO_ON_CONTAINERS);
			ToHyperlink (hwndDlg, IDC_MORE_INFO_ON_SYS_ENCRYPTION);

			EnableWindow (GetDlgItem (hwndDlg, IDC_STD_VOL), TRUE);
			EnableWindow (GetDlgItem (hwndDlg, IDC_HIDDEN_VOL), TRUE);

			SetWindowTextW (GetDlgItem (GetParent (hwndDlg), IDC_NEXT), GetString ("NEXT"));
			SetWindowTextW (GetDlgItem (GetParent (hwndDlg), IDC_PREV), GetString ("PREV"));
			SetWindowTextW (GetDlgItem (GetParent (hwndDlg), IDCANCEL), GetString ("CANCEL"));
			EnableWindow (GetDlgItem (GetParent (hwndDlg), IDC_NEXT), TRUE);
			EnableWindow (GetDlgItem (GetParent (hwndDlg), IDC_PREV), FALSE);

			UpdateWizardModeControls (hwndDlg, WizardMode);
			break;

		case SYSENC_TYPE_PAGE:

			bHiddenVolHost = bHiddenVol = bHiddenOS;

			SetWindowTextW (GetDlgItem (GetParent (hwndDlg), IDC_BOX_TITLE), GetString ("SYSENC_TYPE_PAGE_TITLE"));

			SendMessage (GetDlgItem (hwndDlg, IDC_SYSENC_HIDDEN), WM_SETFONT, (WPARAM) hUserBoldFont, (LPARAM) TRUE);
			SendMessage (GetDlgItem (hwndDlg, IDC_SYSENC_NORMAL), WM_SETFONT, (WPARAM) hUserBoldFont, (LPARAM) TRUE);

			CheckButton (GetDlgItem (hwndDlg, bHiddenOS ? IDC_SYSENC_HIDDEN : IDC_SYSENC_NORMAL));

			SetWindowTextW (GetDlgItem (hwndDlg, IDC_BOX_HELP), GetString ("SYSENC_HIDDEN_TYPE_HELP"));
			SetWindowTextW (GetDlgItem (hwndDlg, IDC_BOX_HELP_SYSENC_NORMAL), GetString ("SYSENC_NORMAL_TYPE_HELP"));

			ToHyperlink (hwndDlg, IDC_HIDDEN_SYSENC_INFO_LINK);

			EnableWindow (GetDlgItem (GetParent (hwndDlg), IDC_NEXT), TRUE);
			EnableWindow (GetDlgItem (GetParent (hwndDlg), IDC_PREV), !bDirectSysEncMode);

			SetWindowTextW (GetDlgItem (MainDlg, IDC_NEXT), GetString ("NEXT"));
			SetWindowTextW (GetDlgItem (MainDlg, IDC_PREV), GetString ("PREV"));
			SetWindowTextW (GetDlgItem (MainDlg, IDCANCEL), GetString ("CANCEL"));
			break;

		case SYSENC_HIDDEN_OS_REQ_CHECK_PAGE:

			SetWindowTextW (GetDlgItem (GetParent (hwndDlg), IDC_BOX_TITLE), GetString ("SYSENC_HIDDEN_OS_REQ_CHECK_PAGE_TITLE"));
			SetWindowTextW (GetDlgItem (hwndDlg, IDC_BOX_HELP), GetString ("SYSENC_HIDDEN_OS_REQ_CHECK_PAGE_HELP"));
			SetWindowTextW (GetDlgItem (MainDlg, IDC_NEXT), GetString ("NEXT"));
			SetWindowTextW (GetDlgItem (MainDlg, IDC_PREV), GetString ("PREV"));
			SetWindowTextW (GetDlgItem (MainDlg, IDCANCEL), GetString ("CANCEL"));

			EnableWindow (GetDlgItem (MainDlg, IDC_NEXT), TRUE);
			EnableWindow (GetDlgItem (MainDlg, IDC_PREV), bDirectSysEncModeCommand != SYSENC_COMMAND_CREATE_HIDDEN_OS && bDirectSysEncModeCommand != SYSENC_COMMAND_CREATE_HIDDEN_OS_ELEV);

			ToHyperlink (hwndDlg, IDC_HIDDEN_SYSENC_INFO_LINK);
			break;

		case SYSENC_SPAN_PAGE:

			SendMessage (GetDlgItem (hwndDlg, IDC_WHOLE_SYS_DRIVE), WM_SETFONT, (WPARAM) hUserBoldFont, (LPARAM) TRUE);
			SendMessage (GetDlgItem (hwndDlg, IDC_SYS_PARTITION), WM_SETFONT, (WPARAM) hUserBoldFont, (LPARAM) TRUE);

			SetWindowTextW (GetDlgItem (GetParent (hwndDlg), IDC_BOX_TITLE), GetString ("SYS_ENCRYPTION_SPAN_TITLE"));

			SetWindowTextW (GetDlgItem (hwndDlg, IDT_WHOLE_SYS_DRIVE), GetString ("SYS_ENCRYPTION_SPAN_WHOLE_SYS_DRIVE_HELP"));

			CheckButton (GetDlgItem (hwndDlg, bWholeSysDrive ? IDC_WHOLE_SYS_DRIVE : IDC_SYS_PARTITION));

			SetWindowTextW (GetDlgItem (GetParent (hwndDlg), IDC_NEXT), GetString ("NEXT"));
			SetWindowTextW (GetDlgItem (GetParent (hwndDlg), IDC_PREV), GetString ("PREV"));
			SetWindowTextW (GetDlgItem (GetParent (hwndDlg), IDCANCEL), GetString ("CANCEL"));

			EnableWindow (GetDlgItem (GetParent (hwndDlg), IDC_NEXT), TRUE);
			EnableWindow (GetDlgItem (GetParent (hwndDlg), IDC_PREV), TRUE);
			break;


		case SYSENC_PRE_DRIVE_ANALYSIS_PAGE:

			Init2RadButtonPageYesNo (SysEncDetectHiddenSectors);
			SetWindowTextW (GetDlgItem (GetParent (hwndDlg), IDC_BOX_TITLE), GetString ("SYSENC_PRE_DRIVE_ANALYSIS_TITLE"));
			SetWindowTextW (GetDlgItem (hwndDlg, IDC_BOX_HELP), GetString ("SYSENC_PRE_DRIVE_ANALYSIS_HELP"));
			break;


		case SYSENC_DRIVE_ANALYSIS_PAGE:

			SetWindowTextW (GetDlgItem (GetParent (hwndDlg), IDC_BOX_TITLE), GetString ("SYSENC_DRIVE_ANALYSIS_TITLE"));
			SetWindowTextW (GetDlgItem (hwndDlg, IDT_SYSENC_DRIVE_ANALYSIS_INFO), GetString ("SYSENC_DRIVE_ANALYSIS_INFO"));
			SetWindowTextW (GetDlgItem (GetParent (hwndDlg), IDC_NEXT), GetString ("NEXT"));
			SetWindowTextW (GetDlgItem (GetParent (hwndDlg), IDC_PREV), GetString ("PREV"));
			SetWindowTextW (GetDlgItem (GetParent (hwndDlg), IDCANCEL), GetString ("CANCEL"));
			EnableWindow (GetDlgItem (MainDlg, IDC_NEXT), FALSE);
			EnableWindow (GetDlgItem (MainDlg, IDC_PREV), FALSE);
			EnableWindow (GetDlgItem (MainDlg, IDCANCEL), FALSE);

			LoadSettings (hwndDlg);

			if (HiddenSectorDetectionStatus == 1)
			{
				// Detection of hidden sectors was already in progress but it did not finish successfully.
				// Ask the user if he wants to try again (to prevent repeated system freezing, etc.)

				char *tmpStr[] = {0, "HIDDEN_SECTOR_DETECTION_FAILED_PREVIOUSLY", "SKIP_HIDDEN_SECTOR_DETECTION", "RETRY_HIDDEN_SECTOR_DETECTION", "IDC_EXIT", 0};
				switch (AskMultiChoice ((void **) tmpStr))
				{
				case 1:
					// Do not try again
					LoadPage (MainDlg, SYSENC_DRIVE_ANALYSIS_PAGE + 1);
					return 0;

				case 2:
					// Try again
					break;

				default:
					EndMainDlg (MainDlg);
					return 0;
				}
			}

			SetTimer (MainDlg, TIMER_ID_SYSENC_DRIVE_ANALYSIS_PROGRESS, TIMER_INTERVAL_SYSENC_DRIVE_ANALYSIS_PROGRESS, NULL);
			bSysEncDriveAnalysisInProgress = TRUE;
			ArrowWaitCursor ();
			SysEncDriveAnalysisStart = GetTickCount ();
			InitProgressBar (SYSENC_DRIVE_ANALYSIS_ETA, 0, FALSE, FALSE, FALSE, TRUE);

			_beginthread (sysEncDriveAnalysisThread, 4096, hwndDlg);

			break;


		case SYSENC_MULTI_BOOT_MODE_PAGE:

			SendMessage (GetDlgItem (hwndDlg, IDC_SINGLE_BOOT), WM_SETFONT, (WPARAM) hUserBoldFont, (LPARAM) TRUE);
			SendMessage (GetDlgItem (hwndDlg, IDC_MULTI_BOOT), WM_SETFONT, (WPARAM) hUserBoldFont, (LPARAM) TRUE);

			SetWindowTextW (GetDlgItem (GetParent (hwndDlg), IDC_BOX_TITLE), GetString ("SYS_MULTI_BOOT_MODE_TITLE"));

			SetWindowTextW (GetDlgItem (GetParent (hwndDlg), IDC_NEXT), GetString ("NEXT"));
			SetWindowTextW (GetDlgItem (GetParent (hwndDlg), IDC_PREV), GetString ("PREV"));
			SetWindowTextW (GetDlgItem (GetParent (hwndDlg), IDCANCEL), GetString ("CANCEL"));

			RefreshMultiBootControls (hwndDlg);

			EnableWindow (GetDlgItem (GetParent (hwndDlg), IDC_NEXT), nMultiBoot > 0);
			EnableWindow (GetDlgItem (GetParent (hwndDlg), IDC_PREV), TRUE);
			EnableWindow (GetDlgItem (GetParent (hwndDlg), IDCANCEL), TRUE);
			break;


		case SYSENC_MULTI_BOOT_SYS_EQ_BOOT_PAGE:

			Init2RadButtonPageYesNo (SysEncMultiBootCfg.SystemOnBootDrive);
			SetWindowTextW (GetDlgItem (GetParent (hwndDlg), IDC_BOX_TITLE), GetString ("SYSENC_MULTI_BOOT_SYS_EQ_BOOT_TITLE"));
			SetWindowTextW (GetDlgItem (hwndDlg, IDC_BOX_HELP), GetString ("SYSENC_MULTI_BOOT_SYS_EQ_BOOT_HELP"));
			break;


		case SYSENC_MULTI_BOOT_NBR_SYS_DRIVES_PAGE:

			SetWindowTextW (GetDlgItem (hCurPage, IDC_CHOICE1), GetString ("DIGIT_ONE"));
			SetWindowTextW (GetDlgItem (hCurPage, IDC_CHOICE2), GetString ("TWO_OR_MORE"));

			SetWindowTextW (GetDlgItem (MainDlg, IDC_NEXT), GetString ("NEXT"));
			SetWindowTextW (GetDlgItem (MainDlg, IDC_PREV), GetString ("PREV"));
			SetWindowTextW (GetDlgItem (MainDlg, IDCANCEL), GetString ("CANCEL"));

			EnableWindow (GetDlgItem (MainDlg, IDC_NEXT), SysEncMultiBootCfg.NumberOfSysDrives > 0);
			EnableWindow (GetDlgItem (MainDlg, IDC_PREV), TRUE);

			if (SysEncMultiBootCfg.NumberOfSysDrives == 2)
				Update2RadButtonPage (0); // 2 or more drives contain an OS
			else if (SysEncMultiBootCfg.NumberOfSysDrives == 1)
				Update2RadButtonPage (1); // Only 1 drive contains an OS
			else
				Update2RadButtonPage (-1);

			SetWindowTextW (GetDlgItem (GetParent (hwndDlg), IDC_BOX_TITLE), GetString ("SYSENC_MULTI_BOOT_NBR_SYS_DRIVES_TITLE"));
			SetWindowTextW (GetDlgItem (hwndDlg, IDC_BOX_HELP), GetString ("SYSENC_MULTI_BOOT_NBR_SYS_DRIVES_HELP"));
			break;


		case SYSENC_MULTI_BOOT_ADJACENT_SYS_PAGE:

			Init2RadButtonPageYesNo (SysEncMultiBootCfg.MultipleSystemsOnDrive);
			SetWindowTextW (GetDlgItem (GetParent (hwndDlg), IDC_BOX_TITLE), GetString ("SYSENC_MULTI_BOOT_ADJACENT_SYS_TITLE"));
			SetWindowTextW (GetDlgItem (hwndDlg, IDC_BOX_HELP), GetString ("SYSENC_MULTI_BOOT_ADJACENT_SYS_HELP"));
			break;


		case SYSENC_MULTI_BOOT_NONWIN_BOOT_LOADER_PAGE:

			Init2RadButtonPageYesNo (SysEncMultiBootCfg.BootLoaderBrand);
			SetWindowTextW (GetDlgItem (GetParent (hwndDlg), IDC_BOX_TITLE), GetString ("SYSENC_MULTI_BOOT_NONWIN_BOOT_LOADER_TITLE"));
			SetWindowTextW (GetDlgItem (hwndDlg, IDC_BOX_HELP), GetString ("SYSENC_MULTI_BOOT_NONWIN_BOOT_LOADER_HELP"));
			break;


		case SYSENC_MULTI_BOOT_OUTCOME_PAGE:

			SetWindowTextW (GetDlgItem (GetParent (hwndDlg), IDC_BOX_TITLE), GetString ("SYSENC_MULTI_BOOT_OUTCOME_TITLE"));
			SetWindowTextW (GetDlgItem (hwndDlg, IDC_BOX_HELP), SysEncMultiBootCfgOutcome);
			SetWindowTextW (GetDlgItem (MainDlg, IDC_NEXT), GetString ("NEXT"));
			SetWindowTextW (GetDlgItem (MainDlg, IDC_PREV), GetString ("PREV"));
			SetWindowTextW (GetDlgItem (MainDlg, IDCANCEL), GetString ("CANCEL"));
			EnableWindow (GetDlgItem (MainDlg, IDC_NEXT), TRUE);
			EnableWindow (GetDlgItem (MainDlg, IDC_PREV), TRUE);
			break;


		case VOLUME_TYPE_PAGE:

			SetWindowTextW (GetDlgItem (GetParent (hwndDlg), IDC_BOX_TITLE), GetString ("VOLUME_TYPE_TITLE"));

			SendMessage (GetDlgItem (hwndDlg, IDC_HIDDEN_VOL), WM_SETFONT, (WPARAM) hUserBoldFont, (LPARAM) TRUE);
			SendMessage (GetDlgItem (hwndDlg, IDC_STD_VOL), WM_SETFONT, (WPARAM) hUserBoldFont, (LPARAM) TRUE);

			CheckButton (GetDlgItem (hwndDlg, bHiddenVol ? IDC_HIDDEN_VOL : IDC_STD_VOL));

			SetWindowTextW (GetDlgItem (hwndDlg, IDC_BOX_HELP), GetString ("HIDDEN_VOLUME_TYPE_HELP"));
			SetWindowTextW (GetDlgItem (hwndDlg, IDC_BOX_HELP_NORMAL_VOL), GetString ("NORMAL_VOLUME_TYPE_HELP"));

			ToHyperlink (hwndDlg, IDC_HIDDEN_VOL_HELP);

			EnableWindow (GetDlgItem (GetParent (hwndDlg), IDC_NEXT), TRUE);
			EnableWindow (GetDlgItem (GetParent (hwndDlg), IDC_PREV), TRUE);

			SetWindowTextW (GetDlgItem (MainDlg, IDC_NEXT), GetString ("NEXT"));
			SetWindowTextW (GetDlgItem (MainDlg, IDC_PREV), GetString ("PREV"));
			SetWindowTextW (GetDlgItem (MainDlg, IDCANCEL), GetString ("CANCEL"));
			break;

		case HIDDEN_VOL_WIZARD_MODE_PAGE:

			SetWindowTextW (GetDlgItem (GetParent (hwndDlg), IDC_BOX_TITLE), GetString ("HIDDEN_VOL_WIZARD_MODE_TITLE"));

			SendMessage (GetDlgItem (hwndDlg, IDC_HIDVOL_WIZ_MODE_DIRECT), WM_SETFONT, (WPARAM) hUserBoldFont, (LPARAM) TRUE);
			SendMessage (GetDlgItem (hwndDlg, IDC_HIDVOL_WIZ_MODE_FULL), WM_SETFONT, (WPARAM) hUserBoldFont, (LPARAM) TRUE);

			CheckButton (GetDlgItem (hwndDlg, bHiddenVolDirect ? IDC_HIDVOL_WIZ_MODE_DIRECT : IDC_HIDVOL_WIZ_MODE_FULL));

			SetWindowTextW (GetDlgItem (hwndDlg, IDC_BOX_HELP), GetString ("HIDDEN_VOL_WIZARD_MODE_NORMAL_HELP"));
			SetWindowTextW (GetDlgItem (hwndDlg, IDC_BOX_HELP2), GetString ("HIDDEN_VOL_WIZARD_MODE_DIRECT_HELP"));

			EnableWindow (GetDlgItem (hwndDlg, IDC_HIDVOL_WIZ_MODE_DIRECT), TRUE);
			EnableWindow (GetDlgItem (hwndDlg, IDC_HIDVOL_WIZ_MODE_FULL), TRUE);

			SetWindowTextW (GetDlgItem (GetParent (hwndDlg), IDC_NEXT), GetString ("NEXT"));
			SetWindowTextW (GetDlgItem (GetParent (hwndDlg), IDC_PREV), GetString ("PREV"));
			SetWindowTextW (GetDlgItem (GetParent (hwndDlg), IDCANCEL), GetString ("CANCEL"));
			EnableWindow (GetDlgItem (GetParent (hwndDlg), IDC_NEXT), TRUE);
			EnableWindow (GetDlgItem (GetParent (hwndDlg), IDC_PREV), TRUE);

			break;

		case FILE_PAGE:
			{
				char *nID;

				SetWindowTextW (GetDlgItem (hwndDlg, IDC_SELECT_VOLUME_LOCATION),
					GetString (bDevice ? "IDC_SELECT_DEVICE" : "IDC_SELECT_FILE"));

				if (bHiddenVolDirect && bHiddenVolHost)
				{
					nID = "FILE_HELP_HIDDEN_HOST_VOL_DIRECT";
				}
				else
				{
					if (bDevice)
						nID = bHiddenVolHost ? "DEVICE_HELP_HIDDEN_HOST_VOL" : "DEVICE_HELP";
					else
						nID = bHiddenVolHost ? "FILE_HELP_HIDDEN_HOST_VOL" : "FILE_HELP";
				}

				SendMessage (GetDlgItem (hwndDlg, IDC_COMBO_BOX), CB_RESETCONTENT, 0, 0);

				SendMessage (GetDlgItem (hwndDlg, IDC_COMBO_BOX), CB_LIMITTEXT, TC_MAX_PATH, 0);

				LoadSettings (hwndDlg);

				SendMessage (GetDlgItem (hwndDlg, IDC_NO_HISTORY), BM_SETCHECK, bHistory ? BST_UNCHECKED : BST_CHECKED, 0);

				SetWindowTextW (GetDlgItem (GetParent (hwndDlg), IDC_BOX_TITLE), GetString ("FILE_TITLE"));
				SetWindowTextW (GetDlgItem (hwndDlg, IDC_BOX_HELP), GetString (nID));

				SetFocus (GetDlgItem (hwndDlg, IDC_COMBO_BOX));

				SetWindowTextW (GetDlgItem (GetParent (hwndDlg), IDC_NEXT), GetString ("NEXT"));
				SetWindowTextW (GetDlgItem (GetParent (hwndDlg), IDC_PREV), GetString ("PREV"));
				EnableWindow (GetDlgItem (GetParent (hwndDlg), IDC_PREV), TRUE);

				AddComboItem (GetDlgItem (hwndDlg, IDC_COMBO_BOX), szFileName, bHistory);

				EnableDisableFileNext (GetDlgItem (hwndDlg, IDC_COMBO_BOX),
				GetDlgItem (GetParent (hwndDlg), IDC_NEXT));

			}
			break;

		case HIDDEN_VOL_HOST_PRE_CIPHER_PAGE:
			{
				SetWindowTextW (GetDlgItem (GetParent (hwndDlg), IDC_BOX_TITLE), GetString ("HIDVOL_HOST_PRE_CIPHER_TITLE"));
				SetWindowTextW (GetDlgItem (hwndDlg, IDC_BOX_HELP), GetString (bHiddenOS ? "HIDVOL_HOST_PRE_CIPHER_HELP_SYSENC" : "HIDVOL_HOST_PRE_CIPHER_HELP"));

				SetWindowTextW (GetDlgItem (GetParent (hwndDlg), IDC_NEXT), GetString ("NEXT"));
				SetWindowTextW (GetDlgItem (GetParent (hwndDlg), IDC_PREV), GetString ("PREV"));
				EnableWindow (GetDlgItem (GetParent (hwndDlg), IDC_NEXT), TRUE);
				EnableWindow (GetDlgItem (GetParent (hwndDlg), IDC_PREV), TRUE);

				if (bHiddenOS)
				{
					if (!GetDevicePathForHiddenOS())
						AbortProcess ("INVALID_PATH");
				}
			}
			break;

		case HIDDEN_VOL_PRE_CIPHER_PAGE:
			{
				SetWindowTextW (GetDlgItem (GetParent (hwndDlg), IDC_NEXT), GetString ("NEXT"));
				SetWindowTextW (GetDlgItem (GetParent (hwndDlg), IDC_PREV), GetString ("PREV"));
				EnableWindow (GetDlgItem (GetParent (hwndDlg), IDC_NEXT), TRUE);
				EnableWindow (GetDlgItem (GetParent (hwndDlg), IDC_PREV), FALSE);
				SetWindowTextW (GetDlgItem (GetParent (hwndDlg), IDC_BOX_TITLE), GetString ("HIDVOL_PRE_CIPHER_TITLE"));

				if (bHiddenOS)
				{
					// Verify whether the clone of the OS fits in the hidden volume (the hidden
					// volume is to host a hidden OS).
					if (nMaximumHiddenVolSize - TC_HIDDEN_VOLUME_HOST_FS_RESERVED_END_AREA_SIZE_HIGH < GetSystemPartitionSize())
					{
						SetWindowTextW (GetDlgItem (hwndDlg, IDC_BOX_HELP), GetString ("HIDDEN_VOLUME_TOO_SMALL_FOR_OS_CLONE"));

						SetWindowTextW (GetDlgItem (GetParent (hwndDlg), IDCANCEL), GetString ("EXIT"));
						EnableWindow (GetDlgItem (GetParent (hwndDlg), IDCANCEL), TRUE);
						EnableWindow (GetDlgItem (GetParent (hwndDlg), IDC_NEXT), FALSE);
						EnableWindow (GetDlgItem (GetParent (hwndDlg), IDC_PREV), FALSE);
					}
					else
					{
						// The hidden volume must be as large as the system partition
						nVolumeSize = GetSystemPartitionSize() + TC_HIDDEN_VOLUME_HOST_FS_RESERVED_END_AREA_SIZE_HIGH;	

						SetWindowTextW (GetDlgItem (hwndDlg, IDC_BOX_HELP), GetString ("HIDDEN_OS_PRE_CIPHER_HELP"));
					}
				}
				else
				{

					SetWindowTextW (GetDlgItem (hwndDlg, IDC_BOX_HELP), GetString ("HIDVOL_PRE_CIPHER_HELP"));
				}
			}
			break;

		case CIPHER_PAGE:
			{
				int ea, hid;
				char buf[100];

				// Encryption algorithms

				SendMessage (GetDlgItem (hwndDlg, IDC_COMBO_BOX), CB_RESETCONTENT, 0, 0);

				if (bHiddenVol)
					SetWindowTextW (GetDlgItem (GetParent (hwndDlg), IDC_BOX_TITLE), GetString (bHiddenVolHost ? "CIPHER_HIDVOL_HOST_TITLE" : "CIPHER_HIDVOL_TITLE"));
				else
					SetWindowTextW (GetDlgItem (GetParent (hwndDlg), IDC_BOX_TITLE), GetString ("CIPHER_TITLE"));

				for (ea = EAGetFirst (); ea != 0; ea = EAGetNext (ea))
				{
					if (EAIsFormatEnabled (ea))
						AddComboPair (GetDlgItem (hwndDlg, IDC_COMBO_BOX), EAGetName (buf, ea), ea);
				}

				SelectAlgo (GetDlgItem (hwndDlg, IDC_COMBO_BOX), &nVolumeEA);
				ComboSelChangeEA (hwndDlg);
				SetFocus (GetDlgItem (hwndDlg, IDC_COMBO_BOX));

				ToHyperlink (hwndDlg, IDC_LINK_MORE_INFO_ABOUT_CIPHER);

				// Hash algorithms

				if (SysEncInEffect ())
				{
					hash_algo = DEFAULT_HASH_ALGORITHM_BOOT;
					RandSetHashFunction (DEFAULT_HASH_ALGORITHM_BOOT);
				}
				else
					hash_algo = RandGetHashFunction();

				for (hid = FIRST_PRF_ID; hid <= LAST_PRF_ID; hid++)
				{
					if (!HashIsDeprecated (hid))
						AddComboPair (GetDlgItem (hwndDlg, IDC_COMBO_BOX_HASH_ALGO), HashGetName(hid), hid);
				}
				SelectAlgo (GetDlgItem (hwndDlg, IDC_COMBO_BOX_HASH_ALGO), &hash_algo);

				ToHyperlink (hwndDlg, IDC_LINK_HASH_INFO);

				// Wizard buttons
				SetWindowTextW (GetDlgItem (GetParent (hwndDlg), IDC_NEXT), GetString ("NEXT"));
				SetWindowTextW (GetDlgItem (GetParent (hwndDlg), IDC_PREV), GetString ("PREV"));
				EnableWindow (GetDlgItem (GetParent (hwndDlg), IDC_PREV), TRUE);
				EnableWindow (GetDlgItem (GetParent (hwndDlg), IDC_NEXT), TRUE);
			}
			break;

		case SIZE_PAGE:
			{
				wchar_t str[1000];

				if (bHiddenVolHost)
				{
					wcsncpy (str, GetString ("SIZE_HELP_HIDDEN_HOST_VOL"), sizeof (str) / 2);
				}
				else
				{
					wcsncpy (str, GetString (bHiddenVol ? "SIZE_HELP_HIDDEN_VOL" : "SIZE_HELP"), sizeof (str) / 2);
				}

				if (bDevice && !(bHiddenVol && !bHiddenVolHost))	// If raw device but not a hidden volume
				{
					_snwprintf (str, sizeof str / 2, L"%s%s",
						GetString ((bHiddenOS && bHiddenVol) ? "SIZE_PARTITION_HIDDEN_SYSENC_HELP" : "SIZE_PARTITION_HELP"),
						 (bHiddenVolHost && !bHiddenOS) ? GetString ("SIZE_PARTITION_HIDDEN_VOL_HELP") : L"");
				}

				SendMessage (GetDlgItem (hwndDlg, IDC_SPACE_LEFT), WM_SETFONT, (WPARAM) hBoldFont, (LPARAM) TRUE);
				SendMessage (GetDlgItem (hwndDlg, IDC_SIZEBOX), EM_LIMITTEXT, 12, 0);

				if(!QueryFreeSpace (hwndDlg, GetDlgItem (hwndDlg, IDC_SPACE_LEFT), TRUE))
				{
					nUIVolumeSize=0;
					nVolumeSize=0;
					SetWindowTextW (GetDlgItem (hwndDlg, IDC_SIZEBOX), GetString ("UNKNOWN"));
					EnableWindow (GetDlgItem (hwndDlg, IDC_SIZEBOX), FALSE);
					EnableWindow (GetDlgItem (hwndDlg, IDC_KB), FALSE);
					EnableWindow (GetDlgItem (hwndDlg, IDC_MB), FALSE);

				}
				else if (bDevice && !(bHiddenVol && !bHiddenVolHost))	// If raw device but not a hidden volume
				{
					EnableWindow (GetDlgItem (hwndDlg, IDC_SIZEBOX), FALSE);
					EnableWindow (GetDlgItem (hwndDlg, IDC_KB), FALSE);
					EnableWindow (GetDlgItem (hwndDlg, IDC_MB), FALSE);
				}
				else
				{
					EnableWindow (GetDlgItem (hwndDlg, IDC_SIZEBOX), TRUE);
					EnableWindow (GetDlgItem (hwndDlg, IDC_KB), TRUE);
					EnableWindow (GetDlgItem (hwndDlg, IDC_MB), TRUE);
				}

				if (nMultiplier == BYTES_PER_KB)
					SendMessage (GetDlgItem (hwndDlg, IDC_KB), BM_SETCHECK, BST_CHECKED, 0);
				else
					SendMessage (GetDlgItem (hwndDlg, IDC_MB), BM_SETCHECK, BST_CHECKED, 0);

				if (nUIVolumeSize != 0)
				{
					char szTmp[32];
					sprintf (szTmp, "%I64u", nUIVolumeSize);
					SetWindowText (GetDlgItem (hwndDlg, IDC_SIZEBOX), szTmp);
				}

				SetFocus (GetDlgItem (hwndDlg, IDC_SIZEBOX));

				SetWindowTextW (GetDlgItem (hwndDlg, IDC_BOX_HELP), str);

				if (bHiddenVol)
					SetWindowTextW (GetDlgItem (GetParent (hwndDlg), IDC_BOX_TITLE), GetString (bHiddenVolHost ? "SIZE_HIDVOL_HOST_TITLE" : "SIZE_HIDVOL_TITLE"));
				else
					SetWindowTextW (GetDlgItem (GetParent (hwndDlg), IDC_BOX_TITLE), GetString ("SIZE_TITLE"));


				SetWindowTextW (GetDlgItem (GetParent (hwndDlg), IDC_NEXT), GetString ("NEXT"));
				SetWindowTextW (GetDlgItem (GetParent (hwndDlg), IDC_PREV), GetString ("PREV"));


				EnableWindow (GetDlgItem (GetParent (hwndDlg), IDC_PREV), TRUE);

				VerifySizeAndUpdate (hwndDlg, FALSE);
			}
			break;

		case HIDDEN_VOL_HOST_PASSWORD_PAGE:
			{
				SendMessage (GetDlgItem (hwndDlg, IDC_PASSWORD_DIRECT), EM_LIMITTEXT, MAX_PASSWORD, 0);

				SetWindowText (GetDlgItem (hwndDlg, IDC_PASSWORD_DIRECT), szRawPassword);

				SetFocus (GetDlgItem (hwndDlg, IDC_PASSWORD_DIRECT));

				SetCheckBox (hwndDlg, IDC_KEYFILES_ENABLE, KeyFilesEnable);
				EnableWindow (GetDlgItem (hwndDlg, IDC_KEY_FILES), KeyFilesEnable);

				SetWindowTextW (GetDlgItem (hwndDlg, IDC_BOX_HELP), GetString ("PASSWORD_HIDDENVOL_HOST_DIRECT_HELP"));

				SetWindowTextW (GetDlgItem (GetParent (hwndDlg), IDC_BOX_TITLE), GetString ("PASSWORD_HIDVOL_HOST_TITLE"));

				SetWindowTextW (GetDlgItem (GetParent (hwndDlg), IDC_NEXT), GetString ("NEXT"));
				SetWindowTextW (GetDlgItem (GetParent (hwndDlg), IDC_PREV), GetString ("PREV"));

				EnableWindow (GetDlgItem (GetParent (hwndDlg), IDC_PREV), TRUE);
				EnableWindow (GetDlgItem (GetParent (hwndDlg), IDC_NEXT), TRUE);
			}
			break;

		case PASSWORD_PAGE:
			{
				wchar_t str[1000];

				hPasswordInputField = GetDlgItem (hwndDlg, IDC_PASSWORD);
				hVerifyPasswordInputField = GetDlgItem (hwndDlg, IDC_VERIFY);

				if (SysEncInEffect ())
				{
					ToBootPwdField (hwndDlg, IDC_PASSWORD);
					ToBootPwdField (hwndDlg, IDC_VERIFY);

					sprintf (OrigKeyboardLayout, "%08X", (DWORD) GetKeyboardLayout (NULL) & 0xFFFF);

					if ((DWORD) GetKeyboardLayout (NULL) != 0x00000409 && (DWORD) GetKeyboardLayout (NULL) != 0x04090409)
					{
						DWORD keybLayout = (DWORD) LoadKeyboardLayout ("00000409", KLF_ACTIVATE);

						if (keybLayout != 0x00000409 && keybLayout != 0x04090409)
						{
							Error ("CANT_CHANGE_KEYB_LAYOUT_FOR_SYS_ENCRYPTION");
							EndMainDlg (MainDlg);
							return 1;
						}
						bKeyboardLayoutChanged = TRUE;
					}

					ShowWindow(GetDlgItem(hwndDlg, IDC_SHOW_PASSWORD), SW_HIDE);

					if (SetTimer (MainDlg, TIMER_ID_KEYB_LAYOUT_GUARD, TIMER_INTERVAL_KEYB_LAYOUT_GUARD, NULL) == 0)
					{
						Error ("CANNOT_SET_TIMER");
						EndMainDlg (MainDlg);
						return 1;
					}
				}

				if (bHiddenVolHost)
				{
					wcsncpy (str, GetString (bHiddenOS ? "PASSWORD_SYSENC_OUTERVOL_HELP" : "PASSWORD_HIDDENVOL_HOST_HELP"), sizeof (str) / 2);
				}
				else if (bHiddenVol)
				{
					_snwprintf (str, sizeof str / 2, L"%s%s",
						GetString (bHiddenOS ? "PASSWORD_HIDDEN_OS_HELP" : "PASSWORD_HIDDENVOL_HELP"),
						GetString ("PASSWORD_HELP"));
				}
				else
				{
					wcsncpy (str, GetString (bHiddenOS ? "PASSWORD_DECOY_OS_HELP" : "PASSWORD_HELP"), sizeof (str) / 2);
				}

				SendMessage (GetDlgItem (hwndDlg, IDC_PASSWORD), EM_LIMITTEXT, MAX_PASSWORD, 0);
				SendMessage (GetDlgItem (hwndDlg, IDC_VERIFY), EM_LIMITTEXT, MAX_PASSWORD, 0);

				SetWindowText (GetDlgItem (hwndDlg, IDC_PASSWORD), szRawPassword);
				SetWindowText (GetDlgItem (hwndDlg, IDC_VERIFY), szVerify);

				SetFocus (GetDlgItem (hwndDlg, IDC_PASSWORD));

				SetCheckBox (hwndDlg, IDC_KEYFILES_ENABLE, KeyFilesEnable && !SysEncInEffect());
				EnableWindow (GetDlgItem (hwndDlg, IDC_KEY_FILES), KeyFilesEnable && !SysEncInEffect());
				EnableWindow (GetDlgItem (hwndDlg, IDC_KEYFILES_ENABLE), !SysEncInEffect ());

				SetWindowTextW (GetDlgItem (hwndDlg, IDC_BOX_HELP), str);

				if (CreatingHiddenSysVol())
					SetWindowTextW (GetDlgItem (GetParent (hwndDlg), IDC_BOX_TITLE), GetString ("PASSWORD_HIDDEN_OS_TITLE"));
				else if (bHiddenVol)
					SetWindowTextW (GetDlgItem (GetParent (hwndDlg), IDC_BOX_TITLE), GetString (bHiddenVolHost ? "PASSWORD_HIDVOL_HOST_TITLE" : "PASSWORD_HIDVOL_TITLE"));
				else if (WizardMode == WIZARD_MODE_SYS_DEVICE)
					SetWindowTextW (GetDlgItem (GetParent (hwndDlg), IDC_BOX_TITLE), GetString (bHiddenOS ? "PASSWORD_DECOY_OS_TITLE" : "PASSWORD"));
				else
					SetWindowTextW (GetDlgItem (GetParent (hwndDlg), IDC_BOX_TITLE), GetString ("PASSWORD_TITLE"));

				SetWindowTextW (GetDlgItem (GetParent (hwndDlg), IDC_NEXT), GetString ("NEXT"));
				SetWindowTextW (GetDlgItem (GetParent (hwndDlg), IDC_PREV), GetString ("PREV"));

				EnableWindow (GetDlgItem (GetParent (hwndDlg), IDC_PREV), !(bHiddenOS && !bHiddenVol));

				VerifyPasswordAndUpdate (hwndDlg, GetDlgItem (GetParent (hwndDlg), IDC_NEXT),
					 GetDlgItem (hwndDlg, IDC_PASSWORD),
					   GetDlgItem (hwndDlg, IDC_VERIFY),
						      NULL,
							  NULL,
							  KeyFilesEnable && FirstKeyFile!=NULL && !SysEncInEffect());
				volumePassword.Length = strlen ((char *) volumePassword.Text);
			}
			break;

		case FILESYS_PAGE:
			{
				wchar_t szTmp[8192];

				Init2RadButtonPageYesNo (nNeedToStoreFilesOver4GB);
				SetWindowTextW (GetDlgItem (GetParent (hwndDlg), IDC_BOX_TITLE), GetString ("FILESYS_PAGE_TITLE"));

				wcscpy (szTmp, GetString ("FILESYS_PAGE_HELP_QUESTION"));

				if (bHiddenVolHost)
					wcscat (szTmp, L"\n\n");
				else
				{
					wcscat (szTmp, L"\n\n\n");
					wcscat (szTmp, GetString ("NOTE_BEGINNING"));
				}

				wcscat (szTmp, GetString ("FILESYS_PAGE_HELP_EXPLANATION"));

				if (bHiddenVolHost)
				{
					wcscat (szTmp, L" ");
					wcscat (szTmp, GetString ("FILESYS_PAGE_HELP_EXPLANATION_HIDVOL"));
				}

				SetWindowTextW (GetDlgItem (hwndDlg, IDC_BOX_HELP), szTmp);
			}
			break;


		case SYSENC_COLLECTING_RANDOM_DATA_PAGE:

			SetWindowTextW (GetDlgItem (GetParent (hwndDlg), IDC_BOX_TITLE), GetString ("COLLECTING_RANDOM_DATA_TITLE"));
			SetWindowTextW (GetDlgItem (GetParent (hwndDlg), IDC_NEXT), GetString ("NEXT"));
			SetWindowTextW (GetDlgItem (GetParent (hwndDlg), IDC_PREV), GetString ("PREV"));
			EnableWindow (GetDlgItem (GetParent (hwndDlg), IDC_NEXT), TRUE);
			EnableWindow (GetDlgItem (GetParent (hwndDlg), IDC_PREV), TRUE);

			SetTimer (GetParent (hwndDlg), TIMER_ID_RANDVIEW, TIMER_INTERVAL_RANDVIEW, NULL);

			hRandPoolSys = GetDlgItem (hwndDlg, IDC_SYS_POOL_CONTENTS);

			SendMessage (GetDlgItem (hwndDlg, IDC_SYS_POOL_CONTENTS), WM_SETFONT, (WPARAM) hFixedDigitFont, (LPARAM) TRUE);

			SendMessage (GetDlgItem (hwndDlg, IDC_DISPLAY_POOL_CONTENTS), BM_SETCHECK, showKeys ? BST_CHECKED : BST_UNCHECKED, 0);

			DisplayRandPool (hRandPoolSys, showKeys);

			break;

		case SYSENC_KEYS_GEN_PAGE:

			SetWindowTextW (GetDlgItem (GetParent (hwndDlg), IDC_BOX_TITLE), GetString ("KEYS_GEN_TITLE"));
			SetWindowTextW (GetDlgItem (GetParent (hwndDlg), IDC_NEXT), GetString ("NEXT"));
			SetWindowTextW (GetDlgItem (GetParent (hwndDlg), IDC_PREV), GetString ("PREV"));
			EnableWindow (GetDlgItem (GetParent (hwndDlg), IDC_NEXT), TRUE);
			EnableWindow (GetDlgItem (GetParent (hwndDlg), IDC_PREV), TRUE);

			hMasterKey = GetDlgItem (hwndDlg, IDC_DISK_KEY);
			hHeaderKey = GetDlgItem (hwndDlg, IDC_HEADER_KEY);

			SendMessage (GetDlgItem (hwndDlg, IDC_DISK_KEY), WM_SETFONT, (WPARAM) hFixedDigitFont, (LPARAM) TRUE);
			SendMessage (GetDlgItem (hwndDlg, IDC_HEADER_KEY), WM_SETFONT, (WPARAM) hFixedDigitFont, (LPARAM) TRUE);

			SendMessage (GetDlgItem (hwndDlg, IDC_DISPLAY_KEYS), BM_SETCHECK, showKeys ? BST_CHECKED : BST_UNCHECKED, 0);

			SetWindowText (GetDlgItem (hwndDlg, IDC_HEADER_KEY), showKeys ? HeaderKeyGUIView : "********************************                                              ");
			SetWindowText (GetDlgItem (hwndDlg, IDC_DISK_KEY), showKeys ? MasterKeyGUIView : "********************************                                              ");

			break;

		case SYSENC_RESCUE_DISK_CREATION_PAGE:

			SetWindowTextW (GetDlgItem (GetParent (hwndDlg), IDC_BOX_TITLE), GetString ("RESCUE_DISK"));
			SetWindowTextW (GetDlgItem (GetParent (hwndDlg), IDC_NEXT), GetString ("NEXT"));
			SetWindowTextW (GetDlgItem (GetParent (hwndDlg), IDC_PREV), GetString ("PREV"));
			SetWindowTextW (GetDlgItem (hwndDlg, IDT_RESCUE_DISK_INFO), GetString ("RESCUE_DISK_INFO"));
			SetDlgItemText (hwndDlg, IDC_RESCUE_DISK_ISO_PATH, szRescueDiskISO);
			EnableWindow (GetDlgItem (GetParent (hwndDlg), IDC_NEXT), (GetWindowTextLength (GetDlgItem (hwndDlg, IDC_RESCUE_DISK_ISO_PATH)) > 1));
			EnableWindow (GetDlgItem (GetParent (hwndDlg), IDC_PREV), TRUE);

			break;

		case SYSENC_RESCUE_DISK_BURN_PAGE:
			{
				wchar_t szTmp[8192];

				SetWindowTextW (GetDlgItem (GetParent (hwndDlg), IDC_BOX_TITLE), GetString (bDontVerifyRescueDisk ? "RESCUE_DISK_CREATED_TITLE" : "RESCUE_DISK_RECORDING_TITLE"));
				SetWindowTextW (GetDlgItem (GetParent (hwndDlg), IDC_NEXT), GetString ("NEXT"));
				SetWindowTextW (GetDlgItem (GetParent (hwndDlg), IDC_PREV), GetString ("PREV"));

				_snwprintf (szTmp, sizeof szTmp / 2,
					GetString (bDontVerifyRescueDisk ? "RESCUE_DISK_BURN_INFO_NO_CHECK" : "RESCUE_DISK_BURN_INFO"),
					szRescueDiskISO);

				SetWindowTextW (GetDlgItem (hwndDlg, IDT_RESCUE_DISK_BURN_INFO), szTmp);
				EnableWindow (GetDlgItem (GetParent (hwndDlg), IDC_NEXT), TRUE);

				/* The 'Back' button must be disabled now because the user could burn a Rescue Disk, then go back, and
				generate a different master key, which would cause the Rescue Disk verification to fail (the result
				would be confusion and bug reports). */
				EnableWindow (GetDlgItem (GetParent (hwndDlg), IDC_PREV), FALSE);

				ToHyperlink (hwndDlg, IDC_DOWNLOAD_CD_BURN_SOFTWARE);
			}
			break;

		case SYSENC_RESCUE_DISK_VERIFIED_PAGE:

			SetWindowTextW (GetDlgItem (GetParent (hwndDlg), IDC_BOX_TITLE), GetString ("RESCUE_DISK_DISK_VERIFIED_TITLE"));
			SetWindowTextW (GetDlgItem (hwndDlg, IDC_BOX_HELP), GetString ("RESCUE_DISK_VERIFIED_INFO"));

			SetWindowTextW (GetDlgItem (GetParent (hwndDlg), IDC_NEXT), GetString ("NEXT"));
			SetWindowTextW (GetDlgItem (GetParent (hwndDlg), IDC_PREV), GetString ("PREV"));

			EnableWindow (GetDlgItem (GetParent (hwndDlg), IDC_NEXT), TRUE);

			// Rescue Disk has been verified, no need to go back
			EnableWindow (GetDlgItem (GetParent (hwndDlg), IDC_PREV), FALSE);

			// Prevent losing the burned rescue disk by inadvertent exit
			bConfirmQuit = TRUE;

			break;

		case SYSENC_WIPE_MODE_PAGE:

			SetWindowTextW (GetDlgItem (GetParent (hwndDlg), IDC_BOX_TITLE), GetString ("WIPE_MODE_TITLE"));
			SetWindowTextW (GetDlgItem (hwndDlg, IDT_WIPE_MODE_INFO), GetString ("WIPE_MODE_INFO"));

			PopulateWipeModeCombo (GetDlgItem (hwndDlg, IDC_WIPE_MODE), 
				SystemEncryptionStatus == SYSENC_STATUS_DECRYPTING || bHiddenOS);	// Decoy OS must not contain any sensitive data, so it is not necessary to wipe it

			SelectAlgo (GetDlgItem (hwndDlg, IDC_WIPE_MODE), (int *) &nWipeMode);

			SetWindowTextW (GetDlgItem (GetParent (hwndDlg), IDC_NEXT), GetString ("NEXT"));
			SetWindowTextW (GetDlgItem (GetParent (hwndDlg), IDC_PREV), GetString ("PREV"));
			EnableWindow (GetDlgItem (GetParent (hwndDlg), IDC_PREV), TRUE);
			EnableWindow (GetDlgItem (GetParent (hwndDlg), IDC_NEXT), TRUE);

			break;

		case SYSENC_PRETEST_INFO_PAGE:

			if (bHiddenOS)
			{
				SetWindowTextW (GetDlgItem (GetParent (hwndDlg), IDC_BOX_TITLE), GetString ("OS_CLONING_PREINFO_TITLE"));
				SetWindowTextW (GetDlgItem (hwndDlg, IDC_BOX_HELP), GetString ("OS_CLONING_PREINFO_HELP"));
				SetWindowTextW (GetDlgItem (GetParent (hwndDlg), IDC_NEXT), GetString ("START"));
			}
			else
			{
				wchar_t finalMsg[8024] = {0};

				SetWindowTextW (GetDlgItem (GetParent (hwndDlg), IDC_BOX_TITLE), GetString ("SYS_ENCRYPTION_PRETEST_TITLE"));

				try
				{
					wsprintfW (finalMsg, 
						GetString ("SYS_ENCRYPTION_PRETEST_INFO"), 
						BootEncObj->GetSystemDriveConfiguration().DriveNumber);
				}
				catch (Exception &e)
				{
					e.Show (hwndDlg);
					EndMainDlg (MainDlg);
					return 0;
				}

				SetWindowTextW (GetDlgItem (hwndDlg, IDC_BOX_HELP), finalMsg);

				SetWindowTextW (GetDlgItem (GetParent (hwndDlg), IDC_NEXT), GetString ("TEST"));
			}

			SetWindowTextW (GetDlgItem (GetParent (hwndDlg), IDC_PREV), GetString ("PREV"));
			EnableWindow (GetDlgItem (GetParent (hwndDlg), IDC_NEXT), TRUE);
			EnableWindow (GetDlgItem (GetParent (hwndDlg), IDC_PREV), TRUE);

			break;

		case SYSENC_PRETEST_RESULT_PAGE:

			if (bHiddenOS)
			{
				SetWindowTextW (GetDlgItem (GetParent (hwndDlg), IDC_BOX_TITLE), GetString ("DECOY_OS_TITLE"));
				SetWindowTextW (GetDlgItem (hwndDlg, IDC_BOX_HELP), GetString ("DECOY_OS_INFO"));
			}
			else
			{
				SetWindowTextW (GetDlgItem (GetParent (hwndDlg), IDC_BOX_TITLE), GetString ("SYS_ENCRYPTION_PRETEST_RESULT_TITLE"));
				SetWindowTextW (GetDlgItem (hwndDlg, IDC_BOX_HELP), GetString ("SYS_ENCRYPTION_PRETEST_RESULT_INFO"));
			}

			SetWindowTextW (GetDlgItem (GetParent (hwndDlg), IDC_NEXT), GetString ("ENCRYPT"));
			SetWindowTextW (GetDlgItem (GetParent (hwndDlg), IDC_PREV), GetString ("PREV"));
			SetWindowTextW (GetDlgItem (GetParent (hwndDlg), IDCANCEL), GetString ("DEFER"));

			EnableWindow (GetDlgItem (GetParent (hwndDlg), IDC_NEXT), TRUE);
			EnableWindow (GetDlgItem (GetParent (hwndDlg), IDC_PREV), FALSE);
			EnableWindow (GetDlgItem (GetParent (hwndDlg), IDCANCEL), TRUE);

			break;

		case SYSENC_ENCRYPTION_PAGE:

			if (CreateSysEncMutex ())
			{
				unsigned int hiddenOSCreationPhase = DetermineHiddenOSCreationPhase();

				bHiddenOS = (hiddenOSCreationPhase != TC_HIDDEN_OS_CREATION_PHASE_NONE);

				try
				{
					BootEncStatus = BootEncObj->GetStatus();
					bSystemEncryptionInProgress = BootEncStatus.SetupInProgress;
				}
				catch (Exception &e)
				{
					e.Show (hwndDlg);
					Error ("ERR_GETTING_SYSTEM_ENCRYPTION_STATUS");
					EndMainDlg (MainDlg);
					return 0;
				}

				SetWindowTextW (GetDlgItem (GetParent (hwndDlg), IDC_BOX_TITLE),
					GetString (SystemEncryptionStatus != SYSENC_STATUS_DECRYPTING ? "ENCRYPTION" : "DECRYPTION"));

				SetWindowTextW (GetDlgItem (hwndDlg, IDC_BOX_HELP), GetString ("SYSENC_ENCRYPTION_PAGE_INFO"));

				SetWindowTextW (GetDlgItem (GetParent (hwndDlg), IDCANCEL), GetString ("DEFER"));

				SetWindowTextW (GetDlgItem (GetParent (hwndDlg), IDC_PREV), GetString ("PREV"));

				SetWindowTextW (GetDlgItem (GetParent (hwndDlg), IDC_NEXT),
					GetString (SystemEncryptionStatus != SYSENC_STATUS_DECRYPTING ? "ENCRYPT" : "DECRYPT"));

				SetWindowTextW (GetDlgItem (hwndDlg, IDC_PAUSE),
					GetString (bSystemEncryptionInProgress ? "IDC_PAUSE" : "RESUME"));

				EnableWindow (GetDlgItem (hwndDlg, IDC_PAUSE), BootEncStatus.DriveEncrypted);
				EnableWindow (GetDlgItem (GetParent (hwndDlg), IDC_PREV), FALSE);
				EnableWindow (GetDlgItem (GetParent (hwndDlg), IDC_NEXT), !BootEncStatus.SetupInProgress);
				EnableWindow (GetDlgItem (GetParent (hwndDlg), IDCANCEL), TRUE);
				EnableWindow (GetDlgItem (GetParent (hwndDlg), IDHELP), TRUE);

				ToHyperlink (hwndDlg, IDC_MORE_INFO_SYS_ENCRYPTION);

				if (SystemEncryptionStatus == SYSENC_STATUS_DECRYPTING
					|| bHiddenOS)	// Decoy OS must not contain any sensitive data, so it is not necessary to wipe it
				{
					nWipeMode = TC_WIPE_NONE;
					EnableWindow (GetDlgItem (hwndDlg, IDC_WIPE_MODE), FALSE);
					EnableWindow (GetDlgItem (hwndDlg, IDT_WIPE_MODE), FALSE);
					PopulateWipeModeCombo (GetDlgItem (hwndDlg, IDC_WIPE_MODE), TRUE);
					SelectAlgo (GetDlgItem (hwndDlg, IDC_WIPE_MODE), (int *) &nWipeMode);
				}
				else
				{
					EnableWindow (GetDlgItem (hwndDlg, IDC_WIPE_MODE), !bSystemEncryptionInProgress);
					PopulateWipeModeCombo (GetDlgItem (hwndDlg, IDC_WIPE_MODE), FALSE);
					SelectAlgo (GetDlgItem (hwndDlg, IDC_WIPE_MODE), (int *) &nWipeMode);
				}

				PostMessage (hwndDlg, TC_APPMSG_PERFORM_POST_SYSENC_WMINIT_TASKS, 0, 0);
			}
			else
			{
				Error ("SYSTEM_ENCRYPTION_IN_PROGRESS_ELSEWHERE");
				EndMainDlg (MainDlg);
				return 0;
			}
			return 0;

		case FORMAT_PAGE:
			{
				BOOL bNTFSallowed = FALSE;
				BOOL bFATallowed = FALSE;
				BOOL bNoFSallowed = FALSE;

				SetTimer (GetParent (hwndDlg), TIMER_ID_RANDVIEW, TIMER_INTERVAL_RANDVIEW, NULL);

				hMasterKey = GetDlgItem (hwndDlg, IDC_DISK_KEY);
				hHeaderKey = GetDlgItem (hwndDlg, IDC_HEADER_KEY);
				hRandPool = GetDlgItem (hwndDlg, IDC_RANDOM_BYTES);

				SendMessage (GetDlgItem (hwndDlg, IDC_RANDOM_BYTES), WM_SETFONT, (WPARAM) hFixedDigitFont, (LPARAM) TRUE);
				SendMessage (GetDlgItem (hwndDlg, IDC_DISK_KEY), WM_SETFONT, (WPARAM) hFixedDigitFont, (LPARAM) TRUE);
				SendMessage (GetDlgItem (hwndDlg, IDC_HEADER_KEY), WM_SETFONT, (WPARAM) hFixedDigitFont, (LPARAM) TRUE);

				SetWindowTextW (GetDlgItem (hwndDlg, IDC_BOX_HELP),
					GetString (bHiddenVolHost ? "FORMAT_HIDVOL_HOST_HELP" : "FORMAT_HELP"));

				if (bHiddenVol)
					SetWindowTextW (GetDlgItem (GetParent (hwndDlg), IDC_BOX_TITLE), GetString (bHiddenVolHost ? "FORMAT_HIDVOL_HOST_TITLE" : "FORMAT_HIDVOL_TITLE"));
				else
					SetWindowTextW (GetDlgItem (GetParent (hwndDlg), IDC_BOX_TITLE), GetString ("FORMAT_TITLE"));

				/* Quick/Dynamic */

				if (bHiddenVol)
				{
					quickFormat = !bHiddenVolHost;
					bSparseFileSwitch = FALSE;

					SetCheckBox (hwndDlg, IDC_QUICKFORMAT, quickFormat);
					SetWindowTextW (GetDlgItem (hwndDlg, IDC_QUICKFORMAT), GetString ((bDevice || !bHiddenVolHost) ? "IDC_QUICKFORMAT" : "SPARSE_FILE"));
					EnableWindow (GetDlgItem (hwndDlg, IDC_QUICKFORMAT), bDevice && bHiddenVolHost);
				}
				else
				{
					if (bDevice)
					{
						bSparseFileSwitch = FALSE;
						SetWindowTextW (GetDlgItem (hwndDlg, IDC_QUICKFORMAT), GetString("IDC_QUICKFORMAT"));
						EnableWindow (GetDlgItem (hwndDlg, IDC_QUICKFORMAT), TRUE);
					}
					else
					{
						char root[TC_MAX_PATH];
						DWORD fileSystemFlags = 0;

						SetWindowTextW (GetDlgItem (hwndDlg, IDC_QUICKFORMAT), GetString("SPARSE_FILE"));

						/* Check if the host file system supports sparse files */

						if (GetVolumePathName (szFileName, root, sizeof (root)))
						{
							GetVolumeInformation (root, NULL, 0, NULL, NULL, &fileSystemFlags, NULL, 0);
							bSparseFileSwitch = fileSystemFlags & FILE_SUPPORTS_SPARSE_FILES;
						}
						else
							bSparseFileSwitch = FALSE;

						EnableWindow (GetDlgItem (hwndDlg, IDC_QUICKFORMAT), bSparseFileSwitch);
					}
				}

				SendMessage (GetDlgItem (hwndDlg, IDC_SHOW_KEYS), BM_SETCHECK, showKeys ? BST_CHECKED : BST_UNCHECKED, 0);
				SetWindowText (GetDlgItem (hwndDlg, IDC_RANDOM_BYTES), showKeys ? "" : "********************************                                              ");
				SetWindowText (GetDlgItem (hwndDlg, IDC_HEADER_KEY), showKeys ? "" : "********************************                                              ");
				SetWindowText (GetDlgItem (hwndDlg, IDC_DISK_KEY), showKeys ? "" : "********************************                                              ");

				SendMessage (GetDlgItem (hwndDlg, IDC_CLUSTERSIZE), CB_RESETCONTENT, 0, 0);
				AddComboPairW (GetDlgItem (hwndDlg, IDC_CLUSTERSIZE), GetString ("DEFAULT"), 0);
				AddComboPair (GetDlgItem (hwndDlg, IDC_CLUSTERSIZE), "0.5 KB", 1);
				AddComboPair (GetDlgItem (hwndDlg, IDC_CLUSTERSIZE), "1 KB", 2);
				AddComboPair (GetDlgItem (hwndDlg, IDC_CLUSTERSIZE), "2 KB", 4);
				AddComboPair (GetDlgItem (hwndDlg, IDC_CLUSTERSIZE), "4 KB", 8);
				AddComboPair (GetDlgItem (hwndDlg, IDC_CLUSTERSIZE), "8 KB", 16);
				AddComboPair (GetDlgItem (hwndDlg, IDC_CLUSTERSIZE), "16 KB", 32);
				AddComboPair (GetDlgItem (hwndDlg, IDC_CLUSTERSIZE), "32 KB", 64);
				AddComboPair (GetDlgItem (hwndDlg, IDC_CLUSTERSIZE), "64 KB", 128);
				SendMessage (GetDlgItem (hwndDlg, IDC_CLUSTERSIZE), CB_SETCURSEL, 0, 0);

				EnableWindow (GetDlgItem (hwndDlg, IDC_CLUSTERSIZE), TRUE);

				/* Filesystems */

				bNTFSallowed = FALSE;
				bFATallowed = FALSE;
				bNoFSallowed = FALSE;

				SendMessage (GetDlgItem (hwndDlg, IDC_FILESYS), CB_RESETCONTENT, 0, 0);

				EnableWindow (GetDlgItem (hwndDlg, IDC_FILESYS), TRUE);

				uint64 dataAreaSize = GetVolumeDataAreaSize (bHiddenVol && !bHiddenVolHost, nVolumeSize);

				if (!CreatingHiddenSysVol())	
				{
					if (dataAreaSize >= TC_MIN_NTFS_FS_SIZE && dataAreaSize <= TC_MAX_NTFS_FS_SIZE)
					{
						AddComboPair (GetDlgItem (hwndDlg, IDC_FILESYS), "NTFS", FILESYS_NTFS);
						bNTFSallowed = TRUE;
					}

					if (dataAreaSize >= TC_MIN_FAT_FS_SIZE && dataAreaSize <= TC_MAX_FAT_FS_SIZE)
					{
						AddComboPair (GetDlgItem (hwndDlg, IDC_FILESYS), "FAT", FILESYS_FAT);
						bFATallowed = TRUE;
					}
				}
				else
				{
					// We're creating a hidden volume for a hidden OS, so we don't need to format it with
					// any filesystem (the entire OS will be copied to the hidden volume sector by sector).
					EnableWindow (GetDlgItem (hwndDlg, IDC_FILESYS), FALSE);
					EnableWindow (GetDlgItem (hwndDlg, IDC_CLUSTERSIZE), FALSE);
				}

				if (!bHiddenVolHost)
				{
					AddComboPairW (GetDlgItem (hwndDlg, IDC_FILESYS), GetString ("NONE"), FILESYS_NONE);
					bNoFSallowed = TRUE;
				}

				EnableWindow (GetDlgItem (GetParent (hwndDlg), IDC_NEXT), TRUE);

				if (fileSystem == FILESYS_NONE)	// If no file system has been previously selected
				{
					// Set default file system

					if (bFATallowed && !(nNeedToStoreFilesOver4GB == 1 && bNTFSallowed))
						fileSystem = FILESYS_FAT;
					else if (bNTFSallowed)
						fileSystem = FILESYS_NTFS;
					else if (bNoFSallowed)
						fileSystem = FILESYS_NONE;
					else
					{
						AddComboPair (GetDlgItem (hwndDlg, IDC_FILESYS), "---", 0);
						EnableWindow (GetDlgItem (GetParent (hwndDlg), IDC_NEXT), FALSE);
					}
				}

				SendMessage (GetDlgItem (hwndDlg, IDC_FILESYS), CB_SETCURSEL, 0, 0);
				SelectAlgo (GetDlgItem (hwndDlg, IDC_FILESYS), (int *) &fileSystem);

				EnableWindow (GetDlgItem (hwndDlg, IDC_ABORT_BUTTON), FALSE);

				SetWindowTextW (GetDlgItem (GetParent (hwndDlg), IDC_NEXT), GetString ("FORMAT"));
				SetWindowTextW (GetDlgItem (GetParent (hwndDlg), IDC_PREV), GetString ("PREV"));

				EnableWindow (GetDlgItem (GetParent (hwndDlg), IDC_PREV), TRUE);

				SetFocus (GetDlgItem (GetParent (hwndDlg), IDC_NEXT));
			}
			break;

		case FORMAT_FINISHED_PAGE:
			{
				if (!bHiddenVolHost && bHiddenVol && !bHiddenVolFinished)
				{
					wchar_t msg[4096];

					nNeedToStoreFilesOver4GB = -1;

					if (bHiddenOS)
					{
						wchar_t szMaxRecomOuterVolFillSize[100];

						__int64 maxRecomOuterVolFillSize = 0;

						// Determine the maximum recommended total size of files that can be copied to the outer volume
						// while leaving enough space for the hidden volume, which must contain a clone of the OS

						maxRecomOuterVolFillSize = nVolumeSize - GetSystemPartitionSize(); 

						// -50% reserve for filesystem "peculiarities"
						maxRecomOuterVolFillSize /= 2;	

						swprintf (szMaxRecomOuterVolFillSize, L"%I64d %s", maxRecomOuterVolFillSize / BYTES_PER_MB, GetString ("MB"));

						swprintf (msg, GetString ("HIDVOL_HOST_FILLING_HELP_SYSENC"), hiddenVolHostDriveNo + 'A', szMaxRecomOuterVolFillSize);			
					}
					else
						swprintf (msg, GetString ("HIDVOL_HOST_FILLING_HELP"), hiddenVolHostDriveNo + 'A');			

					SetWindowTextW (GetDlgItem (hwndDlg, IDC_BOX_HELP), msg);
					SetWindowTextW (GetDlgItem (GetParent (hwndDlg), IDC_BOX_TITLE), GetString ("HIDVOL_HOST_FILLING_TITLE"));
				}
				else 
				{
					if (bHiddenOS)
						SetWindowTextW (GetDlgItem (hwndDlg, IDC_BOX_HELP), GetString ("SYSENC_HIDDEN_VOL_FORMAT_FINISHED_HELP"));
					else
						SetWindowTextW (GetDlgItem (hwndDlg, IDC_BOX_HELP), GetString ("FORMAT_FINISHED_HELP"));

					SetWindowTextW (GetDlgItem (GetParent (hwndDlg), IDC_BOX_TITLE), GetString (bHiddenVol ? "HIDVOL_FORMAT_FINISHED_TITLE" : "FORMAT_FINISHED_TITLE"));
				}


				SetWindowTextW (GetDlgItem (GetParent (hwndDlg), IDC_NEXT), GetString ("NEXT"));
				SetWindowTextW (GetDlgItem (GetParent (hwndDlg), IDC_PREV), GetString ("PREV"));
				EnableWindow (GetDlgItem (GetParent (hwndDlg), IDC_NEXT), TRUE);
				EnableWindow (GetDlgItem (GetParent (hwndDlg), IDC_PREV), (!bHiddenVol || bHiddenVolFinished) && !bHiddenOS);

				if (!bHiddenVol || bHiddenVolFinished)
					SetWindowTextW (GetDlgItem (GetParent (hwndDlg), IDCANCEL), GetString ("EXIT"));
			}
			break;

		}
		return 0;

	case WM_HELP:
		OpenPageHelp (GetParent (hwndDlg), nCurPageNo);
		return 1;

	case TC_APPMSG_PERFORM_POST_SYSENC_WMINIT_TASKS:
		AfterSysEncProgressWMInitTasks (hwndDlg);
		return 1;

	case WM_COMMAND:

		if (nCurPageNo == INTRO_PAGE)
		{
			switch (lw)
			{
			case IDC_FILE_CONTAINER:
				UpdateWizardModeControls (hwndDlg, WIZARD_MODE_FILE_CONTAINER);
				return 1;

			case IDC_NONSYS_DEVICE:
				UpdateWizardModeControls (hwndDlg, WIZARD_MODE_NONSYS_DEVICE);
				return 1;

			case IDC_SYS_DEVICE:
				UpdateWizardModeControls (hwndDlg, WIZARD_MODE_SYS_DEVICE);
				return 1;

			case IDC_MORE_INFO_ON_CONTAINERS:
				Applink ("introcontainer", TRUE, "");
				return 1;

			case IDC_MORE_INFO_ON_SYS_ENCRYPTION:
				Applink ("introsysenc", TRUE, "");
				return 1;
			}
		}

		if (nCurPageNo == SYSENC_TYPE_PAGE)
		{
			switch (lw)
			{
			case IDC_SYSENC_HIDDEN:
				bHiddenOS = TRUE;
				bHiddenVol = TRUE;
				bHiddenVolHost = TRUE;
				return 1;

			case IDC_SYSENC_NORMAL:
				bHiddenOS = FALSE;
				bHiddenVol = FALSE;
				bHiddenVolHost = FALSE;
				return 1;

			case IDC_HIDDEN_SYSENC_INFO_LINK:
				Applink ("hiddensysenc", TRUE, "");
				return 1;
			}
		}

		if (nCurPageNo == SYSENC_HIDDEN_OS_REQ_CHECK_PAGE && lw == IDC_HIDDEN_SYSENC_INFO_LINK)
		{
			Applink ("hiddensysenc", TRUE, "");
			return 1;
		}

		if (nCurPageNo == SYSENC_SPAN_PAGE)
		{
			switch (lw)
			{
			case IDC_WHOLE_SYS_DRIVE:
				bWholeSysDrive = TRUE;
				return 1;
			case IDC_SYS_PARTITION:
				bWholeSysDrive = FALSE;
				return 1;
			}

		}

		if (nCurPageNo == SYSENC_MULTI_BOOT_MODE_PAGE)
		{
			switch (lw)
			{
			case IDC_SINGLE_BOOT:
				nMultiBoot = 1;
				EnableWindow (GetDlgItem (GetParent (hwndDlg), IDC_NEXT), TRUE);
				return 1;
			case IDC_MULTI_BOOT:
				nMultiBoot = 2;
				EnableWindow (GetDlgItem (GetParent (hwndDlg), IDC_NEXT), TRUE);
				return 1;
			}
		}

		// Dual choice pages
		switch (nCurPageNo)
		{
		case SYSENC_MULTI_BOOT_SYS_EQ_BOOT_PAGE:
		case SYSENC_MULTI_BOOT_NBR_SYS_DRIVES_PAGE:
		case SYSENC_MULTI_BOOT_ADJACENT_SYS_PAGE:
		case SYSENC_MULTI_BOOT_NONWIN_BOOT_LOADER_PAGE:
		case SYSENC_PRE_DRIVE_ANALYSIS_PAGE:

			if (lw == IDC_CHOICE1 || lw == IDC_CHOICE2)
			{
				EnableWindow (GetDlgItem (GetParent (hwndDlg), IDC_NEXT), TRUE);
				return 1;
			}
			break;
		}

		if (nCurPageNo == FILESYS_PAGE && (lw == IDC_CHOICE1 || lw == IDC_CHOICE2))
		{
			if (bWarnOuterVolSuitableFileSys && lw == IDC_CHOICE1 && bHiddenVolHost)
			{
				wchar_t szTmp [4096];

				bWarnOuterVolSuitableFileSys = FALSE;	// Do not show this warning anymore (this also prevents potential endless repetition due to some race conditions)

				wcscpy (szTmp, GetString ("FILESYS_PAGE_HELP_EXPLANATION_HIDVOL"));
				wcscat (szTmp, L"\n\n");
				wcscat (szTmp, GetString ("FILESYS_PAGE_HELP_EXPLANATION_HIDVOL_CONFIRM"));

				if (MessageBoxW (MainDlg, szTmp, lpszTitle, MB_ICONWARNING | MB_YESNO | MB_DEFBUTTON2) == IDNO)
				{
					nNeedToStoreFilesOver4GB = 0;
					Init2RadButtonPageYesNo (nNeedToStoreFilesOver4GB);
				}
			}

			EnableWindow (GetDlgItem (GetParent (hwndDlg), IDC_NEXT), TRUE);
			return 1;
		}

		if (lw == IDC_HIDDEN_VOL && nCurPageNo == VOLUME_TYPE_PAGE)
		{
			bHiddenVol = TRUE;
			bHiddenVolHost = TRUE;
			return 1;
		}

		if (lw == IDC_STD_VOL && nCurPageNo == VOLUME_TYPE_PAGE)
		{
			bHiddenVol = FALSE;
			bHiddenVolHost = FALSE;
			return 1;
		}

		if (nCurPageNo == SYSENC_ENCRYPTION_PAGE)
		{
			BootEncryptionStatus locBootEncStatus;

			switch (lw)
			{
			case IDC_PAUSE:
				try
				{
					locBootEncStatus = BootEncObj->GetStatus();

					if (locBootEncStatus.SetupInProgress)
						SysEncPause ();
					else
						SysEncResume ();
				}
				catch (Exception &e)
				{
					e.Show (hwndDlg);
				}
				return 1;

			case IDC_WIPE_MODE:
				if (hw == CBN_SELCHANGE)
				{
					nWipeMode = (WipeAlgorithmId) SendMessage (GetDlgItem (hCurPage, IDC_WIPE_MODE),
						CB_GETITEMDATA, 
						SendMessage (GetDlgItem (hCurPage, IDC_WIPE_MODE), CB_GETCURSEL, 0, 0),
						0);

					return 1;
				}
				break;

			case IDC_MORE_INFO_SYS_ENCRYPTION:
				Applink ("sysencprogressinfo", TRUE, "");
				return 1;
			}
		}

		if (lw == IDC_OPEN_OUTER_VOLUME && nCurPageNo == FORMAT_FINISHED_PAGE)
		{
			OpenVolumeExplorerWindow (hiddenVolHostDriveNo);
			return 1;
		}

		if (lw == IDC_HIDDEN_VOL_HELP && nCurPageNo == VOLUME_TYPE_PAGE)
		{
			Applink ("hiddenvolume", TRUE, "");
			return 1;
		}

		if (lw == IDC_ABORT_BUTTON && nCurPageNo == FORMAT_PAGE)
		{
			if (MessageBoxW (hwndDlg, GetString ("FORMAT_ABORT"), lpszTitle, MB_YESNO | MB_ICONQUESTION | MB_DEFBUTTON2 ) == IDYES)
				bThreadCancel = TRUE;
			return 1;
		}

		if (lw == IDC_CIPHER_TEST && nCurPageNo == CIPHER_PAGE)
		{
			LPARAM nIndex;
			int c;

			nIndex = SendMessage (GetDlgItem (hCurPage, IDC_COMBO_BOX), CB_GETCURSEL, 0, 0);
			nVolumeEA = SendMessage (GetDlgItem (hCurPage, IDC_COMBO_BOX), CB_GETITEMDATA, nIndex, 0);

			for (c = EAGetLastCipher (nVolumeEA); c != 0; c = EAGetPreviousCipher (nVolumeEA, c))
			{
				DialogBoxParamW (hInst, MAKEINTRESOURCEW (IDD_CIPHER_TEST_DLG), 
					GetParent (hwndDlg), (DLGPROC) CipherTestDialogProc, (LPARAM) c);
			}
			return 1;
		}

		if (lw == IDC_WIZ_BENCHMARK && nCurPageNo == CIPHER_PAGE)
		{
			// Reduce CPU load
			bFastPollEnabled = FALSE;	
			bRandmixEnabled = FALSE;

			DialogBoxParamW (hInst,
				MAKEINTRESOURCEW (IDD_BENCHMARK_DLG), hwndDlg,
				(DLGPROC) BenchmarkDlgProc, (LPARAM) NULL);

			bFastPollEnabled = TRUE;
			bRandmixEnabled = TRUE;

			return 1;
		}

		if (lw == IDC_LINK_MORE_INFO_ABOUT_CIPHER && nCurPageNo == CIPHER_PAGE)
		{
			char name[100];

			int nIndex = SendMessage (GetDlgItem (hCurPage, IDC_COMBO_BOX), CB_GETCURSEL, 0, 0);
			nIndex = SendMessage (GetDlgItem (hCurPage, IDC_COMBO_BOX), CB_GETITEMDATA, nIndex, 0);
			EAGetName (name, nIndex);

			if (strcmp (name, "AES") == 0)
				Applink ("aes", FALSE, "");
			else if (strcmp (name, "Serpent") == 0)
				Applink ("serpent", FALSE, "");
			else if (strcmp (name, "Twofish") == 0)
				Applink ("twofish", FALSE, "");
			else if (EAGetCipherCount (nIndex) > 1)
				Applink ("cascades", TRUE, "");

			return 1;
		}

		if (lw == IDC_LINK_HASH_INFO && nCurPageNo == CIPHER_PAGE)
		{
			Applink ("hashalgorithms", TRUE, "");
			return 1;
		}

		if (hw == CBN_EDITCHANGE && nCurPageNo == FILE_PAGE)
		{
			EnableWindow (GetDlgItem (GetParent (hwndDlg), IDC_NEXT), 
				GetWindowTextLength (GetDlgItem (hCurPage, IDC_COMBO_BOX)) > 0);
			return 1;
		}
		
		if (hw == CBN_SELCHANGE && nCurPageNo == FILE_PAGE)
		{
			LPARAM nIndex;

			nIndex = MoveEditToCombo ((HWND) lParam, bHistory);
			nIndex = UpdateComboOrder (GetDlgItem (hwndDlg, IDC_COMBO_BOX));

			if (nIndex != CB_ERR)
				EnableWindow (GetDlgItem (GetParent (hwndDlg), IDC_NEXT), TRUE);
			else
				EnableWindow (GetDlgItem (GetParent (hwndDlg), IDC_NEXT), FALSE);

			return 1;
		}
		
		if (hw == EN_CHANGE && nCurPageNo == SIZE_PAGE)
		{
			VerifySizeAndUpdate (hwndDlg, FALSE);
			return 1;
		}
		
		if (hw == EN_CHANGE && nCurPageNo == PASSWORD_PAGE)
		{
			VerifyPasswordAndUpdate (hwndDlg, GetDlgItem (GetParent (hwndDlg), IDC_NEXT),
				GetDlgItem (hwndDlg, IDC_PASSWORD),
				GetDlgItem (hwndDlg, IDC_VERIFY),
				NULL,
				NULL,
				KeyFilesEnable && FirstKeyFile!=NULL && !SysEncInEffect());
			volumePassword.Length = strlen ((char *) volumePassword.Text);

			return 1;
		}

		if (lw == IDC_SHOW_PASSWORD && nCurPageNo == PASSWORD_PAGE)
		{
			SendMessage (GetDlgItem (hwndDlg, IDC_PASSWORD),
						EM_SETPASSWORDCHAR,
						GetCheckBox (hwndDlg, IDC_SHOW_PASSWORD) ? 0 : '*',
						0);
			SendMessage (GetDlgItem (hwndDlg, IDC_VERIFY),
						EM_SETPASSWORDCHAR,
						GetCheckBox (hwndDlg, IDC_SHOW_PASSWORD) ? 0 : '*',
						0);
			InvalidateRect (GetDlgItem (hwndDlg, IDC_PASSWORD), NULL, TRUE);
			InvalidateRect (GetDlgItem (hwndDlg, IDC_VERIFY), NULL, TRUE);
			return 1;
		}
		
		if (lw == IDC_KEY_FILES && (nCurPageNo == PASSWORD_PAGE || nCurPageNo == HIDDEN_VOL_HOST_PASSWORD_PAGE))
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

				if (nCurPageNo != HIDDEN_VOL_HOST_PASSWORD_PAGE)
				{
					VerifyPasswordAndUpdate (hwndDlg, GetDlgItem (GetParent (hwndDlg), IDC_NEXT),
						GetDlgItem (hCurPage, IDC_PASSWORD),
						GetDlgItem (hCurPage, IDC_VERIFY),
						volumePassword.Text, szVerify, KeyFilesEnable && FirstKeyFile!=NULL);
				}
			}

			return 1;
		}

		if (lw == IDC_KEYFILES_ENABLE && (nCurPageNo == PASSWORD_PAGE || nCurPageNo == HIDDEN_VOL_HOST_PASSWORD_PAGE))
		{
			KeyFilesEnable = GetCheckBox (hwndDlg, IDC_KEYFILES_ENABLE);
			EnableWindow (GetDlgItem (hwndDlg, IDC_KEY_FILES), KeyFilesEnable);

			if (nCurPageNo != HIDDEN_VOL_HOST_PASSWORD_PAGE)
			{
				VerifyPasswordAndUpdate (hwndDlg, GetDlgItem (GetParent (hwndDlg), IDC_NEXT),
					GetDlgItem (hCurPage, IDC_PASSWORD),
					GetDlgItem (hCurPage, IDC_VERIFY),
					volumePassword.Text, szVerify, KeyFilesEnable && FirstKeyFile!=NULL);
			}

			return 1;
		}

		if (hw == EN_CHANGE && nCurPageNo == HIDDEN_VOL_HOST_PASSWORD_PAGE)
		{
			GetWindowText (GetDlgItem (hCurPage, IDC_PASSWORD_DIRECT), (char *) volumePassword.Text, sizeof (volumePassword.Text));
			volumePassword.Length = strlen ((char *) volumePassword.Text);
			return 1;
		}

		if (lw == IDC_SHOW_PASSWORD_HIDVOL_HOST && nCurPageNo == HIDDEN_VOL_HOST_PASSWORD_PAGE)
		{
			SendMessage (GetDlgItem (hwndDlg, IDC_PASSWORD_DIRECT),
						EM_SETPASSWORDCHAR,
						GetCheckBox (hwndDlg, IDC_SHOW_PASSWORD_HIDVOL_HOST) ? 0 : '*',
						0);
			InvalidateRect (GetDlgItem (hwndDlg, IDC_PASSWORD_DIRECT), NULL, TRUE);
			return 1;
		}

		if ((lw == IDC_KB || lw == IDC_MB) && nCurPageNo == SIZE_PAGE)
		{
			VerifySizeAndUpdate (hwndDlg, FALSE);
			return 1;
		}

		if (lw == IDC_HIDVOL_WIZ_MODE_DIRECT && nCurPageNo == HIDDEN_VOL_WIZARD_MODE_PAGE)
		{
			bHiddenVolDirect = TRUE;
			return 1;
		}

		if (lw == IDC_HIDVOL_WIZ_MODE_FULL && nCurPageNo == HIDDEN_VOL_WIZARD_MODE_PAGE)
		{
			bHiddenVolDirect = FALSE;
			return 1;
		}

		if (lw == IDC_SELECT_VOLUME_LOCATION && nCurPageNo == FILE_PAGE)
		{
			if (!bDevice)
			{
				// Select file

				if (BrowseFiles (hwndDlg, "OPEN_TITLE", szFileName, bHistory, !bHiddenVolDirect) == FALSE)
					return 1;

				AddComboItem (GetDlgItem (hwndDlg, IDC_COMBO_BOX), szFileName, bHistory);

				EnableDisableFileNext (GetDlgItem (hwndDlg, IDC_COMBO_BOX),
					GetDlgItem (GetParent (hwndDlg), IDC_NEXT));

				return 1;
			}
			else
			{
				// Select device

				int nResult = DialogBoxParamW (hInst,
					MAKEINTRESOURCEW (IDD_RAWDEVICES_DLG), GetParent (hwndDlg),
					(DLGPROC) RawDevicesDlgProc, (LPARAM) & szFileName[0]);

				// Check administrator privileges
				if (!strstr (szFileName, "Floppy") && !IsAdmin() && !IsUacSupported ())
					MessageBoxW (hwndDlg, GetString ("ADMIN_PRIVILEGES_WARN_DEVICES"), lpszTitle, MB_OK|MB_ICONWARNING);

				if (nResult == IDOK && strlen (szFileName) > 0)
				{
					AddComboItem (GetDlgItem (hwndDlg, IDC_COMBO_BOX), szFileName, bHistory);

					EnableDisableFileNext (GetDlgItem (hwndDlg, IDC_COMBO_BOX),
						GetDlgItem (GetParent (hwndDlg), IDC_NEXT));

				}
				return 1;
			}
		}
			
		if (hw == CBN_SELCHANGE && nCurPageNo == CIPHER_PAGE)
		{
			switch (lw)
			{
			case IDC_COMBO_BOX:
				ComboSelChangeEA (hwndDlg);
				break;

			case IDC_COMBO_BOX_HASH_ALGO:
				if (SysEncInEffect ()
					&& SendMessage (GetDlgItem (hwndDlg, IDC_COMBO_BOX_HASH_ALGO), CB_GETITEMDATA, 
					SendMessage (GetDlgItem (hwndDlg, IDC_COMBO_BOX_HASH_ALGO), CB_GETCURSEL, 0, 0), 0) 
					!= DEFAULT_HASH_ALGORITHM_BOOT)
				{
					hash_algo = DEFAULT_HASH_ALGORITHM_BOOT;
					RandSetHashFunction (DEFAULT_HASH_ALGORITHM_BOOT);
					Info ("ALGO_NOT_SUPPORTED_FOR_SYS_ENCRYPTION");
					SelectAlgo (GetDlgItem (hwndDlg, IDC_COMBO_BOX_HASH_ALGO), &hash_algo);
				}
				break;
			}
			return 1;

		}

		if (lw == IDC_QUICKFORMAT && IsButtonChecked (GetDlgItem (hCurPage, IDC_QUICKFORMAT)))
		{
			if (bSparseFileSwitch)
			{
				if (AskWarnYesNo("CONFIRM_SPARSE_FILE") == IDNO)
					SetCheckBox (hwndDlg, IDC_QUICKFORMAT, FALSE); 
			}
			else
			{
				if (AskWarnYesNo("WARN_QUICK_FORMAT") == IDNO)
					SetCheckBox (hwndDlg, IDC_QUICKFORMAT, FALSE); 
			}
			return 1;
		}

		if (lw == IDC_FILESYS && hw == CBN_SELCHANGE)
		{
			fileSystem = SendMessage (GetDlgItem (hCurPage, IDC_FILESYS), CB_GETITEMDATA,
				SendMessage (GetDlgItem (hCurPage, IDC_FILESYS), CB_GETCURSEL, 0, 0) , 0);

			return 1;
		}

		if (lw == IDC_SHOW_KEYS && nCurPageNo == FORMAT_PAGE)
		{
			showKeys = IsButtonChecked (GetDlgItem (hCurPage, IDC_SHOW_KEYS));

			SetWindowText (GetDlgItem (hCurPage, IDC_RANDOM_BYTES), showKeys ? "                                                                              " : "********************************                                              ");
			SetWindowText (GetDlgItem (hCurPage, IDC_HEADER_KEY), showKeys ? "" : "********************************                                              ");
			SetWindowText (GetDlgItem (hCurPage, IDC_DISK_KEY), showKeys ? "" : "********************************                                              ");
			return 1;
		}
		
		if (lw == IDC_DISPLAY_POOL_CONTENTS && nCurPageNo == SYSENC_COLLECTING_RANDOM_DATA_PAGE)
		{
			showKeys = IsButtonChecked (GetDlgItem (hCurPage, IDC_DISPLAY_POOL_CONTENTS));
			DisplayRandPool (hRandPoolSys, showKeys);

			return 1;
		}

		if (lw == IDC_DISPLAY_KEYS && nCurPageNo == SYSENC_KEYS_GEN_PAGE)
		{
			showKeys = IsButtonChecked (GetDlgItem (hCurPage, IDC_DISPLAY_KEYS));

			SetWindowText (GetDlgItem (hwndDlg, IDC_HEADER_KEY), showKeys ? HeaderKeyGUIView : "********************************                                              ");
			SetWindowText (GetDlgItem (hwndDlg, IDC_DISK_KEY), showKeys ? MasterKeyGUIView : "********************************                                              ");
			return 1;
		}

		if (nCurPageNo == SYSENC_RESCUE_DISK_CREATION_PAGE)
		{
			if (lw == IDC_BROWSE)
			{
				char tmpszRescueDiskISO [TC_MAX_PATH+1];

				if (!BrowseFiles (hwndDlg, "OPEN_TITLE", tmpszRescueDiskISO, FALSE, TRUE))
					return 1;

				strcpy (szRescueDiskISO, tmpszRescueDiskISO);

				SetDlgItemText (hwndDlg, IDC_RESCUE_DISK_ISO_PATH, szRescueDiskISO);
				EnableWindow (GetDlgItem (MainDlg, IDC_NEXT), (GetWindowTextLength (GetDlgItem (hwndDlg, IDC_RESCUE_DISK_ISO_PATH)) > 1));
				return 1;
			}

			if ( hw == EN_CHANGE )
			{
				GetDlgItemText (hwndDlg, IDC_RESCUE_DISK_ISO_PATH, szRescueDiskISO, sizeof(szRescueDiskISO));
				EnableWindow (GetDlgItem (MainDlg, IDC_NEXT), (GetWindowTextLength (GetDlgItem (hwndDlg, IDC_RESCUE_DISK_ISO_PATH)) > 1));
				return 1;
			}
		}

		if (nCurPageNo == SYSENC_RESCUE_DISK_BURN_PAGE && lw == IDC_DOWNLOAD_CD_BURN_SOFTWARE)
		{
			Applink ("isoburning", TRUE, "");
			return 1;
		}

		if (nCurPageNo == SYSENC_WIPE_MODE_PAGE && hw == CBN_SELCHANGE)
		{
			nWipeMode = (WipeAlgorithmId) SendMessage (GetDlgItem (hCurPage, IDC_WIPE_MODE),
				CB_GETITEMDATA, 
				SendMessage (GetDlgItem (hCurPage, IDC_WIPE_MODE), CB_GETCURSEL, 0, 0),
				0);

			return 1;
		}

		if (lw == IDC_NO_HISTORY)
		{
			if (!(bHistory = !IsButtonChecked (GetDlgItem (hCurPage, IDC_NO_HISTORY))))
				ClearHistory (GetDlgItem (hCurPage, IDC_COMBO_BOX));

			return 1;
		}

		return 0;
	}

	return 0;
}

/* Except in response to the WM_INITDIALOG and WM_ENDSESSION messages, the dialog box procedure
   should return nonzero if it processes the message, and zero if it does not. - see DialogProc */
BOOL CALLBACK MainDialogProc (HWND hwndDlg, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
	WORD lw = LOWORD (wParam);

	int nNewPageNo = nCurPageNo;

	switch (uMsg)
	{
	case WM_INITDIALOG:
		{
			MainDlg = hwndDlg;
			InitDialog (hwndDlg);
			LocalizeDialog (hwndDlg, "IDD_VOL_CREATION_WIZARD_DLG");

			if (IsTrueCryptInstallerRunning())
				AbortProcess ("TC_INSTALLER_IS_RUNNING");

			// Resize the bitmap if the user has a non-default DPI 
			if (ScreenDPI != USER_DEFAULT_SCREEN_DPI)
			{
				hbmWizardBitmapRescaled = RenderBitmap (MAKEINTRESOURCE (IDB_WIZARD),
					GetDlgItem (hwndDlg, IDC_BITMAP_WIZARD),
					0, 0, 0, 0, FALSE, FALSE);
			}

			LoadSettings (hwndDlg);

			LoadDefaultKeyFilesParam ();
			RestoreDefaultKeyFilesParam ();

			SysEncMultiBootCfg.NumberOfSysDrives = -1;
			SysEncMultiBootCfg.MultipleSystemsOnDrive = -1;
			SysEncMultiBootCfg.BootLoaderLocation = -1;
			SysEncMultiBootCfg.BootLoaderBrand = -1;
			SysEncMultiBootCfg.SystemOnBootDrive = -1;

			try
			{
				BootEncStatus = BootEncObj->GetStatus();
			}
			catch (Exception &e)
			{
				e.Show (hwndDlg);
				Error ("ERR_GETTING_SYSTEM_ENCRYPTION_STATUS");
				EndMainDlg (MainDlg);
				return 0;
			}

			SendMessage (GetDlgItem (hwndDlg, IDC_BOX_TITLE), WM_SETFONT, (WPARAM) hTitleFont, (LPARAM) TRUE);
			SetWindowTextW (hwndDlg, lpszTitle);

			ExtractCommandLine (hwndDlg, (char *) lParam);

			if (ComServerMode)
			{
				if (!ComServerFormat ())
				{
					handleWin32Error (hwndDlg);
					exit (1);
				}
				exit (0);
			}

			SHGetFolderPath (NULL, CSIDL_MYDOCUMENTS, NULL, 0, szRescueDiskISO);
			strcat (szRescueDiskISO, "\\TrueCrypt Rescue Disk.iso");

			PostMessage (hwndDlg, TC_APPMSG_PERFORM_POST_WMINIT_TASKS, 0, 0);
		}
		return 0;

	case WM_SYSCOMMAND:
		if (lw == IDC_ABOUT)
		{
			DialogBoxW (hInst, MAKEINTRESOURCEW (IDD_ABOUT_DLG), hwndDlg, (DLGPROC) AboutDlgProc);
			return 1;
		}
		return 0;

	case WM_TIMER:
		switch (wParam)
		{
		case TIMER_ID_RANDVIEW:
			if (WizardMode == WIZARD_MODE_SYS_DEVICE)
			{
				DisplayRandPool (hRandPoolSys, showKeys);
			}
			else
			{
				unsigned char tmp[17];
				char tmp2[43];
				int i;

				if (!showKeys) 
					return 1;

				RandpeekBytes (tmp, sizeof (tmp));

				tmp2[0] = 0;

				for (i = 0; i < sizeof (tmp); i++)
				{
					char tmp3[8];
					sprintf (tmp3, "%02X", (int) (unsigned char) tmp[i]);
					strcat (tmp2, tmp3);
				}

				tmp2[32] = 0;

				SetWindowText (GetDlgItem (hCurPage, IDC_RANDOM_BYTES), tmp2);

				burn (tmp, sizeof(tmp));
				burn (tmp2, sizeof(tmp2));
			}
			return 1;

		case TIMER_ID_SYSENC_PROGRESS:
			{
				// Manage system encryption/decryption and update related GUI

				try
				{
					BootEncStatus = BootEncObj->GetStatus();
				}
				catch (Exception &e)
				{
					KillTimer (MainDlg, TIMER_ID_SYSENC_PROGRESS);

					try
					{
						BootEncObj->AbortSetup ();
					}
					catch (Exception &e)
					{
						e.Show (hwndDlg);
					}

					e.Show (hwndDlg);
					Error ("ERR_GETTING_SYSTEM_ENCRYPTION_STATUS");
					EndMainDlg (MainDlg);
					return 1;
				}

				if (BootEncStatus.SetupInProgress)
					UpdateSysEncProgressBar ();

				if (bSystemEncryptionInProgress != BootEncStatus.SetupInProgress)
				{
					bSystemEncryptionInProgress = BootEncStatus.SetupInProgress;

					UpdateSysEncProgressBar ();
					UpdateSysEncControls ();

					if (!bSystemEncryptionInProgress)
					{
						// The driver stopped encrypting/decrypting

						KillTimer (hwndDlg, TIMER_ID_SYSENC_PROGRESS);

						try
						{
							if (BootEncStatus.DriveMounted)	// If we had been really encrypting/decrypting (not just proceeding to deinstall)
								BootEncObj->CheckEncryptionSetupResult();
						}
						catch (Exception &e)
						{
							e.Show (hwndDlg);
						}

						switch (SystemEncryptionStatus)
						{
						case SYSENC_STATUS_ENCRYPTING:

							if (BootEncStatus.ConfiguredEncryptedAreaStart == BootEncStatus.EncryptedAreaStart
								&& BootEncStatus.ConfiguredEncryptedAreaEnd == BootEncStatus.EncryptedAreaEnd)
							{
								// The partition/drive has been fully encrypted

								ManageStartupSeqWiz (TRUE, "");

								SetWindowTextW (GetDlgItem (hwndDlg, IDC_NEXT), GetString ("FINALIZE"));
								EnableWindow (GetDlgItem (hwndDlg, IDC_NEXT), TRUE);
								EnableWindow (GetDlgItem (hwndDlg, IDCANCEL), FALSE);
								EnableWindow (GetDlgItem (hCurPage, IDC_WIPE_MODE), FALSE);
								EnableWindow (GetDlgItem (hCurPage, IDC_PAUSE), FALSE);

								Info ("SYSTEM_ENCRYPTION_FINISHED");

								HandleDecoyOSCompletion ();

								if (WipeHiddenOSCreationConfig())
									ChangeSystemEncryptionStatus (SYSENC_STATUS_NONE);

								return 1;
							}
							break;

						case SYSENC_STATUS_DECRYPTING:

							if (!BootEncStatus.DriveEncrypted)
							{
								// The partition/drive has been fully decrypted

								try
								{
									// Finalize the process
									BootEncObj->Deinstall ();
								}
								catch (Exception &e)
								{
									e.Show (hwndDlg);
								}
					
								ManageStartupSeqWiz (TRUE, "");
								ChangeSystemEncryptionStatus (SYSENC_STATUS_NONE);

								SetWindowTextW (GetDlgItem (hwndDlg, IDC_NEXT), GetString ("FINALIZE"));
								EnableWindow (GetDlgItem (hwndDlg, IDC_NEXT), TRUE);
								EnableWindow (GetDlgItem (hwndDlg, IDCANCEL), FALSE);
								EnableWindow (GetDlgItem (hCurPage, IDC_PAUSE), FALSE);

								Info ("SYSTEM_DECRYPTION_FINISHED");

								return 1;
							}
							break;
						}
					}
				}
			}
			return 1;

		case TIMER_ID_KEYB_LAYOUT_GUARD:
			if (SysEncInEffect ())
			{
				DWORD keybLayout = (DWORD) GetKeyboardLayout (NULL);

				/* Watch the keyboard layout */

				if (keybLayout != 0x00000409 && keybLayout != 0x04090409)
				{
					// Keyboard layout is not standard US

					WipePasswordsAndKeyfiles ();

					SetWindowText (GetDlgItem (hCurPage, IDC_PASSWORD), szRawPassword);
					SetWindowText (GetDlgItem (hCurPage, IDC_VERIFY), szVerify);

					keybLayout = (DWORD) LoadKeyboardLayout ("00000409", KLF_ACTIVATE);

					if (keybLayout != 0x00000409 && keybLayout != 0x04090409)
					{
						KillTimer (hwndDlg, TIMER_ID_KEYB_LAYOUT_GUARD);
						Error ("CANT_CHANGE_KEYB_LAYOUT_FOR_SYS_ENCRYPTION");
						EndMainDlg (MainDlg);
						return 1;
					}

					bKeyboardLayoutChanged = TRUE;

					wchar_t szTmp [4096];
					wcscpy (szTmp, GetString ("KEYB_LAYOUT_CHANGE_PREVENTED"));
					wcscat (szTmp, L"\n\n");
					wcscat (szTmp, GetString ("KEYB_LAYOUT_SYS_ENC_EXPLANATION"));
					MessageBoxW (MainDlg, szTmp, lpszTitle, MB_ICONWARNING | MB_SETFOREGROUND | MB_TOPMOST);
				}

				/* Watch the right Alt key (which is used to enter various characters on non-US keyboards) */

				if (bKeyboardLayoutChanged && !bKeybLayoutAltKeyWarningShown)
				{
					if (GetAsyncKeyState (VK_RMENU) < 0)
					{
						bKeybLayoutAltKeyWarningShown = TRUE;

						wchar_t szTmp [4096];
						wcscpy (szTmp, GetString ("ALT_KEY_CHARS_NOT_FOR_SYS_ENCRYPTION"));
						wcscat (szTmp, L"\n\n");
						wcscat (szTmp, GetString ("KEYB_LAYOUT_SYS_ENC_EXPLANATION"));
						MessageBoxW (MainDlg, szTmp, lpszTitle, MB_ICONINFORMATION  | MB_SETFOREGROUND | MB_TOPMOST);
					}
				}
			}
			return 1;

		case TIMER_ID_SYSENC_DRIVE_ANALYSIS_PROGRESS:

			if (bSysEncDriveAnalysisInProgress)
			{
				UpdateProgressBarProc (GetTickCount() - SysEncDriveAnalysisStart);

				if (GetTickCount() - SysEncDriveAnalysisStart > SYSENC_DRIVE_ANALYSIS_ETA)
				{
					// It's taking longer than expected -- reinit the progress bar
					SysEncDriveAnalysisStart = GetTickCount ();
					InitProgressBar (SYSENC_DRIVE_ANALYSIS_ETA, 0, FALSE, FALSE, FALSE, TRUE);
				}

				ArrowWaitCursor ();
			}
			else
			{
				KillTimer (hwndDlg, TIMER_ID_SYSENC_DRIVE_ANALYSIS_PROGRESS);
				UpdateProgressBarProc (SYSENC_DRIVE_ANALYSIS_ETA);
				Sleep (1500);	// User-friendly GUI

				if (bSysEncDriveAnalysisTimeOutOccurred)
					Warning ("SYS_DRIVE_SIZE_PROBE_TIMEOUT");

				LoadPage (hwndDlg, SYSENC_DRIVE_ANALYSIS_PAGE + 1);
			}
			return 1;
		}
		return 0;

	case TC_APPMSG_PERFORM_POST_WMINIT_TASKS:

		AfterWMInitTasks (hwndDlg);
		return 1;

	case TC_APPMSG_FORMAT_FINISHED:
		{
			char tmp[RNG_POOL_SIZE*2+1];

			EnableWindow (GetDlgItem (hCurPage, IDC_ABORT_BUTTON), FALSE);
			EnableWindow (GetDlgItem (hwndDlg, IDC_PREV), TRUE);
			EnableWindow (GetDlgItem (hwndDlg, IDHELP), TRUE);
			EnableWindow (GetDlgItem (hwndDlg, IDCANCEL), TRUE);
			EnableWindow (GetDlgItem (hwndDlg, IDC_NEXT), TRUE);
			SetFocus (GetDlgItem (hwndDlg, IDC_NEXT));

			if (nCurPageNo == FORMAT_PAGE)
				KillTimer (hwndDlg, TIMER_ID_RANDVIEW);

			// Attempt to wipe the GUI fields showing portions of randpool, of the master and header keys
			memset (tmp, 'X', sizeof(tmp));
			tmp [sizeof(tmp)-1] = 0;
			SetWindowText (hRandPool, tmp);
			SetWindowText (hMasterKey, tmp);
			SetWindowText (hHeaderKey, tmp);

			NormalCursor ();

			LoadPage (hwndDlg, FORMAT_FINISHED_PAGE);
		}
		return 1;

	case TC_APPMSG_FORMAT_THREAD_ENDED:

		// Format was cancelled (did not finish)

		EnableWindow (GetDlgItem (hCurPage, IDC_QUICKFORMAT), (bDevice || bSparseFileSwitch) && !(bHiddenVol && !bHiddenVolHost));
		EnableWindow (GetDlgItem (hCurPage, IDC_FILESYS), TRUE);
		EnableWindow (GetDlgItem (hCurPage, IDC_CLUSTERSIZE), TRUE);
		EnableWindow (GetDlgItem (hwndDlg, IDC_PREV), TRUE);
		EnableWindow (GetDlgItem (hwndDlg, IDHELP), TRUE);
		EnableWindow (GetDlgItem (hwndDlg, IDCANCEL), TRUE);
		EnableWindow (GetDlgItem (hCurPage, IDC_ABORT_BUTTON), FALSE);
		EnableWindow (GetDlgItem (hwndDlg, IDC_NEXT), TRUE);
		SendMessage (GetDlgItem (hCurPage, IDC_PROGRESS_BAR), PBM_SETPOS, 0, 0L);
		SetFocus (GetDlgItem (hwndDlg, IDC_NEXT));

		NormalCursor ();
		return 1;

	case WM_HELP:
		OpenPageHelp (hwndDlg, nCurPageNo);
		return 1;

	case TC_APPMSG_FORMAT_USER_QUIT:

		if (bThreadRunning)
		{
			// Non-system encryption in progress
			if (AskNoYes ("FORMAT_ABORT") == IDYES)
			{
				bThreadCancel = TRUE;
				EndMainDlg (hwndDlg);
				return 1;
			}
			else
				return 1;	// Disallow close
		}
		else if ((nCurPageNo == SYSENC_ENCRYPTION_PAGE || nCurPageNo == SYSENC_PRETEST_RESULT_PAGE)
			&& SystemEncryptionStatus != SYSENC_STATUS_NONE
			&& InstanceHasSysEncMutex ())
		{
			// System encryption/decryption in progress

			if (AskYesNo (SystemEncryptionStatus == SYSENC_STATUS_DECRYPTING ? 
				"SYSTEM_DECRYPTION_DEFER_CONFIRM" : "SYSTEM_ENCRYPTION_DEFER_CONFIRM") == IDYES)
			{
				if (nCurPageNo == SYSENC_PRETEST_RESULT_PAGE && !bHiddenOS)
					TextInfoDialogBox (TC_TBXID_SYS_ENC_RESCUE_DISK);

				try
				{
					BootEncStatus = BootEncObj->GetStatus();

					if (BootEncStatus.SetupInProgress)
					{
						BootEncObj->AbortSetupWait ();
						Sleep (200);
						BootEncStatus = BootEncObj->GetStatus();
					}

					if (!BootEncStatus.SetupInProgress)
					{
						EndMainDlg (MainDlg);
						return 1;
					}
					else
					{
						Error ("FAILED_TO_INTERRUPT_SYSTEM_ENCRYPTION");
						return 1;	// Disallow close
					}
				}
				catch (Exception &e)
				{
					e.Show (hwndDlg);
				}
				return 1;	// Disallow close
			}
			else
				return 1;	// Disallow close
		}
		else if (bConfirmQuitSysEncPretest)
		{
			if (AskWarnNoYes (bHiddenOS ? "CONFIRM_CANCEL_HIDDEN_OS_CREATION" : "CONFIRM_CANCEL_SYS_ENC_PRETEST") == IDNO)
				return 1;	// Disallow close
		}
		else if (bConfirmQuit)
		{
			if (AskWarnNoYes ("CONFIRM_EXIT_UNIVERSAL") == IDNO)
				return 1;	// Disallow close
		}

		if (hiddenVolHostDriveNo > -1)
		{
			CloseVolumeExplorerWindows (hwndDlg, hiddenVolHostDriveNo);
			UnmountVolume (hwndDlg, hiddenVolHostDriveNo, FALSE);
		}

		EndMainDlg (hwndDlg);
		return 1;


	case WM_COMMAND:
		if (lw == IDHELP)
		{
			OpenPageHelp (hwndDlg, nCurPageNo);
			return 1;
		}
		else if (lw == IDCANCEL)
		{
			PostMessage (hwndDlg, TC_APPMSG_FORMAT_USER_QUIT, 0, 0);
			return 1;
		}
		else if (lw == IDC_NEXT)
		{
			if (nCurPageNo == INTRO_PAGE)
			{
				switch (GetSelectedWizardMode (hCurPage))
				{
				case WIZARD_MODE_FILE_CONTAINER:

					CloseSysEncMutex ();
					ChangeWizardMode (WIZARD_MODE_FILE_CONTAINER);
					bHiddenOS = FALSE;
					nNewPageNo = VOLUME_TYPE_PAGE - 1;	// Skip irrelevant pages
					break;

				case WIZARD_MODE_NONSYS_DEVICE:

					CloseSysEncMutex ();
					if (!ChangeWizardMode (WIZARD_MODE_NONSYS_DEVICE))
						return 1;

					bHiddenOS = FALSE;
					nNewPageNo = VOLUME_TYPE_PAGE - 1;	// Skip irrelevant pages
					break;

				case WIZARD_MODE_SYS_DEVICE:

					bHiddenVol = FALSE;
					SwitchWizardToSysEncMode ();
					return 1;
				}
			}
			else if (nCurPageNo == SYSENC_TYPE_PAGE)
			{
				if (bHiddenOS)
				{
					bWholeSysDrive = FALSE;
					bHiddenVolDirect = FALSE;
				}

				if (!bHiddenOS)
					nNewPageNo = SYSENC_SPAN_PAGE - 1;	// Skip irrelevant pages
			}
			else if (nCurPageNo == SYSENC_HIDDEN_OS_REQ_CHECK_PAGE)
			{
				WaitCursor ();
				try
				{
					BootEncObj->CheckRequirementsHiddenOS ();

					if (CheckGapBetweenSysAndHiddenOS ())
						Warning ("GAP_BETWEEN_SYS_AND_HIDDEN_OS_PARTITION");
				}
				catch (Exception &e)
				{
					e.Show (hwndDlg);
					NormalCursor ();
					return 1;
				}

				if (AskWarnYesNo ("DECOY_OS_REQUIREMENTS") == IDNO)
				{
					NormalCursor ();
					return 1;
				}

				Warning ("NO_HIBERNATION_DURING_HIDDEN_OS_CREATION");

				if (!IsAdmin() && IsUacSupported())
				{
					// If UAC elevation is needed, we need to elevate the complete wizard process here, because
					// we will need to switch to the non-sys-device mode, which requires the whole wizard process
					// to have admin rights.

					CloseSysEncMutex ();

					if (!ElevateWholeWizardProcess ("/r"))
					{
						// Failed to obtain admin rights

						NormalCursor ();

						if (!CreateSysEncMutex ())
							AbortProcess ("SYSTEM_ENCRYPTION_IN_PROGRESS_ELSEWHERE");

						return 1;
					}
				}

				// This check requires admin rights
				if (BootEncObj->IsPagingFileActive ())
					AbortProcess ("DISABLE_SWAP_FILE_BEFORE_CREATING_HIDDEN_OS");


				nNewPageNo = SYSENC_MULTI_BOOT_MODE_PAGE - 1;	// Skip irrelevant pages
			}
			else if (nCurPageNo == SYSENC_SPAN_PAGE)
			{
				try
				{
					if (bWholeSysDrive && !BootEncObj->SystemPartitionCoversWholeDrive())
					{
						if (nCurrentOS != WIN_VISTA_OR_LATER)
						{
							if (BootEncObj->SystemDriveContainsExtendedPartition())
							{
								Error ("WDE_UNSUPPORTED_FOR_EXTENDED_PARTITIONS");

								if (AskYesNo ("ASK_ENCRYPT_PARTITION_INSTEAD_OF_DRIVE") == IDNO)
									return 1;

								bWholeSysDrive = FALSE;
							}
							else
								Warning ("WDE_EXTENDED_PARTITIONS_WARNING");
						}
					}

					if (!bWholeSysDrive && BootEncObj->SystemPartitionCoversWholeDrive())
						bWholeSysDrive = (AskYesNo ("WHOLE_SYC_DEVICE_RECOM") == IDYES);
				}
				catch (Exception &e)
				{
					e.Show (hwndDlg);
					NormalCursor ();
					return 1;
				}

				if (!bWholeSysDrive)
					nNewPageNo = SYSENC_MULTI_BOOT_MODE_PAGE - 1;	// Skip irrelevant pages
			}
			else if (nCurPageNo == SYSENC_PRE_DRIVE_ANALYSIS_PAGE)
			{
				if ((SysEncDetectHiddenSectors = Get2RadButtonPageAnswer()) != 1)
				{
					// Skip drive analysis
					nNewPageNo = SYSENC_DRIVE_ANALYSIS_PAGE;

					// If the user had already searched for hidden sectors, we must clear (invalidate) the
					// result because now he changed his mind and no longer wishes to encrypt the hidden sectors.
					try
					{
						BootEncObj->InvalidateCachedSysDriveProperties ();
					}
					catch (Exception &e)
					{
						e.Show (MainDlg);
						EndMainDlg (MainDlg);
						exit(0);
					}
				}
			}
			else if (nCurPageNo == SYSENC_MULTI_BOOT_MODE_PAGE)
			{
				if (nMultiBoot <= 1)
				{
					if (bHiddenOS)
					{
						if (!ChangeWizardMode (WIZARD_MODE_NONSYS_DEVICE))
						{
							NormalCursor ();
							return 1;
						}

						nNewPageNo = HIDDEN_VOL_HOST_PRE_CIPHER_PAGE - 1;		// Skip irrelevant pages
					}
					else
						nNewPageNo = CIPHER_PAGE - 1;		// Skip irrelevant pages
				}
				else if (AskWarnNoYes ("MULTI_BOOT_FOR_ADVANCED_ONLY") == IDNO)
					return 1;
			}
			else if (nCurPageNo == SYSENC_MULTI_BOOT_SYS_EQ_BOOT_PAGE)
			{
				SysEncMultiBootCfg.SystemOnBootDrive = Get2RadButtonPageAnswer ();

				if (!SysEncMultiBootCfg.SystemOnBootDrive)
				{
					Error ("SYS_PARTITION_MUST_BE_ON_BOOT_DRIVE");
					EndMainDlg (MainDlg);
					return 1;
				}
			}
			else if (nCurPageNo == SYSENC_MULTI_BOOT_NBR_SYS_DRIVES_PAGE)
			{
				if (Get2RadButtonPageAnswer () == 0)
				{
					// 2 or more drives contain an OS

					SysEncMultiBootCfg.NumberOfSysDrives = 2;		
				}
				else if (Get2RadButtonPageAnswer () == 1)
				{
					// Only 1 drive contains an OS

					SysEncMultiBootCfg.NumberOfSysDrives = 1;		

					if (bWholeSysDrive)
					{
						// Whole-system-drive encryption is currently not supported if the drive contains
						// more than one system
						Error ("WDE_UNSUPPORTED_FOR_MULTIPLE_SYSTEMS_ON_ONE_DRIVE");
						return 1;
					}

					// Ask whether there is a non-Windows boot loader in the MBR
					nNewPageNo = SYSENC_MULTI_BOOT_NONWIN_BOOT_LOADER_PAGE - 1;
				}
			}
			else if (nCurPageNo == SYSENC_MULTI_BOOT_ADJACENT_SYS_PAGE)
			{
				SysEncMultiBootCfg.MultipleSystemsOnDrive = Get2RadButtonPageAnswer ();

				if (SysEncMultiBootCfg.MultipleSystemsOnDrive && bWholeSysDrive)
				{
					// Whole-system-drive encryption is currently not supported if the drive contains
					// more than one system
					Error ("WDE_UNSUPPORTED_FOR_MULTIPLE_SYSTEMS_ON_ONE_DRIVE");
					return 1;
				}
			}

			else if (nCurPageNo == SYSENC_MULTI_BOOT_NONWIN_BOOT_LOADER_PAGE)
			{
				SysEncMultiBootCfg.BootLoaderBrand = Get2RadButtonPageAnswer ();

				if (SysEncMultiBootCfg.BootLoaderBrand)
				{
					// A non-Windows boot manager in the MBR
					Error ("CUSTOM_BOOT_MANAGERS_IN_MBR_UNSUPPORTED");
					EndMainDlg (MainDlg);
					return 1;
				}
				else
				{
					// Either a standard Windows boot manager or no boot manager
					wcscpy_s (SysEncMultiBootCfgOutcome, sizeof(SysEncMultiBootCfgOutcome) / 2, GetString ("WINDOWS_BOOT_LOADER_HINTS"));
				}
			}

			else if (nCurPageNo == SYSENC_MULTI_BOOT_OUTCOME_PAGE)
			{
				if (bHiddenOS)
				{
					if (!ChangeWizardMode (WIZARD_MODE_NONSYS_DEVICE))
					{
						NormalCursor ();
						return 1;
					}

					nNewPageNo = HIDDEN_VOL_HOST_PRE_CIPHER_PAGE - 1;		// Skip irrelevant pages
				}
				else
					nNewPageNo = CIPHER_PAGE - 1;	// Skip irrelevant pages
			}

			else if (nCurPageNo == VOLUME_TYPE_PAGE)
			{
				if (IsButtonChecked (GetDlgItem (hCurPage, IDC_HIDDEN_VOL)))
				{
					if (!IsAdmin() && !IsUacSupported ()
						&& IDNO == MessageBoxW (hwndDlg, GetString ("ADMIN_PRIVILEGES_WARN_HIDVOL"),
						lpszTitle, MB_ICONWARNING|MB_YESNO|MB_DEFBUTTON2))
					{
						return 1;
					}
					else
					{
						bHiddenVol = TRUE;
						bHiddenVolHost = TRUE;
					}
				}
				else
				{
					if (IsHiddenOSRunning())
					{
						WarningDirect ((wstring (GetString ("CAN_CREATE_ONLY_HIDDEN_VOLUMES_UNDER_HIDDEN_OS"))
							+ L"\n\n"
							+ GetString ("NOTE_BEGINNING")
							+ GetString ("HIDDEN_OS_WRITE_PROTECTION_BRIEF_INFO")
							+ L" "
							+ GetString ("HIDDEN_OS_WRITE_PROTECTION_EXPLANATION")).c_str());

						NormalCursor ();
						return 1;
					}

					bHiddenVol = FALSE;
					bHiddenVolHost = FALSE;
					bHiddenVolDirect = FALSE;
					nNewPageNo = FILE_PAGE - 1;		// Skip the hidden volume creation wizard mode selection
				}
			}

			else if (nCurPageNo == HIDDEN_VOL_WIZARD_MODE_PAGE)
			{
				if (IsButtonChecked (GetDlgItem (hCurPage, IDC_HIDVOL_WIZ_MODE_DIRECT)))
					bHiddenVolDirect = TRUE;
				else
				{
					if (IsHiddenOSRunning())
					{
						WarningDirect ((wstring (GetString ("HIDDEN_VOL_CREATION_UNDER_HIDDEN_OS_HOWTO"))
							+ L"\n\n\n"
							+ GetString ("NOTE_BEGINNING")
							+ GetString ("HIDDEN_OS_WRITE_PROTECTION_BRIEF_INFO")
							+ L" "
							+ GetString ("HIDDEN_OS_WRITE_PROTECTION_EXPLANATION")).c_str());
						NormalCursor ();
						return 1;
					}

					bHiddenVolDirect = FALSE;
				}
			}

			else if (nCurPageNo == FILE_PAGE)
			{
				BOOL tmpbDevice;

				GetWindowText (GetDlgItem (hCurPage, IDC_COMBO_BOX), szFileName, sizeof (szFileName));
				CreateFullVolumePath (szDiskFile, szFileName, &tmpbDevice);

				if (tmpbDevice != bDevice)
				{
					if (bDevice)
					{
						// Not a valid device path
						Error ("CANNOT_CALC_SPACE");
						return 1;
					}
					else
					{
						if (AskWarnYesNo ("DEVICE_SELECTED_IN_NON_DEVICE_MODE") == IDNO)
							return 1;

						SwitchWizardToNonSysDeviceMode ();
						return 1;
					}
				}

				MoveEditToCombo (GetDlgItem (hCurPage, IDC_COMBO_BOX), bHistory);

				if (IsMountedVolume (szFileName))
				{
					Error ("ALREADY_MOUNTED");
					return 1;
				}

				if (bDevice)
				{
					switch (IsSystemDevicePath (szFileName, hCurPage, TRUE))
					{
					case 1:
					case 2:
						if (AskYesNo ("CONFIRM_SYSTEM_ENCRYPTION_MODE") == IDNO)
						{
							return 1;
						}
						szFileName[0] = 0;
						SwitchWizardToSysEncMode ();
						return 1;

					case -1:
						Error ("ERR_CANNOT_DETERMINE_VOLUME_TYPE");
						return 1;
					}
				}
				else
				{
					if (CheckFileExtension(szFileName) 
						&& AskWarnNoYes ("EXE_FILE_EXTENSION_CONFIRM") == IDNO)
					{
						return 1;
					}
				}

				bHistory = !IsButtonChecked (GetDlgItem (hCurPage, IDC_NO_HISTORY));

				SaveSettings (hCurPage);

				if (bHiddenVolDirect && bHiddenVolHost)
				{
					nNewPageNo = HIDDEN_VOL_HOST_PASSWORD_PAGE - 1;

					if (bDevice)
					{
						if(!QueryFreeSpace (hwndDlg, GetDlgItem (hwndDlg, IDC_SPACE_LEFT), FALSE))
						{
							MessageBoxW (hwndDlg, GetString ("CANT_GET_VOLSIZE"), lpszTitle, ICON_HAND);
							nNewPageNo = FILE_PAGE - 1; 
						}
						else
							nHiddenVolHostSize = nVolumeSize;
					}
					else
					{
						if (!GetFileVolSize (hwndDlg, &nHiddenVolHostSize))
						{
							nNewPageNo = FILE_PAGE - 1;
						}
						else if (IsSparseFile (hwndDlg))
						{
							// Hidden volumes must not be created within sparse file containers
							Warning ("HIDDEN_VOL_HOST_SPARSE");
							nNewPageNo = FILE_PAGE - 1;
						}
					}
				}
				else
				{
					if (!bHiddenVol)
						nNewPageNo = HIDDEN_VOL_PRE_CIPHER_PAGE;		// Skip the extra info on hidden volume 
					else if (!bHiddenVolHost)
						nNewPageNo = HIDDEN_VOL_HOST_PRE_CIPHER_PAGE;	// Skip the info on the outer volume
				}
				
			}

			else if (nCurPageNo == HIDDEN_VOL_HOST_PRE_CIPHER_PAGE)
			{
				if (bHiddenVolHost)
					nNewPageNo = HIDDEN_VOL_PRE_CIPHER_PAGE;		// Skip the info on the hiddem volume
			}

			else if (nCurPageNo == CIPHER_PAGE)
			{
				LPARAM nIndex;
				nIndex = SendMessage (GetDlgItem (hCurPage, IDC_COMBO_BOX), CB_GETCURSEL, 0, 0);
				nVolumeEA = SendMessage (GetDlgItem (hCurPage, IDC_COMBO_BOX), CB_GETITEMDATA, nIndex, 0);

				if (SysEncInEffect ()
					&& EAGetCipherCount (nVolumeEA) > 1)		// Cascade?
				{
					if (AskWarnNoYes ("CONFIRM_CASCADE_FOR_SYS_ENCRYPTION") == IDNO)
						return 1;

					Info ("NOTE_CASCADE_FOR_SYS_ENCRYPTION");
				}

				nIndex = SendMessage (GetDlgItem (hCurPage, IDC_COMBO_BOX_HASH_ALGO), CB_GETCURSEL, 0, 0);
				hash_algo = SendMessage (GetDlgItem (hCurPage, IDC_COMBO_BOX_HASH_ALGO), CB_GETITEMDATA, nIndex, 0);

				RandSetHashFunction (hash_algo);

				if (SysEncInEffect ())
					nNewPageNo = PASSWORD_PAGE - 1;			// Skip irrelevant pages
			}

			else if (nCurPageNo == SIZE_PAGE)
			{
				char szFileSystemNameBuffer[256];

				VerifySizeAndUpdate (hCurPage, TRUE);

				if (!bDevice)
				{
					/* Verify that the volume would not be too large for the host file system */

					char root[TC_MAX_PATH];

					if (GetVolumePathName (szFileName, root, sizeof (root))
						&& GetVolumeInformation (root, NULL, 0, NULL, NULL, NULL, szFileSystemNameBuffer, sizeof(szFileSystemNameBuffer))
						&& !strncmp (szFileSystemNameBuffer, "FAT32", 5))
					{
						// The host file system is FAT32
						if (nUIVolumeSize * nMultiplier >= 4 * BYTES_PER_GB)
						{
							Error ("VOLUME_TOO_LARGE_FOR_FAT32");
							return 1;
						}
					}
				}

				if (bHiddenVol && !bHiddenVolHost)	// If it's a hidden volume
				{
					/* Ask for confirmation if the hidden volume is too large for the user to be
					able to write much more data to the outer volume. */

					if (((double) nUIVolumeSize / (nMaximumHiddenVolSize / nMultiplier)) > 0.85)	// 85%
					{
						if (AskWarnNoYes ("FREE_SPACE_FOR_WRITING_TO_OUTER_VOLUME") == IDNO)
							return 1;
					}
				}

				if (!(bHiddenVolDirect && bHiddenVolHost))
					nNewPageNo = PASSWORD_PAGE - 1;
			}

			else if (nCurPageNo == PASSWORD_PAGE)
			{
				VerifyPasswordAndUpdate (hwndDlg, GetDlgItem (MainDlg, IDC_NEXT),
					GetDlgItem (hCurPage, IDC_PASSWORD),
					GetDlgItem (hCurPage, IDC_VERIFY),
					volumePassword.Text,
					szVerify,
					KeyFilesEnable && FirstKeyFile!=NULL && !SysEncInEffect());

				volumePassword.Length = strlen ((char *) volumePassword.Text);

				if (volumePassword.Length > 0)
				{
					// Password character encoding
					if (!CheckPasswordCharEncoding (GetDlgItem (hCurPage, IDC_PASSWORD), NULL))
					{
						Error ("UNSUPPORTED_CHARS_IN_PWD");
						return 1;
					}
					// Check password length (do not check if it's for an outer volume or decoy OS).
					else if (!bHiddenVolHost && !(bHiddenOS && !bHiddenVol)
						&& !CheckPasswordLength (hwndDlg, GetDlgItem (hCurPage, IDC_PASSWORD)))
					{
						return 1;
					}
				}

				// Store the password in case we need to restore it after keyfile is applied to it
				GetWindowText (GetDlgItem (hCurPage, IDC_PASSWORD), szRawPassword, sizeof (szRawPassword));

				if (!SysEncInEffect ()) 
				{
					if (KeyFilesEnable)
					{
						WaitCursor ();
						KeyFilesApply (&volumePassword, FirstKeyFile);
						NormalCursor ();
					}

				}
				else
				{
					KillTimer (hwndDlg, TIMER_ID_KEYB_LAYOUT_GUARD);

					if (bKeyboardLayoutChanged)
					{
						// Restore the original keyboard layout
						if (LoadKeyboardLayout (OrigKeyboardLayout, KLF_ACTIVATE | KLF_SUBSTITUTE_OK) == NULL) 
							Warning ("CANNOT_RESTORE_KEYBOARD_LAYOUT");
						else
							bKeyboardLayoutChanged = FALSE;
					}

					nNewPageNo = SYSENC_COLLECTING_RANDOM_DATA_PAGE - 1;	// Skip irrelevant pages
				}

				if (WizardMode != WIZARD_MODE_SYS_DEVICE
					&& !FileSize4GBLimitQuestionNeeded () 
					|| CreatingHiddenSysVol())		// If we're creating a hidden volume for a hidden OS, we don't need to format it with any filesystem (the entire OS will be copied to the hidden volume sector by sector).
				{
					nNewPageNo = FORMAT_PAGE - 1;				// Skip irrelevant pages
				}
			}

			else if (nCurPageNo == HIDDEN_VOL_HOST_PASSWORD_PAGE)
			{
				WaitCursor ();

				GetWindowText (GetDlgItem (hCurPage, IDC_PASSWORD_DIRECT), (char *) volumePassword.Text, sizeof (volumePassword.Text));
				volumePassword.Length = strlen ((char *) volumePassword.Text);

				// Store the password in case we need to restore it after keyfile is applied to it
				GetWindowText (GetDlgItem (hCurPage, IDC_PASSWORD_DIRECT), szRawPassword, sizeof (szRawPassword));

				if (KeyFilesEnable)
				{
					KeyFilesApply (&volumePassword, FirstKeyFile);
				}

				/* Mount the volume which is to host the new hidden volume as read only */

				if (hiddenVolHostDriveNo >= 0)		// If the hidden volume host is currently mounted (e.g. after previous unsuccessful dismount attempt)
				{
					BOOL tmp_result;

					// Dismount the hidden volume host (in order to remount it as read-only subsequently)
					while (!(tmp_result = UnmountVolume (hwndDlg, hiddenVolHostDriveNo, FALSE)))
					{
						if (MessageBoxW (hwndDlg, GetString ("CANT_DISMOUNT_OUTER_VOL"), lpszTitle, MB_RETRYCANCEL) != IDRETRY)
						{
							// Cancel
							NormalCursor();
							return 1;
						}
					}
					if (tmp_result)		// If dismounted
						hiddenVolHostDriveNo = -1;
				}

				if (hiddenVolHostDriveNo < 0)		// If the hidden volume host is not mounted
				{
					int retCode;

					// Mount the hidden volume host as read-only (to ensure consistent and secure
					// results of the volume bitmap scanning)
					switch (MountHiddenVolHost (hwndDlg, szDiskFile, &hiddenVolHostDriveNo, &volumePassword, TRUE))
					{
					case ERR_NO_FREE_DRIVES:
						NormalCursor ();
						MessageBoxW (hwndDlg, GetString ("NO_FREE_DRIVE_FOR_OUTER_VOL"), lpszTitle, ICON_HAND);
						return 1;
					case ERR_VOL_MOUNT_FAILED:
					case ERR_PASSWORD_WRONG:
						NormalCursor ();
						return 1;
					case 0:

						/* Hidden volume host successfully mounted as read-only */

						WaitCursor ();

						// Verify that the outer volume contains a suitable file system, retrieve cluster size, and 
						// scan the volume bitmap
						if (!IsAdmin () && IsUacSupported ())
							retCode = UacAnalyzeHiddenVolumeHost (hwndDlg, &hiddenVolHostDriveNo, GetVolumeDataAreaSize (FALSE, nHiddenVolHostSize), &realClusterSize, &nbrFreeClusters);
						else
							retCode = AnalyzeHiddenVolumeHost (hwndDlg, &hiddenVolHostDriveNo, GetVolumeDataAreaSize (FALSE, nHiddenVolHostSize), &realClusterSize, &nbrFreeClusters);

						switch (retCode)
						{
						case -1:	// Fatal error
							CloseVolumeExplorerWindows (hwndDlg, hiddenVolHostDriveNo);

							if (UnmountVolume (hwndDlg, hiddenVolHostDriveNo, FALSE))
								hiddenVolHostDriveNo = -1;

							AbortProcessSilent ();
							break;

						case 0:		// Unsupported file system (or other non-fatal error which has already been reported)
							if (bHiddenVolDirect)
							{
								CloseVolumeExplorerWindows (hwndDlg, hiddenVolHostDriveNo);

								if (UnmountVolume (hwndDlg, hiddenVolHostDriveNo, FALSE))
									hiddenVolHostDriveNo = -1;
							}
							NormalCursor ();
							return 1;

						case 1:

							// Determine the maximum possible size of the hidden volume
							if (DetermineMaxHiddenVolSize (hwndDlg) < 1)
							{
								// Non-fatal error while determining maximum possible size of the hidden volume
								NormalCursor();
								return 1;
							}
							else
							{
								BOOL tmp_result;

								/* Maximum possible size of the hidden volume successfully determined */

								// Dismount the hidden volume host
								while (!(tmp_result = UnmountVolume (hwndDlg, hiddenVolHostDriveNo, FALSE)))
								{
									if (MessageBoxW (hwndDlg, GetString ("CANT_DISMOUNT_OUTER_VOL"), lpszTitle, MB_RETRYCANCEL) != IDRETRY)
									{
										// Cancel
										NormalCursor();
										return 1;
									}
								}

								if (tmp_result)		// If dismounted
								{
									hiddenVolHostDriveNo = -1;

									bHiddenVolHost = FALSE; 
									bHiddenVolFinished = FALSE;

									// Clear the outer volume password
									WipePasswordsAndKeyfiles ();

									RestoreDefaultKeyFilesParam ();

									EnableWindow (GetDlgItem (MainDlg, IDC_NEXT), TRUE);
									NormalCursor ();

									nNewPageNo = HIDDEN_VOL_HOST_PRE_CIPHER_PAGE;
								}
							}
							break;
						}
						break;
					}
				}
				NormalCursor();
			}

			else if (nCurPageNo == FILESYS_PAGE)
			{
				if (nNeedToStoreFilesOver4GB != Get2RadButtonPageAnswer())
					fileSystem = FILESYS_NONE;	// The user may have gone back and changed the answer, so default file system must be reselected
	
				nNeedToStoreFilesOver4GB = Get2RadButtonPageAnswer();

				nNewPageNo = FORMAT_PAGE - 1;	// Skip irrelevant pages
			}

			else if (nCurPageNo == SYSENC_COLLECTING_RANDOM_DATA_PAGE)
			{
				char tmp[RANDPOOL_DISPLAY_SIZE+1];

				/* Generate master key and other related data (except the rescue disk) for system encryption. */

				try
				{
					WaitCursor();
					BootEncObj->PrepareInstallation (!bWholeSysDrive, volumePassword, nVolumeEA, FIRST_MODE_OF_OPERATION_ID, hash_algo, "");
				}
				catch (Exception &e)
				{
					e.Show (hwndDlg);
					NormalCursor ();
					return 1;
				}

				KillTimer (hwndDlg, TIMER_ID_RANDVIEW);

				// Attempt to wipe the GUI field showing portions of randpool
				memset (tmp, 'X', sizeof(tmp));
				tmp [sizeof(tmp)-1] = 0;
				SetWindowText (hRandPoolSys, tmp);

				NormalCursor ();
			}

			else if (nCurPageNo == SYSENC_KEYS_GEN_PAGE)
			{
				char tmp[KEY_GUI_VIEW_SIZE+1];

				// Attempt to wipe the GUI fields showing portions of the master and header keys
				memset (tmp, 'X', sizeof(tmp));
				tmp [sizeof(tmp)-1] = 0;
				SetWindowText (hMasterKey, tmp);
				SetWindowText (hHeaderKey, tmp);
			}

			else if (nCurPageNo == SYSENC_RESCUE_DISK_CREATION_PAGE)
			{
				/* Generate rescue disk for boot encryption */

				GetWindowText (GetDlgItem (hCurPage, IDC_RESCUE_DISK_ISO_PATH), szRescueDiskISO, sizeof (szRescueDiskISO));

				try
				{
					WaitCursor();
					BootEncObj->CreateRescueIsoImage (true, szRescueDiskISO);

				}
				catch (Exception &e)
				{
					e.Show (hwndDlg);
					NormalCursor ();
					return 1;
				}
				NormalCursor ();
			}

			else if (nCurPageNo == SYSENC_RESCUE_DISK_BURN_PAGE)
			{
				if (!bDontVerifyRescueDisk)
				{
					/* Verify that the rescue disk has been written correctly */

					try
					{
						WaitCursor();
						if (!BootEncObj->VerifyRescueDisk ())
						{
							Error ("RESCUE_DISK_CHECK_FAILED");
							NormalCursor ();
#ifndef _DEBUG
							return 1;
#else
							MessageBoxW (MainDlg, L"DEBUG INFO:\nPrevious error ignored (Debug build) -- allowed to continue.", lpszTitle, MB_ICONINFORMATION | MB_SETFOREGROUND | MB_TOPMOST);
#endif
						}
					}
					catch (Exception &e)
					{
						e.Show (hwndDlg);
						NormalCursor ();
						return 1;
					}
					NormalCursor ();
				}
				else
				{
					Warning ("RESCUE_DISK_BURN_NO_CHECK_WARN");
					nNewPageNo = SYSENC_RESCUE_DISK_VERIFIED_PAGE;		// Skip irrelevant pages
				}
			}

			else if (nCurPageNo == SYSENC_RESCUE_DISK_VERIFIED_PAGE)
			{
				if (bHiddenOS)
				{
					// Decoy OS must not contain any sensitive data, so it is not necessary to wipe it
					nNewPageNo = SYSENC_PRETEST_INFO_PAGE - 1;			// Skip irrelevant pages
				}
			}

			else if (nCurPageNo == SYSENC_WIPE_MODE_PAGE)
			{
				if (nWipeMode > 0 
					&& AskWarnYesNo ("WIPE_MODE_WARN") == IDNO)
					return 1;
			}

			else if (nCurPageNo == SYSENC_PRETEST_INFO_PAGE)
			{
				if (LocalizationActive
					&& AskWarnYesNo ("PREBOOT_NOT_LOCALIZED") == IDNO)
					return 1;

				bConfirmQuitSysEncPretest = TRUE;

				// No printable materials for hidden OS, because they are saved as temp files when printing and 
				// any physical papers with specific info could reveal the existence of a hidden OS (note that
				// the existing materials are tailored to non-hidden system encryption and we would need new 
				// special versions tailed for hidden OS).
				if (!bHiddenOS)		
					TextInfoDialogBox (TC_TBXID_SYS_ENCRYPTION_PRETEST);

				if (AskWarnYesNo ("CONFIRM_RESTART") == IDNO)
					return 1;

				/* Install the pre-boot authentication component and initiate the system encryption pretest.
				   If we are creating a hidden OS, pretest is omitted and OS cloning will follow. */

				try
				{
					WaitCursor();

					if (bHiddenOS)
					{
						// Make sure the Rescue Disk is not in the drive (we need to read the config flags from 
						// the system drive, not from the Rescue Disk).
						while (BootEncObj->VerifyRescueDisk ())
						{
							Error ("REMOVE_RESCUE_DISK_FROM_DRIVE");
						}
					}

					BootEncObj->Install();
				}
				catch (Exception &e)
				{
					e.Show (hwndDlg);
					Error (bHiddenOS ? "CANNOT_INITIATE_HIDDEN_OS_CREATION" : "CANNOT_INITIATE_SYS_ENCRYPTION_PRETEST");
					NormalCursor ();
					return 1;
				}


				/* Add the main TrueCrypt app to the system startup sequence (the TrueCrypt Background Task), which
				we need e.g. for notifications about prevented hibernation, hidden OS leak protection, inconsistent 
				hidden OS installs (TrueCrypt upgraded in the decoy system but not in the hidden one), etc.
				Note that this must be done before calling ChangeSystemEncryptionStatus(), which broadcasts the change,
				so that the main app (if it's running with different cached settings) will not overwrite our new
				settings when it exits. */
				bStartOnLogon = TRUE;
				SaveSettings (NULL);
				ManageStartupSeq ();


				if (bHiddenOS)
				{
					/* IMPORTANT: When creating or about to create a hidden OS, the system encryption status must be set
					to SYSENC_STATUS_PRETEST (not to any special hidden-OS status), because some remnants of the XML 
					configuration file could remain on the disk (file system journals, etc.) indicating that a hidden 
					OS has been created on the computer. Instead, we update our raw config flags in the master boot record. */

					if (!ChangeSystemEncryptionStatus (SYSENC_STATUS_PRETEST)
						|| !ChangeHiddenOSCreationPhase (TC_HIDDEN_OS_CREATION_PHASE_CLONING))
					{
						ChangeSystemEncryptionStatus (SYSENC_STATUS_NONE);
						Error ("CANNOT_INITIATE_HIDDEN_OS_CREATION");
						NormalCursor ();
						return 1;
					}
				}
				else if (!ChangeSystemEncryptionStatus (SYSENC_STATUS_PRETEST))
				{
					Error ("CANNOT_INITIATE_SYS_ENCRYPTION_PRETEST");
					NormalCursor ();
					return 1;
				}

				// Add the wizard to the system startup sequence
				ManageStartupSeqWiz (FALSE, "/acsysenc");

				EndMainDlg (MainDlg);

				try
				{
					BootEncObj->RestartComputer ();
				}
				catch (Exception &e)
				{
					e.Show (hwndDlg);
				}

				return 1;
			}

			else if (nCurPageNo == SYSENC_PRETEST_RESULT_PAGE)
			{
				if (!bHiddenOS)
					TextInfoDialogBox (TC_TBXID_SYS_ENC_RESCUE_DISK);

				// Begin the actual encryption process

				ChangeSystemEncryptionStatus (SYSENC_STATUS_ENCRYPTING);
			}

			else if (nCurPageNo == SYSENC_ENCRYPTION_PAGE
				&& CreateSysEncMutex ())
			{
				// The 'Next' button functions as Finish or Resume

				if (SystemEncryptionStatus != SYSENC_STATUS_NONE)
				{
					try
					{
						// Resume
						SysEncResume ();
					}
					catch (Exception &e)
					{
						e.Show (hwndDlg);
					}
				}
				else
				{
					// Finish
					PostMessage (hwndDlg, TC_APPMSG_FORMAT_USER_QUIT, 0, 0);
				}

				return 1;
			}

			else if (nCurPageNo == FORMAT_PAGE)
			{
				/* Format start  (the 'Next' button has been clicked on the Format page) */

				if (bThreadRunning)
					return 1;
				else
					bThreadRunning = TRUE;

				bThreadCancel = FALSE;

				fileSystem = SendMessage (GetDlgItem (hCurPage, IDC_FILESYS), CB_GETITEMDATA,
					SendMessage (GetDlgItem (hCurPage, IDC_FILESYS), CB_GETCURSEL, 0, 0) , 0);

				clusterSize = SendMessage (GetDlgItem (hCurPage, IDC_CLUSTERSIZE), CB_GETITEMDATA,
					SendMessage (GetDlgItem (hCurPage, IDC_CLUSTERSIZE), CB_GETCURSEL, 0, 0) , 0);

				quickFormat = IsButtonChecked (GetDlgItem (hCurPage, IDC_QUICKFORMAT));

				if (bHiddenVolHost)
				{
					hiddenVolHostDriveNo = -1;
					nMaximumHiddenVolSize = 0;

					if (fileSystem == FILESYS_NTFS)	
					{
						if (bHiddenOS
							&& (double) nVolumeSize / GetSystemPartitionSize() < MIN_HIDDENOS_DECOY_PARTITION_SIZE_RATIO_NTFS)
						{
							Error("OUTER_VOLUME_TOO_SMALL_FOR_HIDDEN_OS_NTFS");

							if (GetVolumeDataAreaSize (FALSE, nVolumeSize) <= TC_MAX_FAT_FS_SIZE
								&& AskYesNo("OFFER_FAT_FORMAT_ALTERNATIVE") == IDYES)
							{
								fileSystem = FILESYS_FAT;
								SelectAlgo (GetDlgItem (hCurPage, IDC_FILESYS), (int *) &fileSystem);
							}
							else
							{
								bThreadRunning = FALSE;
								return 1;
							}
						}

						if (fileSystem == FILESYS_NTFS)	// The file system may have been changed in the previous block
						{
							if (nCurrentOS == WIN_2000)
							{
								Error("HIDDEN_VOL_HOST_UNSUPPORTED_FILESYS_WIN2000");
								bThreadRunning = FALSE;
								return 1;
							}
							else if (GetVolumeDataAreaSize (FALSE, nVolumeSize) <= TC_MAX_FAT_FS_SIZE
								&& AskYesNo("HIDDEN_VOL_HOST_NTFS_ASK") == IDNO)
							{
								bThreadRunning = FALSE;
								return 1;
							}
						}
					}
				}
				else if (bHiddenVol)
				{
					// Hidden volume is always quick-formatted (if, however, the meaning of quickFormat is 
					// whether to create a sparse file, it must be set to FALSE).
					quickFormat = !bSparseFileSwitch;	
				}


				if (fileSystem == FILESYS_FAT
					&& nNeedToStoreFilesOver4GB == 1
					&& AskWarnNoYes("CONFIRM_FAT_FOR_FILES_OVER_4GB") == IDNO)
				{
					bThreadRunning = FALSE;
					return 1;
				}

				EnableWindow (GetDlgItem (hwndDlg, IDC_PREV), FALSE);
				EnableWindow (GetDlgItem (hwndDlg, IDC_NEXT), FALSE);
				EnableWindow (GetDlgItem (hwndDlg, IDHELP), FALSE);
				EnableWindow (GetDlgItem (hwndDlg, IDCANCEL), FALSE);
				EnableWindow (GetDlgItem (hCurPage, IDC_QUICKFORMAT), FALSE);
				EnableWindow (GetDlgItem (hCurPage, IDC_CLUSTERSIZE), FALSE);
				EnableWindow (GetDlgItem (hCurPage, IDC_FILESYS), FALSE);
				EnableWindow (GetDlgItem (hCurPage, IDC_ABORT_BUTTON), TRUE);
				SetFocus (GetDlgItem (hCurPage, IDC_ABORT_BUTTON));
 
				// Increase cluster size if it's too small for this volume size
				if (fileSystem == FILESYS_FAT && clusterSize > 0)
				{
					BOOL fixed = FALSE;
					while (clusterSize < 128 
						&& nVolumeSize / clusterSize > 17179869184I64)
					{
						clusterSize *= 2;
						fixed = TRUE;
					}
					if (fixed)
						MessageBoxW (hwndDlg, GetString ("CLUSTER_TOO_SMALL"), lpszTitle, MB_ICONWARNING);
				}

				LastDialogId = "FORMAT_IN_PROGRESS";
				ArrowWaitCursor ();
				_beginthread (formatThreadFunction, 4096, hwndDlg);

				return 1;
			}

			else if (nCurPageNo == FORMAT_FINISHED_PAGE)
			{

				if (!bHiddenVol || bHiddenVolFinished)
				{
					/* Wizard loop restart */

					if (bHiddenOS)
					{
						if (!ChangeWizardMode (WIZARD_MODE_SYS_DEVICE))
							return 1;

						bHiddenVol = FALSE;
						LoadPage (hwndDlg, PASSWORD_PAGE);
					}
					else
						LoadPage (hwndDlg, INTRO_PAGE);

					SetWindowTextW (GetDlgItem (MainDlg, IDCANCEL), GetString ("CANCEL"));
					bHiddenVolFinished = FALSE;
					WipePasswordsAndKeyfiles ();

					return 1;
				}
				else
				{
					/* We're going to scan the bitmap of the hidden volume host (in the non-Direct hidden volume wizard mode) */
					int retCode;
					WaitCursor ();

					if (hiddenVolHostDriveNo != -1)		// If the hidden volume host is mounted
					{
						BOOL tmp_result;

						// Dismount the hidden volume host (in order to remount it as read-only subsequently)
						CloseVolumeExplorerWindows (hwndDlg, hiddenVolHostDriveNo);
						while (!(tmp_result = UnmountVolume (hwndDlg, hiddenVolHostDriveNo, FALSE)))
						{
							if (MessageBoxW (hwndDlg, GetString ("CANT_DISMOUNT_OUTER_VOL"), lpszTitle, MB_RETRYCANCEL | MB_ICONERROR | MB_SETFOREGROUND) != IDRETRY)
							{
								// Cancel
								NormalCursor();
								return 1;
							}
						}
						if (tmp_result)		// If dismounted
							hiddenVolHostDriveNo = -1;
					}

					if (hiddenVolHostDriveNo < 0)		// If the hidden volume host is not mounted
					{
						// Remount the hidden volume host as read-only (to ensure consistent and secure
						// results of the volume bitmap scanning)
						switch (MountHiddenVolHost (hwndDlg, szDiskFile, &hiddenVolHostDriveNo, &volumePassword, TRUE))
						{
						case ERR_NO_FREE_DRIVES:
							MessageBoxW (hwndDlg, GetString ("NO_FREE_DRIVE_FOR_OUTER_VOL"), lpszTitle, ICON_HAND);
							NormalCursor ();
							return 1;

						case ERR_VOL_MOUNT_FAILED:
						case ERR_PASSWORD_WRONG:
							NormalCursor ();
							return 1;

						case 0:

							/* Hidden volume host successfully mounted as read-only */

							// Verify that the outer volume contains a suitable file system, retrieve cluster size, and 
							// scan the volume bitmap
							if (!IsAdmin () && IsUacSupported ())
								retCode = UacAnalyzeHiddenVolumeHost (hwndDlg, &hiddenVolHostDriveNo, GetVolumeDataAreaSize (FALSE, nHiddenVolHostSize), &realClusterSize, &nbrFreeClusters);
							else
								retCode = AnalyzeHiddenVolumeHost (hwndDlg, &hiddenVolHostDriveNo, GetVolumeDataAreaSize (FALSE, nHiddenVolHostSize), &realClusterSize, &nbrFreeClusters);

							switch (retCode)
							{
							case -1:	// Fatal error
								CloseVolumeExplorerWindows (hwndDlg, hiddenVolHostDriveNo);

								if (UnmountVolume (hwndDlg, hiddenVolHostDriveNo, FALSE))
									hiddenVolHostDriveNo = -1;

								AbortProcessSilent ();
								break;

							case 0:		// Unsupported file system (or other non-fatal error which has already been reported)
								NormalCursor ();
								return 1;

							case 1:		// Success
								{
									BOOL tmp_result;

									// Determine the maximum possible size of the hidden volume
									if (DetermineMaxHiddenVolSize (hwndDlg) < 1)
									{
										NormalCursor ();
										goto ovf_end;
									}

									/* Maximum possible size of the hidden volume successfully determined */

									// Dismount the hidden volume host
									while (!(tmp_result = UnmountVolume (hwndDlg, hiddenVolHostDriveNo, FALSE)))
									{
										if (MessageBoxW (hwndDlg, GetString ("CANT_DISMOUNT_OUTER_VOL"), lpszTitle, MB_RETRYCANCEL) != IDRETRY)
										{
											// Cancel
											NormalCursor ();
											goto ovf_end;
										}
									}

									hiddenVolHostDriveNo = -1;

									nNewPageNo = HIDDEN_VOL_HOST_PRE_CIPHER_PAGE;

									// Clear the outer volume password
									WipePasswordsAndKeyfiles ();

									EnableWindow (GetDlgItem (MainDlg, IDC_NEXT), TRUE);
									NormalCursor ();

								}
								break;
							}
							break;
						}
					}
				}
			}

			LoadPage (hwndDlg, nNewPageNo + 1);
ovf_end:
			return 1;
		}
		else if (lw == IDC_PREV)
		{
			if (nCurPageNo == SYSENC_SPAN_PAGE)
			{
				// Skip irrelevant pages when going back
				if (!bHiddenOS)
					nNewPageNo = SYSENC_TYPE_PAGE + 1;
			}
			if (nCurPageNo == SYSENC_MULTI_BOOT_MODE_PAGE)
			{
				// Skip the drive analysis page(s) or other irrelevant pages when going back
				if (bHiddenOS)
					nNewPageNo = SYSENC_HIDDEN_OS_REQ_CHECK_PAGE + 1;
				else if (bWholeSysDrive)
					nNewPageNo = SYSENC_PRE_DRIVE_ANALYSIS_PAGE + 1;	
				else
					nNewPageNo = SYSENC_SPAN_PAGE + 1;	
			}
			else if (nCurPageNo == SYSENC_MULTI_BOOT_NONWIN_BOOT_LOADER_PAGE)
			{
				if (SysEncMultiBootCfg.NumberOfSysDrives == 1)
				{
					// We can skip SYSENC_MULTI_BOOT_ADJACENT_SYS_PAGE (it is implied that there are multiple systems on the drive)
					nNewPageNo = SYSENC_MULTI_BOOT_NBR_SYS_DRIVES_PAGE + 1;
				}
			}
			else if (nCurPageNo == HIDDEN_VOL_HOST_PRE_CIPHER_PAGE)
			{
				if (bHiddenOS)
				{
					if (!ChangeWizardMode (WIZARD_MODE_SYS_DEVICE))
					{
						NormalCursor ();
						return 1;
					}

					nNewPageNo = (nMultiBoot <= 1 ? SYSENC_MULTI_BOOT_MODE_PAGE + 1 : SYSENC_MULTI_BOOT_OUTCOME_PAGE + 1);		// Skip irrelevant pages
				}
			}
			else if (nCurPageNo == HIDDEN_VOL_WIZARD_MODE_PAGE)
			{
				if (IsButtonChecked (GetDlgItem (hCurPage, IDC_HIDVOL_WIZ_MODE_DIRECT)))
					bHiddenVolDirect = TRUE;
				else
					bHiddenVolDirect = FALSE;
			}
			else if (nCurPageNo == VOLUME_TYPE_PAGE)
			{
				if (WizardMode != WIZARD_MODE_SYS_DEVICE)
					nNewPageNo = INTRO_PAGE + 1;	// Skip irrelevant pages
			}
			else if (nCurPageNo == FILE_PAGE)
			{
				BOOL tmpbDevice;

				GetWindowText (GetDlgItem (hCurPage, IDC_COMBO_BOX), szFileName, sizeof (szFileName));
				CreateFullVolumePath (szDiskFile, szFileName, &tmpbDevice);

				if (tmpbDevice == bDevice)
				{
					MoveEditToCombo (GetDlgItem (hCurPage, IDC_COMBO_BOX), bHistory);
					SaveSettings (hCurPage);
				}

				if (!bHiddenVol)
					nNewPageNo = VOLUME_TYPE_PAGE + 1;		// Skip the hidden volume creation wizard mode selection
			}

			else if (nCurPageNo == CIPHER_PAGE)
			{
				LPARAM nIndex;
				nIndex = SendMessage (GetDlgItem (hCurPage, IDC_COMBO_BOX), CB_GETCURSEL, 0, 0);
				nVolumeEA = SendMessage (GetDlgItem (hCurPage, IDC_COMBO_BOX), CB_GETITEMDATA, nIndex, 0);

				nIndex = SendMessage (GetDlgItem (hCurPage, IDC_COMBO_BOX_HASH_ALGO), CB_GETCURSEL, 0, 0);
				hash_algo = SendMessage (GetDlgItem (hCurPage, IDC_COMBO_BOX_HASH_ALGO), CB_GETITEMDATA, nIndex, 0);

				RandSetHashFunction (hash_algo);

				if (WizardMode == WIZARD_MODE_SYS_DEVICE)
				{
					if (nMultiBoot > 1)
						nNewPageNo = SYSENC_MULTI_BOOT_OUTCOME_PAGE + 1;	// Skip irrelevant pages
					else
						nNewPageNo = SYSENC_MULTI_BOOT_MODE_PAGE + 1;		// Skip irrelevant pages
				}
				else if (!bHiddenVol)
					nNewPageNo = HIDDEN_VOL_HOST_PRE_CIPHER_PAGE;	// Skip the extra info on hidden volume 
				else if (bHiddenVolHost)
					nNewPageNo = HIDDEN_VOL_PRE_CIPHER_PAGE;		// Skip the info on the hidden volume
			}

			else if (nCurPageNo == SIZE_PAGE)
			{
				VerifySizeAndUpdate (hCurPage, TRUE);
			}

			else if (nCurPageNo == FILESYS_PAGE)
			{
				if (nNeedToStoreFilesOver4GB != Get2RadButtonPageAnswer())
					fileSystem = FILESYS_NONE;	// The user may have gone back and changed the answer, so default file system must be reselected
	
				nNeedToStoreFilesOver4GB = Get2RadButtonPageAnswer();
			}

			else if (nCurPageNo == PASSWORD_PAGE)
			{
				// Store the password in case we need to restore it after keyfile is applied to it
				GetWindowText (GetDlgItem (hCurPage, IDC_PASSWORD), szRawPassword, sizeof (szRawPassword));

				VerifyPasswordAndUpdate (hwndDlg, GetDlgItem (MainDlg, IDC_NEXT),
					GetDlgItem (hCurPage, IDC_PASSWORD),
					GetDlgItem (hCurPage, IDC_VERIFY),
					volumePassword.Text,
					szVerify,
					KeyFilesEnable && FirstKeyFile!=NULL && !SysEncInEffect ());

				volumePassword.Length = strlen ((char *) volumePassword.Text);

				nNewPageNo = SIZE_PAGE + 1;		// Skip the hidden volume host password page

				if (SysEncInEffect ())
				{
					nNewPageNo = CIPHER_PAGE + 1;				// Skip irrelevant pages

					KillTimer (hwndDlg, TIMER_ID_KEYB_LAYOUT_GUARD);

					if (bKeyboardLayoutChanged)
					{
						// Restore the original keyboard layout
						if (LoadKeyboardLayout (OrigKeyboardLayout, KLF_ACTIVATE | KLF_SUBSTITUTE_OK) == NULL) 
							Warning ("CANNOT_RESTORE_KEYBOARD_LAYOUT");
						else
							bKeyboardLayoutChanged = FALSE;
					}
				}
			}

			else if (nCurPageNo == HIDDEN_VOL_HOST_PASSWORD_PAGE)
			{
				// Store the password in case we need to restore it after keyfile is applied to it
				GetWindowText (GetDlgItem (hCurPage, IDC_PASSWORD_DIRECT), szRawPassword, sizeof (szRawPassword));

				GetWindowText (GetDlgItem (hCurPage, IDC_PASSWORD_DIRECT), (char *) volumePassword.Text, sizeof (volumePassword.Text));
				volumePassword.Length = strlen ((char *) volumePassword.Text);
				nNewPageNo = FILE_PAGE + 1;
			}

			else if (nCurPageNo == SYSENC_COLLECTING_RANDOM_DATA_PAGE)
			{
				char tmp[RANDPOOL_DISPLAY_SIZE+1];

				KillTimer (hwndDlg, TIMER_ID_RANDVIEW);

				// Attempt to wipe the GUI field showing portions of randpool
				memset (tmp, 'X', sizeof(tmp));
				tmp [sizeof(tmp)-1] = 0;
				SetWindowText (hRandPoolSys, tmp);

				nNewPageNo = PASSWORD_PAGE + 1;		// Skip irrelevant pages
			}

			else if (nCurPageNo == SYSENC_KEYS_GEN_PAGE)
			{
				char tmp[KEY_GUI_VIEW_SIZE+1];

				// Attempt to wipe the GUI fields showing portions of the master and header keys
				memset (tmp, 'X', sizeof(tmp));
				tmp [sizeof(tmp)-1] = 0;
				SetWindowText (hMasterKey, tmp);
				SetWindowText (hHeaderKey, tmp);
			}

			else if (nCurPageNo == SYSENC_WIPE_MODE_PAGE)
			{
				if (bDontVerifyRescueDisk)
					nNewPageNo = SYSENC_RESCUE_DISK_VERIFIED_PAGE;	// Skip irrelevant pages
			}

			else if (nCurPageNo == SYSENC_PRETEST_INFO_PAGE)
			{
				if (bHiddenOS)
					nNewPageNo = SYSENC_RESCUE_DISK_VERIFIED_PAGE + 1;	// Skip irrelevant pages
			}

			else if (nCurPageNo == FORMAT_PAGE)
			{
				char tmp[RNG_POOL_SIZE*2+1];

				KillTimer (hwndDlg, TIMER_ID_RANDVIEW);

				// Attempt to wipe the GUI fields showing portions of randpool, of the master and header keys
				memset (tmp, 'X', sizeof(tmp));
				tmp [sizeof(tmp)-1] = 0;
				SetWindowText (hRandPool, tmp);
				SetWindowText (hMasterKey, tmp);
				SetWindowText (hHeaderKey, tmp);

				if (WizardMode != WIZARD_MODE_SYS_DEVICE)
				{
					// Skip irrelevant pages

					if (FileSize4GBLimitQuestionNeeded ()
						&& !CreatingHiddenSysVol())		// If we're creating a hidden volume for a hidden OS, we don't need to be format it with any filesystem (the entire OS will be copied to the hidden volume sector by sector).
						nNewPageNo = FILESYS_PAGE + 1;
					else
						nNewPageNo = PASSWORD_PAGE + 1;		
				}
			}

			LoadPage (hwndDlg, nNewPageNo - 1);

			return 1;
		}

		return 0;

	case WM_ENDSESSION:
		EndMainDlg (MainDlg);
		localcleanup ();
		return 0;

	case WM_CLOSE:
		PostMessage (hwndDlg, TC_APPMSG_FORMAT_USER_QUIT, 0, 0);
		return 1;
	}

	return 0;
}

void ExtractCommandLine (HWND hwndDlg, char *lpszCommandLine)
{
	char **lpszCommandLineArgs;	/* Array of command line arguments */
	int nNoCommandLineArgs;	/* The number of arguments in the array */

	if (_stricmp (lpszCommandLine, "-Embedding") == 0)
	{
		ComServerMode = TRUE;
		return;
	}

	/* Extract command line arguments */
	nNoCommandLineArgs = Win32CommandLine (lpszCommandLine, &lpszCommandLineArgs);
	if (nNoCommandLineArgs > 0)
	{
		int i;

		for (i = 0; i < nNoCommandLineArgs; i++)
		{
			argument args[]=
			{
				{"/sysenc", "/s"},	
				{"/dsysenc", "/d"},
				{"/isysenc", "/i"},	
				{"/risysenc", "/r"},	
				{"/csysenc", "/c"},
				{"/acsysenc", "/a"},
				{"/noisocheck", "/n"},
				{"/encdev", "/e"},
				{"/history", "/h"},
				{"/quit", "/q"}
			};

			argumentspec as;

			int nArgPos;
			int x;

			if (lpszCommandLineArgs[i] == NULL)
				continue;

			as.args = args;
			as.arg_cnt = sizeof(args)/ sizeof(args[0]);
			
			x = GetArgumentID (&as, lpszCommandLineArgs[i], &nArgPos);

			switch (x)
			{
			case 's':
				// Encrypt system partition/drive (passed by Mount if system encryption hasn't started or to reverse decryption)

				// From now on, we should be the only instance of the TC wizard allowed to deal with system encryption
				if (CreateSysEncMutex ())
				{
					bDirectSysEncMode = TRUE;
					bDirectSysEncModeCommand = SYSENC_COMMAND_ENCRYPT;
					ChangeWizardMode (WIZARD_MODE_SYS_DEVICE);
				}
				else
				{
					Warning ("SYSTEM_ENCRYPTION_IN_PROGRESS_ELSEWHERE");
					exit(0);
				}

				break;

			case 'd':
				// Decrypt system partition/drive (passed by Mount, also to reverse encryption in progress, when paused)

				// From now on, we should be the only instance of the TC wizard allowed to deal with system encryption
				if (CreateSysEncMutex ())
				{
					bDirectSysEncMode = TRUE;
					bDirectSysEncModeCommand = SYSENC_COMMAND_DECRYPT;
					ChangeWizardMode (WIZARD_MODE_SYS_DEVICE);
				}
				else
				{
					Warning ("SYSTEM_ENCRYPTION_IN_PROGRESS_ELSEWHERE");
					exit(0);
				}
				break;

			case 'i':
				// Create a hidden operating system (passed by Mount when the user selects System -> Create Hidden Operating System)

				// From now on, we should be the only instance of the TC wizard allowed to deal with system encryption
				if (CreateSysEncMutex ())
				{
					bDirectSysEncMode = TRUE;
					bDirectSysEncModeCommand = SYSENC_COMMAND_CREATE_HIDDEN_OS;
					ChangeWizardMode (WIZARD_MODE_SYS_DEVICE);
				}
				else
				{
					Warning ("SYSTEM_ENCRYPTION_IN_PROGRESS_ELSEWHERE");
					exit(0);
				}

				break;

			case 'r':
				// Resume process of creation of a hidden operating system (passed by Wizard when the user needs to UAC-elevate the whole wizard process)

				// From now on, we should be the only instance of the TC wizard allowed to deal with system encryption
				if (CreateSysEncMutex ())
				{
					bDirectSysEncMode = TRUE;
					bDirectSysEncModeCommand = SYSENC_COMMAND_CREATE_HIDDEN_OS_ELEV;
					ChangeWizardMode (WIZARD_MODE_SYS_DEVICE);
				}
				else
				{
					Warning ("SYSTEM_ENCRYPTION_IN_PROGRESS_ELSEWHERE");
					exit(0);
				}

				break;

			case 'c':
				// Resume previous system-encryption operation (passed by Mount) e.g. encryption, decryption, or pretest 

				// From now on, we should be the only instance of the TC wizard allowed to deal with system encryption
				if (CreateSysEncMutex ())
				{
					bDirectSysEncMode = TRUE;
					bDirectSysEncModeCommand = SYSENC_COMMAND_RESUME;
					ChangeWizardMode (WIZARD_MODE_SYS_DEVICE);
				}
				else
				{
					Warning ("SYSTEM_ENCRYPTION_IN_PROGRESS_ELSEWHERE");
					exit(0);
				}
				break;

			case 'a':
				// Same as csysenc but passed only by the system (from the startup sequence)

				// From now on, we should be the only instance of the TC wizard allowed to deal with system encryption
				if (CreateSysEncMutex ())
				{
					bDirectSysEncMode = TRUE;
					bDirectSysEncModeCommand = SYSENC_COMMAND_STARTUP_SEQ_RESUME;
					ChangeWizardMode (WIZARD_MODE_SYS_DEVICE);
				}
				else
				{
					Warning ("SYSTEM_ENCRYPTION_IN_PROGRESS_ELSEWHERE");
					exit(0);
				}
				break;

			case 'e':
				// Resume process of creation of a non-sys-device-hosted volume (passed by Wizard when the user needs to UAC-elevate)
				DirectDeviceEncMode = TRUE;
				break;

			case 'n':
				bDontVerifyRescueDisk = TRUE;
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

			case 'q':
				{
					// Used to indicate non-install elevation
					char szTmp[32];
					GetArgumentValue (lpszCommandLineArgs, nArgPos, &i, nNoCommandLineArgs, szTmp, sizeof (szTmp));
				}
				break;

			default:
				DialogBoxParamW (hInst, MAKEINTRESOURCEW (IDD_COMMANDHELP_DLG), hwndDlg, (DLGPROC)
						CommandHelpDlgProc, (LPARAM) &as);

				exit(0);
			}
		}
	}

	/* Free up the command line arguments */
	while (--nNoCommandLineArgs >= 0)
	{
		free (lpszCommandLineArgs[nNoCommandLineArgs]);
	}
}


int DetermineMaxHiddenVolSize (HWND hwndDlg)
{
	__int64 nbrReserveBytes;

	if (nbrFreeClusters * realClusterSize < TC_MIN_HIDDEN_VOLUME_SIZE)
	{
		MessageBoxW (hwndDlg, GetString ("NO_SPACE_FOR_HIDDEN_VOL"), lpszTitle, ICON_HAND);
		UnmountVolume (hwndDlg, hiddenVolHostDriveNo, FALSE);
		AbortProcessSilent ();
	}

	// Add a reserve (in case the user mounts the outer volume and creates new files
	// on it by accident or OS writes some new data behind his or her back, such as
	// System Restore etc.)
	nbrReserveBytes = GetVolumeDataAreaSize (FALSE, nHiddenVolHostSize) / 200;
	if (nbrReserveBytes > BYTES_PER_MB * 10)
		nbrReserveBytes = BYTES_PER_MB * 10;

	// Compute the final value

	nMaximumHiddenVolSize = nbrFreeClusters * realClusterSize - TC_HIDDEN_VOLUME_HOST_FS_RESERVED_END_AREA_SIZE - nbrReserveBytes;
	nMaximumHiddenVolSize -= nMaximumHiddenVolSize % SECTOR_SIZE;		// Must be a multiple of the sector size

	if (nMaximumHiddenVolSize < TC_MIN_HIDDEN_VOLUME_SIZE)
	{
		MessageBoxW (hwndDlg, GetString ("NO_SPACE_FOR_HIDDEN_VOL"), lpszTitle, ICON_HAND);
		UnmountVolume (hwndDlg, hiddenVolHostDriveNo, FALSE);
		AbortProcessSilent ();
	}

	// Prepare the hidden volume size parameters
	if (nMaximumHiddenVolSize < BYTES_PER_MB)
		nMultiplier = BYTES_PER_KB;
	else
		nMultiplier = BYTES_PER_MB;

	nUIVolumeSize = 0;								// Set the initial value for the hidden volume size input field to the max
	nVolumeSize = nUIVolumeSize * nMultiplier;		// Chop off possible remainder

	return 1;
}


// Tests whether the file system of the given volume is suitable to host a hidden volume,
// retrieves the cluster size, and scans the volume cluster bitmap. In addition, checks
// the TrueCrypt volume format version and the type of volume.
int AnalyzeHiddenVolumeHost (HWND hwndDlg, int *driveNo, __int64 hiddenVolHostSize, int *realClusterSize, __int64 *pnbrFreeClusters)
{
	HANDLE hDevice;
	DWORD bytesReturned;
	DWORD dwSectorsPerCluster, dwBytesPerSector, dwNumberOfFreeClusters, dwTotalNumberOfClusters;
	DWORD dwResult;
	int result;
	char szFileSystemNameBuffer[256];
	char szFileName[7] = {'\\','\\','.','\\',*driveNo + 'A',':',0};
	char szRootPathName[4] = {*driveNo + 'A', ':', '\\', 0};
	BYTE readBuffer[SECTOR_SIZE*2];
	LARGE_INTEGER offset, offsetNew;
	VOLUME_PROPERTIES_STRUCT volProp;

	memset (&volProp, 0, sizeof(volProp));
	volProp.driveNo = *driveNo;
	if (!DeviceIoControl (hDriver, TC_IOCTL_GET_VOLUME_PROPERTIES, &volProp, sizeof (volProp), &volProp, sizeof (volProp), &dwResult, NULL) || dwResult == 0)
	{
		handleWin32Error (hwndDlg);
		Error ("CANT_ACCESS_OUTER_VOL");
		goto efsf_error;
	}

	if (volProp.volFormatVersion < TC_VOLUME_FORMAT_VERSION)
	{
		// We do not support creating hidden volumes within volumes created by TrueCrypt 5.1a or earlier.
		Error ("ERR_VOL_FORMAT_BAD");
		goto efsf_error;
	}

	if (volProp.hiddenVolume)
	{
		// The user entered a password for a hidden volume
		Error ("ERR_HIDDEN_NOT_NORMAL_VOLUME");
		return 0;
	}

	hDevice = CreateFile (szFileName, GENERIC_READ, FILE_SHARE_READ|FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);

	if (hDevice == INVALID_HANDLE_VALUE)
	{
		MessageBoxW (hwndDlg, GetString ("CANT_ACCESS_OUTER_VOL"), lpszTitle, ICON_HAND);
		goto efsf_error;
	}

	offset.QuadPart = 0;

	if (SetFilePointerEx (hDevice, offset, &offsetNew, FILE_BEGIN) == 0)
	{
		handleWin32Error (hwndDlg);
		goto efs_error;
	}

	result = ReadFile(hDevice, &readBuffer, (DWORD) SECTOR_SIZE, &bytesReturned, NULL);

	if (result == 0)
	{
		handleWin32Error (hwndDlg);
		MessageBoxW (hwndDlg, GetString ("CANT_ACCESS_OUTER_VOL"), lpszTitle, ICON_HAND);
		goto efs_error;
	}

	CloseHandle (hDevice);

	// Determine file system type

	GetVolumeInformation(szRootPathName, NULL, 0, NULL, NULL, NULL, szFileSystemNameBuffer, sizeof(szFileSystemNameBuffer));

	// The Windows API sometimes fails to indentify the file system correctly so we're using "raw" analysis too.
	if (!strncmp (szFileSystemNameBuffer, "FAT", 3)
		|| (readBuffer[0x36] == 'F' && readBuffer[0x37] == 'A' && readBuffer[0x38] == 'T')
		|| (readBuffer[0x52] == 'F' && readBuffer[0x53] == 'A' && readBuffer[0x54] == 'T'))
	{
		// FAT12/FAT16/FAT32

		// Retrieve the cluster size
		*realClusterSize = ((int) readBuffer[0xb] + ((int) readBuffer[0xc] << 8)) * (int) readBuffer[0xd];	

		// Get the map of the clusters that are free and in use on the outer volume.
		// The map will be scanned to determine the size of the uninterrupted block of free
		// space (provided there is any) whose end is aligned with the end of the volume.
		// The value will then be used to determine the maximum possible size of the hidden volume.

		return ScanVolClusterBitmap (hwndDlg,
			driveNo,
			hiddenVolHostSize / *realClusterSize,
			pnbrFreeClusters);
	}
	else if (!strncmp (szFileSystemNameBuffer, "NTFS", 4))
	{
		// NTFS

		if (nCurrentOS == WIN_2000)
		{
			Error("HIDDEN_VOL_HOST_UNSUPPORTED_FILESYS_WIN2000");
			return 0;
		}

		if (bHiddenVolDirect && GetVolumeDataAreaSize (FALSE, hiddenVolHostSize) <= TC_MAX_FAT_FS_SIZE)
			Info ("HIDDEN_VOL_HOST_NTFS");

		if (!GetDiskFreeSpace(szRootPathName, 
			&dwSectorsPerCluster, 
			&dwBytesPerSector, 
			&dwNumberOfFreeClusters, 
			&dwTotalNumberOfClusters))
		{
			handleWin32Error (hwndDlg);
			Error ("CANT_GET_OUTER_VOL_INFO");
			return -1;
		};

		*realClusterSize = dwBytesPerSector * dwSectorsPerCluster;

		// Get the map of the clusters that are free and in use on the outer volume.
		// The map will be scanned to determine the size of the uninterrupted block of free
		// space (provided there is any) whose end is aligned with the end of the volume.
		// The value will then be used to determine the maximum possible size of the hidden volume.

		return ScanVolClusterBitmap (hwndDlg,
			driveNo,
			hiddenVolHostSize / *realClusterSize,
			pnbrFreeClusters);
	}
	else
	{
		// Unsupported file system

		Error ((nCurrentOS == WIN_2000) ? "HIDDEN_VOL_HOST_UNSUPPORTED_FILESYS_WIN2000" : "HIDDEN_VOL_HOST_UNSUPPORTED_FILESYS");
		return 0;
	}

efs_error:
	CloseHandle (hDevice);

efsf_error:
	CloseVolumeExplorerWindows (hwndDlg, *driveNo);

	return -1;
}


// Mounts a volume within which the user intends to create a hidden volume
int MountHiddenVolHost (HWND hwndDlg, char *volumePath, int *driveNo, Password *password, BOOL bReadOnly)
{
	MountOptions mountOptions;
	ZeroMemory (&mountOptions, sizeof (mountOptions));

	*driveNo = GetLastAvailableDrive ();

	if (*driveNo == -1)
	{
		*driveNo = -2;
		return ERR_NO_FREE_DRIVES;
	}

	mountOptions.ReadOnly = bReadOnly;
	mountOptions.Removable = ConfigReadInt ("MountVolumesRemovable", FALSE);
	mountOptions.ProtectHiddenVolume = FALSE;
	mountOptions.PreserveTimestamp = bPreserveTimestamp;
	mountOptions.PartitionInInactiveSysEncScope = FALSE;
	mountOptions.UseBackupHeader = FALSE;

	if (MountVolume (hwndDlg, *driveNo, volumePath, password, FALSE, TRUE, &mountOptions, FALSE, TRUE) < 1)
	{
		*driveNo = -3;
		return ERR_VOL_MOUNT_FAILED;
	}
	return 0;
}


/* Gets the map of the clusters that are free and in use on a volume that is to host
   a hidden volume. The map is scanned to determine the size of the uninterrupted
   area of free space (provided there is any) whose end is aligned with the end
   of the volume. The value will then be used to determine the maximum possible size
   of the hidden volume. */
int ScanVolClusterBitmap (HWND hwndDlg, int *driveNo, __int64 nbrClusters, __int64 *nbrFreeClusters)
{
	PVOLUME_BITMAP_BUFFER lpOutBuffer;
	STARTING_LCN_INPUT_BUFFER lpInBuffer;

	HANDLE hDevice;
	DWORD lBytesReturned;
	BYTE rmnd;
	char szFileName[7] = {'\\','\\','.','\\', *driveNo + 'A', ':', 0};

	DWORD bufLen;
	__int64 bitmapCnt;

	hDevice = CreateFile (szFileName, GENERIC_READ, FILE_SHARE_READ|FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);

	if (hDevice == INVALID_HANDLE_VALUE)
	{
		MessageBoxW (hwndDlg, GetString ("CANT_ACCESS_OUTER_VOL"), lpszTitle, ICON_HAND);
		goto vcmf_error;
	}

 	bufLen = (DWORD) (nbrClusters / 8 + 2 * sizeof(LARGE_INTEGER));
	bufLen += 100000 + bufLen/10;	// Add reserve

	lpOutBuffer = (PVOLUME_BITMAP_BUFFER) malloc (bufLen);

	if (lpOutBuffer == NULL)
	{
		MessageBoxW (hwndDlg, GetString ("ERR_MEM_ALLOC"), lpszTitle, ICON_HAND);
		goto vcmf_error;
	}

	lpInBuffer.StartingLcn.QuadPart = 0;

	if ( !DeviceIoControl (hDevice,
		FSCTL_GET_VOLUME_BITMAP,
		&lpInBuffer,
		sizeof(lpInBuffer),
		lpOutBuffer,
		bufLen,  
		&lBytesReturned,
		NULL))
	{
		handleWin32Error (hwndDlg);
		MessageBoxW (hwndDlg, GetString ("CANT_GET_CLUSTER_BITMAP"), lpszTitle, ICON_HAND);

		goto vcm_error;
	}

	rmnd = (BYTE) (lpOutBuffer->BitmapSize.QuadPart % 8);

	if ((rmnd != 0) 
	&& ((lpOutBuffer->Buffer[lpOutBuffer->BitmapSize.QuadPart / 8] & ((1 << rmnd)-1) ) != 0))
	{
		*nbrFreeClusters = 0;
	}
	else
	{
		*nbrFreeClusters = lpOutBuffer->BitmapSize.QuadPart;
		bitmapCnt = lpOutBuffer->BitmapSize.QuadPart / 8;

		// Scan the bitmap from the end
		while (--bitmapCnt >= 0)
		{
			if (lpOutBuffer->Buffer[bitmapCnt] != 0)
			{
				// There might be up to 7 extra free clusters in this byte of the bitmap. 
				// These are ignored because there is always a cluster reserve added anyway.
				*nbrFreeClusters = lpOutBuffer->BitmapSize.QuadPart - ((bitmapCnt + 1) * 8);	
				break;
			}
		}
	}

	CloseHandle (hDevice);
	free(lpOutBuffer);
	return 1;

vcm_error:
	CloseHandle (hDevice);
	free(lpOutBuffer);

vcmf_error:
	return -1;
}


// Wipe the hidden OS config flag bits in the MBR
static BOOL WipeHiddenOSCreationConfig (void)
{
	if (!IsHiddenOSRunning())
	{
		try
		{
			for (int wipePass = 0; wipePass < PRAND_DISK_WIPE_PASSES/3 + 1; wipePass++)
			{
				BootEncObj->SetHiddenOSCreationPhase (TC_HIDDEN_OS_CREATION_PHASE_NONE);
				BootEncObj->SetHiddenOSCreationPhase (TC_HIDDEN_OS_CREATION_PHASE_CLONING);
				BootEncObj->SetHiddenOSCreationPhase (TC_HIDDEN_OS_CREATION_PHASE_DECOY_OS);
			}

			BootEncObj->SetHiddenOSCreationPhase (TC_HIDDEN_OS_CREATION_PHASE_NONE);
		}
		catch (Exception &e)
		{
			e.Show (MainDlg);
			return FALSE;
		}
	}

	return TRUE;
}


// This should be called as soon as the system partition/drive has been successfully and fully encrypted.
// IMPORTANT: It must be called before calling ChangeSystemEncryptionStatus (SYSENC_STATUS_NONE).
static void HandleDecoyOSCompletion (void)
{
	bHiddenOS = (DetermineHiddenOSCreationPhase() != TC_HIDDEN_OS_CREATION_PHASE_NONE);

	if (bHiddenOS && !IsHiddenOSRunning())
	{
		// We have just finished encrypting the decoy OS, by which we also complete the entire process of
		// creation of a hidden operating system

		Warning ("HIDDEN_OS_CREATION_PROCESS_FINISHED_WARN");
		Info ("HIDDEN_OS_CREATION_PROCESS_FINISHED_INFO");

		Warning ("SHUT_DOWN_COMPUTER_NOW");
	}
}


// Tasks that need to be performed after the WM_INITDIALOG message for the SYSENC_ENCRYPTION_PAGE dialog is
// handled should be done here (otherwise the UAC prompt causes the GUI to be only half-rendered). 
static void AfterSysEncProgressWMInitTasks (HWND hwndDlg)
{
	try
	{
		switch (SystemEncryptionStatus)
		{
		case SYSENC_STATUS_ENCRYPTING:

			if (!IsHiddenOSRunning())
			{
				try
				{
					// Unregister the volume class filter because it's really needed only in the hidden OS
					BootEncObj->RegisterFilterDriver (false, true);
				}
				catch (Exception &e)
				{
					e.Show (hwndDlg);
					AbortProcessSilent();
				}
			}

			if (BootEncStatus.ConfiguredEncryptedAreaStart == BootEncStatus.EncryptedAreaStart
				&& BootEncStatus.ConfiguredEncryptedAreaEnd == BootEncStatus.EncryptedAreaEnd)
			{
				// The partition/drive had been fully encrypted

				ManageStartupSeqWiz (TRUE, "");
				Info ("SYSTEM_ENCRYPTION_FINISHED");

				HandleDecoyOSCompletion ();

				if (WipeHiddenOSCreationConfig())
					ChangeSystemEncryptionStatus (SYSENC_STATUS_NONE);

				EndMainDlg (MainDlg);
				return;
			}
			else
			{
				SysEncResume ();
			}

			break;

		case SYSENC_STATUS_DECRYPTING:
			SysEncResume ();
			break;

		default:

			// Unexpected mode here -- fix the inconsistency

			ManageStartupSeqWiz (TRUE, "");
			ChangeSystemEncryptionStatus (SYSENC_STATUS_NONE);
			EndMainDlg (MainDlg);
			InconsistencyResolved (SRC_POS);
			return;
		}
	}
	catch (Exception &e)
	{
		e.Show (hwndDlg);
		EndMainDlg (MainDlg);
		return;
	}

	InitSysEncProgressBar ();

	UpdateSysEncProgressBar ();

	UpdateSysEncControls ();
}


// Tasks that need to be performed after the WM_INITDIALOG message is handled must be done here. 
// For example, any tasks that may invoke the UAC prompt (otherwise the UAC dialog box would not be on top).
static void AfterWMInitTasks (HWND hwndDlg)
{
	// Note that if bDirectSysEncModeCommand is not SYSENC_COMMAND_NONE, we already have the mutex.

	// SYSENC_COMMAND_DECRYPT has the highest priority because it also performs uninstallation (restores the
	// original contents of the first drive cylinder, etc.) so it must be attempted regardless of the phase
	// or content of configuration files.
	if (bDirectSysEncModeCommand == SYSENC_COMMAND_DECRYPT)
	{
		if (IsHiddenOSRunning())
		{
			Warning ("CANNOT_DECRYPT_HIDDEN_OS");
			AbortProcessSilent();
		}

		// Add the wizard to the system startup sequence
		ManageStartupSeqWiz (FALSE, "/acsysenc");

		ChangeSystemEncryptionStatus (SYSENC_STATUS_DECRYPTING);
		LoadPage (hwndDlg, SYSENC_ENCRYPTION_PAGE);
		return;
	}


	if (SystemEncryptionStatus == SYSENC_STATUS_ENCRYPTING
		|| SystemEncryptionStatus == SYSENC_STATUS_DECRYPTING)
	{
		try
		{
			BootEncStatus = BootEncObj->GetStatus();

			if (!BootEncStatus.DriveMounted)
			{
				if (!BootEncStatus.DeviceFilterActive)
				{
					// This is an inconsistent state. SystemEncryptionStatus should never be SYSENC_STATUS_ENCRYPTING
					// or SYSENC_STATUS_DECRYPTING when the drive filter is not active. Possible causes: 1) corrupted
					// or stale config file, 2) corrupted system

					// Fix the inconsistency
					ManageStartupSeqWiz (TRUE, "");
					ChangeSystemEncryptionStatus (SYSENC_STATUS_NONE);
					EndMainDlg (MainDlg);
					InconsistencyResolved (SRC_POS);
					return;
				}
				else if (bDirectSysEncMode)
				{
					// This is an inconsistent state. We have a direct system encryption command, 
					// SystemEncryptionStatus is SYSENC_STATUS_ENCRYPTING or SYSENC_STATUS_DECRYPTING, the
					// system drive is not 'mounted' and drive filter is active.  Possible causes: 1) The drive had
					// been decrypted in the pre-boot environment. 2) The OS is not located on the lowest partition,
					// the drive is to be fully encrypted, but the user rebooted before encryption reached the 
					// system partition and then pressed Esc in the boot loader screen. 3) Corrupted or stale config
					// file. 4) Damaged system.
					
					Warning ("SYSTEM_ENCRYPTION_SCHEDULED_BUT_PBA_FAILED");
					EndMainDlg (MainDlg);
					return;
				}
			}
		}
		catch (Exception &e)
		{
			e.Show (MainDlg);
		}
	}


	if (SystemEncryptionStatus != SYSENC_STATUS_PRETEST)
	{
		// Handle system encryption command line arguments (if we're not in the Pretest phase).
		// Note that if bDirectSysEncModeCommand is not SYSENC_COMMAND_NONE, we already have the mutex.
		// Also note that SYSENC_COMMAND_DECRYPT is handled above.

		switch (bDirectSysEncModeCommand)
		{
		case SYSENC_COMMAND_RESUME:
		case SYSENC_COMMAND_STARTUP_SEQ_RESUME:

			if (bDirectSysEncModeCommand == SYSENC_COMMAND_STARTUP_SEQ_RESUME
				&& AskWarnYesNo ("SYSTEM_ENCRYPTION_RESUME_PROMPT") == IDNO)
			{
				EndMainDlg (MainDlg);
				return;
			}

			if (SysEncryptionOrDecryptionRequired ())
			{
				if (SystemEncryptionStatus != SYSENC_STATUS_ENCRYPTING
					&& SystemEncryptionStatus != SYSENC_STATUS_DECRYPTING)
				{
					// If the config file with status was lost or not written correctly, we
					// don't know whether to encrypt or decrypt (but we know that encryption or
					// decryption is required). Ask the user to select encryption, decryption, 
					// or cancel
					if (!ResolveUnknownSysEncDirection ())
					{
						EndMainDlg (MainDlg);
						return;
					}
				}

				LoadPage (hwndDlg, SYSENC_ENCRYPTION_PAGE);
				return;
			}
			else
			{
				// Nothing to resume
				Warning ("NOTHING_TO_RESUME");
				EndMainDlg (MainDlg);

				return;
			}
			break;

		case SYSENC_COMMAND_ENCRYPT:

			if (SysDriveOrPartitionFullyEncrypted (FALSE))
			{
				Info ("SYS_PARTITION_OR_DRIVE_APPEARS_FULLY_ENCRYPTED");
				EndMainDlg (MainDlg);
				return;
			}

			if (SysEncryptionOrDecryptionRequired ())
			{
				// System partition/drive encryption process already initiated but is incomplete.
				// If we were encrypting, resume the process directly. If we were decrypting, reverse 
				// the process and start encrypting.

				ChangeSystemEncryptionStatus (SYSENC_STATUS_ENCRYPTING);
				LoadPage (hwndDlg, SYSENC_ENCRYPTION_PAGE);
				return;
			}
			else
			{
				// Initiate the Pretest preparation phase
				if (!SwitchWizardToSysEncMode ())
				{
					bDirectSysEncMode = FALSE;
					EndMainDlg (MainDlg);
				}
				return;
			}

			break;

		case SYSENC_COMMAND_CREATE_HIDDEN_OS_ELEV:
		case SYSENC_COMMAND_CREATE_HIDDEN_OS:

			if (!SwitchWizardToHiddenOSMode ())
			{
				bDirectSysEncMode = FALSE;
				EndMainDlg (MainDlg);
			}
			return;
		}
	}


	if (!bDirectSysEncMode
		|| bDirectSysEncMode && SystemEncryptionStatus == SYSENC_STATUS_NONE)
	{
		// Handle system encryption cases where the wizard did not start even though it
		// was added to the startup sequence, as well as other weird cases and "leftovers"

		if (SystemEncryptionStatus != SYSENC_STATUS_NONE
			&& SystemEncryptionStatus != SYSENC_STATUS_PRETEST
			&& SysEncryptionOrDecryptionRequired ())
		{
			// System encryption/decryption had been in progress and did not finish

			if (CreateSysEncMutex ())	// If no other instance is currently taking care of system encryption
			{
				if (AskWarnYesNo ("SYSTEM_ENCRYPTION_RESUME_PROMPT") == IDYES)
				{
					bDirectSysEncMode = TRUE;
					ChangeWizardMode (WIZARD_MODE_SYS_DEVICE);
					LoadPage (hwndDlg, SYSENC_ENCRYPTION_PAGE);
					return;
				}
				else
					CloseSysEncMutex ();
			}
		}

		else if (SystemEncryptionStatus == SYSENC_STATUS_PRETEST)
		{
			// System pretest had been in progress but we were not launched during the startup seq

			if (CreateSysEncMutex ())	// If no other instance is currently taking care of system encryption
			{
				// The pretest has "priority handling"
				bDirectSysEncMode = TRUE;
				ChangeWizardMode (WIZARD_MODE_SYS_DEVICE);

				/* Do not return yet -- the principal pretest handler is below. */
			}
		}

		else if ((SystemEncryptionStatus == SYSENC_STATUS_NONE || SystemEncryptionStatus == SYSENC_STATUS_DECRYPTING)
			&& !BootEncStatus.DriveEncrypted 
			&& (BootEncStatus.DriveMounted || BootEncStatus.VolumeHeaderPresent))
		{
			// The pretest may have been in progress but we can't be sure (it is not in the config file).
			// Another possibility is that the user had finished decrypting the drive, but the config file
			// was not correctly updated. In both cases the best thing we can do is remove the header and 
			// deinstall. Otherwise, the result might be some kind of deadlock.

			if (CreateSysEncMutex ())	// If no other instance is currently taking care of system encryption
			{
				WaitCursor ();

				ForceRemoveSysEnc();

				InconsistencyResolved (SRC_POS);

				NormalCursor();
				CloseSysEncMutex ();
			}
		}
	}

	if (bDirectSysEncMode && CreateSysEncMutex ())
	{
		// We were launched either by Mount or by the system (startup sequence). Most of such cases should have 
		// been handled above already. Here we handle only the pretest phase (which can also be the hidden OS 
		// creation/cloning phase actually) and possible inconsistencies.

		switch (SystemEncryptionStatus)
		{
		case SYSENC_STATUS_PRETEST:
			{
				unsigned int hiddenOSCreationPhase = DetermineHiddenOSCreationPhase();

				bHiddenOS = (hiddenOSCreationPhase != TC_HIDDEN_OS_CREATION_PHASE_NONE);

				// Evaluate the results of the system encryption pretest (or of the hidden OS creation/cloning process)

				try
				{
					BootEncStatus = BootEncObj->GetStatus();
				}
				catch (Exception &e)
				{
					e.Show (hwndDlg);
					Error ("ERR_GETTING_SYSTEM_ENCRYPTION_STATUS");
					EndMainDlg (MainDlg);
					return;
				}

				if (BootEncStatus.DriveMounted)
				{
					/* Pretest (or hidden OS cloning) successful.
					Another possibility is that the hidden OS has been booted for the first time. */

					switch (hiddenOSCreationPhase)
					{
					case TC_HIDDEN_OS_CREATION_PHASE_NONE:

						// Pretest successful (no hidden operating system involved)

						if (IsHiddenOSRunning())
						{
							// The hidden OS has been booted for the first time

							Info ("FIRST_HIDDEN_OS_BOOT_INFO");

							ManageStartupSeqWiz (TRUE, "");
							ChangeSystemEncryptionStatus (SYSENC_STATUS_NONE);

							EndMainDlg (MainDlg);
							return;
						}

						LoadPage (hwndDlg, SYSENC_PRETEST_RESULT_PAGE);
						break; 

					case TC_HIDDEN_OS_CREATION_PHASE_DECOY_OS:

						// Hidden OS successfully created by cloning. Now we are supposed to encrypt the decoy OS.

						LoadPage (hwndDlg, SYSENC_PRETEST_RESULT_PAGE);
						break; 

					default:

						// Unexpected/unknown status -- "fix" the inconsistency

						if (ChangeSystemEncryptionStatus (SYSENC_STATUS_NONE))
						{
							ManageStartupSeqWiz (TRUE, "");

							// Remove our boot loader and restore the original one (if available)

							WaitCursor ();

							ForceRemoveSysEnc();

							NormalCursor();
							CloseSysEncMutex ();
						}
						EndMainDlg (MainDlg);
						InconsistencyResolved (SRC_POS);
						return;
					}
				}
				else
				{
					BOOL bAnswerTerminate = FALSE, bAnswerRetry = FALSE;

					/* Pretest failed (or hidden OS cloning was not finished) */


					if (hiddenOSCreationPhase == TC_HIDDEN_OS_CREATION_PHASE_NONE)
					{
						// Pretest failed (no hidden operating system involved)

						if (AskWarnYesNo ("BOOT_PRETEST_FAILED_RETRY") == IDYES)
						{
							// User wants to retry the pretest
							bAnswerTerminate = FALSE;
							bAnswerRetry = TRUE;
						}
						else
						{
							// User doesn't want to retry the pretest
							bAnswerTerminate = TRUE;
							bAnswerRetry = FALSE;
						}
					}
					else
					{
						// Hidden OS cloning was interrupted (or finished but decoy OS password was not entered).

						char *tmpStr[] = {0,
							hiddenOSCreationPhase == TC_HIDDEN_OS_CREATION_PHASE_DECOY_OS ? "RESTART_AND_ENTER_DECOY_OS_PASSWORD" : "OS_CLONING_NOT_FINISHED_ASK",
							"OS_CLONING_NOT_FINISHED_CHOICE_RETRY",
							"OS_CLONING_NOT_FINISHED_CHOICE_TERMINATE",
							"OS_CLONING_NOT_FINISHED_CHOICE_ASK_LATER",
							0};

						switch (AskMultiChoice ((void **) tmpStr))
						{
						case 1:
							// User wants to restart and continue OS cloning (or enter decoy OS password)
							bAnswerTerminate = FALSE;
							bAnswerRetry = TRUE;
							break;

						case 2:
							// User doesn't want to retry but wants to terminate the entire process of hidden OS creation
							bAnswerTerminate = TRUE;
							bAnswerRetry = FALSE;
							break;

						default:
							// User doesn't want to do anything now
							bAnswerTerminate = FALSE;
							bAnswerRetry = FALSE;
						}
					}


					if (bAnswerRetry)
					{
						// User wants to restart and retry the pretest (or continue OS cloning or enter decoy OS password)

						// We re-register the driver for boot because the user may have selected
						// "Last Known Good Configuration" from the Windows boot menu.
						RegisterBootDriver ();

						if (AskWarnYesNo ("CONFIRM_RESTART") == IDYES)
						{
							EndMainDlg (MainDlg);

							try
							{
								BootEncObj->RestartComputer ();
							}
							catch (Exception &e)
							{
								e.Show (hwndDlg);
							}

							return;
						}

						EndMainDlg (MainDlg);
						return;
					}
					else if (bAnswerTerminate)
					{
						// User doesn't want to retry pretest (or OS cloning), but to terminate the entire process

						try
						{
							BootEncObj->Deinstall ();
						}
						catch (Exception &e)
						{
							e.Show (hwndDlg);
						}

						ManageStartupSeqWiz (TRUE, "");
						ChangeSystemEncryptionStatus (SYSENC_STATUS_NONE);
						EndMainDlg (MainDlg);
						return;
					}
					else 
					{
						// User doesn't want to take any action now

						AbortProcessSilent();
					}
				}
			}
			break;

		default:

			// Unexpected progress status -- fix the inconsistency

			ManageStartupSeqWiz (TRUE, "");
			ChangeSystemEncryptionStatus (SYSENC_STATUS_NONE);
			EndMainDlg (MainDlg);
			InconsistencyResolved (SRC_POS);
			return;
		}
	}
	else
	{
		if (DirectDeviceEncMode)
		{
			SwitchWizardToNonSysDeviceMode();
			return;
		}

		LoadPage (hwndDlg, INTRO_PAGE);
	}
}

int WINAPI WINMAIN (HINSTANCE hInstance, HINSTANCE hPrevInstance, char *lpszCommandLine, int nCmdShow)
{
	int status;
	atexit (localcleanup);

	VirtualLock (&volumePassword, sizeof(volumePassword));
	VirtualLock (szVerify, sizeof(szVerify));
	VirtualLock (szRawPassword, sizeof(szRawPassword));

	VirtualLock (MasterKeyGUIView, sizeof(MasterKeyGUIView));
	VirtualLock (HeaderKeyGUIView, sizeof(HeaderKeyGUIView));

	VirtualLock (randPool, sizeof(randPool));
	VirtualLock (lastRandPool, sizeof(lastRandPool));
	VirtualLock (outRandPoolDispBuffer, sizeof(outRandPoolDispBuffer));

	VirtualLock (&szFileName, sizeof(szFileName));
	VirtualLock (&szDiskFile, sizeof(szDiskFile));

	try
	{
		BootEncObj = new BootEncryption (NULL);
	}
	catch (Exception &e)
	{
		e.Show (NULL);
	}

	if (BootEncObj == NULL)
		AbortProcess ("INIT_SYS_ENC");

	InitCommonControls ();
	InitApp (hInstance, lpszCommandLine);

	nPbar = IDC_PROGRESS_BAR;

	if (Randinit ())
		AbortProcess ("INIT_RAND");

	RegisterRedTick(hInstance);

	/* Allocate, dup, then store away the application title */
	lpszTitle = GetString ("IDD_VOL_CREATION_WIZARD_DLG");

	status = DriverAttach ();
	if (status != 0)
	{
		if (status == ERR_OS_ERROR)
			handleWin32Error (NULL);
		else
			handleError (NULL, status);

		AbortProcess ("NODRIVER");
	}

	if (!AutoTestAlgorithms())
		AbortProcess ("ERR_SELF_TESTS_FAILED");

	/* Create the main dialog box */
	DialogBoxParamW (hInstance, MAKEINTRESOURCEW (IDD_VOL_CREATION_WIZARD_DLG), NULL, (DLGPROC) MainDialogProc, 
		(LPARAM)lpszCommandLine);

	return 0;
}
