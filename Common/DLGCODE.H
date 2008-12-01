/*
 Legal Notice: Some portions of the source code contained in this file were
 derived from the source code of Encryption for the Masses 2.02a, which is
 Copyright (c) 1998-2000 Paul Le Roux and which is governed by the 'License
 Agreement for Encryption for the Masses'. Modifications and additions to
 the original source code (contained in this file) and all other portions of
 this file are Copyright (c) 2003-2008 TrueCrypt Foundation and are governed
 by the TrueCrypt License 2.6 the full text of which is contained in the
 file License.txt included in TrueCrypt binary and source code distribution
 packages. */

#ifndef TC_HEADER_DLGCODE
#define TC_HEADER_DLGCODE

#include "Common.h"
#include "Apidrvr.h"
#include "Keyfiles.h"
#include "Wipe.h"

#ifdef __cplusplus
extern "C" {
#endif


/* IDs for dynamically generated GUI elements */
enum dynamic_gui_element_ids
{
	IDPM_CHECK_FILESYS = 500001,
	IDPM_REPAIR_FILESYS,
	IDPM_OPEN_VOLUME,
	IDPM_SELECT_FILE_AND_MOUNT,
	IDPM_SELECT_DEVICE_AND_MOUNT,
	IDM_SHOW_HIDE,
	IDM_HOMEPAGE_SYSTRAY
};

enum
{
	TC_TBXID_LEGAL_NOTICES,
	TC_TBXID_SYS_ENCRYPTION_PRETEST,
	TC_TBXID_SYS_ENC_RESCUE_DISK,
	TC_TBXID_DECOY_OS_INSTRUCTIONS
};

#define TC_MUTEX_NAME_SYSENC				"Global\\TrueCrypt System Encryption Wizard"
#define TC_MUTEX_NAME_NONSYS_INPLACE_ENC	"Global\\TrueCrypt In-Place Encryption Wizard"
#define TC_MUTEX_NAME_APP_SETUP				"Global\\TrueCrypt Setup"
#define TC_MUTEX_NAME_DRIVER_SETUP			"Global\\TrueCrypt Driver Setup"

#define IDC_ABOUT 0x7fff	/* ID for AboutBox on system menu in wm_user range */

#define EXCL_ACCESS_MAX_AUTO_RETRIES 500
#define EXCL_ACCESS_AUTO_RETRY_DELAY 10

#define UNMOUNT_MAX_AUTO_RETRIES 10
#define UNMOUNT_AUTO_RETRY_DELAY 50

// After the user receives the "Incorrect password" error this number of times in a row, we should automatically
// try using the embedded header backup (if any). This ensures that the "Incorrect password" message is reported faster
// initially (most such errors are really caused by supplying an incorrect password, not by header corruption).
#define TC_TRY_HEADER_BAK_AFTER_NBR_WRONG_PWD_TRIES		2

#define MAX_MULTI_CHOICES		10		/* Maximum number of options for mutliple-choice dialog */

#define TC_APPD_FILENAME_CONFIGURATION						"Configuration.xml"
#define TC_APPD_FILENAME_SYSTEM_ENCRYPTION					"System Encryption.xml"
#define TC_APPD_FILENAME_DEFAULT_KEYFILES					"Default Keyfiles.xml"
#define TC_APPD_FILENAME_HISTORY							"History.xml"
#define TC_APPD_FILENAME_FAVORITE_VOLUMES					"Favorite Volumes.xml"
#define TC_APPD_FILENAME_NONSYS_INPLACE_ENC					"In-Place Encryption"
#define TC_APPD_FILENAME_NONSYS_INPLACE_ENC_WIPE			"In-Place Encryption Wipe Algo"
#define TC_APPD_FILENAME_POST_INSTALL_TASK_TUTORIAL			"Post-Install Task - Tutorial"
#define TC_APPD_FILENAME_POST_INSTALL_TASK_RELEASE_NOTES	"Post-Install Task - Release Notes"

#ifndef USER_DEFAULT_SCREEN_DPI
#define USER_DEFAULT_SCREEN_DPI 96
#endif

#if (USER_DEFAULT_SCREEN_DPI != 96)
#error Revision of GUI and graphics necessary, since everything assumes default screen DPI as 96 (note that 96 is the default on Windows 2000, XP, and Vista).
#endif

enum
{
	TC_POST_INSTALL_CFG_REMOVE_ALL = 0,
	TC_POST_INSTALL_CFG_TUTORIAL,
	TC_POST_INSTALL_CFG_RELEASE_NOTES
};

extern char *LastDialogId;
extern char *ConfigBuffer;
extern char szHelpFile[TC_MAX_PATH];
extern char szHelpFile2[TC_MAX_PATH];
extern char SecurityTokenLibraryPath[TC_MAX_PATH];
extern HFONT hFixedDigitFont;
extern HFONT hBoldFont;
extern HFONT hTitleFont;
extern HFONT hFixedFont;
extern HFONT hUserFont;
extern HFONT hUserUnderlineFont;
extern HFONT hUserBoldFont;
extern int ScreenDPI;
extern double DlgAspectRatio;
extern HWND MainDlg;
extern BOOL Silent;
extern BOOL bHistory;
extern BOOL bPreserveTimestamp;
extern BOOL bStartOnLogon;
extern BOOL bMountDevicesOnLogon;
extern BOOL bMountFavoritesOnLogon;
extern int HiddenSectorDetectionStatus;
extern wchar_t *lpszTitle;
extern int nCurrentOS;
extern int CurrentOSMajor;
extern int CurrentOSMinor;
extern BOOL RemoteSession;
extern HANDLE hDriver;
extern HINSTANCE hInst;
extern int SystemEncryptionStatus;	
extern WipeAlgorithmId nWipeMode;
extern BOOL bSysPartitionSelected;
extern BOOL bSysDriveSelected;

extern BOOL bHyperLinkBeingTracked;
extern BOOL bInPlaceEncNonSysPending;

extern BOOL	KeyFilesEnable;
extern KeyFile	*FirstKeyFile;
extern KeyFilesDlgParam		defaultKeyFilesParam;
extern BOOL UacElevated;
extern BOOL IgnoreWmDeviceChange;

enum 
{
	WIN_UNKNOWN = 0,
	WIN_31,
	WIN_95,
	WIN_98,
	WIN_ME,
	WIN_NT3,
	WIN_NT4,
	WIN_2000,
	WIN_XP,
	WIN_XP64,
	WIN_SERVER_2003,
	WIN_VISTA,
	WIN_SERVER_2008,
	WIN_VISTA_OR_LATER
};

enum tc_app_msg_ids
{
	/* WARNING: Changing these values or their meanings may cause incompatibility with other versions
	(for example, if a new version of the TrueCrypt installer needed to shut down this version of
	TrueCrypt during upgrade, it could fail or do something unwanted because the signal value would
	be incorrect). When adding a new constant, verify that the value is unique within this block and
	that it is less than WM_APP+16383. */

	// Common (inter-app)
	TC_APPMSG_CLOSE_BKG_TASK =						WM_APP + 4,	// Changing this value will prevent smooth upgrades from pre-5.x versions
	TC_APPMSG_SYSENC_CONFIG_UPDATE =				WM_APP + 101,
	TC_APPMSG_TASKBAR_ICON =						WM_APP + 102,
	TC_APPMSG_LOAD_TEXT_BOX_CONTENT =				WM_APP + 103,
	// Mount									
	TC_APPMSG_MOUNT_ENABLE_DISABLE_CONTROLS =		WM_APP + 201,
	TC_APPMSG_MOUNT_SHOW_WINDOW =					WM_APP + 202,
	TC_APPMSG_PREBOOT_PASSWORD_MODE =				WM_APP + 203,
	TC_APPMSG_VOLUMES_DISMOUNTED_ON_POWER =			WM_APP + 204,
	// Format									
	TC_APPMSG_VOL_TRANSFORM_THREAD_ENDED =			WM_APP + 301,
	TC_APPMSG_FORMAT_FINISHED =						WM_APP + 302,
	TC_APPMSG_FORMAT_USER_QUIT =					WM_APP + 303,
	TC_APPMSG_PERFORM_POST_WMINIT_TASKS =			WM_APP + 304,
	TC_APPMSG_PERFORM_POST_SYSENC_WMINIT_TASKS =	WM_APP + 305,
	TC_APPMSG_NONSYS_INPLACE_ENC_FINISHED =			WM_APP + 306,
	// Setup
	TC_APPMSG_INSTALL_SUCCESS =						WM_APP + 401,
	TC_APPMSG_UNINSTALL_SUCCESS =					WM_APP + 402,
	TC_APPMSG_EXTRACTION_SUCCESS =					WM_APP + 403,
	TC_APPMSG_INSTALL_FAILURE =						WM_APP + 404,
	TC_APPMSG_UNINSTALL_FAILURE =					WM_APP + 405,
	TC_APPMSG_EXTRACTION_FAILURE =					WM_APP + 406
};

enum system_encryption_status
{
	/* WARNING: As these values are written to config files, if they or their meanings
	are changed, incompatiblity with other versions may arise (upgrade, downgrade, etc.).
	When adding a new constant, verify that the value is unique within this block. */
	SYSENC_STATUS_NONE = 0,
	SYSENC_STATUS_PRETEST = 200,	// This may also mean that the OS is to be (or has been) copied to a hidden volume (to create a hidden OS).
	SYSENC_STATUS_ENCRYPTING = 400,
	SYSENC_STATUS_DECRYPTING = 600
};

enum vol_creation_wizard_modes
{
	WIZARD_MODE_FILE_CONTAINER = 0,
	WIZARD_MODE_NONSYS_DEVICE,
	WIZARD_MODE_SYS_DEVICE
};


typedef struct
{
	BOOL VolumeIsOpen;

	CRYPTO_INFO *CryptoInfo;
	BOOL IsDevice;
	HANDLE HostFileHandle;
	uint64 HostSize;

	BOOL TimestampsValid;
	FILETIME CreationTime;
	FILETIME LastWriteTime;
	FILETIME LastAccessTime;

} OpenVolumeContext;


#define DEFAULT_VOL_CREATION_WIZARD_MODE	WIZARD_MODE_FILE_CONTAINER

#define ICON_HAND MB_ICONHAND
#define YES_NO MB_YESNO

#ifdef _UNICODE
#define WINMAIN wWinMain
#else
#define WINMAIN WinMain
#endif

#define PRINT_TOOL "notepad"

void cleanup ( void );
void LowerCaseCopy ( char *lpszDest , const char *lpszSource );
void UpperCaseCopy ( char *lpszDest , const char *lpszSource );
void CreateFullVolumePath ( char *lpszDiskFile , const char *lpszFileName , BOOL *bDevice );
int FakeDosNameForDevice ( const char *lpszDiskFile , char *lpszDosDevice , char *lpszCFDevice , BOOL bNameOnly );
int RemoveFakeDosName ( char *lpszDiskFile , char *lpszDosDevice );
void AbortProcess ( char *stringId );
void AbortProcessSilent ( void );
void *err_malloc ( size_t size );
char *err_strdup ( char *lpszText );
DWORD handleWin32Error ( HWND hwndDlg );
BOOL translateWin32Error ( wchar_t *lpszMsgBuf , int nWSizeOfBuf );
BOOL CALLBACK AboutDlgProc ( HWND hwndDlg , UINT msg , WPARAM wParam , LPARAM lParam );
BOOL IsButtonChecked ( HWND hButton );
void CheckButton ( HWND hButton );
void LeftPadString (char *szTmp, int len, int targetLen, char filler);
void ToSBCS ( LPWSTR lpszText );
void ToUNICODE ( char *lpszText );
void InitDialog ( HWND hwndDlg );
HDC CreateMemBitmap ( HINSTANCE hInstance , HWND hwnd , char *resource );
HBITMAP RenderBitmap ( char *resource , HWND hwndDest , int x , int y , int nWidth , int nHeight , BOOL bDirectRender , BOOL bKeepAspectRatio);
LRESULT CALLBACK RedTick ( HWND hwnd , UINT uMsg , WPARAM wParam , LPARAM lParam );
BOOL RegisterRedTick ( HINSTANCE hInstance );
BOOL UnregisterRedTick ( HINSTANCE hInstance );
LRESULT CALLBACK SplashDlgProc ( HWND hwnd , UINT uMsg , WPARAM wParam , LPARAM lParam );
void WaitCursor ( void );
void NormalCursor ( void );
void ArrowWaitCursor ( void );
void HandCursor ();
void AddComboPair (HWND hComboBox, const char *lpszItem, int value);
void AddComboPairW (HWND hComboBox, const wchar_t *lpszItem, int value);
void SelectAlgo ( HWND hComboBox , int *nCipher );
void PopulateWipeModeCombo (HWND hComboBox, BOOL bNA, BOOL bInPlaceEncryption);
wchar_t *GetWipeModeName (WipeAlgorithmId modeId);
wchar_t *GetPathType (const char *path, BOOL bUpperCase, BOOL *bIsPartition);
LRESULT CALLBACK CustomDlgProc ( HWND hwnd , UINT uMsg , WPARAM wParam , LPARAM lParam );
BOOL TCCreateMutex (volatile HANDLE *hMutex, char *name);
void TCCloseMutex (volatile HANDLE *hMutex);
BOOL MutexExistsOnSystem (char *name);
BOOL CreateSysEncMutex (void);
BOOL InstanceHasSysEncMutex (void);
void CloseSysEncMutex (void);
BOOL CreateNonSysInplaceEncMutex (void);
BOOL InstanceHasNonSysInplaceEncMutex (void);
void CloseNonSysInplaceEncMutex (void);
BOOL NonSysInplaceEncInProgressElsewhere (void);
BOOL CreateDriverSetupMutex (void);
void CloseDriverSetupMutex (void);
BOOL CreateAppSetupMutex (void);
BOOL InstanceHasAppSetupMutex (void);
void CloseAppSetupMutex (void);
BOOL IsTrueCryptInstallerRunning (void);
BOOL LoadSysEncSettings (HWND hwndDlg);
int LoadNonSysInPlaceEncSettings (WipeAlgorithmId *wipeAlgorithm);
void SavePostInstallTasksSettings (int command);
void DoPostInstallTasks (void);
BOOL SysEncryptionOrDecryptionRequired (void);
void InitApp ( HINSTANCE hInstance, char *lpszCommandLine );
void InitHelpFileName (void);
BOOL OpenDevice (const char *lpszPath, OPEN_TEST_STRUCT *driver);
void NotifyDriverOfTravelerMode (void);
int GetAvailableFixedDisks ( HWND hComboBox , char *lpszRootPath );
int GetAvailableRemovables ( HWND hComboBox , char *lpszRootPath );
int IsSystemDevicePath (char *path, HWND hwndDlg, BOOL bReliableRequired);
BOOL CALLBACK RawDevicesDlgProc ( HWND hwndDlg , UINT msg , WPARAM wParam , LPARAM lParam );
BOOL TextInfoDialogBox (int nID);
BOOL CALLBACK TextInfoDialogBoxDlgProc (HWND hwndDlg, UINT msg, WPARAM wParam, LPARAM lParam);
char * GetLegalNotices ();
BOOL CALLBACK BenchmarkDlgProc (HWND hwndDlg, UINT msg, WPARAM wParam, LPARAM lParam);
BOOL CALLBACK KeyfileGeneratorDlgProc (HWND hwndDlg, UINT msg, WPARAM wParam, LPARAM lParam);
BOOL CALLBACK MultiChoiceDialogProc (HWND hwndDlg, UINT uMsg, WPARAM wParam, LPARAM lParam);
int DriverAttach ( void );
BOOL CALLBACK CipherTestDialogProc ( HWND hwndDlg , UINT uMsg , WPARAM wParam , LPARAM lParam );
void ResetCipherTest ( HWND hwndDlg , int idTestCipher );
BOOL BrowseFiles (HWND hwndDlg, char *stringId, char *lpszFileName, BOOL keepHistory, BOOL saveMode, wchar_t *browseFilter);
BOOL BrowseFilesInDir (HWND hwndDlg, char *stringId, char *initialDir, char *lpszFileName, BOOL keepHistory, BOOL saveMode, wchar_t *browseFilter);
BOOL BrowseDirectories (HWND hWnd, char *lpszTitle, char *dirName);
void handleError ( HWND hwndDlg , int code );
void LocalizeDialog ( HWND hwnd, char *stringId );
void OpenVolumeExplorerWindow (int driveNo);
static BOOL CALLBACK CloseVolumeExplorerWindowsEnum( HWND hwnd, LPARAM driveNo);
BOOL CloseVolumeExplorerWindows (HWND hwnd, int driveNo);
BOOL CheckCapsLock (HWND hwnd, BOOL quiet);
BOOL CheckFileExtension (char *fileName);
void IncreaseWrongPwdRetryCount (int count);
void ResetWrongPwdRetryCount (void);
BOOL WrongPwdRetryCountOverLimit (void);
int GetFirstAvailableDrive ();
int GetLastAvailableDrive ();
BOOL IsDriveAvailable (int driveNo);
BOOL IsDeviceMounted (char *deviceName);
int DriverUnmountVolume (HWND hwndDlg, int nDosDriveNo, BOOL forced);
void BroadcastDeviceChange (WPARAM message, int nDosDriveNo, DWORD driveMap);
int MountVolume (HWND hwndDlg, int driveNo, char *volumePath, Password *password, BOOL cachePassword, BOOL sharedAccess, MountOptions *mountOptions, BOOL quiet, BOOL bReportWrongPassword);
BOOL UnmountVolume (HWND hwndDlg , int nDosDriveNo, BOOL forceUnmount);
BOOL IsPasswordCacheEmpty (void);
BOOL IsMountedVolume (const char *volname);
int GetMountedVolumeDriveNo (char *volname);
BOOL IsAdmin (void);
BOOL IsUacSupported ();
BOOL ResolveSymbolicLink (PWSTR symLinkName, PWSTR targetName);
int GetDiskDeviceDriveLetter (PWSTR deviceName);
int FileSystemAppearsEmpty (const char *devicePath);
__int64 GetStatsFreeSpaceOnPartition (const char *devicePath, float *percent, __int64 *occupiedBytes, BOOL silent);
__int64 GetDeviceSize (const char *devicePath);
HANDLE DismountDrive (char *devName, char *devicePath);
int64 FindString (const char *buf, const char *str, int64 bufLen, size_t strLen, int64 startOffset);
BOOL FileExists (const char *filePathPtr);
__int64 FindStringInFile (const char *filePath, const char *str, int strLen);
BOOL TCCopyFile (char *sourceFileName, char *destinationFile);
BOOL SaveBufferToFile (char *inputBuffer, char *destinationFile, DWORD inputLength, BOOL bAppend);
BOOL TCFlushFile (FILE *f);
BOOL PrintHardCopyTextUTF16 (wchar_t *text, char *title, int byteLen);
void GetSpeedString (unsigned __int64 speed, wchar_t *str);
BOOL IsNonInstallMode ();
BOOL DriverUnload ();
LRESULT SetCheckBox (HWND hwndDlg, int dlgItem, BOOL state);
BOOL GetCheckBox (HWND hwndDlg, int dlgItem);
void ManageStartupSeq (void);
void CleanLastVisitedMRU (void);
void ClearHistory (HWND hwndDlgItem);
LRESULT ListItemAdd (HWND list, int index, char *string);
LRESULT ListItemAddW (HWND list, int index, wchar_t *string);
LRESULT ListSubItemSet (HWND list, int index, int subIndex, char *string);
LRESULT ListSubItemSetW (HWND list, int index, int subIndex, wchar_t *string);
BOOL GetMountList (MOUNT_LIST_STRUCT *list);
int GetDriverRefCount ();
void GetSizeString (unsigned __int64 size, wchar_t *str);
__int64 GetFileSize64 (const char *path);
BOOL LoadInt16 (char *filePath, int *result, __int64 fileOffset);
BOOL LoadInt32 (char *filePath, unsigned __int32 *result, __int64 fileOffset);
char *LoadFile (const char *fileName, DWORD *size);
char *LoadFileBlock (char *fileName, __int64 fileOffset, int count);
char *GetModPath (char *path, int maxSize);
char *GetConfigPath (char *fileName);
char GetSystemDriveLetter (void);
void OpenPageHelp (HWND hwndDlg, int nPage);
int Info (char *stringId);
int InfoTopMost (char *stringId);
int InfoDirect (const wchar_t *msg);
int Warning (char *stringId);
int WarningTopMost (char *stringId);
int WarningDirect (const wchar_t *warnMsg);
int Error (char *stringId);
int ErrorDirect (const wchar_t *errMsg);
int ErrorTopMost (char *stringId);
int AskYesNo (char *stringId);
int AskNoYes (char *stringId);
int AskOkCancel (char *stringId);
int AskWarnYesNo (char *stringId);
int AskWarnNoYes (char *stringId);
int AskWarnNoYesString (wchar_t *string);
int AskWarnYesNoString (wchar_t *string);
int AskWarnOkCancel (char *stringId);
int AskWarnCancelOk (char *stringId);
int AskErrYesNo (char *stringId);
int AskErrNoYes (char *stringId);
int AskMultiChoice (void *strings[], BOOL bBold);
BOOL ConfigWriteBegin ();
BOOL ConfigWriteEnd ();
BOOL ConfigWriteString (char *configKey, char *configValue);
BOOL ConfigWriteInt (char *configKey, int configValue);
int ConfigReadInt (char *configKey, int defaultValue);
char *ConfigReadString (char *configKey, char *defaultValue, char *str, int maxLen);
void RestoreDefaultKeyFilesParam (void);
BOOL LoadDefaultKeyFilesParam (void);
void Debug (char *format, ...);
void DebugMsgBox (char *format, ...);
BOOL Is64BitOs ();
BOOL IsHiddenOSRunning (void);
BOOL RestartComputer (void);
void Applink (char *dest, BOOL bSendOS, char *extraOutput);
char *RelativePath2Absolute (char *szFileName);
void CheckSystemAutoMount ();
BOOL CALLBACK CloseTCWindowsEnum( HWND hwnd, LPARAM lParam);
BOOL CALLBACK FindTCWindowEnum (HWND hwnd, LPARAM lParam);
BYTE *MapResource (char *resourceType, int resourceId, PDWORD size);
void InconsistencyResolved (char *msg);
void ReportUnexpectedState (char *techInfo);
BOOL SelectMultipleFiles (HWND hwndDlg, char *stringId, char *lpszFileName, BOOL keepHistory);
BOOL SelectMultipleFilesNext (char *lpszFileName);
void OpenOnlineHelp ();
BOOL GetPartitionInfo (const char *deviceName, PPARTITION_INFORMATION rpartInfo);
BOOL GetDeviceInfo (const char *deviceName, DISK_PARTITION_INFO_STRUCT *info);
BOOL GetDriveGeometry (const char *deviceName, PDISK_GEOMETRY diskGeometry);
BOOL IsVolumeDeviceHosted (char *lpszDiskFile);
int CompensateXDPI (int val);
int CompensateYDPI (int val);
int CompensateDPIFont (int val);
int GetTextGfxWidth (HWND hwndDlgItem, wchar_t *text, HFONT hFont);
int GetTextGfxHeight (HWND hwndDlgItem, wchar_t *text, HFONT hFont);
BOOL ToHyperlink (HWND hwndDlg, UINT ctrlId);
void ToBootPwdField (HWND hwndDlg, UINT ctrlId);
void AccommodateTextField (HWND hwndDlg, UINT ctrlId, BOOL bFirstUpdate);
BOOL GetDriveLabel (int driveNo, wchar_t *label, int labelSize);
BOOL DoDriverInstall (HWND hwndDlg);
int OpenVolume (OpenVolumeContext *context, const char *volumePath, Password *password, BOOL write, BOOL preserveTimestamps, BOOL useBackupHeader);
void CloseVolume (OpenVolumeContext *context);
int ReEncryptVolumeHeader (char *buffer, BOOL bBoot, CRYPTO_INFO *cryptoInfo, Password *password, BOOL wipeMode);
BOOL IsPagingFileActive (BOOL checkNonWindowsPartitionsOnly);
BOOL DisablePagingFile ();
BOOL CALLBACK SecurityTokenPasswordDlgProc (HWND hwndDlg, UINT msg, WPARAM wParam, LPARAM lParam);
BOOL CALLBACK SecurityTokenKeyfileDlgProc (HWND hwndDlg, UINT msg, WPARAM wParam, LPARAM lParam);
BOOL InitSecurityTokenLibrary ();
BOOL FileHasReadOnlyAttribute (const char *path);
BOOL IsFileOnReadOnlyFilesystem (const char *path);
void CheckFilesystem (int driveNo, BOOL fixErrors);

#ifdef __cplusplus
}

#include <vector>
#include <string>

struct HostDevice
{
	HostDevice ()
		:
		ContainsSystem (false),
		DynamicVolume (false),
		Floppy (false),
		IsPartition (false),
		IsVirtualPartition (false),
		Removable (false),
		Size (0)
	{
	}

	~HostDevice () { }

	bool ContainsSystem;
	bool DynamicVolume;
	bool Floppy;
	bool IsPartition;
	bool IsVirtualPartition;
	std::string MountPoint;
	std::wstring Name;
	std::string Path;
	bool Removable;
	uint64 Size;
	uint32 SystemNumber;

	std::vector <HostDevice> Partitions;
};

std::wstring SingleStringToWide (const std::string &singleString);
std::wstring Utf8StringToWide (const std::string &utf8String);
std::string WideToSingleString (const std::wstring &wideString);
std::string WideToUtf8String (const std::wstring &wideString);
std::vector <HostDevice> GetAvailableHostDevices (bool noDeviceProperties = false, bool singleList = false, bool noFloppy = true);
std::string ToUpperCase (const std::string &str);

#endif // __cplusplus

#endif // TC_HEADER_DLGCODE
