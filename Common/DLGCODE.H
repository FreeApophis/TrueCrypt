/* Legal Notice: The source code contained in this file has been derived from
   the source code of Encryption for the Masses 2.02a, which is Copyright (c)
   1998-99 Paul Le Roux and which is covered by the 'License Agreement for
   Encryption for the Masses'. Modifications and additions to that source code
   contained in this file are Copyright (c) 2004-2006 TrueCrypt Foundation and
   Copyright (c) 2004 TrueCrypt Team, and are covered by TrueCrypt License 2.0
   the full text of which is contained in the file License.txt included in
   TrueCrypt binary and source code distribution archives.  */

#include "Common.h"
#include "Apidrvr.h"
#include "Keyfiles.h"

/* IDs for dynamically generated GUI elements */
#define IDPM_CHECK_FILESYS		500001
#define IDPM_REPAIR_FILESYS		500002
#define	IDPM_OPEN_VOLUME		500003
#define IDM_SHOW_HIDE			500004

#define IDC_ABOUT 0x7fff	/* ID for AboutBox on system menu in wm_user range */

#define UNMOUNT_MAX_AUTO_RETRIES 5
#define UNMOUNT_AUTO_RETRY_DELAY 50

#define FILE_DEFAULT_KEYFILES		"Default Keyfiles.xml"

extern char szHelpFile[TC_MAX_PATH];
extern char szHelpFile2[TC_MAX_PATH];
extern HFONT hFixedDigitFont;
extern HFONT hBoldFont;
extern HFONT hTitleFont;
extern HFONT hFixedFont;
extern HFONT hUserFont;
extern HFONT hUserUnderlineFont;
extern HFONT hUserBoldFont;
extern HWND MainDlg;
extern BOOL Silent;
extern BOOL bPreserveTimestamp;
extern wchar_t *lpszTitle;
extern int nCurrentOS;
extern int CurrentOSMajor;
extern int CurrentOSMinor;
extern HANDLE hDriver;
extern HINSTANCE hInst;

extern BOOL	KeyFilesEnable;
extern KeyFile	*FirstKeyFile;
extern KeyFilesDlgParam		defaultKeyFilesParam;

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
	WIN_XP64_OR_2003,
	WIN_VISTA,
	WIN_AFTER_VISTA
};

#define ICON_HAND MB_ICONHAND
#define YES_NO MB_YESNO

#ifdef _UNICODE
#define WINMAIN wWinMain
#else
#define WINMAIN WinMain
#endif

#define FILE_CONFIGURATION	"Configuration.xml"

void cleanup ( void );
void LowerCaseCopy ( char *lpszDest , char *lpszSource );
void UpperCaseCopy ( char *lpszDest , char *lpszSource );
void CreateFullVolumePath ( char *lpszDiskFile , char *lpszFileName , BOOL *bDevice );
int FakeDosNameForDevice ( char *lpszDiskFile , char *lpszDosDevice , char *lpszCFDevice , BOOL bNameOnly );
int RemoveFakeDosName ( char *lpszDiskFile , char *lpszDosDevice );
void AbortProcess ( char *stringId );
void AbortProcessSilent ( void );
void *err_malloc ( size_t size );
char *err_strdup ( char *lpszText );
DWORD handleWin32Error ( HWND hwndDlg );
BOOL translateWin32Error ( wchar_t *lpszMsgBuf , int nSizeOfBuf );
BOOL WINAPI AboutDlgProc ( HWND hwndDlg , UINT msg , WPARAM wParam , LPARAM lParam );
BOOL IsButtonChecked ( HWND hButton );
void CheckButton ( HWND hButton );
void ToSBCS ( LPWSTR lpszText );
void ToUNICODE ( char *lpszText );
void InitDialog ( HWND hwndDlg );
HDC CreateMemBitmap ( HINSTANCE hInstance , HWND hwnd , char *resource );
void PaintBitmap ( HDC pdcMem , int x , int y , int nWidth , int nHeight , HDC hDC );
LRESULT CALLBACK RedTick ( HWND hwnd , UINT uMsg , WPARAM wParam , LPARAM lParam );
BOOL RegisterRedTick ( HINSTANCE hInstance );
BOOL UnregisterRedTick ( HINSTANCE hInstance );
LRESULT CALLBACK SplashDlgProc ( HWND hwnd , UINT uMsg , WPARAM wParam , LPARAM lParam );
void WaitCursor ( void );
void NormalCursor ( void );
void ArrowWaitCursor ( void );
void AddComboPair (HWND hComboBox, char *lpszItem, int value);
void AddComboPairW (HWND hComboBox, wchar_t *lpszItem, int value);
void SelectAlgo ( HWND hComboBox , int *nCipher );
LRESULT CALLBACK CustomDlgProc ( HWND hwnd , UINT uMsg , WPARAM wParam , LPARAM lParam );
void InitApp ( HINSTANCE hInstance );
void InitHelpFileName (void);
BOOL OpenDevice ( char *lpszPath , OPEN_TEST_STRUCT *driver );
int GetAvailableFixedDisks ( HWND hComboBox , char *lpszRootPath );
int GetAvailableRemovables ( HWND hComboBox , char *lpszRootPath );
BOOL WINAPI RawDevicesDlgProc ( HWND hwndDlg , UINT msg , WPARAM wParam , LPARAM lParam );
BOOL WINAPI LegalNoticesDlgProc (HWND hwndDlg, UINT msg, WPARAM wParam, LPARAM lParam);
char * GetLegalNotices ();
BOOL WINAPI BenchmarkDlgProc (HWND hwndDlg, UINT msg, WPARAM wParam, LPARAM lParam);
BOOL WINAPI KeyfileGeneratorDlgProc (HWND hwndDlg, UINT msg, WPARAM wParam, LPARAM lParam);
int DriverAttach ( void );
BOOL SeekHiddenVolHeader (HFILE dev, unsigned __int64 volSize, BOOL deviceFlag);
BOOL CALLBACK CipherTestDialogProc ( HWND hwndDlg , UINT uMsg , WPARAM wParam , LPARAM lParam );
void ResetCipherTest ( HWND hwndDlg , int idTestCipher );
BOOL BrowseFiles (HWND hwndDlg, char *stringId, char *lpszFileName, BOOL keepHistory, BOOL saveMode);
BOOL BrowseDirectories (HWND hWnd, char *lpszTitle, char *dirName);
void handleError ( HWND hwndDlg , int code );
void LocalizeDialog ( HWND hwnd, char *stringId );
void OpenVolumeExplorerWindow (int driveNo);
static BOOL CALLBACK CloseVolumeExplorerWindowsEnum( HWND hwnd, LPARAM driveNo);
BOOL CloseVolumeExplorerWindows (HWND hwnd, int driveNo);
BOOL CheckCapsLock (HWND hwnd, BOOL quiet);
int GetFirstAvailableDrive ();
int GetLastAvailableDrive ();
BOOL IsDriveAvailable (int driveNo);
int DriverUnmountVolume (HWND hwndDlg, int nDosDriveNo, BOOL forced);
void BroadcastDeviceChange (WPARAM message, int nDosDriveNo, DWORD driveMap);
int MountVolume (HWND hwndDlg, int driveNo, char *volumePath, Password *password, BOOL cachePassword, BOOL sharedAccess, MountOptions *mountOptions, BOOL quiet, BOOL bReportWrongPassword);
BOOL UnmountVolume (HWND hwndDlg , int nDosDriveNo, BOOL forceUnmount);
BOOL IsPasswordCacheEmpty (void);
BOOL IsMountedVolume (char *volname);
BOOL IsAdmin (void);
BOOL ResolveSymbolicLink (PWSTR symLinkName, PWSTR targetName);
int GetDiskDeviceDriveLetter (PWSTR deviceName);
HANDLE DismountDrive (int driveNo);
BOOL TCCopyFile (char *sourceFileName, char *destinationFile);
int BackupVolumeHeader (HWND hwndDlg, BOOL bRequireConfirmation, char *lpszVolume);
int RestoreVolumeHeader (HWND hwndDlg, char *lpszVolume);
void GetSpeedString (unsigned __int64 speed, wchar_t *str);
BOOL IsNonInstallMode ();
BOOL DriverUnload ();
LRESULT SetCheckBox (HWND hwndDlg, int dlgItem, BOOL state);
BOOL GetCheckBox (HWND hwndDlg, int dlgItem);
void CleanLastVisitedMRU (void);
LRESULT ListItemAdd (HWND list, int index, char *string);
LRESULT ListItemAddW (HWND list, int index, wchar_t *string);
LRESULT ListSubItemSet (HWND list, int index, int subIndex, char *string);
LRESULT ListSubItemSetW (HWND list, int index, int subIndex, wchar_t *string);
BOOL GetMountList (MOUNT_LIST_STRUCT *list);
int GetDriverRefCount ();
void GetSizeString (unsigned __int64 size, wchar_t *str);
char *LoadFile (char *fileName, DWORD *size);
char *GetConfigPath (char *fileName);
void OpenPageHelp (HWND hwndDlg, int nPage);
int Info (char *stringId);
int Warning (char *stringId);
int Error (char *stringId);
int AskYesNo (char *stringId);
int AskNoYes (char *stringId);
int AskWarnYesNo (char *stringId);
int AskWarnNoYes (char *stringId);
int AskWarnCancelOk (char *stringId);
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
char *RelativePath2Absolute (char *szFileName);
void CheckSystemAutoMount ();
BOOL CALLBACK CloseTCWindowsEnum( HWND hwnd, LPARAM lParam);
BOOL CALLBACK FindTCWindowEnum (HWND hwnd, LPARAM lParam);
BYTE *MapResource (char *resourceType, int resourceId, PDWORD size);
BOOL SelectMultipleFiles (HWND hwndDlg, char *stringId, char *lpszFileName, BOOL keepHistory);
BOOL SelectMultipleFilesNext (char *lpszFileName);
