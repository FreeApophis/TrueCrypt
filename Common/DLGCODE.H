/* The source code contained in this file has been derived from the source code
   of Encryption for the Masses 2.02a by Paul Le Roux. Modifications and
   additions to that source code contained in this file are Copyright (c) 2004
   TrueCrypt Foundation and Copyright (c) 2004 TrueCrypt Team. Unmodified
   parts are Copyright (c) 1998-99 Paul Le Roux. This is a TrueCrypt Foundation
   release. Please see the file license.txt for full license details. */

#define IDC_ABOUT 0x7fff	/* ID for AboutBox on system menu in wm_user range */

#define UNMOUNT_WAIT	250

extern char szHelpFile[TC_MAX_PATH];
extern HFONT hSmallFont;
extern HFONT hBoldFont;
extern HFONT hSmallBoldFont;
extern HFONT hTitleFont;
extern HFONT hFixedFont;
extern HFONT hUserFont;
extern HFONT hUserUnderlineFont;
extern HFONT hUserBoldFont;
extern char *lpszTitle;
extern int nCurrentOS;
extern int CurrentOSMajor;
extern int CurrentOSMinor;
extern HANDLE hDriver;
extern HINSTANCE hInst;

#define WIN_95	0xa
#define WIN_98	0xb
#define WIN_NT	0xc


#define ICON_HAND MB_ICONHAND
#define YES_NO MB_YESNO

#ifdef _UNICODE
#define WINMAIN wWinMain
#else
#define WINMAIN WinMain
#endif

/* Everything below this line is automatically updated by the -mkproto-tool- */

void cleanup ( void );
void LowerCaseCopy ( char *lpszDest , char *lpszSource );
void UpperCaseCopy ( char *lpszDest , char *lpszSource );
void CreateFullVolumePath ( char *lpszDiskFile , char *lpszFileName , BOOL *bDevice );
int FakeDosNameForDevice ( char *lpszDiskFile , char *lpszDosDevice , char *lpszCFDevice , BOOL bNameOnly );
int RemoveFakeDosName ( char *lpszDiskFile , char *lpszDosDevice );
char *getstr ( UINT nID );
char *getmultilinestr ( UINT nID [4 ]);
void AbortProcess ( UINT nID );
void AbortProcessSilent ( void );
void *err_malloc ( size_t size );
char *err_strdup ( char *lpszText );
DWORD handleWin32Error ( HWND hwndDlg );
BOOL translateWin32Error ( char *lpszMsgBuf , int nSizeOfBuf );
BOOL WINAPI AboutDlgProc ( HWND hwndDlg , UINT msg , WPARAM wParam , LPARAM lParam );
BOOL WINAPI WarningDlgProc ( HWND hwndDlg , UINT msg , WPARAM wParam , LPARAM lParam );
BOOL IsButtonChecked ( HWND hButton );
void CheckButton ( HWND hButton );
void ToSBCS ( LPWSTR lpszText );
void ToUNICODE ( char *lpszText );
void InitDialog ( HWND hwndDlg );
HDC CreateMemBitmap ( HINSTANCE hInstance , HWND hwnd , char *resource );
void PaintBitmap ( HDC pdcMem , int x , int y , int nWidth , int nHeight , HDC hDC );
LRESULT CALLBACK SplashDlgProc ( HWND hwnd , UINT uMsg , WPARAM wParam , LPARAM lParam );
void WaitCursor ( void );
void NormalCursor ( void );
void ArrowWaitCursor ( void );
LRESULT CALLBACK CustomDlgProc ( HWND hwnd , UINT uMsg , WPARAM wParam , LPARAM lParam );
void InitApp ( HINSTANCE hInstance );
BOOL OpenDevice ( char *lpszPath , OPEN_TEST_STRUCT *driver );
UINT _stdcall win9x_io ( HFILE hFile , char *lpBuffer , UINT uBytes );
int GetAvailableFixedDisks ( HWND hComboBox , char *lpszRootPath );
int GetAvailableRemovables ( HWND hComboBox , char *lpszRootPath );
BOOL WINAPI RawDevicesDlgProc ( HWND hwndDlg , UINT msg , WPARAM wParam , LPARAM lParam );
BOOL WINAPI BenchmarkDlgProc (HWND hwndDlg, UINT msg, WPARAM wParam, LPARAM lParam);
int DriverAttach ( void );
BOOL SeekHiddenVolHeader (HFILE dev, unsigned __int64 volSize, BOOL deviceFlag);
BOOL BrowseFiles ( HWND hwndDlg , UINT nTitleID , char *lpszFileName, BOOL keepHistory );
void handleError ( HWND hwndDlg , int code );
void SetDefaultUserFont (HWND hwnd);
void OpenVolumeExplorerWindow (int driveNo);
static BOOL CALLBACK CloseVolumeExplorerWindowsEnum( HWND hwnd, LPARAM driveNo);
BOOL CloseVolumeExplorerWindows (HWND hwnd, int driveNo);
BOOL CheckCapsLock (HWND hwnd, BOOL quiet);
int GetFirstAvailableDrive ();
int GetLastAvailableDrive ();
BOOL IsDriveAvailable (int driveNo);
int DriverUnmountVolume (HWND hwndDlg, int nDosDriveNo, BOOL forced);
void BroadcastDeviceChange (WPARAM message, int nDosDriveNo);
int MountVolume (HWND hwndDlg, int driveNo, char *volumePath, char *szPassword, BOOL cachePassword, BOOL sharedAccess, BOOL quiet);
BOOL UnmountVolume (HWND hwndDlg , int nDosDriveNo, BOOL forceUnmount);
BOOL IsPasswordCacheEmpty (void);
BOOL IsMountedVolume (char *volname);
BOOL CheckPasswordLength (HWND hwndDlg, HWND hwndItem);		
BOOL IsAdmin (void);
BOOL ResolveSymbolicLink (PWSTR symLinkName, PWSTR targetName);
int GetDiskDeviceDriveLetter (PWSTR deviceName);
HANDLE DismountDrive (int driveNo);
