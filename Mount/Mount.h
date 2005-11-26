/* Legal Notice: The source code contained in this file has been derived from
   the source code of Encryption for the Masses 2.02a, which is Copyright (c)
   1998-99 Paul Le Roux and which is covered by the 'License Agreement for
   Encryption for the Masses'. Modifications and additions to that source code
   contained in this file are Copyright (c) 2004-2005 TrueCrypt Foundation and
   Copyright (c) 2004 TrueCrypt Team, and are covered by TrueCrypt License 2.0
   the full text of which is contained in the file License.txt included in
   TrueCrypt binary and source code distribution archives.  */

#define VMOUNTED					1
#define VFREE						0
#define MAIN_TIMER_INTERVAL	1000
#define MSG_TASKBAR_ICON			7
#define FILE_FAVORITE_VOLUMES		"Favorite Volumes.xml"

#define APP_MESSAGE_ENABLE_DISABLE	100
#define APP_MESSAGE_SHOW_WINDOW		101

#define WM_COPY_SET_VOLUME_NAME		"VNAM"

/* Password Change dialog modes */
enum
{
	PCDM_CHANGE_PASSWORD = 0,
	PCDM_CHANGE_PKCS5_PRF,
	PCDM_ADD_REMOVE_VOL_KEYFILES,
	PCDM_REMOVE_ALL_KEYFILES_FROM_VOL
};

typedef struct
{
	BOOL bHidVolDamagePrevReported[26];
} VOLUME_NOTIFICATIONS_LIST;

extern BOOL bPlaySoundOnHotkeyMountDismount;
extern BOOL bDisplayMsgBoxOnHotkeyDismount;

void localcleanup ( void );
void EndMainDlg ( HWND hwndDlg );
void EnableDisableButtons ( HWND hwndDlg );
BOOL VolumeSelected (HWND hwndDlg );
void LoadSettings ( HWND hwndDlg );
void SaveSettings ( HWND hwndDlg );
BOOL SelectItem ( HWND hTree , char nLetter );
void LoadDriveLetters ( HWND hTree, int drive );
BOOL WINAPI PasswordChangeDlgProc ( HWND hwndDlg , UINT msg , WPARAM wParam , LPARAM lParam );
BOOL WINAPI PasswordDlgProc ( HWND hwndDlg , UINT msg , WPARAM wParam , LPARAM lParam );
BOOL WINAPI MountOptionsDlgProc (HWND hwndDlg, UINT msg, WPARAM wParam, LPARAM lParam);
void BuildTree ( HWND hTree );
LPARAM GetSelectedLong ( HWND hTree );
LPARAM GetItemLong ( HWND hTree, int itemNo );
BOOL WINAPI CommandHelpDlgProc ( HWND hwndDlg , UINT msg , WPARAM wParam , LPARAM lParam );
BOOL CALLBACK MainDialogProc ( HWND hwndDlg , UINT uMsg , WPARAM wParam , LPARAM lParam );
void ExtractCommandLine ( HWND hwndDlg , char *lpszCommandLine );
int WINAPI WINMAIN ( HINSTANCE hInstance , HINSTANCE hPrevInstance , char *lpszCommandLine , int nCmdShow );
void WipeCache (HWND hwndDlg);
void OpenVolumeExplorerWindow (int driveNo);
BOOL TaskBarIconAdd (HWND hwnd);
BOOL TaskBarIconRemove (HWND hwnd);
void DismountIdleVolumes ();
BOOL MountFavoriteVolumes ();
void SaveFavoriteVolumes ();
static void SaveDefaultKeyFilesParam (void);
static BOOL Dismount (HWND hwndDlg, int nDosDriveNo);
static BOOL DismountAll (HWND hwndDlg, BOOL forceUnmount, BOOL interact, int dismountMaxRetries, int dismountAutoRetryDelay);
static void KeyfileDefaultsDlg (HWND hwndDlg);
static void HandleHotKey (HWND hwndDlg, WPARAM wParam);
static BOOL CheckMountList ();
