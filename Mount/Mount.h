/* The source code contained in this file has been derived from the source code
   of Encryption for the Masses 2.02a by Paul Le Roux. Modifications and
   additions to that source code contained in this file are Copyright (c) 2004
   TrueCrypt Team and Copyright (c) 2004 TrueCrypt Foundation. Unmodified
   parts are Copyright (c) 1998-99 Paul Le Roux. This is a TrueCrypt Foundation
   release. Please see the file license.txt for full license details. */

/* Everything below this line is automatically updated by the -mkproto-tool- */

void localcleanup ( void );
void EndMainDlg ( HWND hwndDlg );
void EnableDisableButtons ( HWND hwndDlg );
void OpenPageHelp ( HWND hwndDlg );
void LoadSettings ( HWND hwndDlg );
void SaveSettings ( HWND hwndDlg );
void WriteRegistryInt (char *name, int value);
void WriteRegistryString (char *name, char *str);
BOOL SelectItem ( HWND hTree , char nLetter );
void LoadDriveLetters ( HWND hTree, int drive );
BOOL WINAPI PasswordChangeDlgProc ( HWND hwndDlg , UINT msg , WPARAM wParam , LPARAM lParam );
BOOL WINAPI PasswordDlgProc ( HWND hwndDlg , UINT msg , WPARAM wParam , LPARAM lParam );
void BuildTree ( HWND hTree );
LPARAM GetSelectedLong ( HWND hTree );
LPARAM GetItemLong ( HWND hTree, int itemNo );
BOOL WINAPI CommandHelpDlgProc ( HWND hwndDlg , UINT msg , WPARAM wParam , LPARAM lParam );
BOOL CALLBACK MainDialogProc ( HWND hwndDlg , UINT uMsg , WPARAM wParam , LPARAM lParam );
void ExtractCommandLine ( HWND hwndDlg , char *lpszCommandLine );
int WINAPI WINMAIN ( HINSTANCE hInstance , HINSTANCE hPrevInstance , char *lpszCommandLine , int nCmdShow );
void WipeCache (HWND hwndDlg);
void OpenVolumeExplorerWindow (int driveNo);
void CloseVolumeExplorerWindows (HWND hwnd, int driveNo);
