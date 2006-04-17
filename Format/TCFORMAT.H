/* Legal Notice: The source code contained in this file has been derived from
   the source code of Encryption for the Masses 2.02a, which is Copyright (c)
   1998-99 Paul Le Roux and which is covered by the 'License Agreement for
   Encryption for the Masses'. Modifications and additions to that source code
   contained in this file are Copyright (c) 2004-2006 TrueCrypt Foundation and
   Copyright (c) 2004 TrueCrypt Team, and are covered by TrueCrypt License 2.0
   the full text of which is contained in the file License.txt included in
   TrueCrypt binary and source code distribution archives.  */

#include "../common/common.h"

void localcleanup ( void );
void LoadSettings ( HWND hwndDlg );
void SaveSettings ( HWND hwndDlg );
void EndMainDlg ( HWND hwndDlg );
void ComboSelChangeEA ( HWND hwndDlg );
void VerifySizeAndUpdate ( HWND hwndDlg , BOOL bUpdate );
void formatThreadFunction ( void *hwndDlg );
void LoadPage ( HWND hwndDlg , int nPageNo );
BOOL WINAPI VolstatsDlgProc ( HWND hwndDlg , UINT msg , WPARAM wParam , LPARAM lParam );
int PrintFreeSpace ( HWND hwndTextBox , char *lpszDrive , PLARGE_INTEGER lDiskFree );
void DisplaySizingErrorText ( HWND hwndTextBox );
void EnableDisableFileNext ( HWND hComboBox , HWND hMainButton );
BOOL QueryFreeSpace ( HWND hwndDlg , HWND hwndTextBox , BOOL display );
void AddCipher ( HWND hComboBox , char *lpszCipher , int nCipher );
BOOL CALLBACK PageDialogProc ( HWND hwndDlg , UINT uMsg , WPARAM wParam , LPARAM lParam );
BOOL CALLBACK MainDialogProc ( HWND hwndDlg , UINT uMsg , WPARAM wParam , LPARAM lParam );
void ExtractCommandLine ( HWND hwndDlg , char *lpszCommandLine );
int DetermineMaxHiddenVolSize (HWND hwndDlg);
BOOL IsSparseFile (HWND hwndDlg);
BOOL GetFileVolSize (HWND hwndDlg, unsigned __int64 *size);
int MountHiddenVolHost ( HWND hwndDlg, char *volumePath, int *driveNo, Password *password );
int AnalyzeHiddenVolumeHost ( HWND hwndDlg, int *driveNo, int *realClusterSize);
int ScanVolClusterBitmap ( HWND hwndDlg, int *driveNo, __int64 nbrClusters, __int64 *nbrFreeClusters);
int WINAPI WINMAIN ( HINSTANCE hInstance , HINSTANCE hPrevInstance , char *lpszCommandLine , int nCmdShow );

