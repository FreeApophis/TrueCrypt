/* The source code contained in this file has been derived from the source code
   of Encryption for the Masses 2.02a by Paul Le Roux. Modifications and
   additions to that source code contained in this file are Copyright (c) 2004-2005
   TrueCrypt Foundation and Copyright (c) 2004 TrueCrypt Team. Unmodified
   parts are Copyright (c) 1998-99 Paul Le Roux. This is a TrueCrypt Foundation
   release. Please see the file license.txt for full license details. */

/* Everything below this line is automatically updated by the -mkproto-tool- */

void localcleanup ( void );
void LoadSettings ( HWND hwndDlg );
void SaveSettings ( HWND hwndDlg );
void EndMainDlg ( HWND hwndDlg );
void ComboSelChangeEA ( HWND hwndDlg );
void VerifySizeAndUpdate ( HWND hwndDlg , BOOL bUpdate );
void formatThreadFunction ( void *hwndDlg );
void OpenPageHelp ( HWND hwndDlg , int nPage );
void LoadPage ( HWND hwndDlg , int nPageNo );
BOOL WINAPI VolstatsDlgProc ( HWND hwndDlg , UINT msg , WPARAM wParam , LPARAM lParam );
int PrintFreeSpace ( HWND hwndTextBox , char *lpszDrive , PLARGE_INTEGER lDiskFree );
void DisplaySizingErrorText ( HWND hwndTextBox );
void EnableDisableFileNext ( HWND hComboBox , HWND hMainButton );
BOOL QueryFreeSpace ( HWND hwndDlg , HWND hwndTextBox , BOOL display );
void AddCipher ( HWND hComboBox , char *lpszCipher , int nCipher );
void SelectEA ( HWND hComboBox , int *nCipher );
BOOL CALLBACK PageDialogProc ( HWND hwndDlg , UINT uMsg , WPARAM wParam , LPARAM lParam );
BOOL CALLBACK MainDialogProc ( HWND hwndDlg , UINT uMsg , WPARAM wParam , LPARAM lParam );
void ExtractCommandLine ( HWND hwndDlg , char *lpszCommandLine );
int DetermineMaxHiddenVolSize (HWND hwndDlg);
BOOL GetFileVolSize (HWND hwndDlg, unsigned __int64 *size);
int MountHiddenVolHost ( HWND hwndDlg, char *volumePath, int *driveNo, char *lpszPassword );
int AnalyzeHiddenVolumeHost ( HWND hwndDlg, int *driveNo, int *realClusterSize);
int ScanVolClusterBitmap ( HWND hwndDlg, int *driveNo, __int64 nbrClusters, __int64 *nbrFreeClusters);
int WINAPI WINMAIN ( HINSTANCE hInstance , HINSTANCE hPrevInstance , char *lpszCommandLine , int nCmdShow );

