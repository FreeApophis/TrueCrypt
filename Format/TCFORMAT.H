/* Copyright (C) 2004 TrueCrypt Team, truecrypt.org
   This product uses components written by Paul Le Roux <pleroux@swprofessionals.com> */

/* Everything below this line is automatically updated by the -mkproto-tool- */

void localcleanup ( void );
void LoadSettings ( HWND hwndDlg );
void SaveSettings ( HWND hwndDlg );
void EndMainDlg ( HWND hwndDlg );
void ComboSelChangeCipher ( HWND hwndDlg );
void VerifySizeAndUpdate ( HWND hwndDlg , BOOL bUpdate );
void formatThreadFunction ( void *hwndDlg );
void OpenPageHelp ( HWND hwndDlg , int nPage );
void LoadPage ( HWND hwndDlg , int nPageNo );
BOOL WINAPI VolstatsDlgProc ( HWND hwndDlg , UINT msg , WPARAM wParam , LPARAM lParam );
int PrintFreeSpace ( HWND hwndTextBox , char *lpszDrive , PLARGE_INTEGER lDiskFree );
void DisplaySizingErrorText ( HWND hwndTextBox );
void EnableDisableFileNext ( HWND hComboBox , HWND hMainButton );
BOOL QueryFreeSpace ( HWND hwndDlg , HWND hwndTextBox );
void AddCipher ( HWND hComboBox , char *lpszCipher , int nCipher );
void SelectCipher ( HWND hComboBox , int *nCipher );
BOOL CALLBACK PageDialogProc ( HWND hwndDlg , UINT uMsg , WPARAM wParam , LPARAM lParam );
BOOL CALLBACK MainDialogProc ( HWND hwndDlg , UINT uMsg , WPARAM wParam , LPARAM lParam );
void ExtractCommandLine ( HWND hwndDlg , char *lpszCommandLine );
int WINAPI WINMAIN ( HINSTANCE hInstance , HINSTANCE hPrevInstance , char *lpszCommandLine , int nCmdShow );
