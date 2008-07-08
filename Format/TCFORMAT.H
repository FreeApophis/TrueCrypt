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

#include "Common/Common.h"

#ifdef __cplusplus
extern "C" {
#endif

#define NBR_KEY_BYTES_TO_DISPLAY	16
#define KEY_GUI_VIEW_SIZE			64		// Max characters of the key hex dump to display

void localcleanup ( void );
void LoadSettings ( HWND hwndDlg );
void SaveSettings ( HWND hwndDlg );
void EndMainDlg ( HWND hwndDlg );
void ComboSelChangeEA ( HWND hwndDlg );
void VerifySizeAndUpdate ( HWND hwndDlg , BOOL bUpdate );
void __cdecl sysEncDriveAnalysisThread (void *hwndDlgArg);
void __cdecl formatThreadFunction ( void *hwndDlg );
BOOL RegisterBootDriver (void);
void LoadPage ( HWND hwndDlg , int nPageNo );
int PrintFreeSpace ( HWND hwndTextBox , char *lpszDrive , PLARGE_INTEGER lDiskFree );
void DisplaySizingErrorText ( HWND hwndTextBox );
void EnableDisableFileNext ( HWND hComboBox , HWND hMainButton );
BOOL QueryFreeSpace ( HWND hwndDlg , HWND hwndTextBox , BOOL display );
void AddCipher ( HWND hComboBox , char *lpszCipher , int nCipher );
BOOL CALLBACK PageDialogProc ( HWND hwndDlg , UINT uMsg , WPARAM wParam , LPARAM lParam );
BOOL CALLBACK MainDialogProc ( HWND hwndDlg , UINT uMsg , WPARAM wParam , LPARAM lParam );
void ExtractCommandLine ( HWND hwndDlg , char *lpszCommandLine );
void DisplayRandPool (HWND hPoolDisplay, BOOL bShow);
int DetermineMaxHiddenVolSize (HWND hwndDlg);
BOOL IsSparseFile (HWND hwndDlg);
BOOL GetFileVolSize (HWND hwndDlg, unsigned __int64 *size);
BOOL SwitchWizardToSysEncMode (void);
void SwitchWizardToFileContainerMode (void);
BOOL ResolveUnknownSysEncDirection (void);
BOOL WipeHiddenOSCreationConfig (void);
void HandleDecoyOSCompletion (void);
void AfterWMInitTasks (HWND hwndDlg);
void AfterSysEncProgressWMInitTasks (HWND hwndDlg);
void InitSysEncProgressBar (void);
BOOL SysEncInEffect (void);
BOOL CreatingHiddenSysVol(void);
int MountHiddenVolHost ( HWND hwndDlg, char *volumePath, int *driveNo, Password *password, BOOL bReadOnly );
int AnalyzeHiddenVolumeHost (HWND hwndDlg, int *driveNo, __int64 hiddenVolHostSize, int *realClusterSize, __int64 *pnbrFreeClusters);
int ScanVolClusterBitmap ( HWND hwndDlg, int *driveNo, __int64 nbrClusters, __int64 *nbrFreeClusters);
int WINAPI WINMAIN ( HINSTANCE hInstance , HINSTANCE hPrevInstance , char *lpszCommandLine , int nCmdShow );
	
extern BOOL showKeys;
extern volatile HWND hMasterKey;
extern volatile HWND hHeaderKey;
extern volatile BOOL bHiddenVolHost;
extern volatile BOOL bHiddenVolDirect;
extern BOOL bRemovableHostDevice;
extern BOOL bWarnDeviceFormatAdvanced;
extern HWND hCurPage;
extern HWND hProgressBar;
extern volatile BOOL bThreadCancel;
extern int nPbar;
extern volatile int WizardMode;

extern char HeaderKeyGUIView [KEY_GUI_VIEW_SIZE];
extern char MasterKeyGUIView [KEY_GUI_VIEW_SIZE];

#ifdef __cplusplus
}
#endif
