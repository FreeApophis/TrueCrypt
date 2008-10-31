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

#include "Common/Common.h"

#ifdef __cplusplus
extern "C" {
#endif

#define NBR_KEY_BYTES_TO_DISPLAY	16
#define KEY_GUI_VIEW_SIZE			64		// Max characters of the key hex dump to display

enum timer_ids
{
	TIMER_ID_RANDVIEW = 0xff,
	TIMER_ID_SYSENC_PROGRESS,
	TIMER_ID_NONSYS_INPLACE_ENC_PROGRESS,
	TIMER_ID_WIPE_PROGRESS,
	TIMER_ID_SYSENC_DRIVE_ANALYSIS_PROGRESS,
	TIMER_ID_KEYB_LAYOUT_GUARD
};

void localcleanup ( void );
void LoadSettings ( HWND hwndDlg );
void SaveSettings ( HWND hwndDlg );
void EndMainDlg ( HWND hwndDlg );
void ComboSelChangeEA ( HWND hwndDlg );
void VerifySizeAndUpdate ( HWND hwndDlg , BOOL bUpdate );
void __cdecl sysEncDriveAnalysisThread (void *hwndDlgArg);
void __cdecl volTransformThreadFunction ( void *hwndDlg );
void LoadPage ( HWND hwndDlg , int nPageNo );
int PrintFreeSpace ( HWND hwndTextBox , char *lpszDrive , PLARGE_INTEGER lDiskFree );
void DisplaySizingErrorText ( HWND hwndTextBox );
void EnableDisableFileNext ( HWND hComboBox , HWND hMainButton );
BOOL QueryFreeSpace ( HWND hwndDlg , HWND hwndTextBox , BOOL display );
BOOL FinalPreTransformPrompts (void);
void HandleOldAssignedDriveLetter (void);
void AddCipher ( HWND hComboBox , char *lpszCipher , int nCipher );
BOOL CALLBACK PageDialogProc ( HWND hwndDlg , UINT uMsg , WPARAM wParam , LPARAM lParam );
BOOL CALLBACK MainDialogProc ( HWND hwndDlg , UINT uMsg , WPARAM wParam , LPARAM lParam );
void ExtractCommandLine ( HWND hwndDlg , char *lpszCommandLine );
void DisplayRandPool (HWND hPoolDisplay, BOOL bShow);
int DetermineMaxHiddenVolSize (HWND hwndDlg);
BOOL IsSparseFile (HWND hwndDlg);
BOOL GetFileVolSize (HWND hwndDlg, unsigned __int64 *size);
void ManageStartupSeqWiz (BOOL bRemove, const char *arg);
BOOL SwitchWizardToSysEncMode (void);
void SwitchWizardToFileContainerMode (void);
BOOL ResolveUnknownSysEncDirection (void);
BOOL WipeHiddenOSCreationConfig (void);
void AfterWMInitTasks (HWND hwndDlg);
void AfterSysEncProgressWMInitTasks (HWND hwndDlg);
void InitSysEncProgressBar (void);
void InitNonSysInplaceEncProgressBar (void);
void UpdateNonSysInplaceEncProgressBar (void);
BOOL SysEncInEffect (void);
BOOL CreatingHiddenSysVol(void);
void NonSysInplaceEncPause (void);
void NonSysInplaceEncResume (void);
void ShowNonSysInPlaceEncUIStatus (void);
void UpdateNonSysInPlaceEncControls (void);
int MountHiddenVolHost ( HWND hwndDlg, char *volumePath, int *driveNo, Password *password, BOOL bReadOnly );
int AnalyzeHiddenVolumeHost (HWND hwndDlg, int *driveNo, __int64 hiddenVolHostSize, int *realClusterSize, __int64 *pnbrFreeClusters);
int ScanVolClusterBitmap ( HWND hwndDlg, int *driveNo, __int64 nbrClusters, __int64 *nbrFreeClusters);
int WINAPI WINMAIN ( HINSTANCE hInstance , HINSTANCE hPrevInstance , char *lpszCommandLine , int nCmdShow );
void WipeStart (void);
void WipeAbort (void);
void UpdateWipeProgressBar (void);
void InitWipeProgressBar (void);
void UpdateWipeControls (void);

extern BOOL showKeys;
extern volatile HWND hMasterKey;
extern volatile HWND hHeaderKey;
extern volatile BOOL bHiddenVolHost;
extern volatile BOOL bHiddenVolDirect;
extern BOOL bRemovableHostDevice;
extern BOOL bWarnDeviceFormatAdvanced;
extern HWND hCurPage;
extern HWND hProgressBar;
extern volatile BOOL bVolTransformThreadCancel;
extern volatile BOOL bInPlaceEncNonSysResumed;
extern volatile BOOL bFirstNonSysInPlaceEncResumeDone;
extern volatile BOOL bInPlaceEncNonSys;
extern __int64 NonSysInplaceEncBytesDone;
extern __int64 NonSysInplaceEncTotalSectors;
extern int nPbar;
extern volatile int WizardMode;

extern char HeaderKeyGUIView [KEY_GUI_VIEW_SIZE];
extern char MasterKeyGUIView [KEY_GUI_VIEW_SIZE];
extern volatile int NonSysInplaceEncStatus;

#ifdef __cplusplus
}
#endif
