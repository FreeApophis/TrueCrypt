/*
 Copyright (c) TrueCrypt Foundation. All rights reserved.

 Covered by the TrueCrypt License 2.3 the full text of which is contained
 in the file License.txt included in TrueCrypt binary and source code
 distribution packages.
*/

#include <windows.h>

#ifdef __cplusplus
extern "C" {
#endif

BOOL ComServerFormat ();
int UacFormatNtfs (HWND hWnd, int driveNo, int clusterSize);
int UacAnalyzeHiddenVolumeHost (HWND hwndDlg, int *driveNo, __int64 hiddenVolHostSize, int *realClusterSize, __int64 *nbrFreeClusters);
int UacFormatVolume (char *cvolumePath , BOOL bDevice , unsigned __int64 size , unsigned __int64 hiddenVolHostSize , Password *password , int cipher , int pkcs5 , BOOL quickFormat, BOOL sparseFileSwitch, int fileSystem , int clusterSize, HWND hwndDlg , BOOL hiddenVol , int *realClusterSize);
BOOL UacUpdateProgressBar (__int64 nSecNo, BOOL *bThreadCancel);

#ifdef __cplusplus
}
#endif
