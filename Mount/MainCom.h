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

BOOL ComServerMain ();
int UacBackupVolumeHeader (HWND hwndDlg, BOOL bRequireConfirmation, char *lpszVolume);
int UacRestoreVolumeHeader (HWND hwndDlg, char *lpszVolume);
int UacChangePwd (char *lpszVolume, Password *oldPassword, Password *newPassword, int pkcs5, HWND hwndDlg);

#ifdef __cplusplus
}
#endif
