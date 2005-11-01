/* The source code contained in this file has been derived from the source code
   of Encryption for the Masses 2.02a by Paul Le Roux. Modifications and
   additions to that source code contained in this file are Copyright (c) 2004-2005
   TrueCrypt Foundation and Copyright (c) 2004 TrueCrypt Team. Unmodified
   parts are Copyright (c) 1998-99 Paul Le Roux. This is a TrueCrypt Foundation
   release. Please see the file license.txt for full license details. */

void CipherInit2 ( int cipher , void *key , void *ks , int key_len );
void ResetCipherTest ( HWND hwndDlg , int nCipherChoice );
BOOL Des56TestLoop ( void *test_vectors , int nVectorCount , int enc );
BOOL CALLBACK CipherTestDialogProc ( HWND hwndDlg , UINT uMsg , WPARAM wParam , LPARAM lParam );
BOOL AutoTestAlgorithms (void);
