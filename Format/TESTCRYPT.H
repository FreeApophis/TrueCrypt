/* Copyright (C) 2004 TrueCrypt Foundation
   This product uses components written by Paul Le Roux <pleroux@swprofessionals.com> */

/* Everything below this line is automatically updated by the -mkproto-tool- */

void init_cipher2 ( int cipher , void *key , void *ks , int key_len );
void ResetCipherTest ( HWND hwndDlg , int nCipherChoice );
BOOL Des56TestLoop ( void *test_vectors , int nVectorCount , int enc );
BOOL CALLBACK CipherTestDialogProc ( HWND hwndDlg , UINT uMsg , WPARAM wParam , LPARAM lParam );
