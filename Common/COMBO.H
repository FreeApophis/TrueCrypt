/* The source code contained in this file has been derived from the source code
   of Encryption for the Masses 2.02a by Paul Le Roux. Modifications and
   additions to that source code contained in this file are Copyright (c) 2004
   TrueCrypt Foundation and Copyright (c) 2004 TrueCrypt Team. Unmodified
   parts are Copyright (c) 1998-99 Paul Le Roux. This is a TrueCrypt Foundation
   release. Please see the file license.txt for full license details. */


/* Everything below this line is automatically updated by the -mkproto-tool- */

void AddComboItem ( HWND hComboBox , char *lpszFileName );
LPARAM MoveEditToCombo ( HWND hComboBox );
int GetOrderComboIdx ( HWND hComboBox , int *nIdxList , int nElems );
LPARAM UpdateComboOrder ( HWND hComboBox );
void LoadCombo ( HWND hComboBox , char *lpszKey );
void DumpCombo ( HWND hComboBox , char *lpszKey , int bClear );
void ClearCombo (HWND hComboBox);
int IsComboEmpty (HWND hComboBox);