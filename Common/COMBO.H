/* Copyright (C) 2004 TrueCrypt Foundation
   This product uses components written by Paul Le Roux <pleroux@swprofessionals.com> */


/* Everything below this line is automatically updated by the -mkproto-tool- */

void AddComboItem ( HWND hComboBox , char *lpszFileName );
LPARAM MoveEditToCombo ( HWND hComboBox );
int GetOrderComboIdx ( HWND hComboBox , int *nIdxList , int nElems );
LPARAM UpdateComboOrder ( HWND hComboBox );
void LoadCombo ( HWND hComboBox , char *lpszKey );
void DumpCombo ( HWND hComboBox , char *lpszKey , int bClear );
void ClearCombo (HWND hComboBox);
int IsComboEmpty (HWND hComboBox);