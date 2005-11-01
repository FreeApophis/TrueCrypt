/* 
Copyright (c) 2004-2005 TrueCrypt Foundation. All rights reserved. 

Covered by TrueCrypt License 2.0 the full text of which is contained in the file
License.txt included in TrueCrypt binary and source code distribution archives. 
*/

#ifndef KEYFILES_H
#define	KEYFILES_H


#include "Common.h"

#define KEYFILE_POOL_SIZE	64
#define	KEYFILE_MAX_READ_LEN	(1024*1024)

typedef struct KeyFileStruct
{
	char FileName[MAX_PATH];
	struct KeyFileStruct *Next;
} KeyFile;

typedef struct
{
	BOOL EnableKeyFiles;
	KeyFile *FirstKeyFile;
} KeyFilesDlgParam;

KeyFile *KeyFileAdd (KeyFile *firstKeyFile, KeyFile *keyFile);
void KeyFileRemoveAll (KeyFile **firstKeyFile);
KeyFile *KeyFileClone (KeyFile *keyFile);
KeyFile *KeyFileCloneAll (KeyFile *firstKeyFile);
BOOL KeyFilesApply (Password *password, KeyFile *firstKeyFile, BOOL preserveTimestamp);

#ifdef _WIN32
BOOL WINAPI KeyFilesDlgProc (HWND hwndDlg, UINT msg, WPARAM wParam, LPARAM lParam);
#endif


#endif	/* #ifndef KEYFILES_H */ 
