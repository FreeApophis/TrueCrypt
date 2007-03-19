/*
 Copyright (c) TrueCrypt Foundation. All rights reserved.

 Covered by the TrueCrypt License 2.2 the full text of which is contained
 in the file License.txt included in TrueCrypt binary and source code
 distribution packages.
*/

#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>

#include "Tcdefs.h"
#include "Keyfiles.h"
#include "Crc.h"

#ifdef _WIN32

#include <io.h>
#include "Dlgcode.h"
#include "Language.h"
#include "../common/resource.h"

#define stat _stat
#define S_IFDIR _S_IFDIR
#define snprintf _snprintf

#else

#include <dirent.h>
#include <utime.h>

#endif

KeyFile *KeyFileAdd (KeyFile *firstKeyFile, KeyFile *keyFile)
{
	KeyFile *kf = firstKeyFile;

	if (firstKeyFile != NULL)
	{
		while (kf->Next)
			kf = kf->Next;

		kf->Next = keyFile;
	}
	else
		firstKeyFile = keyFile;

	keyFile->Next = NULL;

	return firstKeyFile;
}


// Returns first keyfile, NULL if last keyfile was removed
static KeyFile *KeyFileRemove (KeyFile *firstKeyFile, KeyFile *keyFile)
{
	KeyFile *prevkf = NULL, *kf = firstKeyFile;

	if (firstKeyFile == NULL) return NULL;
	do
	{
		if (kf == keyFile)
		{
			if (prevkf == NULL)
				firstKeyFile = kf->Next;
			else
				prevkf->Next = kf->Next;

			memset (keyFile, 0, sizeof(*keyFile));	// wipe
			free (keyFile);
			break;
		}
		prevkf = kf;
	}
	while (kf = kf->Next);

	return firstKeyFile;
}


void KeyFileRemoveAll (KeyFile **firstKeyFile)
{
	KeyFile *kf = *firstKeyFile;
	while (kf != NULL)
	{
		KeyFile *d = kf;
		kf = kf->Next;
		burn (d, sizeof(*d));	// wipe
		free (d);
	}

	*firstKeyFile = NULL;
}


KeyFile *KeyFileClone (KeyFile *keyFile)
{
	KeyFile *clone;

	if (keyFile == NULL) return NULL;

	clone = malloc (sizeof (KeyFile));
	strcpy (clone->FileName, keyFile->FileName);
	clone->Next = NULL;
	return clone;
}


KeyFile *KeyFileCloneAll (KeyFile *firstKeyFile)
{
	KeyFile *cloneFirstKeyFile = KeyFileClone (firstKeyFile);
	KeyFile *kf;

	if (firstKeyFile == NULL) return NULL;
	kf = firstKeyFile->Next;
	while (kf != NULL)
	{
		KeyFileAdd (cloneFirstKeyFile, KeyFileClone (kf));
		kf = kf->Next;
	}

	return cloneFirstKeyFile;
}


static BOOL KeyFileProcess (unsigned __int8 *keyPool, KeyFile *keyFile, BOOL preserveTimestamp)
{
	FILE *f;
	unsigned __int8 buffer[64 * 1024];
	unsigned __int32 crc = 0xffffffff;
	int writePos = 0;
	size_t bytesRead, totalRead = 0;

#ifdef _WIN32
	HANDLE src;
	FILETIME ftCreationTime;
	FILETIME ftLastWriteTime;
	FILETIME ftLastAccessTime;
#else
	struct stat kfStat;
#endif

	BOOL bTimeStampValid = FALSE;

	if (preserveTimestamp)
	{
		/* Remember the last access time of the keyfile. It will be preserved in order to prevent
		   an adversary from determining which file may have been used as keyfile. */
#ifdef _WIN32
		src = CreateFile (keyFile->FileName,
			preserveTimestamp ? (GENERIC_READ | GENERIC_WRITE) : GENERIC_READ,
			FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);

		if (src != INVALID_HANDLE_VALUE)
		{
			if (GetFileTime ((HANDLE) src, &ftCreationTime, &ftLastAccessTime, &ftLastWriteTime))
				bTimeStampValid = TRUE;
			else
				Warning ("GETFILETIME_FAILED_KEYFILE");
		}
#else
		bTimeStampValid = stat (keyFile->FileName, &kfStat) == 0;
#endif
	}

	f = fopen (keyFile->FileName, "rb");
	if (f == NULL) return FALSE;

	while ((bytesRead = fread (buffer, 1, sizeof (buffer), f)) > 0)
	{
		size_t i;

		for (i = 0; i < bytesRead; i++)
		{
			crc = UPDC32 (buffer[i], crc);

			keyPool[writePos++] += (unsigned __int8) (crc >> 24);
			keyPool[writePos++] += (unsigned __int8) (crc >> 16);
			keyPool[writePos++] += (unsigned __int8) (crc >> 8);
			keyPool[writePos++] += (unsigned __int8) crc;

			if (writePos >= KEYFILE_POOL_SIZE)
				writePos = 0;

			if (++totalRead >= KEYFILE_MAX_READ_LEN)
				goto close;
		}
	}

close:
	fclose (f);

	if (bTimeStampValid)
	{
		// Restore the keyfile timestamp
#ifdef _WIN32
		if (!SetFileTime (src, &ftCreationTime, &ftLastAccessTime, &ftLastWriteTime))
			Warning ("SETFILETIME_FAILED_KEYFILE");
		CloseHandle (src);
#else
		struct utimbuf u;
		u.actime = kfStat.st_atime;
		u.modtime = kfStat.st_atime;
		utime (keyFile->FileName, &u);
#endif
	}

	return TRUE;
}


BOOL KeyFilesApply (Password *password, KeyFile *firstKeyFile, BOOL preserveTimestamp)
{
	BOOL status = TRUE;
	KeyFile kfSubStruct;
	KeyFile *kf;
	KeyFile *kfSub = &kfSubStruct;
	static unsigned __int8 keyPool [KEYFILE_POOL_SIZE];
	int i;
	struct stat statStruct;
	char searchPath [TC_MAX_PATH*2];
#ifdef _WIN32
	struct _finddata_t fBuf;
	intptr_t searchHandle;
#else
	struct dirent *fBuf;
	DIR *searchHandle;
#endif

	if (firstKeyFile == NULL) return TRUE;

#ifdef _WIN32
	VirtualLock (keyPool, sizeof (keyPool));
#endif
	memset (keyPool, 0, sizeof (keyPool));

	for (kf = firstKeyFile; kf != NULL; kf = kf->Next)
	{
		// Determine whether it's a path or a file
		if (stat (kf->FileName, &statStruct) != 0)
		{
#ifdef _WIN32
			Error ("ERR_PROCESS_KEYFILE");
#else
			perror ("stat");
#endif
			status = FALSE;
			continue;
		}

		if (statStruct.st_mode & S_IFDIR)		// If it's a directory
		{
			/* Find and process all keyfiles in the directory */

#ifdef _WIN32
			snprintf (searchPath, sizeof (searchPath), "%s\\*.*", kf->FileName);
			if ((searchHandle = _findfirst (searchPath, &fBuf)) == -1)
#else
			if ((searchHandle = opendir (kf->FileName)) == NULL)
#endif
			{
#ifdef _WIN32
				Error ("ERR_PROCESS_KEYFILE_PATH");
#endif
				status = FALSE;
				continue;
			}

#ifdef _WIN32
			do
#else
			while ((fBuf = readdir (searchHandle)) != NULL)
#endif
			{
				snprintf (kfSub->FileName, sizeof(kfSub->FileName), "%s%c%s", kf->FileName,
#ifdef _WIN32
					'\\',
					fBuf.name
#else
					'/',
					fBuf->d_name
#endif
					);

				// Determine whether it's a path or a file
				if (stat (kfSub->FileName, &statStruct) != 0)
				{
#ifdef _WIN32
					Error ("ERR_PROCESS_KEYFILE");
#endif
					status = FALSE;
					continue;
				}
				else if (statStruct.st_mode & S_IFDIR)		// If it's a directory
				{
					// Prevent recursive folder scanning
					continue;	 
				}


				// Apply keyfile to the pool
				if (!KeyFileProcess (keyPool, kfSub, preserveTimestamp))
				{
#ifdef _WIN32
					handleWin32Error (NULL);
					Error ("ERR_PROCESS_KEYFILE");
#endif
					status = FALSE;
				}

#ifdef _WIN32
			} while (_findnext (searchHandle, &fBuf) != -1);
			_findclose (searchHandle);
#else
			}
			closedir (searchHandle);
#endif

			burn (&kfSubStruct, sizeof (kfSubStruct));

		}
		// Apply keyfile to the pool
		else if (!KeyFileProcess (keyPool, kf, preserveTimestamp))
		{
#ifdef _WIN32
			handleWin32Error (NULL);
			Error ("ERR_PROCESS_KEYFILE");
#endif
			status = FALSE;
		}
	}

	/* Mix the keyfile pool contents into the password */

	for (i = 0; i < (int)sizeof(keyPool); i++)
	{
		if (i < password->Length)
			password->Text[i] += keyPool[i];
		else
			password->Text[i] = keyPool[i];
	}

	if (password->Length < (int)sizeof (keyPool))
        password->Length = sizeof (keyPool);

	burn (keyPool, sizeof (keyPool));

	return status;
}

#ifdef _WIN32

static void LoadKeyList (HWND hwndDlg, KeyFile *firstKeyFile)
{
	KeyFile *kf;
	LVITEM LvItem;
	int line = 0;
	HWND hList = GetDlgItem (hwndDlg, IDC_KEYLIST);

	ListView_DeleteAllItems (hList);
	EnableWindow (GetDlgItem (hwndDlg, IDC_KEYREMOVE), FALSE);
	EnableWindow (GetDlgItem (hwndDlg, IDC_KEYREMOVEALL), firstKeyFile != NULL);
	SetCheckBox (hwndDlg, IDC_KEYFILES_ENABLE, firstKeyFile != NULL);

	for (kf = firstKeyFile; kf != NULL; kf = kf->Next)
	{
		memset (&LvItem,0,sizeof(LvItem));
		LvItem.mask = LVIF_TEXT|LVIF_PARAM;
		LvItem.iItem = line++;
		LvItem.iSubItem = 0;
		LvItem.pszText = kf->FileName;
		LvItem.lParam = (LPARAM) kf;
		SendMessage (hList, LVM_INSERTITEM, 0, (LPARAM)&LvItem);
	}
}

#if KEYFILE_POOL_SIZE % 4 != 0
#error KEYFILE_POOL_SIZE must be a multiple of 4
#endif

BOOL WINAPI KeyFilesDlgProc (HWND hwndDlg, UINT msg, WPARAM wParam, LPARAM lParam)
{
	static KeyFilesDlgParam *param;
	static KeyFilesDlgParam origParam;

	WORD lw = LOWORD (wParam);

	switch (msg)
	{
	case WM_INITDIALOG:
		{
			LVCOLUMNW LvCol;
			HWND hList = GetDlgItem (hwndDlg, IDC_KEYLIST);

			param = (KeyFilesDlgParam *) lParam;
			origParam = *(KeyFilesDlgParam *) lParam;

			param->FirstKeyFile = KeyFileCloneAll (param->FirstKeyFile);

			LocalizeDialog (hwndDlg, "IDD_KEYFILES");
			DragAcceptFiles (hwndDlg, TRUE);

			SendMessageW (hList,LVM_SETEXTENDEDLISTVIEWSTYLE,0,
				LVS_EX_FULLROWSELECT|LVS_EX_HEADERDRAGDROP
				); 

			memset (&LvCol,0,sizeof(LvCol));               
			LvCol.mask = LVCF_TEXT|LVCF_WIDTH|LVCF_SUBITEM|LVCF_FMT;  
			LvCol.pszText = GetString ("KEYFILE");                           
			LvCol.cx = 366;
			LvCol.fmt = LVCFMT_LEFT;
			SendMessageW (hList, LVM_INSERTCOLUMNW, 0, (LPARAM)&LvCol);

			LoadKeyList (hwndDlg, param->FirstKeyFile);
			SetCheckBox (hwndDlg, IDC_KEYFILES_ENABLE, param->EnableKeyFiles);

			SetWindowTextW(GetDlgItem(hwndDlg, IDT_KEYFILES_NOTE), GetString ("IDT_KEYFILES_NOTE"));

			ToHyperlink (hwndDlg, IDC_LINK_KEYFILES_INFO);
		}
		return 1;

	case WM_COMMAND:

		if (lw == IDC_KEYADD)
		{
			KeyFile *kf = malloc (sizeof (KeyFile));
			if (SelectMultipleFiles (hwndDlg, "SELECT_KEYFILE", kf->FileName, bHistory))
			{
				do
				{
					param->FirstKeyFile = KeyFileAdd (param->FirstKeyFile, kf);
					LoadKeyList (hwndDlg, param->FirstKeyFile);

					kf = malloc (sizeof (KeyFile));
				} while (SelectMultipleFilesNext (kf->FileName));
			}

			free (kf);
			return 1;
		}

		if (lw == IDC_ADD_KEYFILE_PATH)
		{
			KeyFile *kf = malloc (sizeof (KeyFile));

			if (BrowseDirectories (hwndDlg,"SELECT_KEYFILE_PATH", kf->FileName))
			{
				param->FirstKeyFile = KeyFileAdd (param->FirstKeyFile, kf);
				LoadKeyList (hwndDlg, param->FirstKeyFile);
			}
			else
			{
				free (kf);
			}
			return 1;
		}

		if (lw == IDC_KEYREMOVE)
		{
			HWND list = GetDlgItem (hwndDlg, IDC_KEYLIST);
			LVITEM LvItem;
			memset (&LvItem, 0, sizeof(LvItem));
			LvItem.mask = LVIF_PARAM;   
			LvItem.iItem = -1;

			while (-1 != (LvItem.iItem = ListView_GetNextItem (list, LvItem.iItem, LVIS_SELECTED)))
			{
				ListView_GetItem (list, &LvItem);
				param->FirstKeyFile = KeyFileRemove (param->FirstKeyFile, (KeyFile *) LvItem.lParam);
			} 
			
			LoadKeyList (hwndDlg, param->FirstKeyFile);
 			return 1;
		}

		if (lw == IDC_KEYREMOVEALL)
		{
			KeyFileRemoveAll (&param->FirstKeyFile);
			LoadKeyList (hwndDlg, NULL);
			return 1;
		}

		if (lw == IDC_GENERATE_KEYFILE)
		{
			DialogBoxParamW (hInst, 
				MAKEINTRESOURCEW (IDD_KEYFILE_GENERATOR), hwndDlg,
				(DLGPROC) KeyfileGeneratorDlgProc, (LPARAM) 0);
			return 1;
		}

		if (lw == IDC_LINK_KEYFILES_INFO)
		{
			Applink ("keyfiles", TRUE, "");
		}

		if (lw == IDOK)
		{
			param->EnableKeyFiles = IsButtonChecked (GetDlgItem (hwndDlg, IDC_KEYFILES_ENABLE));
			EndDialog (hwndDlg, IDOK);
			return 1;
		}

		if (lw == IDCANCEL)
		{
			KeyFileRemoveAll (&param->FirstKeyFile);
			*param = origParam;

			EndDialog (hwndDlg, IDCLOSE);
			return 1;
		}

	case WM_DROPFILES:
		{
			HDROP hdrop = (HDROP) wParam;

			int i = 0, count = DragQueryFile (hdrop, -1, NULL, 0);

			while (count-- > 0)
			{
				KeyFile *kf = malloc (sizeof (KeyFile));
				DragQueryFile (hdrop, i++, kf->FileName, sizeof (kf->FileName));
				param->FirstKeyFile = KeyFileAdd (param->FirstKeyFile, kf);
				LoadKeyList (hwndDlg, param->FirstKeyFile);
			}

			DragFinish (hdrop);
		}
		return 1;

	case WM_NOTIFY:
		if (((LPNMHDR) lParam)->code == LVN_ITEMCHANGED)
		{
			EnableWindow (GetDlgItem (hwndDlg, IDC_KEYREMOVE),
				ListView_GetNextItem (GetDlgItem (hwndDlg, IDC_KEYLIST), -1, LVIS_SELECTED) != -1);
			return 1;
		}
		break;

	case WM_CLOSE:
		KeyFileRemoveAll (&param->FirstKeyFile);
		*param = origParam;

		EndDialog (hwndDlg, IDCLOSE);
		return 1;

		break;

	}

	return 0;
}


#endif	/* #ifdef _WIN32 */
