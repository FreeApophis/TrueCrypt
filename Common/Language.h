/*
 Copyright (c) 2008 TrueCrypt Foundation. All rights reserved.

 Governed by the TrueCrypt License 2.6 the full text of which is contained
 in the file License.txt included in TrueCrypt binary and source code
 distribution packages.
*/

#include <windows.h>

#ifdef __cplusplus
extern "C" {
#endif

#define UNKNOWN_STRING_ID L"[?]"

extern BOOL LocalizationActive;
extern int LocalizationSerialNo;
extern wchar_t UnknownString[1024];

typedef struct
{
	wchar_t *FaceName;
	int Size;
} Font;

BOOL CALLBACK LanguageDlgProc (HWND hwndDlg, UINT msg, WPARAM wParam, LPARAM lParam);
wchar_t *GetString (const char *stringId);
Font *GetFont (char *fontType);
BOOL LoadLanguageFile ();
char *GetPreferredLangId ();
void SetPreferredLangId (char *langId);
char *GetActiveLangPackVersion ();

#ifdef __cplusplus
}
#endif
