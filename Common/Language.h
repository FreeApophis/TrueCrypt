#include <windows.h>

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
wchar_t *GetString (char *stringId);
Font *GetFont (char *fontType);
BOOL LoadLanguageFile ();
char *GetPreferredLangId ();
void SetPreferredLangId (char *langId);
char *GetActiveLangPackVersion ();
