/*
 Copyright (c) TrueCrypt Foundation. All rights reserved.

 Covered by the TrueCrypt License 2.2 the full text of which is contained
 in the file License.txt included in TrueCrypt binary and source code
 distribution packages.
*/

#include <atlbase.h>
#include <statreg.h>
#include <windows.h>
#include "ComSetup.h"
#include "Resource.h"
#include "../Mount/MainCom_i.c"
#include "../Format/FormatCom_i.c"


extern "C" BOOL RegisterComServers (char *modulePath)
{
	BOOL ret = FALSE;
	wchar_t mainModule[1024], formatModule[1024];
	CComPtr<ITypeLib> tl, tl2;

	wsprintfW (mainModule, L"%hsTrueCrypt.exe", modulePath);
	wsprintfW (formatModule, L"%hsTrueCrypt Format.exe", modulePath);

	UnRegisterTypeLib (LIBID_TrueCrypt, 1, 0, 0, SYS_WIN32);
	UnRegisterTypeLib (LIBID_TrueCryptFormat, 1, 0, 0, SYS_WIN32);

	CRegObject ro;
	ro.FinalConstruct ();

	ro.AddReplacement (L"MAIN_MODULE", mainModule);
	ro.AddReplacement (L"FORMAT_MODULE", formatModule);

	wchar_t setupModule[MAX_PATH];
	GetModuleFileNameW (NULL, setupModule, sizeof (setupModule));
	if (ro.ResourceRegister (setupModule, IDR_COMREG, L"REGISTRY") != S_OK)
		goto error;

	if (LoadTypeLib (mainModule, &tl) != S_OK
		|| RegisterTypeLib (tl, mainModule, 0) != S_OK)
		goto error;

	if (LoadTypeLib (formatModule, &tl2) != S_OK
		|| RegisterTypeLib (tl2, formatModule, 0) != S_OK)
		goto error;

	ret = TRUE;
error:
	ro.FinalRelease ();
	return ret;
}


extern "C" BOOL UnregisterComServers (char *modulePath)
{
	BOOL ret;

	if (UnRegisterTypeLib (LIBID_TrueCrypt, 1, 0, 0, SYS_WIN32) != S_OK)
		return FALSE;
	if (UnRegisterTypeLib (LIBID_TrueCryptFormat, 1, 0, 0, SYS_WIN32) != S_OK)
		return FALSE;

	wchar_t module[1024];
	CRegObject ro;
	ro.FinalConstruct ();

	wsprintfW (module, L"%hs\\TrueCrypt.exe", modulePath);
	ro.AddReplacement (L"MAIN_MODULE", module);

	wsprintfW (module, L"%hs\\TrueCrypt Format.exe", modulePath);
	ro.AddReplacement (L"FORMAT_MODULE", module);

	wchar_t setupModule[MAX_PATH];
	GetModuleFileNameW (NULL, setupModule, sizeof (setupModule));

	ret = ro.ResourceUnregister (setupModule, IDR_COMREG, L"REGISTRY") == S_OK;

	ro.FinalRelease ();
	return ret;
}
