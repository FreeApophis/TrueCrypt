/*
 Copyright (c) TrueCrypt Foundation. All rights reserved.

 Covered by the TrueCrypt License 2.3 the full text of which is contained
 in the file License.txt included in TrueCrypt binary and source code
 distribution packages.
*/

#include <atlcomcli.h>
#include <strsafe.h>
#include <windows.h>
#include "BaseCom.h"
#include "Dlgcode.h"


HRESULT CreateElevatedComObject (HWND hwnd, REFGUID guid, REFIID iid, void **ppv)
{
    WCHAR monikerName[1024];
    WCHAR clsid[1024];
    BIND_OPTS3 bo;

    StringFromGUID2 (guid, clsid, sizeof (clsid) / 2);
	swprintf_s (monikerName, sizeof (monikerName) / 2, L"Elevation:Administrator!new:%s", clsid);

    memset (&bo, 0, sizeof (bo));
    bo.cbStruct = sizeof (bo);
    bo.hwnd = hwnd;
    bo.dwClassContext = CLSCTX_LOCAL_SERVER;

    return CoGetObject (monikerName, &bo, iid, ppv);
}


BOOL ComGetInstanceBase (HWND hWnd, REFCLSID clsid, REFIID iid, void **tcServer)
{
	BOOL r;

	if (IsUacSupported ())
		r = CreateElevatedComObject (hWnd, clsid, iid, tcServer) == S_OK;
	else
		r = CoCreateInstance (clsid, NULL, CLSCTX_LOCAL_SERVER, iid, tcServer) == S_OK;

	if (!r)
		Error ("UAC_INIT_ERROR");

	return r;
}

