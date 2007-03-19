/*
 Copyright (c) TrueCrypt Foundation. All rights reserved.

 Covered by the TrueCrypt License 2.2 the full text of which is contained
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
    BIND_OPTS3 bo;
    WCHAR wszCLSID[50];
    WCHAR wszMonikerName[300];

    StringFromGUID2 (guid, wszCLSID, sizeof (wszCLSID) / sizeof (wszCLSID[0]));
    
	HRESULT hr = StringCchPrintfW (
		wszMonikerName, sizeof (wszMonikerName) / sizeof (wszMonikerName[0]),
		L"Elevation:Administrator!new:%s", wszCLSID);

    if (FAILED(hr))
        return hr;

    memset (&bo, 0, sizeof (bo));
    bo.cbStruct = sizeof (bo);
    bo.hwnd = hwnd;
    bo.dwClassContext = CLSCTX_LOCAL_SERVER;

    return CoGetObject (wszMonikerName, &bo, iid, ppv);
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

