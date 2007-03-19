/*
 Copyright (c) TrueCrypt Foundation. All rights reserved.

 Covered by the TrueCrypt License 2.2 the full text of which is contained
 in the file License.txt included in TrueCrypt binary and source code
 distribution packages.
*/

#include <atlcomcli.h>
#include <atlconv.h>
#include <comutil.h>
#include <strsafe.h>
#include <windows.h>
#include "BaseCom.h"
#include "Dlgcode.h"
#include "Format.h"
#include "Progress.h"
#include "TcFormat.h"
#include "FormatCom.h"
#include "FormatCom_h.h"
#include "FormatCom_i.c"

static volatile LONG ObjectCount = 0;
static ITrueCryptFormat *CallBackObj;

class TrueCryptFormat : public ITrueCryptFormat
{

public:
	TrueCryptFormat (DWORD messageThreadId) : RefCount (0),
		MessageThreadId (messageThreadId),
		CallBack (NULL)
	{
		InterlockedIncrement (&ObjectCount);
	}

	~TrueCryptFormat ()
	{
		if (CallBackObj)
			CallBackObj = NULL;

		if (CallBack)
			CallBack->Release ();
			
		if (InterlockedDecrement (&ObjectCount) == 0)
			PostThreadMessage (MessageThreadId, WM_APP, 0, 0);
	}

	virtual ULONG STDMETHODCALLTYPE AddRef ()
	{
		return InterlockedIncrement (&RefCount);
	}

	virtual ULONG STDMETHODCALLTYPE Release ()
	{
		if (!InterlockedDecrement (&RefCount))
		{
			delete this;
			return 0;
		}

		return RefCount;
	}

	virtual HRESULT STDMETHODCALLTYPE QueryInterface (REFIID riid, void **ppvObject)
	{
		if (riid == IID_IUnknown || riid == IID_ITrueCryptFormat)
			*ppvObject = this;
		else
		{
			*ppvObject = NULL;
			return E_NOINTERFACE;
		}

		AddRef ();
		return S_OK;
	}

	virtual BOOL STDMETHODCALLTYPE FormatNtfs (int driveNo, int clusterSize)
	{
		return ::FormatNtfs (driveNo, clusterSize);
	}

	virtual int STDMETHODCALLTYPE AnalyzeHiddenVolumeHost (
		LONG_PTR hwndDlg, int *driveNo, __int64 hiddenVolHostSize, int *realClusterSize, __int64 *nbrFreeClusters)
	{
		return ::AnalyzeHiddenVolumeHost (
			(HWND) hwndDlg, driveNo, hiddenVolHostSize, realClusterSize, nbrFreeClusters);
	}

	virtual int STDMETHODCALLTYPE FormatVolume (
		BSTR volumePath, BOOL bDevice, unsigned __int64 size,
		unsigned __int64 hiddenVolHostSize, Password *password, int cipher, int pkcs5,
		BOOL quickFormat, BOOL sparseFileSwitch, int fileSystem, int clusterSize,
		LONG_PTR hwndDlg, LONG_PTR hDiskKey, LONG_PTR hHeaderKey, BOOL showKeys, BOOL hiddenVol, int *realClusterSize)
	{
		USES_CONVERSION;

		::showKeys = showKeys;
		::hDiskKey = (HWND) hDiskKey;
		::hHeaderKey = (HWND) hHeaderKey;

		return ::FormatVolume (CW2A (volumePath), bDevice, size,
			hiddenVolHostSize, password, cipher, pkcs5, quickFormat, sparseFileSwitch, fileSystem, clusterSize,
			(HWND) hwndDlg, hiddenVol, realClusterSize, TRUE);
	}

	virtual BOOL STDMETHODCALLTYPE UpdateProgressBar (__int64 secNo, BOOL *bThreadCancel)
	{
		if (CallBack == NULL)
			return FALSE;

		*bThreadCancel = CallBack->UpdateProgressBarCallBack (secNo);
		return TRUE;
	}

	virtual BOOL STDMETHODCALLTYPE UpdateProgressBarCallBack (__int64 secNo)
	{
		return ::UpdateProgressBarProc (secNo);
	}

	virtual void STDMETHODCALLTYPE SetCallBack (ITrueCryptFormat *callBack)
	{
		callBack->AddRef ();
		CallBack = callBack;
		CallBackObj = this;
	}

protected:
	DWORD MessageThreadId;
	LONG RefCount;
	ITrueCryptFormat *CallBack;
};


extern "C" BOOL ComServerFormat ()
{
	TrueCryptFactory<TrueCryptFormat> factory (GetCurrentThreadId ());
	DWORD cookie;

	if (IsUacSupported ())
		UacElevated = TRUE;

	if (CoRegisterClassObject (CLSID_TrueCryptFormat, (LPUNKNOWN) &factory,
		CLSCTX_LOCAL_SERVER, REGCLS_SINGLEUSE, &cookie) != S_OK)
		return FALSE;

	MSG msg;
	while (GetMessage (&msg, NULL, 0, 0))
	{
		TranslateMessage (&msg);
		DispatchMessage (&msg);

		if (msg.message == WM_APP
			&& ObjectCount < 1
			&& !factory.IsServerLocked ())
			break;
	}
	CoRevokeClassObject (cookie);

	return TRUE;
}


static BOOL ComGetInstance (HWND hWnd, ITrueCryptFormat **tcServer)
{
	return ComGetInstanceBase (hWnd, CLSID_TrueCryptFormat, IID_ITrueCryptFormat, (void **) tcServer);
}


extern "C" int UacFormatNtfs (HWND hWnd, int driveNo, int clusterSize)
{
	CComPtr<ITrueCryptFormat> tc;
	int r;

	CoInitialize (NULL);

	if (ComGetInstance (hWnd, &tc))
		r = tc->FormatNtfs (driveNo, clusterSize);
	else
		r = 0;

	CoUninitialize ();

	return r;
}


extern "C" int UacAnalyzeHiddenVolumeHost (HWND hwndDlg, int *driveNo, __int64 hiddenVolHostSize, int *realClusterSize, __int64 *nbrFreeClusters)
{
	CComPtr<ITrueCryptFormat> tc;
	int r;

	CoInitialize (NULL);

	if (ComGetInstance (hwndDlg, &tc))
		r = tc->AnalyzeHiddenVolumeHost ((LONG_PTR) hwndDlg, driveNo, hiddenVolHostSize, realClusterSize, nbrFreeClusters);
	else
		r = 0;

	CoUninitialize ();

	return r;
}


extern "C" BOOL UacUpdateProgressBar (__int64 nSecNo, BOOL *bThreadCancel)
{
	if (CallBackObj == NULL)
		return FALSE;

	CallBackObj->UpdateProgressBar (nSecNo, bThreadCancel);
	return TRUE;
}


extern "C" int UacFormatVolume (char *volumePath , BOOL bDevice ,
	unsigned __int64 size , unsigned __int64 hiddenVolHostSize , Password *password , int cipher ,
	int pkcs5 , BOOL quickFormat, BOOL sparseFileSwitch, int fileSystem , int clusterSize,
	HWND hwndDlg , BOOL hiddenVol , int *realClusterSize)
{
	CComPtr<ITrueCryptFormat> tc;
	int r;

	CoInitialize (NULL);

	if (ComGetInstance (hwndDlg, &tc))
	{
		TrueCryptFormat cb (GetCurrentThreadId ());
		cb.AddRef();
		tc->SetCallBack (&cb);

		r = tc->FormatVolume (CComBSTR (volumePath), bDevice,
			size, hiddenVolHostSize, password, cipher, pkcs5, quickFormat, sparseFileSwitch,
			fileSystem, clusterSize, (LONG_PTR) hwndDlg, (LONG_PTR) hDiskKey, (LONG_PTR) hHeaderKey, showKeys, hiddenVol, realClusterSize);
	}
	else
		r = ERR_DONT_REPORT;

	CoUninitialize ();

	return r;
}

