/* The source code contained in this file has been derived from the source code
   of Encryption for the Masses 2.02a by Paul Le Roux. Modifications and
   additions to that source code contained in this file are Copyright (c) 2004-2005
   TrueCrypt Foundation and Copyright (c) 2004 TrueCrypt Team. Unmodified
   parts are Copyright (c) 1998-99 Paul Le Roux. This is a TrueCrypt Foundation
   release. Please see the file license.txt for full license details. */

#include "TCdefs.h"
#include "combo.h"

#include <time.h>

#define SIZEOF_MRU_LIST 8

void
AddComboItem (HWND hComboBox, char *lpszFileName)
{
	LPARAM nIndex;

	nIndex = SendMessage (hComboBox, CB_FINDSTRINGEXACT, (WPARAM) - 1,
			      (LPARAM) & lpszFileName[0]);

	if (nIndex == CB_ERR && *lpszFileName)
	{
		long lTime = time (NULL);
		nIndex = SendMessage (hComboBox, CB_ADDSTRING, 0, (LPARAM) & lpszFileName[0]);
		if (nIndex != CB_ERR)
			SendMessage (hComboBox, CB_SETITEMDATA, nIndex, (LPARAM) lTime);
	}

	if (nIndex != CB_ERR && *lpszFileName)
		nIndex = SendMessage (hComboBox, CB_SETCURSEL, nIndex, 0);

	if (*lpszFileName == 0)
	{
		SendMessage (hComboBox, CB_SETCURSEL, (WPARAM) - 1, 0);
	}
}


LPARAM
MoveEditToCombo (HWND hComboBox)
{
	char szTmp[256] =
	{0};

	GetWindowText (hComboBox, szTmp, sizeof (szTmp));

	if (strlen (szTmp) > 0)
	{
		LPARAM nIndex = SendMessage (hComboBox, CB_FINDSTRINGEXACT, (WPARAM) - 1,
					     (LPARAM) & szTmp[0]);
		if (nIndex == CB_ERR)
		{
			long lTime = time (NULL);
			nIndex = SendMessage (hComboBox, CB_ADDSTRING, 0, (LPARAM) & szTmp[0]);
			if (nIndex != CB_ERR)
				SendMessage (hComboBox, CB_SETITEMDATA, nIndex, (DWORD) lTime);
		}
		else
		{
			long lTime = time (NULL);
			SendMessage (hComboBox, CB_SETITEMDATA, nIndex, (DWORD) lTime);
		}

		return nIndex;
	}

	return SendMessage (hComboBox, CB_GETCURSEL, 0, 0);
}

int
GetOrderComboIdx (HWND hComboBox, int *nIdxList, int nElems)
{
	int x = (int) SendMessage (hComboBox, CB_GETCOUNT, 0, 0);
	if (x != CB_ERR)
	{
		int i, nHighIdx = CB_ERR;
		long lHighTime = -1;

		for (i = 0; i < x; i++)
		{
			long lTime = SendMessage (hComboBox, CB_GETITEMDATA, (WPARAM) i, 0);
			if (lTime > lHighTime)
			{
				int n;
				for (n = 0; n < nElems; n++)
					if (nIdxList[n] == i)
						break;
				if (n == nElems)
				{
					lHighTime = lTime;
					nHighIdx = i;
				}
			}
		}

		return nHighIdx;
	}

	return CB_ERR;
}

LPARAM
UpdateComboOrder (HWND hComboBox)
{
	LPARAM nIndex;

	nIndex = SendMessage (hComboBox, CB_GETCURSEL, 0, 0);

	if (nIndex != CB_ERR)
	{
		long lTime = time (NULL);
		nIndex = SendMessage (hComboBox, CB_SETITEMDATA, (WPARAM) nIndex,
				      (LPARAM) lTime);
	}

	return nIndex;
}

void
LoadCombo (HWND hComboBox, char *lpszKey)
{
	int i;

	for (i = 0; i < SIZEOF_MRU_LIST; i++)
	{
		char szTmp[256], szKey[32], szTmp2[32];

		*szTmp = 0;

		sprintf (szTmp2, "%s%s", lpszKey, "%d");
		sprintf (szKey, szTmp2, i);
		ReadRegistryString (szKey, "", szTmp, sizeof (szTmp));

		AddComboItem (hComboBox, szTmp);
	}

	SendMessage (hComboBox, CB_SETCURSEL, 0, 0);

}

void
DumpCombo (HWND hComboBox, char *lpszKey, int bClear)
{
	int i, nComboIdx[SIZEOF_MRU_LIST];

	/* combo list part:- get mru items */
	for (i = 0; i < SIZEOF_MRU_LIST; i++)
		nComboIdx[i] = bClear ? CB_ERR : GetOrderComboIdx (hComboBox, &nComboIdx[0], i);

	/* combo list part:- write out mru items */
	for (i = 0; i < SIZEOF_MRU_LIST; i++)
	{
		char szTmp[256], szKey[32], szTmp2[32];

		*szTmp = 0;

		if (nComboIdx[i] != CB_ERR)
			SendMessage (hComboBox, CB_GETLBTEXT, nComboIdx[i], (LPARAM) & szTmp[0]);

		sprintf (szTmp2, "%s%s", lpszKey, "%d");
		sprintf (szKey, szTmp2, i);

		WriteRegistryString (szKey, szTmp);
	}
}

void
ClearCombo (HWND hComboBox)
{
	int i;
	for (i = 0; i < SIZEOF_MRU_LIST; i++)
	{
		SendMessage (hComboBox, CB_DELETESTRING, 0, 0);
	}
}

int
IsComboEmpty (HWND hComboBox)
{
	return SendMessage (hComboBox, CB_GETCOUNT, 0, 0) < 1;
}
