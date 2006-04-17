/* Legal Notice: The source code contained in this file has been derived from
   the source code of Encryption for the Masses 2.02a, which is Copyright (c)
   1998-99 Paul Le Roux and which is covered by the 'License Agreement for
   Encryption for the Masses'. Modifications and additions to that source code
   contained in this file are Copyright (c) 2004-2006 TrueCrypt Foundation and
   Copyright (c) 2004 TrueCrypt Team, and are covered by TrueCrypt License 2.0
   the full text of which is contained in the file License.txt included in
   TrueCrypt binary and source code distribution archives.  */

#include "Tcdefs.h"
#include "Combo.h"
#include "Dlgcode.h"
#include "Xml.h"

#include <time.h>

#define SIZEOF_MRU_LIST 20

void
AddComboItem (HWND hComboBox, char *lpszFileName)
{
	LPARAM nIndex;

	nIndex = SendMessage (hComboBox, CB_FINDSTRINGEXACT, (WPARAM) - 1,
			      (LPARAM) & lpszFileName[0]);

	if (nIndex == CB_ERR && *lpszFileName)
	{
		time_t lTime = time (NULL);
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
			time_t lTime = time (NULL);
			nIndex = SendMessage (hComboBox, CB_ADDSTRING, 0, (LPARAM) & szTmp[0]);
			if (nIndex != CB_ERR)
				SendMessage (hComboBox, CB_SETITEMDATA, nIndex, (DWORD) lTime);
		}
		else
		{
			time_t lTime = time (NULL);
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
		time_t lHighTime = -1;

		for (i = 0; i < x; i++)
		{
			time_t lTime = SendMessage (hComboBox, CB_GETITEMDATA, (WPARAM) i, 0);
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
		time_t lTime = time (NULL);
		nIndex = SendMessage (hComboBox, CB_SETITEMDATA, (WPARAM) nIndex,
				      (LPARAM) lTime);
	}

	return nIndex;
}

void
LoadCombo (HWND hComboBox)
{
	DWORD size;
	char *history = LoadFile (GetConfigPath (FILE_HISTORY), &size);
	char *xml = history;
	char volume[MAX_PATH];

	if (xml == NULL) return;

	while (xml = XmlFindElement (xml, "volume"))
	{
		XmlNodeText (xml, volume, sizeof (volume));
		AddComboItem (hComboBox, volume);
		xml++;
	}

	SendMessage (hComboBox, CB_SETCURSEL, 0, 0);

	free (history);
}

void
DumpCombo (HWND hComboBox, int bClear)
{
	FILE *f;
	int i, nComboIdx[SIZEOF_MRU_LIST];

	if (bClear)
	{
		DeleteFile (GetConfigPath (FILE_HISTORY));
		return;
	}

	f = fopen (GetConfigPath (FILE_HISTORY), "w");
	if (f == NULL) return;

	XmlWriteHeader (f);
	fputs ("\n\t<history>", f);

	/* combo list part:- get mru items */
	for (i = 0; i < SIZEOF_MRU_LIST; i++)
		nComboIdx[i] = GetOrderComboIdx (hComboBox, &nComboIdx[0], i);

	/* combo list part:- write out mru items */
	for (i = 0; i < SIZEOF_MRU_LIST; i++)
	{
		char szTmp[MAX_PATH] = { 0 };
		 
		if (SendMessage (hComboBox, CB_GETLBTEXTLEN, nComboIdx[i], 0) < sizeof (szTmp))
			SendMessage (hComboBox, CB_GETLBTEXT, nComboIdx[i], (LPARAM) & szTmp[0]);

		if (szTmp[0] != 0)
			fprintf (f, "\n\t\t<volume>%s</volume>", szTmp);
	}

	fputs ("\n\t</history>", f);
	XmlWriteFooter (f);
	fclose (f);
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
