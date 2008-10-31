/*
 Legal Notice: Some portions of the source code contained in this file were
 derived from the source code of Encryption for the Masses 2.02a, which is
 Copyright (c) 1998-2000 Paul Le Roux and which is governed by the 'License
 Agreement for Encryption for the Masses'. Modifications and additions to
 the original source code (contained in this file) and all other portions of
 this file are Copyright (c) 2003-2008 TrueCrypt Foundation and are governed
 by the TrueCrypt License 2.6 the full text of which is contained in the
 file License.txt included in TrueCrypt binary and source code distribution
 packages. */

#include "Tcdefs.h"

#include <malloc.h>
#include <ctype.h>
#include "Cmdline.h"

#include "Resource.h"
#include "Crypto.h"
#include "Apidrvr.h"
#include "Dlgcode.h"
#include "Language.h"

/* Except in response to the WM_INITDIALOG message, the dialog box procedure
   should return nonzero if it processes the message, and zero if it does
   not. - see DialogProc */
BOOL CALLBACK CommandHelpDlgProc (HWND hwndDlg, UINT msg, WPARAM wParam, LPARAM lParam)
{
	if (lParam);		/* remove warning */
	if (wParam);		/* remove warning */

	switch (msg)
	{
	case WM_INITDIALOG:
		{
		char * tmp = err_malloc(8192);
		char tmp2[MAX_PATH * 2];
		argumentspec *as;
		int i;

		LocalizeDialog (hwndDlg, "IDD_COMMANDHELP_DLG");

		as = (argumentspec*) lParam;

		*tmp = 0;

		strcpy (tmp, "Command line options:\n\n");
		for (i = 0; i < as->arg_cnt; i ++)
		{
			if (!as->args[i].Internal)
			{
				sprintf(tmp2, "%s\t%s\n", as->args[i].short_name, as->args[i].long_name);
				strcat(tmp,tmp2);
			}
		}

		SetWindowText (GetDlgItem (hwndDlg, IDC_COMMANDHELP_TEXT), (char*) tmp);
		return 1;
		}

	case WM_COMMAND:
		EndDialog (hwndDlg, IDOK);
		return 1;
	case WM_CLOSE:
		EndDialog (hwndDlg, 0);
		return 1;
	}

	return 0;
}

int Win32CommandLine (char *lpszCommandLine, char ***lpszArgs)
{
	int i = 0, k = 0, x = 0, nValid = TRUE;
	int nLen = strlen (lpszCommandLine);
	int nArrSize = 1024;
	char szTmp[MAX_PATH * 2];

	*lpszArgs = malloc (sizeof (char *)* nArrSize);

	if (*lpszArgs == NULL)
		return 0;

	while (i < nLen)
	{
		if (lpszCommandLine[i] == ' ')
		{
			if (k > 0)
			{
				szTmp[k] = 0;
				(*lpszArgs)[x] = _strdup (szTmp);
				if ((*lpszArgs)[x] == NULL)
				{
					free (*lpszArgs);
					return 0;
				}
				x++;
				k = 0;
				if (x == nArrSize)
				{
					break;
				}
			}
			i++;
			continue;
		}
		if (lpszCommandLine[i] == '"')
		{
			i++;
			while (i < nLen)
			{
				if (lpszCommandLine[i] == '"')
					break;
				if (k < sizeof (szTmp))
					szTmp[k++] = lpszCommandLine[i++];
				else
				{
					free (*lpszArgs);
					return 0;
				}
			}

			if (lpszCommandLine[i] != '"')
			{
				nValid = FALSE;
				break;
			}
		}
		else
		{
			if (k < sizeof (szTmp))
				szTmp[k++] = lpszCommandLine[i];
			else
			{
				free (*lpszArgs);
				return 0;
			}
		}

		i++;
	}

	if (nValid == FALSE)
	{
		free (*lpszArgs);
		return 0;
	}
	else if (k > 0)
	{
		szTmp[k] = 0;
		(*lpszArgs)[x] = _strdup (szTmp);
		if ((*lpszArgs)[x] == NULL)
		{
			free (*lpszArgs);
			return 0;
		}
		x++;
		k = 0;
	}
	if (!x)
	{
		free (*lpszArgs);
		return 0;
	}
	return x;
}

int GetArgSepPosOffset (char *lpszArgument)
{
	if (lpszArgument[0] == '/')
		return 1;
	else if (lpszArgument[0] == '-' && lpszArgument[1] == '-')
		return 2;
	else if (lpszArgument[0] == '-')
		return 1;
	else
		return 0;
}

int GetArgumentID (argumentspec *as, char *lpszArgument, int *nArgPos)
{
	char szTmp[MAX_PATH * 2];
	int i;

	i = strlen (lpszArgument);
	szTmp[i] = 0;
	while (--i >= 0)
	{
		szTmp[i] = (char) tolower (lpszArgument[i]);
	}

	for (i = 0; i < as->arg_cnt; i++)
	{
		size_t k;

		k = strlen (as->args[i].long_name);
		if (memcmp (as->args[i].long_name, szTmp, k * sizeof (char)) == 0)
		{
			int x;
			for (x = i + 1; x < as->arg_cnt; x++)
			{
				size_t m;

				m = strlen (as->args[x].long_name);
				if (memcmp (as->args[x].long_name, szTmp, m * sizeof (char)) == 0)
				{
					break;
				}
			}

			if (x == as->arg_cnt)
			{
				if (strlen (lpszArgument) != k)
					*nArgPos = k;
				else
					*nArgPos = 0;
				return as->args[i].Id;
			}
		}
	}

	for (i = 0; i < as->arg_cnt; i++)
	{
		size_t k;

		if (as->args[i].short_name[0] == 0)
			continue;

		k = strlen (as->args[i].short_name);
		if (memcmp (as->args[i].short_name, szTmp, k * sizeof (char)) == 0)
		{
			int x;
			for (x = i + 1; x < as->arg_cnt; x++)
			{
				size_t m;

				if (as->args[x].short_name[0] == 0)
					continue;

				m = strlen (as->args[x].short_name);
				if (memcmp (as->args[x].short_name, szTmp, m * sizeof (char)) == 0)
				{
					break;
				}
			}

			if (x == as->arg_cnt)
			{
				if (strlen (lpszArgument) != k)
					*nArgPos = k;
				else
					*nArgPos = 0;
				return as->args[i].Id;
			}
		}
	}


	return -1;
}

int GetArgumentValue (char **lpszCommandLineArgs, int nArgPos, int *nArgIdx,
		  int nNoCommandLineArgs, char *lpszValue, int nValueSize)
{
	*lpszValue = 0;

	if (nArgPos)
	{
		/* Handles the case of no space between parameter code and
		   value */
		strncpy (lpszValue, &lpszCommandLineArgs[*nArgIdx][nArgPos], nValueSize);
		lpszValue[nValueSize - 1] = 0;
		return HAS_ARGUMENT;
	}
	else if (*nArgIdx + 1 < nNoCommandLineArgs)
	{
		int x = GetArgSepPosOffset (lpszCommandLineArgs[*nArgIdx + 1]);
		if (x == 0)
		{
			/* Handles the case of space between parameter code
			   and value */
			strncpy (lpszValue, &lpszCommandLineArgs[*nArgIdx + 1][x], nValueSize);
			lpszValue[nValueSize - 1] = 0;
			(*nArgIdx)++;
			return HAS_ARGUMENT;
		}
	}

	return HAS_NO_ARGUMENT;
}
