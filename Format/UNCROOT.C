/* The source code contained in this file has been derived from the source code
   of Encryption for the Masses 2.02a by Paul Le Roux. Modifications and
   additions to that source code contained in this file are Copyright (c) 2004
   TrueCrypt Team and Copyright (c) 2004 TrueCrypt Foundation. Unmodified
   parts are Copyright (c) 1998-99 Paul Le Roux. This is a TrueCrypt Foundation
   release. Please see the file license.txt for full license details. */

#include "TCdefs.h"

#include <ctype.h>

#include "uncroot.h"

char *
MakeRootName (char *lpszDest, char *lpszSrc)
{
	strcpy (lpszDest, lpszSrc);

	if (lpszDest[1] == ':' && isalpha (lpszDest[0]))
		lpszDest[3] = 0;/* Straight drive letter */
	else
	{
		if (lpszDest[0] == '\\' && lpszDest[1] == '\\')
		{
			char *p = strchr (lpszDest + 2, '\\');
			if (p != NULL)
			{
				p = strchr (p + 1, '\\');
				if (p != NULL)
					*(p + 1) = 0;	/* UNC + path */
				else
				{
					strcat (lpszDest, "\\");	/* UNC + share name no
									   path */
				}
			}
			else
				lpszDest[1] = 0;
		}
		else
			lpszDest[1] = 0;	/* Default drive letter */
	}

	return lpszDest;
}
