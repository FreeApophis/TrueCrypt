/* Copyright (C) 2004 TrueCrypt Team, truecrypt.org
   This product uses components written by Paul Le Roux <pleroux@swprofessionals.com> */

#include "tcdefs.h"

#ifndef NT4_DRIVER
#pragma VxD_LOCKED_CODE_SEG
#pragma VxD_LOCKED_DATA_SEG
#endif

#include "crypto.h"
#include "fat.h"
#include "volumes.h"
#include "apidrvr.h"

#include "cache.h"

#define CACHE_SIZE 4

char szDriverPassword[CACHE_SIZE][MAX_PASSWORD + 1];
int nDriverPasswordLen[CACHE_SIZE];
int nPasswordIdx = 0;
int cacheEmpty = 1;

int
VolumeReadHeaderCache (BOOL bCache, char *dev, char *lpszPassword, int nPasswordLen,
		       PCRYPTO_INFO * retInfo)
{
	int nReturnCode = ERR_PASSWORD_WRONG;
	int i;

	/* Attempt to recognize volume using mount password */
	if (nPasswordLen > 0)
	{
		nReturnCode = VolumeReadHeader (dev, lpszPassword, retInfo);

		/* Save mount passwords back into cache if asked to do so */
		if (bCache == TRUE && nReturnCode == 0)
		{
			for (i = 0; i < CACHE_SIZE; i++)
			{
				if (nDriverPasswordLen[i] > 0 && nDriverPasswordLen[i] == nPasswordLen &&
					memcmp (szDriverPassword[i], lpszPassword, nPasswordLen) == 0)
					break;
			}

			if (i == CACHE_SIZE)
			{
				/* Store the password */
				memcpy (szDriverPassword[nPasswordIdx], lpszPassword, nPasswordLen);

				/* Add in the null as we made room for this */
				szDriverPassword[nPasswordIdx][nPasswordLen] = 0;

				/* Save the length for later */
				nDriverPasswordLen[nPasswordIdx] = nPasswordLen;

				/* Try another slot */
				nPasswordIdx = (nPasswordIdx + 1) % CACHE_SIZE;

				cacheEmpty = 0;
			}
		}
	}
	else if (!cacheEmpty)
	{
		/* Attempt to recognize volume using cached passwords */
		for (i = 0; i < CACHE_SIZE; i++)
		{
			if (nDriverPasswordLen[i] > 0)
			{
				nReturnCode = VolumeReadHeader (dev, szDriverPassword[i], retInfo);

				if (nReturnCode != ERR_PASSWORD_WRONG)
					break;
			}

		}
	}

	return nReturnCode;
}

void
WipeCache ()
{
	burn (szDriverPassword, sizeof (szDriverPassword));
	burn (nDriverPasswordLen, sizeof (nDriverPasswordLen));
	nPasswordIdx = 0;
	cacheEmpty = 1;
}
