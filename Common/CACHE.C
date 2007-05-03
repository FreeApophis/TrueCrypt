/*
 Legal Notice: The source code contained in this file has been derived from
 the source code of Encryption for the Masses 2.02a, which is Copyright (c)
 Paul Le Roux and which is covered by the 'License Agreement for Encryption
 for the Masses'. Modifications and additions to that source code contained
 in this file are Copyright (c) TrueCrypt Foundation and are covered by the
 TrueCrypt License 2.3 the full text of which is contained in the file
 License.txt included in TrueCrypt binary and source code distribution
 packages. */

#include "Tcdefs.h"

#ifndef NT4_DRIVER
#pragma VxD_LOCKED_CODE_SEG
#pragma VxD_LOCKED_DATA_SEG
#endif

#include "Crypto.h"
#include "Fat.h"
#include "Volumes.h"
#include "Apidrvr.h"
#include "Common.h"
#include "Cache.h"

Password CachedPasswords[CACHE_SIZE];
int cacheEmpty = 1;
static int nPasswordIdx = 0;

int
VolumeReadHeaderCache (BOOL bCache, char *header, Password *password, PCRYPTO_INFO *retInfo)
{
	int nReturnCode = ERR_PASSWORD_WRONG;
	int i;

	/* Attempt to recognize volume using mount password */
	if (password->Length > 0)
	{
		nReturnCode = VolumeReadHeader (header, password, retInfo);

		/* Save mount passwords back into cache if asked to do so */
		if (bCache && (nReturnCode == 0 || nReturnCode == ERR_CIPHER_INIT_WEAK_KEY))
		{
			for (i = 0; i < CACHE_SIZE; i++)
			{
				if (memcmp (&CachedPasswords[i], password, sizeof (Password)) == 0)
					break;
			}

			if (i == CACHE_SIZE)
			{
				/* Store the password */
				CachedPasswords[nPasswordIdx] = *password;

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
			if (CachedPasswords[i].Length > 0)
			{
				nReturnCode = VolumeReadHeader (header, &CachedPasswords[i], retInfo);

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
	burn (CachedPasswords, sizeof (CachedPasswords));
	nPasswordIdx = 0;
	cacheEmpty = 1;
}
