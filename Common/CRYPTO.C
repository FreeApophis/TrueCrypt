/* The source code contained in this file has been derived from the source code
   of Encryption for the Masses 2.02a by Paul Le Roux. Modifications and
   additions to that source code contained in this file are Copyright (c) 2004
   TrueCrypt Team and Copyright (c) 2004 TrueCrypt Foundation. Unmodified
   parts are Copyright (c) 1998-99 Paul Le Roux. This is a TrueCrypt Foundation
   release. Please see the file license.txt for full license details. */

#include "TCdefs.h"
#include "crypto.h"
#include "random.h"

PCRYPTO_INFO
crypto_open ()
{
	/* Do the crt allocation */
	PCRYPTO_INFO cryptoInfo = TCalloc (sizeof (CRYPTO_INFO));
#ifndef DEVICE_DRIVER
	VirtualLock (cryptoInfo, sizeof (CRYPTO_INFO));
#endif

	if (cryptoInfo == NULL)
		return NULL;

	cryptoInfo->cipher = -1;
	return cryptoInfo;
}

void
crypto_loadkey (PKEY_INFO keyInfo, char *lpszUserKey, int nUserKeyLen)
{
	keyInfo->keyLength = nUserKeyLen;
	burn (keyInfo->userKey, sizeof (keyInfo->userKey));
	memcpy (keyInfo->userKey, lpszUserKey, nUserKeyLen);
}

void
crypto_close (PCRYPTO_INFO cryptoInfo)
{
	burn (cryptoInfo, sizeof (CRYPTO_INFO));
#ifndef DEVICE_DRIVER
	VirtualUnlock (cryptoInfo, sizeof (CRYPTO_INFO));
#endif
	TCfree (cryptoInfo);
}

int
get_block_size (int cipher)
{
	if (cipher == AES)
		return 16;
	else
		return 8;
}

int
get_key_size (int cipher)
{
	if (cipher == DES56)
		return 7;
	else if (cipher == IDEA)
		return 16;
	else if (cipher == BLOWFISH)
		return 56;
	else if (cipher == AES)
		return 32;
	else if (cipher == TRIPLEDES)
		return 21;
	else if (cipher == CAST)
		return 16;
	else
	{
		return 0;
	}
}

char *
get_cipher_name (int cipher)
{
	if (cipher == BLOWFISH)
		return "Blowfish";
	if (cipher == AES)
		return "AES";
	else if (cipher == IDEA)
		return "IDEA";
	else if (cipher == DES56)
		return "DES";
	else if (cipher == TRIPLEDES)
		return "Triple-DES";
	else if (cipher == CAST)
		return "CAST";
	else if (cipher == NONE)
		return "None";
	else
		return "Unknown";
}

char * get_hash_name (int pkcs5)
{
	switch (pkcs5)
	{
	case SHA1:		return "HMAC-SHA-1";
	case RIPEMD160:	return "HMAC-RIPEMD-160";
	default:		return "Unknown";
	}
}
