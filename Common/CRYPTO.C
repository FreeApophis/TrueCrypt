/* Legal Notice: The source code contained in this file has been derived from
   the source code of Encryption for the Masses 2.02a, which is Copyright (c)
   1998-99 Paul Le Roux and which is covered by the 'License Agreement for
   Encryption for the Masses'. Modifications and additions to that source code
   contained in this file are Copyright (c) 2004-2005 TrueCrypt Foundation and
   Copyright (c) 2004 TrueCrypt Team, and are covered by TrueCrypt License 2.0
   the full text of which is contained in the file License.txt included in
   TrueCrypt binary and source code distribution archives.  */

#include "Tcdefs.h"
#include "Crypto.h"
#include "Crc.h"
#include "Endian.h"

#ifdef LINUX_DRIVER
#include <linux/string.h>
#endif

/* Update the following when adding a new cipher or EA:

   Crypto.h:
     ID #define
     MAX_EXPANDED_KEY #define

   Crypto.c:
     Ciphers[]
     EncryptionAlgorithms[]
     CipherInit()
     EncipherBlock()
     DecipherBlock()

*/

// Cipher configuration
static Cipher Ciphers[] =
{
//								Block Size	Key Size	Key Schedule Size
//	  ID		Name			(Bytes)		(Bytes)		(Bytes)
	{ AES,		"AES",			16,			32,			sizeof(aes_encrypt_ctx)+sizeof(aes_decrypt_ctx)	},
	{ BLOWFISH,	"Blowfish",		8,			56,			4168											},
	{ CAST,		"CAST5",		8,			16,			128												},
	{ DES56,	"DES",			8,			7,			128												},
	{ SERPENT,	"Serpent",		16,			32,			140*4											},
	{ TRIPLEDES,"Triple DES",	8,			8*3,		128*3											},
	{ TWOFISH,	"Twofish",		16,			32,			TWOFISH_KS										},
	{ 0,		0,				0,			0,			0												}
};

// Encryption algorithm configuration
static EncryptionAlgorithm EncryptionAlgorithms[] =
{
	//  Cipher(s)                     Mode
	{ { 0,						0 } , 0			},	// (must be null)
	{ { AES,					0 } , CBC		},	// AES
	{ { BLOWFISH,				0 } , CBC		},	// Blowfish
	{ { CAST,					0 } , CBC		},	// CAST5
	{ { SERPENT,				0 } , CBC		},	// Serpent
	{ { TRIPLEDES,				0 } , CBC		},	// Triple DES
	{ { TWOFISH,				0 } , CBC		},	// Twofish
	{ { BLOWFISH, AES,			0 } , INNER_CBC },	// AES-Blowfish
	{ { SERPENT, BLOWFISH, AES,	0 } , INNER_CBC },	// AES-Blowfish-Serpent
	{ { TWOFISH, AES,			0 } , OUTER_CBC },	// AES-Twofish
	{ { SERPENT, TWOFISH, AES,	0 } , OUTER_CBC },	// AES-Twofish-Serpent
	{ { AES, SERPENT,			0 } , OUTER_CBC },	// Serpent-AES
	{ { AES, TWOFISH, SERPENT,	0 } , OUTER_CBC },	// Serpent-Twofish-AES
	{ { SERPENT, TWOFISH,		0 } , OUTER_CBC },	// Twofish-Serpent
	{ { 0,						0 } , 0			}	// (must be null)
};

/* Return values: 0 = success, ERR_CIPHER_INIT_FAILURE (fatal), ERR_CIPHER_INIT_WEAK_KEY (non-fatal) */
int CipherInit (int cipher, unsigned char *key, unsigned char *ks)
{
	int retVal = 0;

	switch (cipher)
	{
	case BLOWFISH:
		BF_set_key ((BF_KEY *)ks, CipherGetKeySize(BLOWFISH), key);
		break;

	case AES:
		if (aes_encrypt_key(key, CipherGetKeySize(AES), (aes_encrypt_ctx *) ks) != aes_good)
			return ERR_CIPHER_INIT_FAILURE;

		if (aes_decrypt_key(key, CipherGetKeySize(AES), (aes_decrypt_ctx *) (ks + sizeof(aes_encrypt_ctx))) != aes_good)
			return ERR_CIPHER_INIT_FAILURE;

		break;

	case DES56:		
		/* Included for testing purposes only */
		switch (des_key_sched ((des_cblock *) key, (struct des_ks_struct *) ks))
		{
		case -1:
			return ERR_CIPHER_INIT_FAILURE;
		case -2:
			retVal = ERR_CIPHER_INIT_WEAK_KEY;		// Non-fatal error
			break;
		}
		break;

	case CAST:
		CAST_set_key((CAST_KEY *) ks, CipherGetKeySize(CAST), key);
		break;

	case SERPENT:
		serpent_set_key (key, CipherGetKeySize(SERPENT) * 8, ks);
		break;

	case TRIPLEDES:
		switch (des_key_sched ((des_cblock *) key, (struct des_ks_struct *) ks))
		{
		case -1:
			return ERR_CIPHER_INIT_FAILURE;
		case -2:
			retVal = ERR_CIPHER_INIT_WEAK_KEY;		// Non-fatal error
			break;
		}
		switch (des_key_sched ((des_cblock *) ((char*)(key)+8), (struct des_ks_struct *) (ks + CipherGetKeyScheduleSize (DES56))))
		{
		case -1:
			return ERR_CIPHER_INIT_FAILURE;
		case -2:
			retVal = ERR_CIPHER_INIT_WEAK_KEY;		// Non-fatal error
			break;
		}
		switch (des_key_sched ((des_cblock *) ((char*)(key)+16), (struct des_ks_struct *) (ks + CipherGetKeyScheduleSize (DES56) * 2)))
		{
		case -1:
			return ERR_CIPHER_INIT_FAILURE;
		case -2:
			retVal = ERR_CIPHER_INIT_WEAK_KEY;		// Non-fatal error
			break;
		}
		break;

	case TWOFISH:
		twofish_set_key ((TwofishInstance *)ks, (const u4byte *)key, CipherGetKeySize(TWOFISH) * 8);
		break;

	}
	return retVal;
}

void EncipherBlock(int cipher, void *data, void *ks)
{
	switch (cipher)
	{
	case BLOWFISH:		BF_ecb_le_encrypt (data, data, ks, 1); break;
	case AES:			aes_encrypt (data, data, ks); break;
	case DES56:			des_encrypt (data, ks, 1); break;
	case CAST:			CAST_ecb_encrypt (data, data, ks, 1); break;
	case SERPENT:		serpent_encrypt (data, data, ks); break;
	case TRIPLEDES:		des_ecb3_encrypt (data, data, ks,
						(void*)((char*) ks + CipherGetKeyScheduleSize (DES56)), (void*)((char*) ks + CipherGetKeyScheduleSize (DES56) * 2), 1); break;
	case TWOFISH:		twofish_encrypt (ks, data, data); break;
	}
}

void DecipherBlock(int cipher, void *data, void *ks)
{
	switch (cipher)
	{
	case BLOWFISH:	BF_ecb_le_encrypt (data, data, ks, 0); break;
	case AES:		aes_decrypt (data, data, (void *) ((char *) ks + sizeof(aes_encrypt_ctx))); break;
	case DES56:		des_encrypt (data, ks, 0); break;
	case CAST:		CAST_ecb_encrypt (data, data, ks,0); break;
	case SERPENT:	serpent_decrypt (data, data, ks); break;
	case TRIPLEDES:	des_ecb3_encrypt (data, data, ks,
					(void*)((char*) ks + CipherGetKeyScheduleSize (DES56)),
					(void*)((char*) ks + CipherGetKeyScheduleSize (DES56) * 2), 0); break;
	case TWOFISH:	twofish_decrypt (ks, data, data); break;
	}
}

// Ciphers support

Cipher *CipherGet (int id)
{
	int i;
	for (i = 0; Ciphers[i].Id != 0; i++)
		if (Ciphers[i].Id == id)
			return &Ciphers[i];

	return 0;
}

char *CipherGetName (int cipherId)
{
	return CipherGet (cipherId) -> Name;
}

int CipherGetBlockSize (int cipherId)
{
	return CipherGet (cipherId) -> BlockSize;
}

int CipherGetKeySize (int cipherId)
{
	return CipherGet (cipherId) -> KeySize;
}

int CipherGetKeyScheduleSize (int cipherId)
{
	return CipherGet (cipherId) -> KeyScheduleSize;
}


// Encryption algorithms support

int EAGetFirst ()
{
	return 1;
}

// Returns number of EAs
int EAGetCount (void)
{
	int ea, count = 0;

	for (ea = EAGetFirst (); ea != 0; ea = EAGetNext (ea))
	{
		count++;
	}
	return count;
}

int EAGetNext (int previousEA)
{
	int id = previousEA + 1;
	if (EncryptionAlgorithms[id].Ciphers[0] != 0) return id;
	return 0;
}

/* Return values: 0 = success, ERR_CIPHER_INIT_FAILURE (fatal), ERR_CIPHER_INIT_WEAK_KEY (non-fatal) */
int EAInit (int ea, unsigned char *key, unsigned char *ks)
{
	int c, retVal = 0;

	for (c = EAGetFirstCipher (ea); c != 0; c = EAGetNextCipher (ea, c))
	{
		switch (CipherInit (c, key, ks))
		{
		case ERR_CIPHER_INIT_FAILURE:
			return ERR_CIPHER_INIT_FAILURE;

		case ERR_CIPHER_INIT_WEAK_KEY:
			retVal = ERR_CIPHER_INIT_WEAK_KEY;		// Non-fatal error
			break;
		}

		key += CipherGetKeySize (c);
		ks += CipherGetKeyScheduleSize (c);
	}
	return retVal;
}

// Returns name of EA, cascaded cipher names are separated by hyphens
char *EAGetName (char *buf, int ea)
{
	int i = EAGetLastCipher(ea);
	strcpy (buf, CipherGetName (i));

	while (i = EAGetPreviousCipher(ea, i))
	{
		strcat (buf, "-");
		strcat (buf, CipherGetName (i));
	}

	return buf;
}

// Returns sum of key sizes of all EA ciphers
int EAGetKeySize (int ea)
{
	int i = EAGetFirstCipher(ea);
	int size = CipherGetKeySize (i);

	while (i = EAGetNextCipher(ea, i))
	{
		size += CipherGetKeySize (i);
	}

	return size;
}

// Returns the mode of operation of the whole EA
int EAGetMode (int ea)
{
	return (EncryptionAlgorithms[ea].Mode);
}

// Returns the name of the mode of operation of the whole EA
char *EAGetModeName (int ea, BOOL capitalLetters)
{
	switch (EncryptionAlgorithms[ea].Mode)
	{
	case CBC:
		{
			char eaName[100];
			EAGetName (eaName, ea);

			if (strcmp (eaName, "Triple DES") == 0)
				return capitalLetters ? "Outer-CBC" : "outer-CBC";

			return "CBC";
		}

	case OUTER_CBC:
		return  capitalLetters ? "Outer-CBC" : "outer-CBC";

	case INNER_CBC:
		return capitalLetters ? "Inner-CBC" : "inner-CBC";

	}
	return "[unknown]";
}

// Returns sum of key schedule sizes of all EA ciphers
int EAGetKeyScheduleSize (int ea)
{
	int i = EAGetFirstCipher(ea);
	int size = CipherGetKeyScheduleSize (i);

	while (i = EAGetNextCipher(ea, i))
	{
		size += CipherGetKeyScheduleSize (i);
	}

	return size;
}

// Returns largest key needed by all EAs
int EAGetLargestKey ()
{
	int ea, key = 0;

	for (ea = EAGetFirst (); ea != 0 ; ea = EAGetNext (ea))
	{
		if (EAGetKeySize (ea) >= key)
			key = EAGetKeySize (ea);
	}

	return key;
}

// Returns number of ciphers in EA
int EAGetCipherCount (int ea)
{
	int i = 0;
	while (EncryptionAlgorithms[ea].Ciphers[i++]);

	return i - 1;
}


int EAGetFirstCipher (int ea)
{
	return EncryptionAlgorithms[ea].Ciphers[0];
}

int EAGetLastCipher (int ea)
{
	int c, i = 0;
	while (c = EncryptionAlgorithms[ea].Ciphers[i++]);

	return EncryptionAlgorithms[ea].Ciphers[i - 2];
}

int EAGetNextCipher (int ea, int previousCipherId)
{
	int c, i = 0;
	while (c = EncryptionAlgorithms[ea].Ciphers[i++])
	{
		if (c == previousCipherId) 
			return EncryptionAlgorithms[ea].Ciphers[i];
	}

	return 0;
}

int EAGetPreviousCipher (int ea, int previousCipherId)
{
	int c, i = 0;

	if (EncryptionAlgorithms[ea].Ciphers[i++] == previousCipherId)
		return 0;

	while (c = EncryptionAlgorithms[ea].Ciphers[i++])
	{
		if (c == previousCipherId) 
			return EncryptionAlgorithms[ea].Ciphers[i - 2];
	}

	return 0;
}

char *get_hash_algo_name (int hash_algo_id)
{
	switch (hash_algo_id)
	{
	case SHA1:		return "SHA-1";
	case RIPEMD160:	return "RIPEMD-160";
	case WHIRLPOOL:	return "Whirlpool";
	default:		return "Unknown";
	}
}

#ifndef LINUX_DRIVER

PCRYPTO_INFO
crypto_open ()
{
	/* Do the crt allocation */
	PCRYPTO_INFO cryptoInfo = TCalloc (sizeof (CRYPTO_INFO));
#ifndef DEVICE_DRIVER
#ifdef _WIN32
	VirtualLock (cryptoInfo, sizeof (CRYPTO_INFO));
#endif
#endif

	if (cryptoInfo == NULL)
		return NULL;

	cryptoInfo->ea = -1;
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
	if (cryptoInfo != NULL)
	{
		burn (cryptoInfo, sizeof (CRYPTO_INFO));
#ifndef DEVICE_DRIVER
#ifdef _WIN32
		VirtualUnlock (cryptoInfo, sizeof (CRYPTO_INFO));
#endif
#endif
		TCfree (cryptoInfo);
	}
}
 
#endif	// LINUX_DRIVER


// Initializes IV and whitening values for sector encryption/decryption
static void 
InitSectorIVAndWhitening (unsigned __int64 secNo,
	int blockSize,
	unsigned __int32 *iv,
	unsigned __int64 *ivSeed,
	unsigned __int32 *whitening)
{
	unsigned __int64 iv64[4];
	unsigned __int32 *iv32 = (unsigned __int32 *) iv64;

	iv64[0] = ivSeed[0] ^ LE64(secNo);
	iv64[1] = ivSeed[1] ^ LE64(secNo);
	iv64[2] = ivSeed[2] ^ LE64(secNo);
	if (blockSize == 16)
	{
		iv64[3] = ivSeed[3] ^ LE64(secNo);
	}

	iv[0] = iv32[0];
	iv[1] = iv32[1];

	switch (blockSize)
	{
	case 16:

		// 128-bit block

		iv[2] = iv32[2];
		iv[3] = iv32[3];

		whitening[0] = LE32( crc32int ( &iv32[4] ) ^ crc32int ( &iv32[7] ) );
		whitening[1] = LE32( crc32int ( &iv32[5] ) ^ crc32int ( &iv32[6] ) );
		break;

	case 8:

		// 64-bit block

		whitening[0] = LE32( crc32int ( &iv32[2] ) ^ crc32int ( &iv32[5] ) );
		whitening[1] = LE32( crc32int ( &iv32[3] ) ^ crc32int ( &iv32[4] ) );
		break;
	}
}


// EncryptBufferCBC
//
// data:		data to be encrypted
// len:			number of bytes to encrypt (must be divisible by the largest cipher block size)
// ks:			scheduled key
// iv:			IV
// whitening:	whitening constants
// ea:			outer-CBC cascade ID (0 = CBC/inner-CBC)
// cipher:		CBC/inner-CBC cipher ID (0 = outer-CBC)

static void
EncryptBufferCBC (unsigned __int32 *data, 
		 unsigned int len,
		 unsigned char *ks,
		 unsigned __int32 *iv,
		 unsigned __int32 *whitening,
		 int ea,
		 int cipher)
{
	unsigned __int32 bufIV[4];
	unsigned __int64 i;
	int blockSize = CipherGetBlockSize (ea != 0 ? EAGetFirstCipher (ea) : cipher);

	//  IV
	bufIV[0] = iv[0];
	bufIV[1] = iv[1];
	if (blockSize == 16)
	{
		bufIV[2] = iv[2];
		bufIV[3] = iv[3];
	}

	// Encrypt each block
	for (i = 0; i < len/blockSize; i++)
	{
		// CBC
		data[0] ^= bufIV[0];
		data[1] ^= bufIV[1];
		if (blockSize == 16)
		{
			data[2] ^= bufIV[2];
			data[3] ^= bufIV[3];
		}

		if (ea != 0)
		{
			// Outer-CBC
			for (cipher = EAGetFirstCipher (ea); cipher != 0; cipher = EAGetNextCipher (ea, cipher))
			{
				EncipherBlock (cipher, data, ks);
				ks += CipherGetKeyScheduleSize (cipher);
			}
			ks -= EAGetKeyScheduleSize (ea);
		}
		else
		{
			// CBC/inner-CBC
			EncipherBlock (cipher, data, ks);
		}

		// CBC
		bufIV[0] = data[0];
		bufIV[1] = data[1];
		if (blockSize == 16)
		{
			bufIV[2] = data[2];
			bufIV[3] = data[3];
		}

		// Whitening
		data[0] ^= whitening[0];
		data[1] ^= whitening[1];
		if (blockSize == 16)
		{
			data[2] ^= whitening[0];
			data[3] ^= whitening[1];
		}

		data += blockSize / sizeof(*data);
	}
}


// DecryptBufferCBC
//
// data:		data to be decrypted
// len:			number of bytes to decrypt (must be divisible by the largest cipher block size)
// ks:			scheduled key
// iv:			IV
// whitening:	whitening constants
// ea:			outer-CBC cascade ID (0 = CBC/inner-CBC)
// cipher:		CBC/inner-CBC cipher ID (0 = outer-CBC)

static void
DecryptBufferCBC (unsigned __int32 *data,
		 unsigned int len,
		 unsigned char *ks,
		 unsigned __int32 *iv,
 		 unsigned __int32 *whitening,
		 int ea,
		 int cipher)
{
	unsigned __int32 bufIV[4];
	unsigned __int64 i;
	unsigned __int32 ct[4];
	int blockSize = CipherGetBlockSize (ea != 0 ? EAGetFirstCipher (ea) : cipher);

	//  IV
	bufIV[0] = iv[0];
	bufIV[1] = iv[1];
	if (blockSize == 16)
	{
		bufIV[2] = iv[2];
		bufIV[3] = iv[3];
	}

	// Decrypt each block
	for (i = 0; i < len/blockSize; i++)
	{
		// Dewhitening
		data[0] ^= whitening[0];
		data[1] ^= whitening[1];
		if (blockSize == 16)
		{
			data[2] ^= whitening[0];
			data[3] ^= whitening[1];
		}

		// CBC
		ct[0] = data[0];
		ct[1] = data[1];
		if (blockSize == 16)
		{
			ct[2] = data[2];
			ct[3] = data[3];
		}

		if (ea != 0)
		{
			// Outer-CBC
			ks += EAGetKeyScheduleSize (ea);
			for (cipher = EAGetLastCipher (ea); cipher != 0; cipher = EAGetPreviousCipher (ea, cipher))
			{
				ks -= CipherGetKeyScheduleSize (cipher);
				DecipherBlock (cipher, data, ks);
			}
		}
		else
		{
			// CBC/inner-CBC
			DecipherBlock (cipher, data, ks);
		}

		// CBC
		data[0] ^= bufIV[0];
		data[1] ^= bufIV[1];
		bufIV[0] = ct[0];
		bufIV[1] = ct[1];
		if (blockSize == 16)
		{
			data[2] ^= bufIV[2];
			data[3] ^= bufIV[3];
			bufIV[2] = ct[2];
			bufIV[3] = ct[3];
		}

		data += blockSize / sizeof(*data);
	}
}


// EncryptBuffer
//
// buf:			data to be encrypted
// len:			number of bytes to encrypt; must be divisible by the block size (for cascaded
//              ciphers divisible by the largest block size used within the cascade)
// ks:			scheduled key
// iv:			IV
// whitening:	whitening constants
// ea:			encryption algorithm

void 
EncryptBuffer (unsigned __int32 *buf,
			   unsigned __int64 len,
			   unsigned char *ks,
			   void *iv,
			   void *whitening,
			   int ea)
{
	int cipher;

	switch (EAGetMode(ea))
	{
	case CBC:
	case INNER_CBC:

		for (cipher = EAGetFirstCipher (ea); cipher != 0; cipher = EAGetNextCipher (ea, cipher))
		{
			EncryptBufferCBC (buf,
				(unsigned int) len,
				ks,
				(unsigned __int32 *) iv,
				(unsigned __int32 *) whitening,
				0,
				cipher);

			ks += CipherGetKeyScheduleSize (cipher);
		}

		break;

	case OUTER_CBC:

		EncryptBufferCBC (buf,
			(unsigned int) len,
			ks,
			(unsigned __int32 *) iv,
			(unsigned __int32 *) whitening,
			ea,
			0);

		break;
	}
}

// EncryptSectors
//
// buf:			data to be encrypted
// secNo:		sector number relative to volume start
// noSectors:	number of sectors in buffer
// ks:			scheduled key
// iv:			IV
// ea:			encryption algorithm

void _cdecl 
EncryptSectors (unsigned __int32 *buf,
		unsigned __int64 secNo,
		unsigned __int64 noSectors,
		unsigned char *ks,
		void *iv,
		int ea)
{
	unsigned __int64 *iv64 = (unsigned __int64 *) iv;
	unsigned __int32 sectorIV[4];
	unsigned __int32 secWhitening[2];
	int cipher;

	switch (EAGetMode(ea))
	{
	case CBC:
	case INNER_CBC:

		while (noSectors--)
		{
			for (cipher = EAGetFirstCipher (ea); cipher != 0; cipher = EAGetNextCipher (ea, cipher))
			{
				InitSectorIVAndWhitening (secNo, CipherGetBlockSize (cipher), sectorIV, iv64, secWhitening);

				EncryptBufferCBC (buf,
					SECTOR_SIZE,
					ks,
					sectorIV,
					secWhitening,
					0,
					cipher);

				ks += CipherGetKeyScheduleSize (cipher);
			}
			ks -= EAGetKeyScheduleSize (ea);
			buf += SECTOR_SIZE / sizeof(*buf);
			secNo++;
		}
		break;

	case OUTER_CBC:

		while (noSectors--)
		{
			InitSectorIVAndWhitening (secNo, CipherGetBlockSize (EAGetFirstCipher (ea)), sectorIV, iv64, secWhitening);

			EncryptBufferCBC (buf,
				SECTOR_SIZE,
				ks,
				sectorIV,
				secWhitening,
				ea,
				0);

			buf += SECTOR_SIZE / sizeof(*buf);
			secNo++;
		}
		break;
	}
}

// DecryptBuffer
//
// buf:			data to be decrypted
// len:			number of bytes to decrypt; must be divisible by the block size (for cascaded
//              ciphers divisible by the largest block size used within the cascade)
// ks:			scheduled key
// iv:			IV
// whitening:	whitening constants
// ea:			encryption algorithm
void 
DecryptBuffer (unsigned __int32 *buf,
		unsigned __int64 len,
		unsigned char *ks,
		void *iv,
		void *whitening,
		int ea)
{
	int cipher;

	switch (EAGetMode(ea))
	{
	case CBC:
	case INNER_CBC:

		ks += EAGetKeyScheduleSize (ea);
		for (cipher = EAGetLastCipher (ea); cipher != 0; cipher = EAGetPreviousCipher (ea, cipher))
		{
			ks -= CipherGetKeyScheduleSize (cipher);

			DecryptBufferCBC (buf,
				(unsigned int) len,
				ks,
				(unsigned __int32 *) iv,
				(unsigned __int32 *) whitening,
				0,
				cipher);
		}
		break;

	case OUTER_CBC:

		DecryptBufferCBC (buf,
			(unsigned int) len,
			ks,
			(unsigned __int32 *) iv,
			(unsigned __int32 *) whitening,
			ea,
			0);

		break;
	}
}

// DecryptSectors
//
// buf:			data to be decrypted
// secNo:		sector number relative to volume start
// noSectors:	number of sectors in buffer
// ks:			scheduled key
// iv:			IV
// ea:			encryption algorithm

void _cdecl 
DecryptSectors (unsigned __int32 *buf,
		unsigned __int64 secNo,
		unsigned __int64 noSectors,
		unsigned char *ks,
		void *iv,
		int ea)
{
	unsigned __int64 *iv64 = (unsigned __int64 *) iv;
	unsigned __int32 sectorIV[4];
	unsigned __int32 secWhitening[2];
	int cipher;

	switch (EAGetMode(ea))
	{
	case CBC:
	case INNER_CBC:

		while (noSectors--)
		{
			ks += EAGetKeyScheduleSize (ea);
			for (cipher = EAGetLastCipher (ea); cipher != 0; cipher = EAGetPreviousCipher (ea, cipher))
			{
				InitSectorIVAndWhitening (secNo, CipherGetBlockSize (cipher), sectorIV, iv64, secWhitening);

				ks -= CipherGetKeyScheduleSize (cipher);

				DecryptBufferCBC (buf,
					SECTOR_SIZE,
					ks,
					sectorIV,
					secWhitening,
					0,
					cipher);
			}
			buf += SECTOR_SIZE / sizeof(*buf);
			secNo++;
		}
		break;

	case OUTER_CBC:

		while (noSectors--)
		{
			InitSectorIVAndWhitening (secNo, CipherGetBlockSize (EAGetFirstCipher (ea)), sectorIV, iv64, secWhitening);

			DecryptBufferCBC (buf,
				SECTOR_SIZE,
				ks,
				sectorIV,
				secWhitening,
				ea,
				0);

			buf += SECTOR_SIZE / sizeof(*buf);
			secNo++;
		}
		break;
	}
}

