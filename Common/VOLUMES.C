/* The source code contained in this file has been derived from the source code
   of Encryption for the Masses 2.02a by Paul Le Roux. Modifications and
   additions to that source code contained in this file are Copyright (c) 2004
   TrueCrypt Team and Copyright (c) 2004 TrueCrypt Foundation. Unmodified
   parts are Copyright (c) 1998-99 Paul Le Roux. This is a TrueCrypt Foundation
   release. Please see the file license.txt for full license details. */

#include "TCdefs.h"

#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <io.h>
#include <time.h>

#include "crypto.h"
#include "random.h"
#include "endian.h"
#include "fat.h"
#include "volumes.h"

#include "pkcs5.h"
#include "crc.h"

void _cdecl
EncryptSector8 (unsigned long *data,
		unsigned __int64 secNo,
		unsigned long noSectors,
		unsigned char *ks,
		unsigned char *iv,
		int cipher)
{
	unsigned __int64 *iv64 = (unsigned __int64 *) iv;
	unsigned __int64 IV64[3];
	unsigned long *IV = (unsigned long *) IV64;
	unsigned long sectorIV[2];
	unsigned long x1, x2;
	unsigned long j;

	while (noSectors--)
	{
		// Sector encryption is implemented by making IV unique for each
		// sector and obfuscating cipher text
		IV64[0] = iv64[0] ^ secNo;
		IV64[1] = iv64[1] ^ secNo;
		IV64[2] = iv64[2] ^ secNo;

		sectorIV[0] = IV[0];
		sectorIV[1] = IV[1];

		x1 = crc32long ( &IV[2] ) ^ crc32long ( &IV[5] );
		x2 = crc32long ( &IV[3] ) ^ crc32long ( &IV[4] );

		// CBC encrypt the entire sector
		for (j = 0; j < 64; j++)
		{
			// CBC
			data[0] ^= sectorIV[0];
			data[1] ^= sectorIV[1];

			encipher_block (cipher, data, ks);

			sectorIV[0] = data[0];
			sectorIV[1] = data[1];

			// Cipher text XOR
			data[0] ^= x1;
			data[1] ^= x2;

			data += 2;
		}

		secNo++;
	}
}

void
  _cdecl
DecryptSector8 (unsigned long *data,
		unsigned __int64 secNo,
		unsigned long noSectors,
		unsigned char *ks,
		unsigned char *iv,
		int cipher)
{
	unsigned __int64 *iv64 = (unsigned __int64 *) iv;
	unsigned __int64 IV64[3];
	unsigned long *IV = (unsigned long *) IV64;
	unsigned long sectorIV[2];
	unsigned long x1, x2;
	int j;

	while (noSectors--)
	{
		IV64[0] = iv64[0] ^ secNo;
		IV64[1] = iv64[1] ^ secNo;
		IV64[2] = iv64[2] ^ secNo;

		sectorIV[0] = IV[0];
		sectorIV[1] = IV[1];

		x1 = crc32long ( &IV[2] ) ^ crc32long ( &IV[5] );
		x2 = crc32long ( &IV[3] ) ^ crc32long ( &IV[4] );

		// CBC decrypt the sector
		for (j = 0; j < 64; j++)
		{
			unsigned long a, b;

			// Cipher text XOR
			data[0] ^= x1;
			data[1] ^= x2;

			// CBC
			a = data[0];
			b = data[1];

			decipher_block (cipher, data, ks);

			data[0] ^= sectorIV[0];
			data[1] ^= sectorIV[1];

			sectorIV[0] = a;
			sectorIV[1] = b;

			data += 2;
		}

		secNo++;
	}
}

void _cdecl
EncryptSector16 (unsigned long *data,
		unsigned __int64 secNo,
		unsigned long noSectors,
		unsigned char *ks,
		unsigned char *iv,
		int cipher)
{
	unsigned __int64 *iv64 = (unsigned __int64 *) iv;
	unsigned __int64 IV64[4];
	unsigned long *IV = (unsigned long *) IV64;
	unsigned long sectorIV[4];
	unsigned long x1, x2;
	unsigned long j;

	while (noSectors--)
	{
		IV64[0] = iv64[0] ^ secNo;
		IV64[1] = iv64[1] ^ secNo;
		IV64[2] = iv64[2] ^ secNo;
		IV64[3] = iv64[3] ^ secNo;

		sectorIV[0] = IV[0];
		sectorIV[1] = IV[1];
		sectorIV[2] = IV[2];
		sectorIV[3] = IV[3];

		x1 = crc32long ( &IV[4] ) ^ crc32long ( &IV[7] );
		x2 = crc32long ( &IV[5] ) ^ crc32long ( &IV[6] );

		// CBC encrypt the entire sector
		for (j = 0; j < 32; j++)
		{
			// CBC
			data[0] ^= sectorIV[0];
			data[1] ^= sectorIV[1];
			data[2] ^= sectorIV[2];
			data[3] ^= sectorIV[3];

			encipher_block (cipher, data, ks);

			sectorIV[0] = data[0];
			sectorIV[1] = data[1];
			sectorIV[2] = data[2];
			sectorIV[3] = data[3];

			// Cipher text XOR
			data[0] ^= x1;
			data[1] ^= x2;
			data[2] ^= x1;
			data[3] ^= x2;

			data += 4;
		}

		secNo++;
	}
}


void
  _cdecl
DecryptSector16 (unsigned long *data,
		unsigned __int64 secNo,
		unsigned long noSectors,
		unsigned char *ks,
		unsigned char *iv,
		int cipher)
{
	unsigned __int64 *iv64 = (unsigned __int64 *) iv;
	unsigned __int64 IV64[4];
	unsigned long *IV = (unsigned long *) IV64;
	unsigned long sectorIV[4];
	unsigned long x1, x2;
	int j;

	while (noSectors--)
	{
		IV64[0] = iv64[0] ^ secNo;
		IV64[1] = iv64[1] ^ secNo;
		IV64[2] = iv64[2] ^ secNo;
		IV64[3] = iv64[3] ^ secNo;

		sectorIV[0] = IV[0];
		sectorIV[1] = IV[1];
		sectorIV[2] = IV[2];
		sectorIV[3] = IV[3];

		x1 = crc32long ( &IV[4] ) ^ crc32long ( &IV[7] );
		x2 = crc32long ( &IV[5] ) ^ crc32long ( &IV[6] );

		// CBC decrypt the sector
		for (j = 0; j < 32; j++)
		{
			unsigned long a[4];

			// Cipher text XOR
			data[0] ^= x1;
			data[1] ^= x2;
			data[2] ^= x1;
			data[3] ^= x2;

			// CBC
			a[0] = data[0];
			a[1] = data[1];
			a[2] = data[2];
			a[3] = data[3];

			decipher_block (cipher, data, ks);

			data[0] ^= sectorIV[0];
			data[1] ^= sectorIV[1];
			data[2] ^= sectorIV[2];
			data[3] ^= sectorIV[3];

			sectorIV[0] = a[0];
			sectorIV[1] = a[1];
			sectorIV[2] = a[2];
			sectorIV[3] = a[3];

			data += 4;
		}

		secNo++;
	}
}

// EncryptBuffer
//
// Encrypts data in buffer
// Returns number of bytes encrypted
//
// len = length of data in bytes
int _cdecl 
EncryptBuffer (unsigned char *buf,
		unsigned long len,
		unsigned char *ks,
		unsigned char *iv,
		int cipher)
{
	unsigned long *data = (unsigned long *) buf;
	unsigned long *IV = (unsigned long *) iv;
	unsigned long bufIV[4];
	unsigned long j;

	len /= get_block_size (cipher);

	bufIV[0] = IV[0];
	bufIV[1] = IV[1];
	bufIV[2] = IV[2];
	bufIV[3] = IV[3];

	if (get_block_size (cipher) == 8)
	{
		/* CBC encrypt the buffer */
		for (j = 0; j < len; j++)
		{
			// CBC
			data[0] ^= bufIV[0];
			data[1] ^= bufIV[1];

			encipher_block (cipher, data, ks);

			bufIV[0] = data[0];
			bufIV[1] = data[1];

			// Cipher text XOR
			data[0] ^= IV[2];
			data[1] ^= IV[3];

			data += 2;
		}
	}
	else if (get_block_size (cipher) == 16)
	{
		/* CBC encrypt the buffer */
		for (j = 0; j < len; j++)
		{
			// CBC
			data[0] ^= bufIV[0];
			data[1] ^= bufIV[1];
			data[2] ^= bufIV[2];
			data[3] ^= bufIV[3];

			encipher_block (cipher, data, ks);

			bufIV[0] = data[0];
			bufIV[1] = data[1];
			bufIV[2] = data[2];
			bufIV[3] = data[3];

			// Cipher text XOR
			data[0] ^= IV[2];
			data[1] ^= IV[3];
			data[2] ^= IV[2];
			data[3] ^= IV[3];

			data += 4;
		}
	}
	else
		return 0;

	return len;
}

// DecryptBuffer
//
// Decrypts data in buffer
// Returns number of bytes encrypted
//
// len = length of data in bytes

int _cdecl
DecryptBuffer (unsigned char *buf,
		unsigned long len,
		unsigned char *ks,
		unsigned char *iv,
		int cipher)
{
	unsigned long *data = (unsigned long *)buf;
	unsigned long *IV = (unsigned long *) iv;
	unsigned long bufIV[4];
	unsigned long j;

	len /= get_block_size (cipher);

	bufIV[0] = IV[0];
	bufIV[1] = IV[1];
	bufIV[2] = IV[2];
	bufIV[3] = IV[3];

	if (get_block_size (cipher) == 8)
	{
		/* CBC decrypt the buffer */
		for (j = 0; j < len; j++)
		{
			unsigned long a, b;

			// Cipher text XOR
			data[0] ^= IV[2];
			data[1] ^= IV[3];

			// CBC
			a = data[0];
			b = data[1];

			decipher_block (cipher, data, ks);

			data[0] ^= bufIV[0];
			data[1] ^= bufIV[1];

			bufIV[0] = a;
			bufIV[1] = b;

			data += 2;
		}
	}
	else if (get_block_size (cipher) == 16)
	{
		/* CBC decrypt the buffer */
		for (j = 0; j < len; j++)
		{
			unsigned long a[4];

			// Cipher text XOR
			data[0] ^= IV[2];
			data[1] ^= IV[3];
			data[2] ^= IV[2];
			data[3] ^= IV[3];

			// CBC
			a[0] = data[0];
			a[1] = data[1];
			a[2] = data[2];
			a[3] = data[3];

			decipher_block (cipher, data, ks);

			data[0] ^= bufIV[0];
			data[1] ^= bufIV[1];
			data[2] ^= bufIV[2];
			data[3] ^= bufIV[3];

			bufIV[0] = a[0];
			bufIV[1] = a[1];
			bufIV[2] = a[2];
			bufIV[3] = a[3];

			data += 4;
		}
	}
	else
		return 0;

	return len;
}

// Volume header structure:
//
// Offset	Length	Description
// ------------------------------------------
// Unencrypted:
// 0		64		Key salt
// Encrypted:
// 64		4		Magic 'TRUE'
// 68		2		Header version
// 70		2		Required program version
// 72		4		CRC32 of disk IV and key
// 76		8		Volume creation time
// 84		8		Header creation time
// 92		164		unused
// 256		32		Disk IV
// 288		224		Disk key

int
VolumeReadHeader (char *encryptedHeader, char *lpszPassword, PCRYPTO_INFO * retInfo)
{
	char header[SECTOR_SIZE];
	unsigned char *input = (unsigned char *) header;
	KEY_INFO keyInfo;
	PCRYPTO_INFO cryptoInfo;
	int nStatus = 0, nKeyLen;
	char dk[DISKKEY_SIZE];
	int pkcs5;
	int headerVersion, requiredVersion;
	
	cryptoInfo = *retInfo = crypto_open ();
	if (cryptoInfo == NULL)
		return ERR_OUTOFMEMORY;

	crypto_loadkey (&keyInfo, lpszPassword, strlen (lpszPassword));

	// PKCS5 is used to derive header key and IV from user password
	memcpy (keyInfo.key_salt, encryptedHeader + HEADER_USERKEY_SALT, USERKEY_SALT_SIZE);
	keyInfo.noIterations = USERKEY_ITERATIONS;		

	// Test all available PKCS5 PRFs
	for (pkcs5 = 1; pkcs5 <= LAST_PRF_ID; pkcs5++)
	{
		if (pkcs5 == SHA1)
		{
			derive_sha_key (keyInfo.userKey, keyInfo.keyLength, keyInfo.key_salt,
				USERKEY_SALT_SIZE, keyInfo.noIterations, dk, DISK_IV_SIZE + MAX_CIPHER_KEY);
		} else if (pkcs5 == RIPEMD160)
		{
			derive_rmd160_key (keyInfo.userKey, keyInfo.keyLength, keyInfo.key_salt,
				USERKEY_SALT_SIZE, keyInfo.noIterations, dk, DISK_IV_SIZE + MAX_CIPHER_KEY);
		}

		// IV for header decryption
		memcpy (cryptoInfo->iv, dk, DISK_IV_SIZE);

		// Test all available ciphers
		for (cryptoInfo->cipher = 1; cryptoInfo->cipher <= LAST_CIPHER_ID; cryptoInfo->cipher++)
		{
			// Copy header for decryption
			memcpy (header, encryptedHeader, SECTOR_SIZE);  
			input = header;

			// Try to decrypt header 
			init_cipher (cryptoInfo->cipher, dk + DISK_IV_SIZE, cryptoInfo->ks);

			DecryptBuffer (header + HEADER_ENCRYPTEDDATA, HEADER_ENCRYPTEDDATASIZE,
				cryptoInfo->ks, cryptoInfo->iv, cryptoInfo->cipher);

			input += HEADER_ENCRYPTEDDATA;

			// Magic
			if (mgetLong (input) != 'TRUE')
				continue;

			// Header version
			headerVersion = mgetWord (input);

			// Required program version
			requiredVersion = mgetWord (input);

			// Check CRC of disk IV and key
			if (mgetLong (input) != crc32 (header + HEADER_DISKKEY, DISKKEY_SIZE))
				continue;

			// Volume creation time
			((unsigned long *)(&cryptoInfo->volume_creation_time))[1] = mgetLong (input);
			((unsigned long *)(&cryptoInfo->volume_creation_time))[0] = mgetLong (input);

			// Header creation time
			((unsigned long *)(&cryptoInfo->header_creation_time))[1] = mgetLong (input);
			((unsigned long *)(&cryptoInfo->header_creation_time))[0] = mgetLong (input);

			// Password and cipher OK

			// Check the version required to handle this volume
			if (requiredVersion > VERSION_NUM)
				return ERR_NEW_VERSION_REQUIRED;

			// Disk key
			nKeyLen = DISKKEY_SIZE;
			memcpy (keyInfo.key, header + HEADER_DISKKEY, nKeyLen);

			memcpy (cryptoInfo->master_decrypted_key, keyInfo.key, nKeyLen);
			memcpy (cryptoInfo->key_salt, keyInfo.key_salt, USERKEY_SALT_SIZE);
			cryptoInfo->pkcs5 = pkcs5;
			cryptoInfo->noIterations = keyInfo.noIterations;

			// Init with decrypted master disk key for sector decryption
			init_cipher (cryptoInfo->cipher, keyInfo.key + DISK_IV_SIZE, cryptoInfo->ks);

			// Disk IV
			memcpy (cryptoInfo->iv, keyInfo.key, DISK_IV_SIZE);

			/* Clear out the temp. key buffer */
			burn (dk, sizeof(dk));

			switch (get_block_size (cryptoInfo->cipher))
			{
			case 8:
				cryptoInfo->encrypt_sector = &EncryptSector8;
				cryptoInfo->decrypt_sector = &DecryptSector8;
				break;
			case 16:
				cryptoInfo->encrypt_sector = &EncryptSector16;
				cryptoInfo->decrypt_sector = &DecryptSector16;
				break;
			}

			return 0;
		}
	}

	crypto_close(cryptoInfo);
	burn (&keyInfo, sizeof (keyInfo));
	return ERR_PASSWORD_WRONG;
}

#ifndef DEVICE_DRIVER

#ifdef VOLFORMAT
extern BOOL showKeys;
extern HWND hDiskKey;
extern HWND hHeaderKey;
#endif

// VolumeWriteHeader:
// Creates volume header in memory
int
VolumeWriteHeader (char *header, int cipher, char *lpszPassword,
		   int pkcs5, char *masterKey, unsigned __int64 volumeCreationTime, PCRYPTO_INFO * retInfo )
{
	unsigned char *p = (unsigned char *) header;
	KEY_INFO keyInfo;

	int nUserKeyLen = strlen(lpszPassword);
	PCRYPTO_INFO cryptoInfo = crypto_open ();
	char dk[DISKKEY_SIZE];
	int x;

	if (cryptoInfo == NULL)
		return ERR_OUTOFMEMORY;

	memset (header, 0, SECTOR_SIZE);
	VirtualLock (&keyInfo, sizeof (keyInfo));

	//// Encryption setup

	// Generate disk key and IV
	if(masterKey == 0)
		RandgetBytes (keyInfo.key, DISKKEY_SIZE, TRUE);
	else
		memcpy (keyInfo.key, masterKey, DISKKEY_SIZE);

	// User key
	memcpy (keyInfo.userKey, lpszPassword, nUserKeyLen);
	keyInfo.keyLength = nUserKeyLen;
	keyInfo.noIterations = USERKEY_ITERATIONS;

	// User selected encryption algorithm
	cryptoInfo->cipher = cipher;

	// Salt for header key derivation 
	RandgetBytes (keyInfo.key_salt, USERKEY_SALT_SIZE, TRUE);

	// PKCS5 is used to derive header key and IV from user password
	if (pkcs5 == SHA1)
	{
		derive_sha_key (keyInfo.userKey, keyInfo.keyLength, keyInfo.key_salt,
				USERKEY_SALT_SIZE, keyInfo.noIterations, dk, DISK_IV_SIZE + MAX_CIPHER_KEY );
	}
	else if (pkcs5 == RIPEMD160)
	{
		derive_rmd160_key (keyInfo.userKey, keyInfo.keyLength, keyInfo.key_salt,
				USERKEY_SALT_SIZE, keyInfo.noIterations, dk, DISK_IV_SIZE + MAX_CIPHER_KEY );
	}


	//// Header setup

	// Salt
	mputBytes (p, keyInfo.key_salt, USERKEY_SALT_SIZE);	

	// Magic
	mputLong (p, 'TRUE');

	// Header version
	mputWord (p, 0x0001);

	// Required program version to handle this volume
	mputWord (p, VOLUME_VERSION_NUM);

	// CRC of disk key
	x = crc32(keyInfo.key, DISKKEY_SIZE);
	mputLong (p, x);

	// Time
	{
		SYSTEMTIME st;
		FILETIME ft;

		// Volume creation time
		if (volumeCreationTime == 0)
		{
			GetLocalTime (&st);
			SystemTimeToFileTime (&st, &ft);
		}
		else
		{
			ft.dwHighDateTime = (DWORD)(volumeCreationTime >> 32);
			ft.dwLowDateTime = (DWORD)volumeCreationTime;
		}
		mputLong (p, ft.dwHighDateTime);
		mputLong (p, ft.dwLowDateTime);

		// Password change time
		GetLocalTime (&st);
		SystemTimeToFileTime (&st, &ft);
		mputLong (p, ft.dwHighDateTime);
		mputLong (p, ft.dwLowDateTime);
	}

	// Disk key and IV
	memcpy (header + HEADER_DISKKEY, keyInfo.key, DISKKEY_SIZE);


	//// Header encryption

	memcpy (cryptoInfo->iv, dk, DISK_IV_SIZE);
	init_cipher (cryptoInfo->cipher, dk + DISK_IV_SIZE, cryptoInfo->ks);

	EncryptBuffer (header + HEADER_ENCRYPTEDDATA, HEADER_ENCRYPTEDDATASIZE, 
			cryptoInfo->ks, cryptoInfo->iv, cryptoInfo->cipher);


	//// cryptoInfo setup for further use (disk format)

	// Init with master disk key for sector decryption
	init_cipher (cryptoInfo->cipher, keyInfo.key + DISK_IV_SIZE, cryptoInfo->ks);

	// Disk IV
	memcpy (cryptoInfo->iv, keyInfo.key, DISK_IV_SIZE);

	switch (get_block_size (cryptoInfo->cipher))
	{
	case 8:
		cryptoInfo->encrypt_sector = &EncryptSector8;
		cryptoInfo->decrypt_sector = &DecryptSector8;
		break;
	case 16:
		cryptoInfo->encrypt_sector = &EncryptSector16;
		cryptoInfo->decrypt_sector = &DecryptSector16;
		break;
	}


#ifdef VOLFORMAT
	if (showKeys)
	{
		char tmp[64];
		BOOL dots3 = FALSE;
		int i, j;

		j = get_key_size (cipher);

		if (j > 14)
		{
			dots3 = TRUE;
			j = 14;
		}

		tmp[0] = 0;
		for (i = 0; i < j; i++)
		{
			char tmp2[8] =
			{0};
			sprintf (tmp2, "%02X", (int) (unsigned char) keyInfo.key[i + DISK_IV_SIZE]);
			strcat (tmp, tmp2);
		}

		if (dots3 == TRUE)
		{
			strcat (tmp, "...");
		}


		SetWindowText (hDiskKey, tmp);

		tmp[0] = 0;
		for (i = 0; i < 14; i++)
		{
			char tmp2[8];
			sprintf (tmp2, "%02X", (int) (unsigned char) dk[DISK_IV_SIZE + i]);
			strcat (tmp, tmp2);
		}

		if (dots3 == TRUE)
		{
			strcat (tmp, "...");
		}

		SetWindowText (hHeaderKey, tmp);
	}
#endif

	burn (dk, sizeof(dk));
	burn (&keyInfo, sizeof (keyInfo));
	VirtualUnlock (&keyInfo, sizeof (keyInfo));

	*retInfo = cryptoInfo;
	return 0;
}


#endif				/* !NT4_DRIVER */
