/* Copyright (C) 2004 TrueCrypt Team, truecrypt.org
   This product uses components written by Paul Le Roux <pleroux@swprofessionals.com> */

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
	unsigned long sectorIV[2];
	unsigned long *IV = (unsigned long *) iv;
	unsigned __int64 *IV64 = (unsigned __int64 *) iv;
	unsigned long x1, x2;
	unsigned long j;

	while (noSectors--)
	{
		// Sector encryption is implemented by making IV unique for each
		// sector and obfuscating cipher text
		IV64[0] ^= secNo;
		IV64[1] ^= secNo;
		IV64[2] ^= secNo;

		sectorIV[0] = IV[0];
		sectorIV[1] = IV[1];

		x1 = crc32long ( &IV[2] ) ^ crc32long ( &IV[5] );
		x2 = crc32long ( &IV[3] ) ^ crc32long ( &IV[4] );

		IV64[0] ^= secNo;
		IV64[1] ^= secNo;
		IV64[2] ^= secNo;

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
	unsigned long sectorIV[2];
	unsigned long *IV = (unsigned long *) iv;
	unsigned __int64 *IV64 = (unsigned __int64 *) iv;
	unsigned long x1, x2;
	int j;

	while (noSectors--)
	{
		IV64[0] ^= secNo;
		IV64[1] ^= secNo;
		IV64[2] ^= secNo;

		sectorIV[0] = IV[0];
		sectorIV[1] = IV[1];

		x1 = crc32long ( &IV[2] ) ^ crc32long ( &IV[5] );
		x2 = crc32long ( &IV[3] ) ^ crc32long ( &IV[4] );

		IV64[0] ^= secNo;
		IV64[1] ^= secNo;
		IV64[2] ^= secNo;

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
	unsigned long bufIV[2];
	unsigned long j;

	len /= get_block_size (cipher);

	bufIV[0] = IV[0];
	bufIV[1] = IV[1];

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
	unsigned long bufIV[2];
	unsigned long j;

	len /= get_block_size (cipher);

	bufIV[0] = IV[0];
	bufIV[1] = IV[1];

	if (get_block_size (cipher) == 8)
	{
		/* CBC encrypt the buffer */
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
	pkcs5 = SHA1;

	if (pkcs5 == SHA1)
	{
		derive_sha_key (keyInfo.userKey, keyInfo.keyLength, keyInfo.key_salt,
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

		cryptoInfo->encrypt_sector = &EncryptSector8;
		cryptoInfo->decrypt_sector = &DecryptSector8;
	
		return 0;
	}

	crypto_close(cryptoInfo);
	burn (&keyInfo, sizeof (keyInfo));
	return ERR_PASSWORD_WRONG;
}

#ifndef DEVICE_DRIVER

#ifdef VOLFORMAT
extern HWND hDiskKey;
extern HWND hKeySalt;
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

	//// Encryption setup

	// User key
	memcpy (keyInfo.userKey, lpszPassword, nUserKeyLen);
	keyInfo.keyLength = nUserKeyLen;
	keyInfo.noIterations = USERKEY_ITERATIONS;

	// User selected encryption algorithm
	cryptoInfo->cipher = cipher;

	// Salt for header key derivation 
	RandgetBytes (keyInfo.key_salt, USERKEY_SALT_SIZE);

	// PKCS5 is used to derive header key and IV from user password
	if (pkcs5 == SHA1)
	{
		derive_sha_key (keyInfo.userKey, keyInfo.keyLength, keyInfo.key_salt,
				USERKEY_SALT_SIZE, keyInfo.noIterations, dk, DISK_IV_SIZE + MAX_CIPHER_KEY );
	}

	// Generate disk key and IV
	if(masterKey == 0)
		RandgetBytes (keyInfo.key, DISKKEY_SIZE);
	else
		memcpy(keyInfo.key, masterKey, DISKKEY_SIZE);


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

	// Clear out the temp. key buffer
	burn (dk, sizeof(dk));

	if (get_block_size(cipher) == 8)
	{
		cryptoInfo->encrypt_sector = &EncryptSector8;
		cryptoInfo->decrypt_sector = &DecryptSector8;
	}

#ifdef VOLFORMAT
	{
		char tmp[64];
		BOOL dots3 = FALSE;
		int i, j;

		j = get_key_size (cipher);

		if (j > 21)
		{
			dots3 = TRUE;
			j = 21;
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
		for (i = 0; i < 20; i++)
		{
			char tmp2[8];
			sprintf (tmp2, "%02X", (int) (unsigned char) keyInfo.key_salt[i]);
			strcat (tmp, tmp2);
		}

		SetWindowText (hKeySalt, tmp);
	}
#endif

	burn (&keyInfo, sizeof (keyInfo));

	*retInfo = cryptoInfo;
	return 0;
}


#endif				/* !NT4_DRIVER */
