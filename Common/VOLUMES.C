/* The source code contained in this file has been derived from the source code
   of Encryption for the Masses 2.02a by Paul Le Roux. Modifications and
   additions to that source code contained in this file are Copyright (c) 2004
   TrueCrypt Foundation and Copyright (c) 2004 TrueCrypt Team. Unmodified
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

#include "Aes.h"
#include "pkcs5.h"
#include "crc.h"


/* When FALSE, hidden volumes will not be attempted to mount. This variable could be used in future.
Should a large number of new ciphers be implemented, setting this to FALSE (via program prefs) might
speed mounting up. */
BOOL mountingHiddenVolumesAllowed = TRUE;	


// Volume header structure:
//
// Offset	Length	Description
// ------------------------------------------
// Unencrypted:
// 0		64		Key salt
// Encrypted:
// 64		4		ASCII string 'TRUE'
// 68		2		Header version
// 70		2		Required program version
// 72		4		CRC32 of disk IV and key
// 76		8		Volume creation time
// 84		8		Header creation time
// 92		8		Size of hidden volume in bytes (0 = normal volume)
// 100		156		Unused
// 256		32		Disk IV
// 288		224		Disk key

int
VolumeReadHeader (char *encryptedHeader, char *encryptedHeaderHiddenVol, char *lpszPassword, PCRYPTO_INFO *retInfo)
{
	char header[SECTOR_SIZE];
	unsigned char *input = (unsigned char *) header;
	KEY_INFO keyInfo;
	KEY_INFO keyInfoHiddenVol;
	PCRYPTO_INFO cryptoInfo;
	int nStatus = 0, nKeyLen;
	char dk[DISKKEY_SIZE];
	char dkHiddenVol[DISKKEY_SIZE];
	int pkcs5;
	int headerVersion, requiredVersion;
	int volType, lastVolType = NORMAL_VOLUME;
	
	cryptoInfo = *retInfo = crypto_open ();
	if (cryptoInfo == NULL)
		return ERR_OUTOFMEMORY;

	crypto_loadkey (&keyInfo, lpszPassword, strlen (lpszPassword));

	// PKCS5 is used to derive header key and IV from user password
	memcpy (keyInfo.key_salt, encryptedHeader + HEADER_USERKEY_SALT, USERKEY_SALT_SIZE);

	if (mountingHiddenVolumesAllowed && encryptedHeaderHiddenVol != 0)
	{
		// Salt for a possible hidden volume
		memcpy (keyInfoHiddenVol.key_salt, encryptedHeaderHiddenVol + HEADER_USERKEY_SALT, USERKEY_SALT_SIZE);
		lastVolType = HIDDEN_VOLUME;
	}

	keyInfo.noIterations = USERKEY_ITERATIONS;		

	// Test all available PKCS5 PRFs
	for (pkcs5 = 1; pkcs5 <= LAST_PRF_ID; pkcs5++)
	{
		if (pkcs5 == SHA1)
		{
			derive_sha_key (keyInfo.userKey, keyInfo.keyLength, keyInfo.key_salt,
				USERKEY_SALT_SIZE, keyInfo.noIterations, dk, DISK_IV_SIZE + EAGetLargestKey());
			if (mountingHiddenVolumesAllowed)
			{
				// Derive header for a possible hidden volume (HMAC-SHA-1)
				derive_sha_key (keyInfo.userKey, keyInfo.keyLength, keyInfoHiddenVol.key_salt,
					USERKEY_SALT_SIZE, keyInfo.noIterations, dkHiddenVol, DISK_IV_SIZE + EAGetLargestKey());
			}
		} 
		else if (pkcs5 == RIPEMD160)
		{
			derive_rmd160_key (keyInfo.userKey, keyInfo.keyLength, keyInfo.key_salt,
				USERKEY_SALT_SIZE, keyInfo.noIterations, dk, DISK_IV_SIZE + EAGetLargestKey());
			if (mountingHiddenVolumesAllowed)
			{
				// Derive header for a possible hidden volume (HMAC-RIPEMD-160)
				derive_rmd160_key (keyInfo.userKey, keyInfo.keyLength, keyInfoHiddenVol.key_salt,
					USERKEY_SALT_SIZE, keyInfo.noIterations, dkHiddenVol, DISK_IV_SIZE + EAGetLargestKey());
			}
		}

		// Test all available encryption algorithms
		for (cryptoInfo->ea = EAGetFirst (); cryptoInfo->ea != 0; cryptoInfo->ea = EAGetNext (cryptoInfo->ea))
		{
			// Test all volume types
			for (volType = NORMAL_VOLUME; volType <= lastVolType; volType++)
			{
				// Copy header for decryption and init an encryption algorithm
				if (volType == NORMAL_VOLUME)
				{
					memcpy (header, encryptedHeader, SECTOR_SIZE);  
					memcpy (cryptoInfo->iv, dk, DISK_IV_SIZE);
					EAInit (cryptoInfo->ea, dk + DISK_IV_SIZE, cryptoInfo->ks);
				}
				else if (volType == HIDDEN_VOLUME)
				{					
					memcpy (header, encryptedHeaderHiddenVol, SECTOR_SIZE);  
					memcpy (cryptoInfo->iv, dkHiddenVol, DISK_IV_SIZE);
					EAInit (cryptoInfo->ea, dkHiddenVol + DISK_IV_SIZE, cryptoInfo->ks);
				}

				input = header;

				// Try to decrypt header 

				DecryptBuffer ((unsigned long *) (header + HEADER_ENCRYPTEDDATA), HEADER_ENCRYPTEDDATASIZE,
					cryptoInfo->ks, cryptoInfo->iv, &cryptoInfo->iv[8], cryptoInfo->ea);

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

				// Now we have the correct password, cipher, hash algorithm, and volume type

				// Check the version required to handle this volume
				if (requiredVersion > VERSION_NUM)
					return ERR_NEW_VERSION_REQUIRED;

				// Volume creation time
				cryptoInfo->volume_creation_time = mgetInt64 (input);

				// Header creation time
				cryptoInfo->header_creation_time = mgetInt64 (input);

				// Hidden volume
				cryptoInfo->hiddenVolumeSize = mgetInt64 (input);

				if (volType == HIDDEN_VOLUME)	// If mounted as a hidden volume
				{
					cryptoInfo->hiddenVolume = TRUE;
				}
				else
				{
					cryptoInfo->hiddenVolume = FALSE;
					cryptoInfo->hiddenVolumeSize = 0;
				}

				// Disk key
				nKeyLen = DISKKEY_SIZE;
				memcpy (keyInfo.key, header + HEADER_DISKKEY, nKeyLen);

				memcpy (cryptoInfo->master_decrypted_key, keyInfo.key, nKeyLen);
				memcpy (cryptoInfo->key_salt, keyInfo.key_salt, USERKEY_SALT_SIZE);
				cryptoInfo->pkcs5 = pkcs5;
				cryptoInfo->noIterations = keyInfo.noIterations;

				// Init the encryption algorithm with the decrypted master key
				EAInit (cryptoInfo->ea, keyInfo.key + DISK_IV_SIZE, cryptoInfo->ks);

				// Disk IV
				memcpy (cryptoInfo->iv, keyInfo.key, DISK_IV_SIZE);

				// Clear out the temp. key buffers
				burn (dk, sizeof(dk));
				burn (dkHiddenVol, sizeof(dkHiddenVol));

				return 0;
			}
		}
	}

	crypto_close(cryptoInfo);
	burn (&keyInfo, sizeof (keyInfo));
	burn (&keyInfoHiddenVol, sizeof (keyInfoHiddenVol));
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
VolumeWriteHeader (char *header, int ea, char *lpszPassword,
		   int pkcs5, char *masterKey, unsigned __int64 volumeCreationTime, PCRYPTO_INFO * retInfo,
		   unsigned __int64 hiddenVolumeSize)
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
	cryptoInfo->ea = ea;

	// Salt for header key derivation 
	RandgetBytes (keyInfo.key_salt, USERKEY_SALT_SIZE, TRUE);

	// PKCS5 is used to derive the header key and IV from the password
	if (pkcs5 == SHA1)
	{
		derive_sha_key (keyInfo.userKey, keyInfo.keyLength, keyInfo.key_salt,
				USERKEY_SALT_SIZE, keyInfo.noIterations, dk, DISK_IV_SIZE + EAGetLargestKey() );
	}
	else if (pkcs5 == RIPEMD160)
	{
		derive_rmd160_key (keyInfo.userKey, keyInfo.keyLength, keyInfo.key_salt,
				USERKEY_SALT_SIZE, keyInfo.noIterations, dk, DISK_IV_SIZE + EAGetLargestKey() );
	}


	//// Header setup

	// Salt
	mputBytes (p, keyInfo.key_salt, USERKEY_SALT_SIZE);	

	// Magic
	mputLong (p, 'TRUE');

	// Header version
	mputWord (p, VOLUME_HEADER_VERSION);

	// Required program version to handle this volume
	mputWord (p, VOL_REQ_PROG_VERSION);

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

	// Hidden volume size
	cryptoInfo->hiddenVolumeSize = hiddenVolumeSize;
	mputInt64 (p, cryptoInfo->hiddenVolumeSize);

	// Disk key and IV
	memcpy (header + HEADER_DISKKEY, keyInfo.key, DISKKEY_SIZE);


	//// Header encryption

	memcpy (cryptoInfo->iv, dk, DISK_IV_SIZE);
	EAInit (cryptoInfo->ea, dk + DISK_IV_SIZE, cryptoInfo->ks);

	EncryptBuffer ((unsigned long *) (header + HEADER_ENCRYPTEDDATA), HEADER_ENCRYPTEDDATASIZE,
			cryptoInfo->ks, cryptoInfo->iv, &cryptoInfo->iv[8], cryptoInfo->ea);


	//// cryptoInfo setup for further use (disk format)

	// Init with master disk key for sector decryption
	EAInit (cryptoInfo->ea, keyInfo.key + DISK_IV_SIZE, cryptoInfo->ks);

	// Disk IV
	memcpy (cryptoInfo->iv, keyInfo.key, DISK_IV_SIZE);


#ifdef VOLFORMAT
	if (showKeys)
	{
		char tmp[64];
		BOOL dots3 = FALSE;
		int i, j;

		j = EAGetKeySize (ea);

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

