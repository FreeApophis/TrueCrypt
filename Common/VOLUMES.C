/*
 Legal Notice: Some portions of the source code contained in this file were
 derived from the source code of Encryption for the Masses 2.02a, which is
 Copyright (c) 1998-2000 Paul Le Roux and which is governed by the 'License
 Agreement for Encryption for the Masses'. Modifications and additions to
 the original source code (contained in this file) and all other portions of
 this file are Copyright (c) 2003-2008 TrueCrypt Foundation and are governed
 by the TrueCrypt License 2.4 the full text of which is contained in the
 file License.txt included in TrueCrypt binary and source code distribution
 packages. */

#include "Tcdefs.h"

#ifndef TC_WINDOWS_BOOT
#include <fcntl.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <time.h>
#endif

#ifdef _WIN32
#include <io.h>
#include "Random.h"
#endif

#include "Crypto.h"
#include "Common/Endian.h"
#include "Volumes.h"

#include "Pkcs5.h"
#include "Crc.h"



/* Volume header v3 structure: */
//
// Offset	Length	Description
// ------------------------------------------
// Unencrypted:
// 0		64		Salt
// Encrypted:
// 64		4		ASCII string 'TRUE'
// 68		2		Header version
// 70		2		Required program version
// 72		4		CRC-32 checksum of the (decrypted) bytes 256-511
// 76		8		Volume creation time
// 84		8		Header creation time
// 92		8		Size of hidden volume in bytes (0 = normal volume)
// 100		8		Size of the volume in bytes (identical with field 92 for hidden volumes)
// 108		8		Start byte offset of the encrypted area of the volume
// 116		8		Size of the encrypted area of the volume in bytes
// 124		132		Reserved (set to zero)
// 256		256		Concatenated primary master key(s) and secondary master key(s) (XTS mode)


/* Deprecated/legacy volume header v2 structure (used before TrueCrypt 5.0): */
//
// Offset	Length	Description
// ------------------------------------------
// Unencrypted:
// 0		64		Salt
// Encrypted:
// 64		4		ASCII string 'TRUE'
// 68		2		Header version
// 70		2		Required program version
// 72		4		CRC-32 checksum of the (decrypted) bytes 256-511
// 76		8		Volume creation time
// 84		8		Header creation time
// 92		8		Size of hidden volume in bytes (0 = normal volume)
// 100		156		Reserved (set to zero)
// 256		32		For LRW (deprecated/legacy), secondary key
//					For CBC (deprecated/legacy), data used to generate IV and whitening values
// 288		224		Master key(s)



uint16 GetHeaderField16 (byte *header, size_t offset)
{
	return BE16 (*(uint16 *) (header + offset));
}


uint32 GetHeaderField32 (byte *header, size_t offset)
{
	return BE32 (*(uint32 *) (header + offset));
}


UINT64_STRUCT GetHeaderField64 (byte *header, size_t offset)
{
	UINT64_STRUCT uint64Struct;

#ifndef TC_NO_COMPILER_INT64
	uint64Struct.Value = BE64 (*(uint64 *) (header + offset));
#else
	uint64Struct.HighPart = BE32 (*(uint32 *) (header + offset));
	uint64Struct.LowPart = BE32 (*(uint32 *) (header + offset + 4));
#endif
	return uint64Struct;
}


int VolumeReadHeader (BOOL bBoot, char *encryptedHeader, Password *password, PCRYPTO_INFO *retInfo, CRYPTO_INFO *retHeaderCryptoInfo)
{
	char header[HEADER_SIZE];
	KEY_INFO keyInfo;
	PCRYPTO_INFO cryptoInfo;
	char dk[MASTER_KEYDATA_SIZE];
	int pkcs5_prf;
	int headerVersion, requiredVersion;
	int status;
	int primaryKeyOffset;

#ifdef _WIN32
#ifndef DEVICE_DRIVER
	VirtualLock (&keyInfo, sizeof (keyInfo));
	VirtualLock (&dk, sizeof (dk));
#endif
#endif

	if (retHeaderCryptoInfo != NULL)
	{
		cryptoInfo = retHeaderCryptoInfo;
	}
	else
	{
		cryptoInfo = *retInfo = crypto_open ();
		if (cryptoInfo == NULL)
			return ERR_OUTOFMEMORY;
	}

	crypto_loadkey (&keyInfo, password->Text, (int) password->Length);

	// PKCS5 is used to derive the primary header key(s) and secondary header key(s) (XTS mode) from the password
	memcpy (keyInfo.salt, encryptedHeader + HEADER_SALT_OFFSET, PKCS5_SALT_SIZE);

	// Test all available PKCS5 PRFs
	for (pkcs5_prf = FIRST_PRF_ID; pkcs5_prf <= LAST_PRF_ID; pkcs5_prf++)
	{
		BOOL lrw64InitDone = FALSE;		// Deprecated/legacy
		BOOL lrw128InitDone = FALSE;	// Deprecated/legacy

		keyInfo.noIterations = get_pkcs5_iteration_count (pkcs5_prf, bBoot);

		switch (pkcs5_prf)
		{
		case RIPEMD160:
			derive_key_ripemd160 (keyInfo.userKey, keyInfo.keyLength, keyInfo.salt,
				PKCS5_SALT_SIZE, keyInfo.noIterations, dk, GetMaxPkcs5OutSize());
			break;

#ifndef TC_WINDOWS_BOOT

		case SHA512:
			derive_key_sha512 (keyInfo.userKey, keyInfo.keyLength, keyInfo.salt,
				PKCS5_SALT_SIZE, keyInfo.noIterations, dk, GetMaxPkcs5OutSize());
			break;

		case SHA1:
			// Deprecated/legacy
			derive_key_sha1 (keyInfo.userKey, keyInfo.keyLength, keyInfo.salt,
				PKCS5_SALT_SIZE, keyInfo.noIterations, dk, GetMaxPkcs5OutSize());
			break;

		case WHIRLPOOL:
			derive_key_whirlpool (keyInfo.userKey, keyInfo.keyLength, keyInfo.salt,
				PKCS5_SALT_SIZE, keyInfo.noIterations, dk, GetMaxPkcs5OutSize());
			break;
#endif

		default:		
			// Unknown/wrong ID
			TC_THROW_FATAL_EXCEPTION;
		} 

		// Test all available modes of operation
		for (cryptoInfo->mode = FIRST_MODE_OF_OPERATION_ID;
			cryptoInfo->mode <= LAST_MODE_OF_OPERATION;
			cryptoInfo->mode++)
		{
			switch (cryptoInfo->mode)
			{
#ifndef TC_WINDOWS_BOOT
			case LRW:
			case CBC:
			case INNER_CBC:
			case OUTER_CBC:

				// For LRW (deprecated/legacy), copy the tweak key 
				// For CBC (deprecated/legacy), copy the IV/whitening seed 
				memcpy (cryptoInfo->k2, dk, LEGACY_VOL_IV_SIZE);
				primaryKeyOffset = LEGACY_VOL_IV_SIZE;
				break;
#endif
			default:
				primaryKeyOffset = 0;
			}

			// Test all available encryption algorithms
			for (cryptoInfo->ea = EAGetFirst ();
				cryptoInfo->ea != 0;
				cryptoInfo->ea = EAGetNext (cryptoInfo->ea))
			{
				int blockSize;

				if (!EAIsModeSupported (cryptoInfo->ea, cryptoInfo->mode))
					continue;	// This encryption algorithm has never been available with this mode of operation

				blockSize = CipherGetBlockSize (EAGetFirstCipher (cryptoInfo->ea));

				status = EAInit (cryptoInfo->ea, dk + primaryKeyOffset, cryptoInfo->ks);
				if (status == ERR_CIPHER_INIT_FAILURE)
					goto err;

				// Init objects related to the mode of operation

				if (cryptoInfo->mode == XTS)
				{
					// Copy the secondary key (if cascade, multiple concatenated)
					memcpy (cryptoInfo->k2, dk + EAGetKeySize (cryptoInfo->ea), EAGetKeySize (cryptoInfo->ea));

					// Secondary key schedule
					if (!EAInitMode (cryptoInfo))
					{
						status = ERR_MODE_INIT_FAILED;
						goto err;
					}
				}
#ifndef TC_WINDOWS_BOOT
				else if (cryptoInfo->mode == LRW
					&& (blockSize == 8 && !lrw64InitDone || blockSize == 16 && !lrw128InitDone))
				{
					// Deprecated/legacy

					if (!EAInitMode (cryptoInfo))
					{
						status = ERR_MODE_INIT_FAILED;
						goto err;
					}

					if (blockSize == 8)
						lrw64InitDone = TRUE;
					else if (blockSize == 16)
						lrw128InitDone = TRUE;
				}
#endif

				// Copy the header for decryption
				memcpy (header, encryptedHeader, HEADER_SIZE);

				// Try to decrypt header 

				DecryptBuffer (header + HEADER_ENCRYPTED_DATA_OFFSET, HEADER_ENCRYPTED_DATA_SIZE, cryptoInfo);

				// Magic 'TRUE'
				if (GetHeaderField32 (header, TC_HEADER_OFFSET_MAGIC) != 0x54525545)
					continue;

				// Header version
				headerVersion = GetHeaderField16 (header, TC_HEADER_OFFSET_VERSION);

				// Required program version
				requiredVersion = GetHeaderField16 (header, TC_HEADER_OFFSET_REQUIRED_VERSION);

				// Check CRC of the key set
				if (GetHeaderField32 (header, TC_HEADER_OFFSET_KEY_AREA_CRC) != GetCrc32 (header + HEADER_MASTER_KEYDATA_OFFSET, MASTER_KEYDATA_SIZE))
					continue;

				// Now we have the correct password, cipher, hash algorithm, and volume type

				// Check the version required to handle this volume
				if (requiredVersion > VERSION_NUM)
				{
					status = ERR_NEW_VERSION_REQUIRED;
					goto err;
				}

#ifndef TC_WINDOWS_BOOT
				// Volume creation time
				cryptoInfo->volume_creation_time = GetHeaderField64 (header, TC_HEADER_OFFSET_VOLUME_CREATION_TIME).Value;

				// Header creation time
				cryptoInfo->header_creation_time = GetHeaderField64 (header, TC_HEADER_OFFSET_MODIFICATION_TIME).Value;

				// Hidden volume size (if any)
				cryptoInfo->hiddenVolumeSize = GetHeaderField64 (header, TC_HEADER_OFFSET_HIDDEN_VOLUME_SIZE).Value;
#endif
				// Volume size
				cryptoInfo->VolumeSize = GetHeaderField64 (header, TC_HEADER_OFFSET_VOLUME_SIZE);
				
				// Encrypted area size and length
				cryptoInfo->EncryptedAreaStart = GetHeaderField64 (header, TC_HEADER_OFFSET_ENCRYPTED_AREA_START);
				cryptoInfo->EncryptedAreaLength = GetHeaderField64 (header, TC_HEADER_OFFSET_ENCRYPTED_AREA_LENGTH);

				// Preserve scheduled header keys if requested			
				if (retHeaderCryptoInfo)
				{
					if (retInfo == NULL)
					{
						cryptoInfo->pkcs5 = pkcs5_prf;
						cryptoInfo->noIterations = keyInfo.noIterations;
						goto ret;
					}

					cryptoInfo = *retInfo = crypto_open ();
					if (cryptoInfo == NULL)
					{
						status = ERR_OUTOFMEMORY;
						goto err;
					}

					memcpy (cryptoInfo, retHeaderCryptoInfo, sizeof (*cryptoInfo));
				}

				// Master key data
				memcpy (keyInfo.master_keydata, header + HEADER_MASTER_KEYDATA_OFFSET, MASTER_KEYDATA_SIZE);
				memcpy (cryptoInfo->master_keydata, keyInfo.master_keydata, MASTER_KEYDATA_SIZE);

#ifndef TC_WINDOWS_BOOT
				// PKCS #5
				memcpy (cryptoInfo->salt, keyInfo.salt, PKCS5_SALT_SIZE);
				cryptoInfo->pkcs5 = pkcs5_prf;
				cryptoInfo->noIterations = keyInfo.noIterations;
#endif

				// Init the encryption algorithm with the decrypted master key
				status = EAInit (cryptoInfo->ea, keyInfo.master_keydata + primaryKeyOffset, cryptoInfo->ks);
				if (status == ERR_CIPHER_INIT_FAILURE)
					goto err;

				switch (cryptoInfo->mode)
				{
#ifndef TC_WINDOWS_BOOT
				case LRW:
				case CBC:
				case INNER_CBC:
				case OUTER_CBC:

					// For LRW (deprecated/legacy), the tweak key
					// For CBC (deprecated/legacy), the IV/whitening seed
					memcpy (cryptoInfo->k2, keyInfo.master_keydata, LEGACY_VOL_IV_SIZE);
					break;
#endif
				default:
					// The secondary master key (if cascade, multiple concatenated)
					memcpy (cryptoInfo->k2, keyInfo.master_keydata + EAGetKeySize (cryptoInfo->ea), EAGetKeySize (cryptoInfo->ea));

				}

				if (!EAInitMode (cryptoInfo))
				{
					status = ERR_MODE_INIT_FAILED;
					goto err;
				}

				// Clear out the temporary key buffers
ret:
				burn (dk, sizeof(dk));
				burn (&keyInfo, sizeof (keyInfo));

				return 0;
			}
		}
	}
	status = ERR_PASSWORD_WRONG;

err:
	if (cryptoInfo != retHeaderCryptoInfo)
	{
		crypto_close(cryptoInfo);
		*retInfo = NULL; 
	}

	burn (&keyInfo, sizeof (keyInfo));
	burn (dk, sizeof(dk));
	return status;
}

#if !defined (DEVICE_DRIVER) && !defined (TC_WINDOWS_BOOT)

#ifdef VOLFORMAT
#include "../Format/TcFormat.h"
#endif

// Creates a volume header in memory
int VolumeWriteHeader (BOOL bBoot, char *header, int ea, int mode, Password *password,
		   int pkcs5_prf, char *masterKeydata, unsigned __int64 volumeCreationTime, PCRYPTO_INFO *retInfo,
		   unsigned __int64 volumeSize, unsigned __int64 hiddenVolumeSize,
		   unsigned __int64 encryptedAreaStart, unsigned __int64 encryptedAreaLength, BOOL bWipeMode)
{
	unsigned char *p = (unsigned char *) header;
	static KEY_INFO keyInfo;

	int nUserKeyLen = password->Length;
	PCRYPTO_INFO cryptoInfo = crypto_open ();
	static char dk[MASTER_KEYDATA_SIZE];
	int x;
	int retVal = 0;
	int primaryKeyOffset;

	if (cryptoInfo == NULL)
		return ERR_OUTOFMEMORY;

	memset (header, 0, HEADER_SIZE);

#ifdef _WIN32
	VirtualLock (&keyInfo, sizeof (keyInfo));
	VirtualLock (&dk, sizeof (dk));
#endif

	/* Encryption setup */

	if (masterKeydata == NULL)
	{
		// We have no master key data (creating a new volume) so we'll use the TrueCrypt RNG to generate them

		int bytesNeeded;

		switch (mode)
		{
		case LRW:
		case CBC:
		case INNER_CBC:
		case OUTER_CBC:

			// Deprecated/legacy modes of operation
			bytesNeeded = LEGACY_VOL_IV_SIZE + EAGetKeySize (ea);

			/* In fact, this should never be the case since new volumes are not supposed to use
			   any deprecated mode of operation. */
			return ERR_VOL_FORMAT_BAD;

		default:
			bytesNeeded = EAGetKeySize (ea) * 2;	// Size of primary + secondary key(s)
		}

		if (!RandgetBytes (keyInfo.master_keydata, bytesNeeded, TRUE))
			return ERR_CIPHER_INIT_WEAK_KEY;
	}
	else
	{
		// We already have existing master key data (the header is being re-encrypted)
		memcpy (keyInfo.master_keydata, masterKeydata, MASTER_KEYDATA_SIZE);
	}

	// User key 
	memcpy (keyInfo.userKey, password->Text, nUserKeyLen);
	keyInfo.keyLength = nUserKeyLen;
	keyInfo.noIterations = get_pkcs5_iteration_count (pkcs5_prf, bBoot);

	// User selected encryption algorithm
	cryptoInfo->ea = ea;

	// Mode of operation
	cryptoInfo->mode = mode;

	// Salt for header key derivation
	if (!RandgetBytes (keyInfo.salt, PKCS5_SALT_SIZE, !bWipeMode))
		return ERR_CIPHER_INIT_WEAK_KEY; 

	// PBKDF2 (PKCS5) is used to derive primary header key(s) and secondary header key(s) (XTS) from the password/keyfiles
	switch (pkcs5_prf)
	{
	case SHA512:
		derive_key_sha512 (keyInfo.userKey, keyInfo.keyLength, keyInfo.salt,
			PKCS5_SALT_SIZE, keyInfo.noIterations, dk, GetMaxPkcs5OutSize());
		break;

	case SHA1:
		// Deprecated/legacy
		derive_key_sha1 (keyInfo.userKey, keyInfo.keyLength, keyInfo.salt,
			PKCS5_SALT_SIZE, keyInfo.noIterations, dk, GetMaxPkcs5OutSize());
		break;

	case RIPEMD160:
		derive_key_ripemd160 (keyInfo.userKey, keyInfo.keyLength, keyInfo.salt,
			PKCS5_SALT_SIZE, keyInfo.noIterations, dk, GetMaxPkcs5OutSize());
		break;

	case WHIRLPOOL:
		derive_key_whirlpool (keyInfo.userKey, keyInfo.keyLength, keyInfo.salt,
			PKCS5_SALT_SIZE, keyInfo.noIterations, dk, GetMaxPkcs5OutSize());
		break;

	default:		
		// Unknown/wrong ID
		TC_THROW_FATAL_EXCEPTION;
	} 

	/* Header setup */

	// Salt
	mputBytes (p, keyInfo.salt, PKCS5_SALT_SIZE);	

	// Magic
	mputLong (p, 0x54525545);

	// Header version
	switch (mode)
	{
	case LRW:
	case CBC:
	case OUTER_CBC:
	case INNER_CBC:
		// Deprecated/legacy modes (used before TrueCrypt 5.0)
		mputWord (p, 0x0002);
		break;
	default:
		mputWord (p, VOLUME_HEADER_VERSION);
	}

	// Required program version to handle this volume
	switch (mode)
	{
	case LRW:
		// Deprecated/legacy
		mputWord (p, 0x0410);
		break;
	case OUTER_CBC:
	case INNER_CBC:
		// Deprecated/legacy
		mputWord (p, 0x0300);
		break;
	case CBC:
		// Deprecated/legacy
		mputWord (p, hiddenVolumeSize > 0 ? 0x0300 : 0x0100);
		break;
	default:
		mputWord (p, VOL_REQ_PROG_VERSION);
	}

	// CRC of the master key data
	x = GetCrc32(keyInfo.master_keydata, MASTER_KEYDATA_SIZE);
	mputLong (p, x);

	// Time
	{
#ifdef _WIN32
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

		// Header modification time/date
		GetLocalTime (&st);
		SystemTimeToFileTime (&st, &ft);
		mputLong (p, ft.dwHighDateTime);
		mputLong (p, ft.dwLowDateTime);

#else
		struct timeval tv;
		unsigned __int64 ct, wt;
		gettimeofday (&tv, NULL);

		// Unix time => Windows file time
		wt = ((unsigned __int64)tv.tv_sec + 134774LL * 24 * 3600) * 1000LL * 1000 * 10;

		if (volumeCreationTime == 0)
			ct = wt;
		else
			ct = volumeCreationTime;

		mputInt64 (p, ct);
		mputInt64 (p, wt);
#endif

	}

	// Size of hidden volume (if any)
	cryptoInfo->hiddenVolumeSize = hiddenVolumeSize;
	mputInt64 (p, cryptoInfo->hiddenVolumeSize);

	cryptoInfo->hiddenVolume = cryptoInfo->hiddenVolumeSize != 0;

	// Volume size
	cryptoInfo->VolumeSize.Value = volumeSize;
	mputInt64 (p, volumeSize);

	// Encrypted area start
	cryptoInfo->EncryptedAreaStart.Value = encryptedAreaStart;
	mputInt64 (p, encryptedAreaStart);

	// Encrypted area size
	cryptoInfo->EncryptedAreaLength.Value = encryptedAreaLength;
	mputInt64 (p, encryptedAreaLength);

	// The master key data
	memcpy (header + HEADER_MASTER_KEYDATA_OFFSET, keyInfo.master_keydata, MASTER_KEYDATA_SIZE);


	/* Header encryption */

	switch (mode)
	{
	case LRW:
	case CBC:
	case INNER_CBC:
	case OUTER_CBC:

		// For LRW (deprecated/legacy), the tweak key
		// For CBC (deprecated/legacy), the IV/whitening seed
		memcpy (cryptoInfo->k2, dk, LEGACY_VOL_IV_SIZE);
		primaryKeyOffset = LEGACY_VOL_IV_SIZE;
		break;

	default:
		// The secondary key (if cascade, multiple concatenated)
		memcpy (cryptoInfo->k2, dk + EAGetKeySize (cryptoInfo->ea), EAGetKeySize (cryptoInfo->ea));
		primaryKeyOffset = 0;
	}

	retVal = EAInit (cryptoInfo->ea, dk + primaryKeyOffset, cryptoInfo->ks);
	if (retVal != ERR_SUCCESS)
		return retVal;

	// Mode of operation
	if (!EAInitMode (cryptoInfo))
		return ERR_OUTOFMEMORY;


	// Encrypt the entire header (except the salt)
	EncryptBuffer (header + HEADER_ENCRYPTED_DATA_OFFSET,
		HEADER_ENCRYPTED_DATA_SIZE,
		cryptoInfo);


	/* cryptoInfo setup for further use (disk format) */

	// Init with the master key(s) 
	retVal = EAInit (cryptoInfo->ea, keyInfo.master_keydata + primaryKeyOffset, cryptoInfo->ks);
	if (retVal != ERR_SUCCESS)
		return retVal;

	memcpy (cryptoInfo->master_keydata, keyInfo.master_keydata, MASTER_KEYDATA_SIZE);

	switch (cryptoInfo->mode)
	{
	case LRW:
	case CBC:
	case INNER_CBC:
	case OUTER_CBC:

		// For LRW (deprecated/legacy), the tweak key
		// For CBC (deprecated/legacy), the IV/whitening seed
		memcpy (cryptoInfo->k2, keyInfo.master_keydata, LEGACY_VOL_IV_SIZE);
		break;

	default:
		// The secondary master key (if cascade, multiple concatenated)
		memcpy (cryptoInfo->k2, keyInfo.master_keydata + EAGetKeySize (cryptoInfo->ea), EAGetKeySize (cryptoInfo->ea));
	}

	// Mode of operation
	if (!EAInitMode (cryptoInfo))
		return ERR_OUTOFMEMORY;


#ifdef VOLFORMAT
	if (showKeys)
	{
		BOOL dots3 = FALSE;
		int i, j;

		j = EAGetKeySize (ea);

		if (j > NBR_KEY_BYTES_TO_DISPLAY)
		{
			dots3 = TRUE;
			j = NBR_KEY_BYTES_TO_DISPLAY;
		}

		MasterKeyGUIView[0] = 0;
		for (i = 0; i < j; i++)
		{
			char tmp2[8] = {0};
			sprintf (tmp2, "%02X", (int) (unsigned char) keyInfo.master_keydata[i + primaryKeyOffset]);
			strcat (MasterKeyGUIView, tmp2);
		}

		if (dots3)
		{
			strcat (MasterKeyGUIView, "...");
		}

		SendMessage (hMasterKey, WM_SETTEXT, 0, (LPARAM) MasterKeyGUIView);

		HeaderKeyGUIView[0] = 0;
		for (i = 0; i < NBR_KEY_BYTES_TO_DISPLAY; i++)
		{
			char tmp2[8];
			sprintf (tmp2, "%02X", (int) (unsigned char) dk[primaryKeyOffset + i]);
			strcat (HeaderKeyGUIView, tmp2);
		}

		if (dots3)
		{
			strcat (HeaderKeyGUIView, "...");
		}

		SendMessage (hHeaderKey, WM_SETTEXT, 0, (LPARAM) HeaderKeyGUIView);
	}
#endif	// #ifdef VOLFORMAT

	burn (dk, sizeof(dk));
	burn (&keyInfo, sizeof (keyInfo));

	*retInfo = cryptoInfo;
	return 0;
}

#endif // !defined (DEVICE_DRIVER) && !defined (TC_WINDOWS_BOOT)
