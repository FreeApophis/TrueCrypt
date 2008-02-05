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

#ifndef CRYPTO_H
#define CRYPTO_H

#include "Tcdefs.h"

#ifdef __cplusplus
extern "C" {
#endif

// Encryption data unit size, which may differ from the sector size and must always be 512
#define ENCRYPTION_DATA_UNIT_SIZE	512

// Size of the salt (in bytes)
#define PKCS5_SALT_SIZE				64

// Size of the volume header area containing concatenated master key(s) and secondary key(s) (XTS mode)
#define MASTER_KEYDATA_SIZE			256

// Size of the deprecated volume header item containing either an IV seed (CBC mode) or tweak key (LRW mode)
#define LEGACY_VOL_IV_SIZE			32

// Volume header byte offsets
#define	HEADER_SALT_OFFSET					0
#define HEADER_ENCRYPTED_DATA_OFFSET		PKCS5_SALT_SIZE
#define	HEADER_MASTER_KEYDATA_OFFSET		256

// Volume header sizes
#define HEADER_SIZE					512
#define HEADER_ENCRYPTED_DATA_SIZE	(HEADER_SIZE - HEADER_ENCRYPTED_DATA_OFFSET)

/* The offset, in bytes, of the hidden volume header position from the end of the file (a positive value).
   The extra offset (SECTOR_SIZE * 2) was added because FAT file system fills the last sector with zeroes
   (marked as free; observed when quick format was performed using the OS format tool). One extra sector was
   added to the offset for future expandability (should the header size increase, or should header backup be
   introduced). */
#define HIDDEN_VOL_HEADER_OFFSET	(HEADER_SIZE + SECTOR_SIZE * 2)		

	
// The first PRF to try when mounting
#define FIRST_PRF_ID		1	

// Hash algorithms (pseudorandom functions). 
enum
{
	RIPEMD160 = FIRST_PRF_ID,
#ifndef TC_WINDOWS_BOOT
	SHA512,
	WHIRLPOOL,
	SHA1,				// Deprecated/legacy
#endif
	HASH_ENUM_END_ID
};

// The last PRF to try when mounting and also the number of implemented PRFs
#define LAST_PRF_ID			(HASH_ENUM_END_ID - 1)	

#define RIPEMD160_BLOCKSIZE		64
#define RIPEMD160_DIGESTSIZE	20

#define SHA1_BLOCKSIZE			64	
#define SHA1_DIGESTSIZE			20

#define SHA512_BLOCKSIZE		128
#define SHA512_DIGESTSIZE		64

#define WHIRLPOOL_BLOCKSIZE		64
#define WHIRLPOOL_DIGESTSIZE	64

#define MAX_DIGESTSIZE			WHIRLPOOL_DIGESTSIZE

#define DEFAULT_HASH_ALGORITHM			FIRST_PRF_ID
#define DEFAULT_HASH_ALGORITHM_BOOT		RIPEMD160

// The mode of operation used for newly created volumes and first to try when mounting
#define FIRST_MODE_OF_OPERATION_ID		1

// Modes of operation
enum
{
	/* If you add/remove a mode, update the following: GetMaxPkcs5OutSize(), EAInitMode() */

	XTS = FIRST_MODE_OF_OPERATION_ID,
#ifndef TC_WINDOWS_BOOT
	LRW,		// Deprecated/legacy
	CBC,		// Deprecated/legacy
	OUTER_CBC,	// Deprecated/legacy
	INNER_CBC,	// Deprecated/legacy
#endif
	MODE_ENUM_END_ID
};


// The last mode of operation to try when mounting and also the number of implemented modes
#define LAST_MODE_OF_OPERATION		(MODE_ENUM_END_ID - 1)

// Ciphertext/plaintext block size for XTS mode (in bytes)
#define BYTES_PER_XTS_BLOCK			16

// Number of ciphertext/plaintext blocks per XTS data unit
#define BLOCKS_PER_XTS_DATA_UNIT	(ENCRYPTION_DATA_UNIT_SIZE / BYTES_PER_XTS_BLOCK)


// Cipher IDs
enum
{
	NONE = 0,
	AES,
	SERPENT,			
	TWOFISH,			
#ifndef TC_WINDOWS_BOOT
	BLOWFISH,		// Deprecated/legacy
	CAST,			// Deprecated/legacy
	TRIPLEDES,		// Deprecated/legacy
	DES56			// Deprecated/legacy (used only by Triple DES)
#endif
};

typedef struct
{
	int Id;					// Cipher ID
	char *Name;				// Name
	int BlockSize;			// Block size (bytes)
	int KeySize;			// Key size (bytes)
	int KeyScheduleSize;	// Scheduled key size (bytes)
} Cipher;

typedef struct
{
	int Ciphers[4];			// Null terminated array of ciphers used by encryption algorithm
	int Modes[LAST_MODE_OF_OPERATION + 1];			// Null terminated array of modes of operation
	int FormatEnabled;
} EncryptionAlgorithm;

typedef struct
{
	int Id;					// Hash ID
	char *Name;				// Name
	BOOL Deprecated;
	BOOL SystemEncryption;	// Available for system encryption
} Hash;

// Maxium length of scheduled key
#ifndef TC_WINDOWS_BOOT
#	define AES_KS				(sizeof(aes_encrypt_ctx) + sizeof(aes_decrypt_ctx))
#else
#	define AES_KS				(sizeof(aes_context))
#endif
#define SERPENT_KS			(140 * 4)
#define MAX_EXPANDED_KEY	(AES_KS + SERPENT_KS + TWOFISH_KS)

#define PRAND_DISK_WIPE_PASSES	200

#ifndef TC_WINDOWS_BOOT
#	include "Aes.h"
#else
#	include "AesSmall.h"
#endif

#include "Blowfish.h"
#include "Cast.h"
#include "Des.h"
#include "Serpent.h"
#include "Twofish.h"

#ifndef LINUX_DRIVER
#	include "Rmd160.h"
#	ifndef TC_WINDOWS_BOOT
#		include "Sha1.h"
#		include "Sha2.h"
#		include "Whirlpool.h"
#	endif
#endif

#include "GfMul.h"
#include "Password.h"

typedef struct keyInfo_t
{
	int noIterations;					/* Number of times to iterate (PKCS-5) */
	int keyLength;						/* Length of the key */
	__int8 userKey[MAX_PASSWORD];		/* Password (to which keyfiles may have been applied). WITHOUT +1 for the null terminator. */
	__int8 salt[PKCS5_SALT_SIZE];		/* PKCS-5 salt */
	__int8 master_keydata[MASTER_KEYDATA_SIZE];		/* Concatenated master primary and secondary key(s) (XTS mode). For LRW (deprecated/legacy), it contains the tweak key before the master key(s). For CBC (deprecated/legacy), it contains the IV seed before the master key(s). */
} KEY_INFO, *PKEY_INFO;

typedef struct CRYPTO_INFO_t
{
	int ea;									/* Encryption algorithm ID */
	int mode;								/* Mode of operation (e.g., XTS) */
	unsigned __int8 ks[MAX_EXPANDED_KEY];	/* Primary key schedule (if it is a cascade, it conatins multiple concatenated keys) */
	unsigned __int8 ks2[MAX_EXPANDED_KEY];	/* Secondary key schedule (if cascade, multiple concatenated) for XTS mode. */

#ifndef TC_WINDOWS_BOOT
	GfCtx gf_ctx; 
#endif // TC_WINDOWS_BOOT

	unsigned __int8 master_keydata[MASTER_KEYDATA_SIZE];	/* This holds the volume header area containing concatenated master key(s) and secondary key(s) (XTS mode). For LRW (deprecated/legacy), it contains the tweak key before the master key(s). For CBC (deprecated/legacy), it contains the IV seed before the master key(s). */
	unsigned __int8 k2[MASTER_KEYDATA_SIZE];				/* For XTS, this contains the secondary key (if cascade, multiple concatenated). For LRW (deprecated/legacy), it contains the tweak key. For CBC (deprecated/legacy), it contains the IV seed. */
	unsigned __int8 salt[PKCS5_SALT_SIZE];
	int noIterations;
	int pkcs5;

#ifndef TC_NO_COMPILER_INT64
	unsigned __int64 volume_creation_time;
	unsigned __int64 header_creation_time;
#endif

	// Hidden volume status & parameters
	BOOL hiddenVolume;					// Indicates whether the volume is mounted/mountable as hidden volume
	BOOL bProtectHiddenVolume;			// Indicates whether the volume contains a hidden volume to be protected against overwriting
	BOOL bHiddenVolProtectionAction;		// TRUE if a write operation has been denied by the driver in order to prevent the hidden volume from being overwritten (set to FALSE upon volume mount).

#ifndef TC_NO_COMPILER_INT64
	unsigned __int64 hiddenVolumeSize;		// Size of the hidden volume excluding the header (in bytes). Set to 0 for standard volumes.
	unsigned __int64 hiddenVolumeOffset;	// Absolute position, in bytes, of the first hidden volume data sector within the host volume (provided that there is a hidden volume within). This must be set for all hidden volumes; in case of a normal volume, this variable is only used when protecting a hidden volume within it.
#endif

	UINT64_STRUCT VolumeSize;

	UINT64_STRUCT EncryptedAreaStart;
	UINT64_STRUCT EncryptedAreaLength;

} CRYPTO_INFO, *PCRYPTO_INFO;

PCRYPTO_INFO crypto_open (void);
void crypto_loadkey (PKEY_INFO keyInfo, char *lpszUserKey, int nUserKeyLen);
void crypto_close (PCRYPTO_INFO cryptoInfo);

int CipherGetBlockSize (int cipher);
int CipherGetKeySize (int cipher);
int CipherGetKeyScheduleSize (int cipher);
char * CipherGetName (int cipher);

int CipherInit (int cipher, unsigned char *key, unsigned char *ks);
int EAInit (int ea, unsigned char *key, unsigned char *ks);
int EAInitMode (PCRYPTO_INFO ci);
void EncipherBlock(int cipher, void *data, void *ks);
void DecipherBlock(int cipher, void *data, void *ks);

int EAGetFirst ();
int EAGetCount (void);
int EAGetNext (int previousEA);
char * EAGetName (char *buf, int ea);
int EAGetByName (char *name);
int EAGetKeySize (int ea);
int EAGetFirstMode (int ea);
int EAGetNextMode (int ea, int previousModeId);
char * EAGetModeName (int ea, int mode, BOOL capitalLetters);
int EAGetKeyScheduleSize (int ea);
int EAGetLargestKey ();
int EAGetLargestKeyForMode (int mode);

int EAGetCipherCount (int ea);
int EAGetFirstCipher (int ea);
int EAGetLastCipher (int ea);
int EAGetNextCipher (int ea, int previousCipherId);
int EAGetPreviousCipher (int ea, int previousCipherId);
int EAIsFormatEnabled (int ea);
BOOL EAIsModeSupported (int ea, int testedMode);

char *HashGetName (int hash_algo_id);
BOOL HashIsDeprecated (int hashId);

int GetMaxPkcs5OutSize (void);

void EncryptDataUnits (unsigned __int8 *buf, const UINT64_STRUCT *structUnitNo, TC_LARGEST_COMPILER_UINT nbrUnits, PCRYPTO_INFO ci);
void DecryptDataUnits (unsigned __int8 *buf, const UINT64_STRUCT *structUnitNo, TC_LARGEST_COMPILER_UINT nbrUnits, PCRYPTO_INFO ci);
void EncryptBuffer (unsigned __int8 *buf, TC_LARGEST_COMPILER_UINT len, PCRYPTO_INFO cryptoInfo);
void DecryptBuffer (unsigned __int8 *buf, TC_LARGEST_COMPILER_UINT len, PCRYPTO_INFO cryptoInfo);
#ifndef TC_NO_COMPILER_INT64
void EncryptBufferLRW128 (unsigned __int8 *buffer, unsigned __int64 length, unsigned __int64 blockIndex, PCRYPTO_INFO cryptoInfo);
void DecryptBufferLRW128 (unsigned __int8 *buffer, unsigned __int64 length, unsigned __int64 blockIndex, PCRYPTO_INFO cryptoInfo);
void EncryptBufferLRW64 (unsigned __int8 *buffer, unsigned __int64 length, unsigned __int64 blockIndex, PCRYPTO_INFO cryptoInfo);
void DecryptBufferLRW64 (unsigned __int8 *buffer, unsigned __int64 length, unsigned __int64 blockIndex, PCRYPTO_INFO cryptoInfo);
unsigned __int64 DataUnit2LRWIndex (unsigned __int64 dataUnit, int blockSize, PCRYPTO_INFO ci);
#endif	// #ifndef TC_NO_COMPILER_INT64

#ifdef __cplusplus
}
#endif

#endif		/* CRYPTO_H */
