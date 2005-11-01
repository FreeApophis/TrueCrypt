/* Legal Notice: The source code contained in this file has been derived from
   the source code of Encryption for the Masses 2.02a, which is Copyright (c)
   1998-99 Paul Le Roux and which is covered by the 'License Agreement for
   Encryption for the Masses'. Modifications and additions to that source code
   contained in this file are Copyright (c) 2004-2005 TrueCrypt Foundation and
   Copyright (c) 2004 TrueCrypt Team, and are covered by TrueCrypt License 2.0
   the full text of which is contained in the file License.txt included in
   TrueCrypt binary and source code distribution archives.  */

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

// User text input limits
#define MIN_PASSWORD		1			// Minimum password length
#define MAX_PASSWORD		64			// Maximum password length

#define PASSWORD_LEN_WARNING	12		// Display a warning when a password is shorter than this

// Header key derivation
#define PKCS5_SALT_SIZE				64

// Disk/master key + IV
#define DISKKEY_SIZE		256
#define DISK_IV_SIZE		32

// Volume header byte offsets
#define	HEADER_USERKEY_SALT		0
#define HEADER_ENCRYPTEDDATA	PKCS5_SALT_SIZE
#define	HEADER_DISKKEY			256

// Volume header sizes
#define HEADER_SIZE					512
#define HEADER_ENCRYPTEDDATASIZE	(HEADER_SIZE - HEADER_ENCRYPTEDDATA)

/* The offset, in bytes, of the hidden volume header position from the end of the file (a positive value).
   The extra offset (SECTOR_SIZE * 2) was added because FAT file system fills the last sector with zeroes
   (marked as free; observed when quick format was performed using the OS format tool). One extra sector was
   added to the offset for future expandability (should the header size increase, or should header backup be
   introduced). */
#define HIDDEN_VOL_HEADER_OFFSET	(HEADER_SIZE + SECTOR_SIZE * 2)		

// Hash algorithms
#define	RIPEMD160			1
#define	SHA1				2
#define	WHIRLPOOL			3
#define LAST_PRF_ID			3			// The number of implemented/available pseudo-random functions (PKCS #5 v2.0)

#define SHA1_BLOCKSIZE			64
#define SHA1_DIGESTSIZE			20
#define RIPEMD160_BLOCKSIZE		64
#define RIPEMD160_DIGESTSIZE	20
#define WHIRLPOOL_BLOCKSIZE		64
#define WHIRLPOOL_DIGESTSIZE	64
#define MAX_DIGESTSIZE			WHIRLPOOL_DIGESTSIZE

#define DEFAULT_HASH_ALGORITHM		RIPEMD160

// Modes of operation
enum
{
	CBC = 1,
	OUTER_CBC,
	INNER_CBC
};

// Cipher IDs
#define NONE				0
#define AES					1
#define BLOWFISH			2
#define CAST				3
#define SERPENT				4
#define TRIPLEDES			5
#define TWOFISH				6
#define DES56				7			// Used only by Triple DES

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
	int Mode;				// The mode of operation of the whole EA (cipher cascade)
} EncryptionAlgorithm;

// Maxium length of scheduled key
#define AES_KS				(sizeof(aes_encrypt_ctx) + sizeof(aes_decrypt_ctx))
#define SERPENT_KS			(140 * 4)
#define MAX_EXPANDED_KEY	(AES_KS + SERPENT_KS + TWOFISH_KS)

#define DISK_WIPE_PASSES	36	// (Gutmann)

#include "Aes.h"
#include "Blowfish.h"
#include "Cast.h"
#include "Des.h"
#include "Serpent.h"
#include "Twofish.h"

#ifndef LINUX_DRIVER
#include "Rmd160.h"
#include "Sha1.h"
#include "Whirlpool.h"
#endif

typedef struct keyInfo_t
{
	int noIterations;					/* No.of times to iterate setup */
	int keyLength;						/* Length of the key */
	char userKey[MAX_PASSWORD];			/* Max pass, WITHOUT +1 for the NULL */
	char key_salt[PKCS5_SALT_SIZE];	/* Key setup salt */
	char key[DISKKEY_SIZE];				/* The keying material itself */
} KEY_INFO, *PKEY_INFO;

typedef struct CRYPTO_INFO_t
{
	/* Encryption alogrithm information */
	int ea;
	unsigned char iv[DISK_IV_SIZE];
	unsigned char ks[MAX_EXPANDED_KEY];

	/* Volume information */

	unsigned char master_key[DISKKEY_SIZE];
	unsigned char key_salt[PKCS5_SALT_SIZE];
	int noIterations;
	int pkcs5;

	unsigned __int64 volume_creation_time;
	unsigned __int64 header_creation_time;

	// Hidden volume status & parameters
	BOOL hiddenVolume;					// Indicates whether the volume is mounted/mountable as hidden volume
	BOOL bProtectHiddenVolume;			// Indicates whether the volume contains a hidden volume to be protected against overwriting (if so, no data must be written at offset hiddenVolumeOffset or beyond).
	BOOL bHiddenVolProtectionAction;		// TRUE if a write operation has been denied by the driver in order to prevent the hidden volume from being overwritten (set to FALSE upon volume mount).
	unsigned __int64 hiddenVolumeSize;		// Size of the hidden volume excluding the header (in bytes). Set to 0 for standard volumes.
	unsigned __int64 hiddenVolumeOffset;	// Absolute position, in bytes, of the first hidden volume data sector within the host volume (provided that there is a hidden volume within). This must be set for all hidden volumes; in case of a normal volume, this variable is only used when protecting a hidden volume within it.

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
void EncipherBlock(int cipher, void *data, void *ks);
void DecipherBlock(int cipher, void *data, void *ks);

int EAGetFirst ();
int EAGetCount (void);
int EAGetNext (int previousEA);
char * EAGetName (char *buf, int ea);
int EAGetKeySize (int ea);
int EAGetMode (int ea);
char * EAGetModeName (int ea, BOOL capitalLetters);
int EAGetKeyScheduleSize (int ea);
int EAGetLargestKey ();

int EAGetCipherCount (int ea);
int EAGetFirstCipher (int ea);
int EAGetLastCipher (int ea);
int EAGetNextCipher (int ea, int previousCipherId);
int EAGetPreviousCipher (int ea, int previousCipherId);

void EncryptBuffer (unsigned __int32 *buf, unsigned __int64 len, unsigned char *ks, void *iv, void *whitening, int ea);
void DecryptBuffer (unsigned __int32 *buf, unsigned __int64 len, unsigned char *ks, void *iv, void *whitening, int ea);
void _cdecl EncryptSectors (unsigned __int32 *buf, unsigned __int64 secNo, unsigned __int64 noSectors, unsigned char *ks, void *iv, int ea);
void _cdecl DecryptSectors (unsigned __int32 *buf, unsigned __int64 secNo, unsigned __int64 noSectors, unsigned char *ks, void *iv, int ea);

char *get_hash_algo_name (int hash_algo_id);

#endif		/* CRYPTO_H */
