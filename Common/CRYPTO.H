/* Copyright (C) 2004 TrueCrypt Team, truecrypt.org
   This product uses components written by Paul Le Roux <pleroux@swprofessionals.com> */


// User text input limits
#ifndef _DEBUG
#define MIN_PASSWORD		12
#else
#define MIN_PASSWORD		0
#endif
#define MAX_PASSWORD		64		 

// User key
#define USERKEY_ITERATIONS	2000
#define USERKEY_SALT_SIZE	64

// Disk key + IV
#define DISKKEY_SIZE		256
#define DISK_IV_SIZE		32

// Volume header byte offsets
#define	HEADER_USERKEY_SALT		0
#define HEADER_ENCRYPTEDDATA	USERKEY_SALT_SIZE
#define	HEADER_DISKKEY			256

// Volume header sizes
#define HEADER_SIZE					512
#define HEADER_ENCRYPTEDDATASIZE	(HEADER_SIZE - HEADER_ENCRYPTEDDATA)

// PKCS5 PRF hash algorithm ID
#define	SHA1				1
#define	RIPEMD160			2

/* The encryption algorithm ID  */
#define NONE				0
#define BLOWFISH			1
#define CAST				2
#define IDEA				3
#define TRIPLEDES			4
#define DES56				100			// Used only for DES test vectors

#define LAST_CIPHER_ID		4			// Last cipher used for volume encryption

// Length in bytes of the longest key used by encryption algorithms
#define	MAX_CIPHER_KEY		56			// Blowfish 448 bits

/* Length of scheduled keys */
#define IDEA_KS				104
#define DES_KS				128
#define TRIPLEDES_KS		(DES_KS*3)
#define BLOWFISH_KS			4168
#define CAST_KS				128

#define MAX_EXPANDED_KEY		4168

#include "des.h"
#include "blowfish.h"
#include "idea.h"
#include "sha.h"
#include "sha1.h"
#include "cast.h"

/* _cdecl is needed here because the device driver defaults to stdcall */
typedef void (_cdecl * sector_func) (unsigned long *, unsigned __int64, unsigned long,
				     unsigned char *, unsigned char *, int);

typedef struct keyInfo_t
{
	int noIterations;					/* No.of times to iterate setup */
	int keyLength;						/* Length of the key */
	char userKey[MAX_PASSWORD];			/* Max pass, WITHOUT +1 for the NULL */
	char key_salt[USERKEY_SALT_SIZE];	/* Key setup salt */
	char key[DISKKEY_SIZE];				/* The keying material itself */
} KEY_INFO, *PKEY_INFO;

typedef struct CRYPTO_INFO_t
{
	/* cipher information */
	int cipher;
	sector_func encrypt_sector;
	sector_func decrypt_sector;
	unsigned char iv[DISK_IV_SIZE];
	unsigned char ks[MAX_EXPANDED_KEY];

	/* volume information */
	unsigned char master_decrypted_key[DISKKEY_SIZE];
	unsigned char key_salt[USERKEY_SALT_SIZE];
	int noIterations;
	int pkcs5;

	unsigned __int64 volume_creation_time;
	unsigned __int64 header_creation_time;
} CRYPTO_INFO, *PCRYPTO_INFO;

#define decipher_block(cipher, data, ks) \
{\
	if (cipher == BLOWFISH) BF_decrypt ((void *) data, (void *) ks); \
	else if (cipher == IDEA) ideaCrypt ((void *) data,(void *)  data, (void *) ((char *) ks + IDEA_KS)); \
	else if (cipher == DES56) des_encrypt ((void *) data, (void *) ks, 0); \
	else if (cipher == CAST) CAST_ecb_encrypt((void *) data,(void *) data,(void*)ks,0);  \
	else if (cipher == TRIPLEDES) des_ecb3_encrypt ((void *) data,(void *) data, (void *) ks, \
		(void*)((char*)ks+DES_KS),(void*)((char*)ks+DES_KS*2),0); \
}

#define encipher_block(cipher, data, ks) \
{\
	if (cipher == BLOWFISH) BF_encrypt ((void *) data, (void *) ks); \
	else if (cipher == IDEA) ideaCrypt ((void *) data, (void *) data, (void *) ks); \
	else if (cipher == DES56) des_encrypt ((void *) data, (void *) ks, 1); \
	else if (cipher == CAST) CAST_ecb_encrypt((void *) data,(void *) data,(void*)ks,1);  \
	else if (cipher == TRIPLEDES) des_ecb3_encrypt ((void *) data,(void *) data, (void *) ks, \
		(void*)((char*)ks+DES_KS),(void*)((char*)ks+DES_KS*2),1); \
}

#define init_cipher(cipher, key, ks) \
{\
	if (cipher == BLOWFISH) BF_set_key ((void*)ks, 56, (void*) (key)); \
	else if (cipher == IDEA) ideaExpandKey ((void*) (key), (void*)ks, (void *) ((char *) ks + IDEA_KS)); \
	else if (cipher == DES56) des_key_sched ((void*) (key), (void*)ks); \
	else if (cipher == CAST) CAST_set_key((void*)ks, 16, (void*)(key)); \
	else if (cipher == TRIPLEDES) {  \
		des_key_sched ((void*) (key), (void*)ks); \
		des_key_sched ((void*) ((char*)(key)+8), (void*)((char*)ks+DES_KS)); \
		des_key_sched ((void*) ((char*)(key)+16), (void*)((char*)ks+DES_KS*2)); \
	} \
}

#define is_valid_tc_cipher(cipher) \
	(cipher == BLOWFISH || \
	 cipher == IDEA || \
	cipher == DES56 || \
	cipher == CAST || \
	cipher == TRIPLEDES)


PCRYPTO_INFO crypto_open (void);
void crypto_loadkey (PKEY_INFO keyInfo, char *lpszUserKey, int nUserKeyLen);
void crypto_close (PCRYPTO_INFO cryptoInfo);
int get_block_size (int cipher);
int get_key_size (int cipher);
char * get_cipher_name (int cipher);
char * get_hash_name (int pkcs5);
