/*
 Legal Notice: The source code contained in this file has been derived from
 the source code of Encryption for the Masses 2.02a, which is Copyright (c)
 Paul Le Roux and which is covered by the 'License Agreement for Encryption
 for the Masses'. Modifications and additions to that source code contained
 in this file are Copyright (c) TrueCrypt Foundation and are covered by the
 TrueCrypt License 2.3 the full text of which is contained in the file
 License.txt included in TrueCrypt binary and source code distribution
 packages. */


#include "Crypto.h"

/* RNG defines & pool pointers */
#define RNG_POOL_SIZE 320	// Must be divisible by the size of the output of each of the implemented hash functions. (in bytes)
#if RNG_POOL_SIZE % SHA1_DIGESTSIZE || RNG_POOL_SIZE % WHIRLPOOL_DIGESTSIZE || RNG_POOL_SIZE % RIPEMD160_DIGESTSIZE
#error RNG_POOL_SIZE must be divisible by the size of the output of each of the implemented hash functions.
#endif

#define RANDOMPOOL_ALLOCSIZE	RNG_POOL_SIZE

void RandAddInt ( unsigned __int32 x );
int Randinit ( void );
void Randfree ( void );
void RandSetHashFunction ( int hash_algo_id );
int RandGetHashFunction (void);
BOOL Randmix ( void );
void RandaddBuf ( void *buf , int len );
BOOL FastPoll ( void );
BOOL SlowPoll ( void );
BOOL RandpeekBytes ( unsigned char *buf , int len );
BOOL RandgetBytes ( unsigned char *buf , int len, BOOL forceSlowPoll );

#ifdef _WIN32

extern BOOL volatile bFastPollEnabled;
extern BOOL volatile bRandmixEnabled;

LRESULT CALLBACK MouseProc ( int nCode , WPARAM wParam , LPARAM lParam );
LRESULT CALLBACK KeyboardProc ( int nCode , WPARAM wParam , LPARAM lParam );
void ThreadSafeThreadFunction ( void *dummy );

#endif
