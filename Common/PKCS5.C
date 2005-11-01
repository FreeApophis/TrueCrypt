/* Legal Notice: The source code contained in this file has been derived from
   the source code of Encryption for the Masses 2.02a, which is Copyright (c)
   1998-99 Paul Le Roux and which is covered by the 'License Agreement for
   Encryption for the Masses'. Modifications and additions to that source code
   contained in this file are Copyright (c) 2004-2005 TrueCrypt Foundation and
   Copyright (c) 2004 TrueCrypt Team, and are covered by TrueCrypt License 2.0
   the full text of which is contained in the file License.txt included in
   TrueCrypt binary and source code distribution archives.  */

#include "Tcdefs.h"

#include <memory.h>
#include "Sha1.h"
#include "Rmd160.h"
#include "Whirlpool.h"
#include "Pkcs5.h"
#include "Crypto.h"

void truncate
  (
	  char *d1,		/* data to be truncated */
	  char *d2,		/* truncated data */
	  int len		/* length in bytes to keep */
)
{
	int i;
	for (i = 0; i < len; i++)
		d2[i] = d1[i];
}

void hmac_sha1
(
	  char *k,		/* secret key */
	  int lk,		/* length of the key in bytes */
	  char *d,		/* data */
	  int ld,		/* length of data in bytes */
	  char *out,		/* output buffer, at least "t" bytes */
	  int t
)
{
	sha1_ctx ictx, octx;
	char isha[SHA1_DIGESTSIZE], osha[SHA1_DIGESTSIZE];
	char key[SHA1_DIGESTSIZE];
	char buf[SHA1_BLOCKSIZE];
	int i;

    /* If the key is longer than the hash algorithm block size,
	   let key = sha1(key), as per HMAC specifications. */
	if (lk > SHA1_BLOCKSIZE)
	{
		sha1_ctx tctx;

		sha1_begin (&tctx);
		sha1_hash ((unsigned char *) k, lk, &tctx);
		sha1_end ((unsigned char *) key, &tctx);

		k = key;
		lk = SHA1_DIGESTSIZE;

		memset (&tctx, 0, sizeof(tctx));		// Prevent leaks
	}

	/**** Inner Digest ****/

	sha1_begin (&ictx);

	/* Pad the key for inner digest */
	for (i = 0; i < lk; ++i)
		buf[i] = (char) (k[i] ^ 0x36);
	for (i = lk; i < SHA1_BLOCKSIZE; ++i)
		buf[i] = 0x36;

	sha1_hash ((unsigned char *) buf, SHA1_BLOCKSIZE, &ictx);
	sha1_hash ((unsigned char *) d, ld, &ictx);

	sha1_end ((unsigned char *) isha, &ictx);

	/**** Outter Digest ****/

	sha1_begin (&octx);

	for (i = 0; i < lk; ++i)
		buf[i] = (char) (k[i] ^ 0x5C);
	for (i = lk; i < SHA1_BLOCKSIZE; ++i)
		buf[i] = 0x5C;

	sha1_hash ((unsigned char *) buf, SHA1_BLOCKSIZE, &octx);
	sha1_hash ((unsigned char *) isha, SHA1_DIGESTSIZE, &octx);

	sha1_end ((unsigned char *) osha, &octx);

	/* truncate and print the results */
	t = t > SHA1_DIGESTSIZE ? SHA1_DIGESTSIZE : t;
	truncate (osha, out, t);

	/* Prevent leaks */
	memset (&ictx, 0, sizeof(ictx));
	memset (&octx, 0, sizeof(octx));
	memset (isha, 0, sizeof(isha));
	memset (osha, 0, sizeof(osha));
	memset (buf, 0, sizeof(buf));
	memset (key, 0, sizeof(key));
}


void derive_u_sha1 (char *pwd, int pwd_len, char *salt, int salt_len, int iterations, char *u, int b)
{
	char j[SHA1_DIGESTSIZE], k[SHA1_DIGESTSIZE];
	char init[128];
	char counter[4];
	int c, i;

	/* iteration 1 */
	memset (counter, 0, 4);
	counter[3] = (char) b;
	memcpy (init, salt, salt_len);	/* salt */
	memcpy (&init[salt_len], counter, 4);	/* big-endian block number */
	hmac_sha1 (pwd, pwd_len, init, salt_len + 4, j, SHA1_DIGESTSIZE);
	memcpy (u, j, SHA1_DIGESTSIZE);

	/* remaining iterations */
	for (c = 1; c < iterations; c++)
	{
		hmac_sha1 (pwd, pwd_len, j, SHA1_DIGESTSIZE, k, SHA1_DIGESTSIZE);
		for (i = 0; i < SHA1_DIGESTSIZE; i++)
		{
			u[i] ^= k[i];
			j[i] = k[i];
		}
	}

	/* Prevent possible leaks. */
	memset (j, 0, sizeof(j));
	memset (k, 0, sizeof(k));
}

void derive_key_sha1 (char *pwd, int pwd_len, char *salt, int salt_len, int iterations, char *dk, int dklen)
{
	char u[SHA1_DIGESTSIZE];
	int b, l, r;

	if (dklen % SHA1_DIGESTSIZE)
	{
		l = 1 + dklen / SHA1_DIGESTSIZE;
	}
	else
	{
		l = dklen / SHA1_DIGESTSIZE;
	}

	r = dklen - (l - 1) * SHA1_DIGESTSIZE;

	/* first l - 1 blocks */
	for (b = 1; b < l; b++)
	{
		derive_u_sha1 (pwd, pwd_len, salt, salt_len, iterations, u, b);
		memcpy (dk, u, SHA1_DIGESTSIZE);
		dk += SHA1_DIGESTSIZE;
	}

	/* last block */
	derive_u_sha1 (pwd, pwd_len, salt, salt_len, iterations, u, b);
	memcpy (dk, u, r);


	/* Prevent possible leaks. */
	memset (u, 0, sizeof(u));
}

void hmac_ripemd160 (char *key, int keylen, char *input, int len, char *digest)
{
    RMD160_CTX context;
    unsigned char k_ipad[65];  /* inner padding - key XORd with ipad */
    unsigned char k_opad[65];  /* outer padding - key XORd with opad */
    unsigned char tk[RIPEMD160_DIGESTSIZE];
    int i;

    /* If the key is longer than the hash algorithm block size,
	   let key = ripemd160(key), as per HMAC specifications. */
    if (keylen > RIPEMD160_BLOCKSIZE) 
	{
        RMD160_CTX      tctx;

        RMD160Init(&tctx);
        RMD160Update(&tctx, key, keylen);
        RMD160Final(tk, &tctx);

        key = tk;
        keylen = RIPEMD160_DIGESTSIZE;

		memset (&tctx, 0, sizeof(tctx));	// Prevent leaks
    }

	/*

	RMD160(K XOR opad, RMD160(K XOR ipad, text))

	where K is an n byte key
	ipad is the byte 0x36 repeated RIPEMD160_BLOCKSIZE times
	opad is the byte 0x5c repeated RIPEMD160_BLOCKSIZE times
	and text is the data being protected */


	/* start out by storing key in pads */
	memset(k_ipad, 0x36, sizeof(k_ipad));
    memset(k_opad, 0x5c, sizeof(k_opad));

    /* XOR key with ipad and opad values */
    for (i=0; i<keylen; i++) 
	{
        k_ipad[i] ^= key[i];
        k_opad[i] ^= key[i];
    }

    /* perform inner RIPEMD-160 */

    RMD160Init(&context);           /* init context for 1st pass */
    RMD160Update(&context, k_ipad, RIPEMD160_BLOCKSIZE);  /* start with inner pad */
    RMD160Update(&context, input, len); /* then text of datagram */
    RMD160Final(digest, &context);         /* finish up 1st pass */

    /* perform outer RIPEMD-160 */
    RMD160Init(&context);           /* init context for 2nd pass */
    RMD160Update(&context, k_opad, RIPEMD160_BLOCKSIZE);  /* start with outer pad */
    /* results of 1st hash */
    RMD160Update(&context, digest, RIPEMD160_DIGESTSIZE);
    RMD160Final(digest, &context);         /* finish up 2nd pass */

	/* Prevent possible leaks. */
    memset(k_ipad, 0, sizeof(k_ipad));
    memset(k_opad, 0, sizeof(k_opad));
	memset (tk, 0, sizeof(tk));
	memset (&context, 0, sizeof(context));
}

void derive_u_ripemd160 (char *pwd, int pwd_len, char *salt, int salt_len, int iterations, char *u, int b)
{
	char j[RIPEMD160_DIGESTSIZE], k[RIPEMD160_DIGESTSIZE];
	char init[128];
	char counter[4];
	int c, i;

	/* iteration 1 */
	memset (counter, 0, 4);
	counter[3] = (char) b;
	memcpy (init, salt, salt_len);	/* salt */
	memcpy (&init[salt_len], counter, 4);	/* big-endian block number */
	hmac_ripemd160 (pwd, pwd_len, init, salt_len + 4, j);
	memcpy (u, j, RIPEMD160_DIGESTSIZE);

	/* remaining iterations */
	for (c = 1; c < iterations; c++)
	{
		hmac_ripemd160 (pwd, pwd_len, j, RIPEMD160_DIGESTSIZE, k);
		for (i = 0; i < RIPEMD160_DIGESTSIZE; i++)
		{
			u[i] ^= k[i];
			j[i] = k[i];
		}
	}

	/* Prevent possible leaks. */
	memset (j, 0, sizeof(j));
	memset (k, 0, sizeof(k));
}

void derive_key_ripemd160 (char *pwd, int pwd_len, char *salt, int salt_len, int iterations, char *dk, int dklen)
{
	char u[RIPEMD160_DIGESTSIZE];
	int b, l, r;

	if (dklen % RIPEMD160_DIGESTSIZE)
	{
		l = 1 + dklen / RIPEMD160_DIGESTSIZE;
	}
	else
	{
		l = dklen / RIPEMD160_DIGESTSIZE;
	}

	r = dklen - (l - 1) * RIPEMD160_DIGESTSIZE;

	/* first l - 1 blocks */
	for (b = 1; b < l; b++)
	{
		derive_u_ripemd160 (pwd, pwd_len, salt, salt_len, iterations, u, b);
		memcpy (dk, u, RIPEMD160_DIGESTSIZE);
		dk += RIPEMD160_DIGESTSIZE;
	}

	/* last block */
	derive_u_ripemd160 (pwd, pwd_len, salt, salt_len, iterations, u, b);
	memcpy (dk, u, r);


	/* Prevent possible leaks. */
	memset (u, 0, sizeof(u));
}

void hmac_whirlpool
(
	  char *k,		/* secret key */
	  int lk,		/* length of the key in bytes */
	  char *d,		/* data */
	  int ld,		/* length of data in bytes */
	  char *out,	/* output buffer, at least "t" bytes */
	  int t
)
{
	WHIRLPOOL_CTX ictx, octx;
	char iwhi[WHIRLPOOL_DIGESTSIZE], owhi[WHIRLPOOL_DIGESTSIZE];
	char key[WHIRLPOOL_DIGESTSIZE];
	char buf[WHIRLPOOL_BLOCKSIZE];
	int i;

    /* If the key is longer than the hash algorithm block size,
	   let key = whirlpool(key), as per HMAC specifications. */
	if (lk > WHIRLPOOL_BLOCKSIZE)
	{
		WHIRLPOOL_CTX tctx;

		WHIRLPOOL_init (&tctx);
		WHIRLPOOL_add ((unsigned char *) k, lk * 8, &tctx);
		WHIRLPOOL_finalize (&tctx, (unsigned char *) key);

		k = key;
		lk = WHIRLPOOL_DIGESTSIZE;

		memset (&tctx, 0, sizeof(tctx));		// Prevent leaks
	}

	/**** Inner Digest ****/

	WHIRLPOOL_init (&ictx);

	/* Pad the key for inner digest */
	for (i = 0; i < lk; ++i)
		buf[i] = (char) (k[i] ^ 0x36);
	for (i = lk; i < WHIRLPOOL_BLOCKSIZE; ++i)
		buf[i] = 0x36;

	WHIRLPOOL_add ((unsigned char *) buf, WHIRLPOOL_BLOCKSIZE * 8, &ictx);
	WHIRLPOOL_add ((unsigned char *) d, ld * 8, &ictx);

	WHIRLPOOL_finalize (&ictx, (unsigned char *) iwhi);

	/**** Outter Digest ****/

	WHIRLPOOL_init (&octx);

	for (i = 0; i < lk; ++i)
		buf[i] = (char) (k[i] ^ 0x5C);
	for (i = lk; i < WHIRLPOOL_BLOCKSIZE; ++i)
		buf[i] = 0x5C;

	WHIRLPOOL_add ((unsigned char *) buf, WHIRLPOOL_BLOCKSIZE * 8, &octx);
	WHIRLPOOL_add ((unsigned char *) iwhi, WHIRLPOOL_DIGESTSIZE * 8, &octx);

	WHIRLPOOL_finalize (&octx, (unsigned char *) owhi);

	/* truncate and print the results */
	t = t > WHIRLPOOL_DIGESTSIZE ? WHIRLPOOL_DIGESTSIZE : t;
	truncate (owhi, out, t);

	/* Prevent possible leaks. */
	memset (&ictx, 0, sizeof(ictx));
	memset (&octx, 0, sizeof(octx));
	memset (owhi, 0, sizeof(owhi));
	memset (iwhi, 0, sizeof(iwhi));
	memset (buf, 0, sizeof(buf));
	memset (key, 0, sizeof(key));
}

void derive_u_whirlpool (char *pwd, int pwd_len, char *salt, int salt_len, int iterations, char *u, int b)
{
	char j[WHIRLPOOL_DIGESTSIZE], k[WHIRLPOOL_DIGESTSIZE];
	char init[128];
	char counter[4];
	int c, i;

	/* iteration 1 */
	memset (counter, 0, 4);
	counter[3] = (char) b;
	memcpy (init, salt, salt_len);	/* salt */
	memcpy (&init[salt_len], counter, 4);	/* big-endian block number */
	hmac_whirlpool (pwd, pwd_len, init, salt_len + 4, j, WHIRLPOOL_DIGESTSIZE);
	memcpy (u, j, WHIRLPOOL_DIGESTSIZE);

	/* remaining iterations */
	for (c = 1; c < iterations; c++)
	{
		hmac_whirlpool (pwd, pwd_len, j, WHIRLPOOL_DIGESTSIZE, k, WHIRLPOOL_DIGESTSIZE);
		for (i = 0; i < WHIRLPOOL_DIGESTSIZE; i++)
		{
			u[i] ^= k[i];
			j[i] = k[i];
		}
	}

	/* Prevent possible leaks. */
	memset (j, 0, sizeof(j));
	memset (k, 0, sizeof(k));
}

void derive_key_whirlpool (char *pwd, int pwd_len, char *salt, int salt_len, int iterations, char *dk, int dklen)
{
	char u[WHIRLPOOL_DIGESTSIZE];
	int b, l, r;

	if (dklen % WHIRLPOOL_DIGESTSIZE)
	{
		l = 1 + dklen / WHIRLPOOL_DIGESTSIZE;
	}
	else
	{
		l = dklen / WHIRLPOOL_DIGESTSIZE;
	}

	r = dklen - (l - 1) * WHIRLPOOL_DIGESTSIZE;

	/* first l - 1 blocks */
	for (b = 1; b < l; b++)
	{
		derive_u_whirlpool (pwd, pwd_len, salt, salt_len, iterations, u, b);
		memcpy (dk, u, WHIRLPOOL_DIGESTSIZE);
		dk += WHIRLPOOL_DIGESTSIZE;
	}

	/* last block */
	derive_u_whirlpool (pwd, pwd_len, salt, salt_len, iterations, u, b);
	memcpy (dk, u, r);


	/* Prevent possible leaks. */
	memset (u, 0, sizeof(u));
}


int get_pkcs5_iteration_count (int pkcs5_prf_id)
{
	switch (pkcs5_prf_id)
	{
	case SHA1:		return 2000;
	case RIPEMD160:	return 2000;
	case WHIRLPOOL:	return 1000;
	default:		return 0;
	}
}

char *get_pkcs5_prf_name (int pkcs5_prf_id)
{
	switch (pkcs5_prf_id)
	{
	case SHA1:		return "HMAC-SHA-1";
	case RIPEMD160:	return "HMAC-RIPEMD-160";
	case WHIRLPOOL:	return "HMAC-Whirlpool";
	default:		return "Unknown";
	}
}
