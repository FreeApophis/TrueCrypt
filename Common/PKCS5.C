/* Copyright (C) 2004 TrueCrypt Foundation
   This product uses components written by Paul Le Roux <pleroux@swprofessionals.com> */

#include "TCdefs.h"

#include <memory.h>
#include "sha1.h"
#include "md5.h"
#include "pkcs5.h"

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


/* Function to compute the digest */
void
  hmac_sha
  (
	  char *k,		/* secret key */
	  int lk,		/* length of the key in bytes */
	  char *d,		/* data */
	  int ld,		/* length of data in bytes */
	  char *out,		/* output buffer, at least "t" bytes */
	  int t
)
{
	SHA1_CTX ictx, octx;
	char isha[SHA_DIGESTSIZE], osha[SHA_DIGESTSIZE];
	char key[SHA_DIGESTSIZE];
	char buf[SHA_BLOCKSIZE];
	int i;

	if (lk > SHA_BLOCKSIZE)
	{

		SHA1_CTX tctx;

		SHA1Init (&tctx);
		SHA1Update (&tctx, (unsigned char *) k, lk);
		SHA1Final ((unsigned char *) key, &tctx);

		k = key;
		lk = SHA_DIGESTSIZE;
	}

	/**** Inner Digest ****/

	SHA1Init (&ictx);

	/* Pad the key for inner digest */
	for (i = 0; i < lk; ++i)
		buf[i] = (char) (k[i] ^ 0x36);
	for (i = lk; i < SHA_BLOCKSIZE; ++i)
		buf[i] = 0x36;

	SHA1Update (&ictx, (unsigned char *) buf, SHA_BLOCKSIZE);
	SHA1Update (&ictx, (unsigned char *) d, ld);

	SHA1Final ((unsigned char *) isha, &ictx);

	/**** Outter Digest ****/

	SHA1Init (&octx);

	for (i = 0; i < lk; ++i)
		buf[i] = (char) (k[i] ^ 0x5C);
	for (i = lk; i < SHA_BLOCKSIZE; ++i)
		buf[i] = 0x5C;

	SHA1Update (&octx, (unsigned char *) buf, SHA_BLOCKSIZE);
	SHA1Update (&octx, (unsigned char *) isha, SHA_DIGESTSIZE);

	SHA1Final ((unsigned char *) osha, &octx);

	/* truncate and print the results */
	t = t > SHA_DIGESTSIZE ? SHA_DIGESTSIZE : t;
	truncate (osha, out, t);
}


void
derive_u_sha (char *pwd, int pwd_len, char *salt, int salt_len, int iterations, char *u, int b)
{
	char j[SHA_DIGESTSIZE], k[SHA_DIGESTSIZE];
	char init[128];
	char counter[4];
	int c, i;

	/* iteration 1 */
	memset (counter, 0, 4);
	counter[3] = (char) b;
	memcpy (init, salt, salt_len);	/* salt */
	memcpy (&init[salt_len], counter, 4);	/* big-endian block number */
	hmac_sha (pwd, pwd_len, init, salt_len + 4, j, SHA_DIGESTSIZE);
	memcpy (u, j, SHA_DIGESTSIZE);

	/* remaining iterations */
	for (c = 1; c < iterations; c++)
	{
		hmac_sha (pwd, pwd_len, j, SHA_DIGESTSIZE, k, SHA_DIGESTSIZE);
		for (i = 0; i < SHA_DIGESTSIZE; i++)
		{
			u[i] ^= k[i];
			j[i] = k[i];
		}
	}
}

void
derive_sha_key (char *pwd, int pwd_len, char *salt, int salt_len, int iterations, char *dk, int dklen)
{
	char u[SHA_DIGESTSIZE];
	int b, l, r;

	if (dklen % SHA_DIGESTSIZE)
	{
		l = 1 + dklen / SHA_DIGESTSIZE;
	}
	else
	{
		l = dklen / SHA_DIGESTSIZE;
	}

	r = dklen - (l - 1) * SHA_DIGESTSIZE;

	/* first l - 1 blocks */
	for (b = 1; b < l; b++)
	{
		derive_u_sha (pwd, pwd_len, salt, salt_len, iterations, u, b);
		memcpy (dk, u, SHA_DIGESTSIZE);
		dk += SHA_DIGESTSIZE;
	}

	/* last block */
	derive_u_sha (pwd, pwd_len, salt, salt_len, iterations, u, b);
	memcpy (dk, u, r);
}

#define MD5_DIGESTSIZE 16

void
hmac_md5 (char *text,		/* pointer to data stream */
	  int text_len,		/* length of data stream */
	  char *key,		/* pointer to authentication key */
	  int key_len,		/* length of authentication key */
	  char *digest)		/* caller digest to be filled in */
{
	MD5_CTX context;
	char k_ipad[65];	/* inner padding - key XORd with ipad */
	char k_opad[65];	/* outer padding - key XORd with opad */
	char tk[MD5_DIGESTSIZE];
	int i;
	/* if key is longer than 64 bytes reset it to key=MD5(key) */
	if (key_len > 64)
	{

		MD5_CTX tctx;

		MD5Init (&tctx);
		MD5Update (&tctx, (unsigned char *) key, key_len);
		MD5Final ((unsigned char *) tk, &tctx);

		key = tk;
		key_len = MD5_DIGESTSIZE;
	}

	/* the HMAC_MD5 transform looks like:
	
	MD5(K XOR opad, MD5(K XOR ipad, text))
	
	where K is an n byte key ipad is the byte 0x36 repeated 64 times opad
	   is the byte 0x5c repeated 64 times and text is the data being
	   protected */

	/* start out by storing key in pads */
	memset (k_ipad, 0, sizeof k_ipad);
	memset (k_opad, 0, sizeof k_opad);
	memcpy (k_ipad, key, key_len);
	memcpy (k_opad, key, key_len);

	/* XOR key with ipad and opad values */
	for (i = 0; i < 64; i++)
	{
		k_ipad[i] ^= 0x36;
		k_opad[i] ^= 0x5c;
	}

	/* perform inner MD5 */
	MD5Init (&context);	/* init context for 1st pass */
	MD5Update (&context, (unsigned char *) k_ipad, 64);	/* start with inner pad */
	MD5Update (&context, (unsigned char *) text, text_len);	/* then text of datagram */
	MD5Final ((unsigned char *) digest, &context);	/* finish up 1st pass */
	/* perform outer MD5 */
	MD5Init (&context);	/* init context for 2nd pass */
	MD5Update (&context, (unsigned char *) k_opad, 64);	/* start with outer pad */
	MD5Update (&context, (unsigned char *) digest, MD5_DIGESTSIZE);	/* then results of 1st
									   hash */
	MD5Final ((unsigned char *) digest, &context);	/* finish up 2nd pass */
}

void
derive_u_md5 (char *pwd, int pwd_len, char *salt, int salt_len, int iterations, char *u, int b)
{
	char j[MD5_DIGESTSIZE], k[MD5_DIGESTSIZE];
	char init[128];
	char counter[4];
	int c, i;

	/* iteration 1 */
	memset (counter, 0, 4);
	counter[3] = (char) b;
	memcpy (init, salt, salt_len);	/* salt */
	memcpy (&init[salt_len], counter, 4);	/* big-endian block number */
	hmac_md5 (pwd, pwd_len, init, salt_len + 4, j);
	memcpy (u, j, MD5_DIGESTSIZE);

	/* remaining iterations */
	for (c = 1; c < iterations; c++)
	{
		hmac_md5 (pwd, pwd_len, j, MD5_DIGESTSIZE, k);
		for (i = 0; i < MD5_DIGESTSIZE; i++)
		{
			u[i] ^= k[i];
			j[i] = k[i];
		}
	}
}

void
derive_md5_key (char *pwd, int pwd_len, char *salt, int salt_len, int iterations, char *dk, int dklen)
{
	char u[MD5_DIGESTSIZE];
	int b, l, r;

	if (dklen % MD5_DIGESTSIZE)
	{
		l = 1 + dklen / MD5_DIGESTSIZE;
	}
	else
	{
		l = dklen / MD5_DIGESTSIZE;
	}

	r = dklen - (l - 1) * MD5_DIGESTSIZE;

	/* first l - 1 blocks */
	for (b = 1; b < l; b++)
	{
		derive_u_md5 (pwd, pwd_len, salt, salt_len, iterations, u, b);
		memcpy (dk, u, MD5_DIGESTSIZE);
		dk += MD5_DIGESTSIZE;
	}

	/* last block */
	derive_u_md5 (pwd, pwd_len, salt, salt_len, iterations, u, b);
	memcpy (dk, u, r);
}



/* rfc2104 & 2202 */

char *hmac_test_keys[3] =
{
	"\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b",
	"Jefe",
	"\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA"
};


char *hmac_test_data[3] =
{
	"Hi There",
	"what do ya want for nothing?",
	"\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD"
      "\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD"
	"\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD"
};

char *hmac_md5_test_vectors[3] =
{
	"\x92\x94\x72\x7a\x36\x38\xbb\x1c\x13\xf4\x8e\xf8\x15\x8b\xfc\x9d",
	"\x75\x0c\x78\x3e\x6a\xb0\xb5\x03\xea\xa8\x6e\x31\x0a\x5d\xb7\x38",
	"\x56\xbe\x34\x52\x1d\x14\x4c\x88\xdb\xb8\xc7\x33\xf0\xe8\xb3\xf6"
};

char *hmac_sha_test_vectors[3] =
{
	"\xb6\x17\x31\x86\x55\x05\x72\x64\xe2\x8b\xc0\xb6\xfb\x37\x8c\x8e\xf1\x46\xbe\x00",
	"\xef\xfc\xdf\x6a\xe5\xeb\x2f\xa2\xd2\x74\x16\xd5\xf1\x84\xdf\x9c\x25\x9a\x7c\x79",
	"\x12\x5d\x73\x42\xb9\xac\x11\xcd\x91\xa3\x9a\xf4\x8a\xa1\x7b\x4f\x63\xf1\x75\xd3"
};

BOOL
test_hmac_sha1 ()
{
	BOOL bOK = TRUE;
	int i;

	for (i = 0; i < 3; i++)
	{
		char digest[SHA_DIGESTSIZE];
		hmac_sha (hmac_test_keys[i], strlen (hmac_test_keys[i]), hmac_test_data[i], strlen (hmac_test_data[i]), digest, SHA_DIGESTSIZE);
		if (memcmp (digest, hmac_sha_test_vectors[i], SHA_DIGESTSIZE) != 0)
			return FALSE;
	}

	return TRUE;
}

BOOL
test_hmac_md5 ()
{
	int i;
	for (i = 0; i < 3; i++)
	{
		char digest[MD5_DIGESTSIZE];
		int x = strlen (hmac_test_keys[i]);
		hmac_md5 (hmac_test_data[i], strlen (hmac_test_data[i]), hmac_test_keys[i], x > MD5_DIGESTSIZE ? MD5_DIGESTSIZE : x, digest);
		if (memcmp (digest, hmac_md5_test_vectors[i], MD5_DIGESTSIZE) != 0)
			return FALSE;
	}

	return TRUE;
}

BOOL
test_pkcs5 ()
{
	char dk[4];

	/* First make sure the hmacs are ok */
	if (test_hmac_sha1 ()== FALSE)
		return FALSE;
	if (test_hmac_md5 ()== FALSE)
		return FALSE;

	/* Next check the sha1 with pkcs5 */
	derive_sha_key ("password", 8, "\x12\x34\x56\x78", 4, 5, dk, 4);
	if (memcmp (dk, "\x5c\x75\xce\xf0", 4) != 0)
		return FALSE;

	/* Next check md5 with pkcs5 */
	derive_md5_key ("password", 8, "\x12\x34\x56\x78", 4, 5, dk, 4);
	if (memcmp (dk, "\x91\xa9\xd7\x92", 4) != 0)
		return FALSE;

	return TRUE;

}

