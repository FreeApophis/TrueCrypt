/* The source code contained in this file has been derived from the source code
   of Encryption for the Masses 2.02a by Paul Le Roux. Modifications and
   additions to that source code contained in this file are Copyright (c) 2004-2005
   TrueCrypt Foundation and Copyright (c) 2004 TrueCrypt Team. Unmodified
   parts are Copyright (c) 1998-99 Paul Le Roux. This is a TrueCrypt Foundation
   release. Please see the file license.txt for full license details. */

#include "TCdefs.h"

#include <memory.h>
#include "sha1.h"
#include "rmd160.h"
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


#define RMD160_DIGESTSIZE  20

void hmac_rmd160 (unsigned char *key, int keylen, unsigned char *input, int len, unsigned char *digest)
{
    RMD160_CTX context;
    unsigned char k_ipad[65];  /* inner padding - key XORd with ipad */
    unsigned char k_opad[65];  /* outer padding - key XORd with opad */
    unsigned char tk[RMD160_DIGESTSIZE];
    int i;

    /* if key is longer than 64 bytes reset it to key=SHA1(key) */
    if (keylen > 64) {
        RMD160_CTX      tctx;

        RMD160Init(&tctx);
        RMD160Update(&tctx, key, keylen);
        RMD160Final(tk, &tctx);

        key = tk;
        keylen = RMD160_DIGESTSIZE;
    }

        /* The HMAC_SHA1 transform looks like:

           RMD160(K XOR opad, RMD160(K XOR ipad, text))

           where K is an n byte key
           ipad is the byte 0x36 repeated 64 times
           opad is the byte 0x5c repeated 64 times
           and text is the data being protected */

        /* start out by storing key in pads */
    memset(k_ipad, 0x36, sizeof(k_ipad));
    memset(k_opad, 0x5c, sizeof(k_opad));

        /* XOR key with ipad and opad values */
    for (i=0; i<keylen; i++) {
        k_ipad[i] ^= key[i];
        k_opad[i] ^= key[i];
    }

        /* perform inner RIPEMD-160 */

    RMD160Init(&context);           /* init context for 1st pass */
    RMD160Update(&context, k_ipad, 64);  /* start with inner pad */
    RMD160Update(&context, input, len); /* then text of datagram */
    RMD160Final(digest, &context);         /* finish up 1st pass */

        /* perform outer RIPEMD-160 */
    RMD160Init(&context);           /* init context for 2nd pass */
    RMD160Update(&context, k_opad, 64);  /* start with outer pad */
    /* then results of 1st hash */
    RMD160Update(&context, digest, RMD160_DIGESTSIZE);
    RMD160Final(digest, &context);         /* finish up 2nd pass */

    memset(k_ipad, 0x00, sizeof(k_ipad));
    memset(k_opad, 0x00, sizeof(k_opad));
}

void
derive_u_rmd160 (char *pwd, int pwd_len, char *salt, int salt_len, int iterations, char *u, int b)
{
	char j[RMD160_DIGESTSIZE], k[RMD160_DIGESTSIZE];
	char init[128];
	char counter[4];
	int c, i;

	/* iteration 1 */
	memset (counter, 0, 4);
	counter[3] = (char) b;
	memcpy (init, salt, salt_len);	/* salt */
	memcpy (&init[salt_len], counter, 4);	/* big-endian block number */
	hmac_rmd160 (pwd, pwd_len, init, salt_len + 4, j);
	memcpy (u, j, RMD160_DIGESTSIZE);

	/* remaining iterations */
	for (c = 1; c < iterations; c++)
	{
		hmac_rmd160 (pwd, pwd_len, j, RMD160_DIGESTSIZE, k);
		for (i = 0; i < RMD160_DIGESTSIZE; i++)
		{
			u[i] ^= k[i];
			j[i] = k[i];
		}
	}
}

void
derive_rmd160_key (char *pwd, int pwd_len, char *salt, int salt_len, int iterations, char *dk, int dklen)
{
	char u[RMD160_DIGESTSIZE];
	int b, l, r;

	if (dklen % RMD160_DIGESTSIZE)
	{
		l = 1 + dklen / RMD160_DIGESTSIZE;
	}
	else
	{
		l = dklen / RMD160_DIGESTSIZE;
	}

	r = dklen - (l - 1) * RMD160_DIGESTSIZE;

	/* first l - 1 blocks */
	for (b = 1; b < l; b++)
	{
		derive_u_rmd160 (pwd, pwd_len, salt, salt_len, iterations, u, b);
		memcpy (dk, u, RMD160_DIGESTSIZE);
		dk += RMD160_DIGESTSIZE;
	}

	/* last block */
	derive_u_rmd160 (pwd, pwd_len, salt, salt_len, iterations, u, b);
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


char *hmac_sha_test_vectors[3] =
{
	"\xb6\x17\x31\x86\x55\x05\x72\x64\xe2\x8b\xc0\xb6\xfb\x37\x8c\x8e\xf1\x46\xbe\x00",
	"\xef\xfc\xdf\x6a\xe5\xeb\x2f\xa2\xd2\x74\x16\xd5\xf1\x84\xdf\x9c\x25\x9a\x7c\x79",
	"\x12\x5d\x73\x42\xb9\xac\x11\xcd\x91\xa3\x9a\xf4\x8a\xa1\x7b\x4f\x63\xf1\x75\xd3"
};

char *hmac_rmd160_test_keys[] =
{
	"\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xaa\xbb\xcc\xdd\xee\xff\x01\x23\x45\x67",
	"\x01\x23\x45\x67\x89\xab\xcd\xef\xfe\xdc\xba\x98\x76\x54\x32\x10\x00\x11\x22\x33"
};

char *hmac_rmd160_test_data[] =
{
	"message digest",
	"12345678901234567890123456789012345678901234567890123456789012345678901234567890"
};

char *hmac_rmd160_test_vectors[] =
{
	"\xf8\x36\x62\xcc\x8d\x33\x9c\x22\x7e\x60\x0f\xcd\x63\x6c\x57\xd2\x57\x1b\x1c\x34",
	"\x85\xf1\x64\x70\x3e\x61\xa6\x31\x31\xbe\x7e\x45\x95\x8e\x07\x94\x12\x39\x04\xf9"
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
test_hmac_rmd160 ()
{
	int i;
	for (i = 0; i < sizeof (hmac_rmd160_test_data) / sizeof(char *); i++)
	{
		char digest[RMD160_DIGESTSIZE];
		hmac_rmd160 (hmac_rmd160_test_keys[i], 20, hmac_rmd160_test_data[i], strlen (hmac_rmd160_test_data[i]), digest);
		if (memcmp (digest, hmac_rmd160_test_vectors[i], RMD160_DIGESTSIZE) != 0)
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
	if (test_hmac_rmd160 ()== FALSE)
		return FALSE;

	/* Next check the sha1 with pkcs5 */
	derive_sha_key ("password", 8, "\x12\x34\x56\x78", 4, 5, dk, 4);
	if (memcmp (dk, "\x5c\x75\xce\xf0", 4) != 0)
		return FALSE;

	/* Next check ripemd160 with pkcs5 */
	derive_rmd160_key ("password", 8, "\x12\x34\x56\x78", 4, 5, dk, 4);
	if (memcmp (dk, "\x7a\x3d\x7c\x03", 4) != 0)
		return FALSE;

	return TRUE;

}

