/* The source code contained in this file has been derived from the source code
   of Encryption for the Masses 2.02a by Paul Le Roux. Modifications and
   additions to that source code contained in this file are Copyright (c) 2004
   TrueCrypt Team and Copyright (c) 2004 TrueCrypt Foundation. Unmodified
   parts are Copyright (c) 1998-99 Paul Le Roux. This is a TrueCrypt Foundation
   release. Please see the file license.txt for full license details. */


/* Everything below this line is automatically updated by the -mkproto-tool- */

void truncate (char *d1, char *d2, int len);
void hmac_sha (char *k, int lk, char *d, int ld, char *out, int t);
void derive_u_sha (char *pwd, int pwd_len, char *salt, int salt_len, int iterations, char *u, int b);
void derive_sha_key (char *pwd, int pwd_len, char *salt, int salt_len, int iterations, char *dk, int dklen);
void hmac_rmd160 (unsigned char *key, int keylen, unsigned char *input, int len, unsigned char *digest);
void derive_u_rmd160 (char *pwd, int pwd_len, char *salt, int salt_len, int iterations, char *u, int b);
void derive_rmd160_key (char *pwd, int pwd_len, char *salt, int salt_len, int iterations, char *dk, int dklen);
BOOL test_hmac_sha1 (void);
BOOL test_hmac_rmd160 (void);
BOOL test_pkcs5 (void);
int pkcs5main (void);
