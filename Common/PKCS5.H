/* Copyright (C) 2004 TrueCrypt Foundation
   This product uses components written by Paul Le Roux <pleroux@swprofessionals.com> */


/* Everything below this line is automatically updated by the -mkproto-tool- */

void truncate (char *d1, char *d2, int len);
void hmac_sha (char *k, int lk, char *d, int ld, char *out, int t);
void derive_u_sha (char *pwd, int pwd_len, char *salt, int salt_len, int iterations, char *u, int b);
void derive_sha_key (char *pwd, int pwd_len, char *salt, int salt_len, int iterations, char *dk, int dklen);
void hmac_md5 (char *text, int text_len, char *key, int key_len, char *digest);
void derive_u_md5 (char *pwd, int pwd_len, char *salt, int salt_len, int iterations, char *u, int b);
void derive_md5_key (char *pwd, int pwd_len, char *salt, int salt_len, int iterations, char *dk, int dklen);
BOOL test_hmac_sha1 (void);
BOOL test_hmac_md5 (void);
BOOL test_pkcs5 (void);
int pkcs5main (void);
