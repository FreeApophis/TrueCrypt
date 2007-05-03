/*
 Legal Notice: The source code contained in this file has been derived from
 the source code of Encryption for the Masses 2.02a, which is Copyright (c)
 Paul Le Roux and which is covered by the 'License Agreement for Encryption
 for the Masses'. Modifications and additions to that source code contained
 in this file are Copyright (c) TrueCrypt Foundation and are covered by the
 TrueCrypt License 2.3 the full text of which is contained in the file
 License.txt included in TrueCrypt binary and source code distribution
 packages. */

extern unsigned char ks_tmp[MAX_EXPANDED_KEY]; 

void CipherInit2(int cipher, void* key, void* ks, int key_len);
BOOL Des56TestLoop ( void *test_vectors , int nVectorCount , int enc );
BOOL test_hmac_sha1 (void);
BOOL test_hmac_ripemd160 (void);
BOOL test_hmac_whirlpool (void);
BOOL test_pkcs5 (void);
BOOL TestSectorBufEncryption ();
BOOL AutoTestAlgorithms (void);
