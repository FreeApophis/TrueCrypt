/* The source code contained in this file has been derived from the source code
   of Encryption for the Masses 2.02a by Paul Le Roux. Modifications and
   additions to that source code contained in this file are Copyright (c) 2004
   TrueCrypt Team and Copyright (c) 2004 TrueCrypt Foundation. Unmodified
   parts are Copyright (c) 1998-99 Paul Le Roux. This is a TrueCrypt Foundation
   release. Please see the file license.txt for full license details. */

/* Everything below this line is automatically updated by the -mkproto-tool- */

void _cdecl EncryptSector8 ( unsigned long *data , unsigned __int64 secNo , unsigned long noSectors , unsigned char *ks , unsigned char *iv , int cipher );
void _cdecl DecryptSector8 ( unsigned long *data , unsigned __int64 secNo , unsigned long noSectors , unsigned char *ks , unsigned char *iv , int cipher );
int _cdecl DecryptBuffer (unsigned char *buf, unsigned long len, unsigned char *ks, unsigned char *iv, int cipher);
int _cdecl EncryptBuffer (unsigned char *buf, unsigned long len, unsigned char *ks, unsigned char *iv, int cipher);
int VolumeReadHeader ( char *header , char *lpszPassword , PCRYPTO_INFO *retInfo );
int VolumeWriteHeader ( char *header , int cipher , char *lpszPassword , int pkcs5 , char *masterKey, unsigned __int64 volumeCreationTime, PCRYPTO_INFO *retInfo );
