/* Copyright (C) 2004 TrueCrypt Foundation
   This product uses components written by Paul Le Roux <pleroux@swprofessionals.com> */

/* Everything below this line is automatically updated by the -mkproto-tool- */

void _cdecl EncryptSector8 ( unsigned long *data , unsigned __int64 secNo , unsigned long noSectors , unsigned char *ks , unsigned char *iv , int cipher );
void _cdecl DecryptSector8 ( unsigned long *data , unsigned __int64 secNo , unsigned long noSectors , unsigned char *ks , unsigned char *iv , int cipher );
int _cdecl DecryptBuffer (unsigned char *buf, unsigned long len, unsigned char *ks, unsigned char *iv, int cipher);
int _cdecl EncryptBuffer (unsigned char *buf, unsigned long len, unsigned char *ks, unsigned char *iv, int cipher);
int VolumeReadHeader ( char *header , char *lpszPassword , PCRYPTO_INFO *retInfo );
int VolumeWriteHeader ( char *header , int cipher , char *lpszPassword , int pkcs5 , char *masterKey, unsigned __int64 volumeCreationTime, PCRYPTO_INFO *retInfo );
