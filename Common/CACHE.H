/* Copyright (C) 2004 TrueCrypt Foundation
   This product uses components written by Paul Le Roux <pleroux@swprofessionals.com> */

extern char szDriverPassword[4][MAX_PASSWORD + 1];
extern int nDriverPasswordLen[4];
extern int nPasswordIdx;
extern int cacheEmpty;

/* Everything below this line is automatically updated by the -mkproto-tool- */

int VolumeReadHeaderCache (BOOL bCache, char *dev, char *lpszPassword, int nPasswordLen, PCRYPTO_INFO * retInfo);
void WipeCache (void);
