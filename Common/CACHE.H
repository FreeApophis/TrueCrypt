/* The source code contained in this file has been derived from the source code
   of Encryption for the Masses 2.02a by Paul Le Roux. Modifications and
   additions to that source code contained in this file are Copyright (c) 2004-2005
   TrueCrypt Foundation and Copyright (c) 2004 TrueCrypt Team. Unmodified
   parts are Copyright (c) 1998-99 Paul Le Roux. This is a TrueCrypt Foundation
   release. Please see the file license.txt for full license details. */

extern char szDriverPassword[4][MAX_PASSWORD + 1];
extern int nDriverPasswordLen[4];
extern int nPasswordIdx;
extern int cacheEmpty;

/* Everything below this line is automatically updated by the -mkproto-tool- */

int VolumeReadHeaderCache (BOOL bCache, char *header, char *headerHiddenVol, char *lpszPassword, int nPasswordLen, PCRYPTO_INFO * retInfo);
void WipeCache (void);
