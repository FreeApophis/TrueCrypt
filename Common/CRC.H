/* The source code contained in this file has been derived from the source code
   of Encryption for the Masses 2.02a by Paul Le Roux. Modifications and
   additions to that source code contained in this file are Copyright (c) 2004
   TrueCrypt Team and Copyright (c) 2004 TrueCrypt Foundation. Unmodified
   parts are Copyright (c) 1998-99 Paul Le Roux. This is a TrueCrypt Foundation
   release. Please see the file license.txt for full license details. */

extern unsigned long crc_32_tab[];

#define UPDC32(octet, crc)\
  (unsigned long)((crc_32_tab[(((unsigned long)(crc)) ^ ((unsigned char)(octet))) & 0xff] ^ (((unsigned long)(crc)) >> 8)))

unsigned long crc32 (unsigned char *data, int length);
unsigned long crc32long (unsigned long *data);
int crc32_selftest (void);