/* Copyright (C) 2004 TrueCrypt Team, truecrypt.org
   This product uses components written by Paul Le Roux <pleroux@swprofessionals.com> */

extern unsigned long crc_32_tab[];

#define UPDC32(octet, crc)\
  (unsigned long)((crc_32_tab[(((unsigned long)(crc)) ^ ((unsigned char)(octet))) & 0xff] ^ (((unsigned long)(crc)) >> 8)))

unsigned long crc32 (unsigned char *data, int length);
unsigned long crc32long (unsigned long *data);
int crc32_selftest (void);