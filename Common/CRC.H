/*
 Legal Notice: The source code contained in this file has been derived from
 the source code of Encryption for the Masses 2.02a, which is Copyright (c)
 Paul Le Roux and which is covered by the 'License Agreement for Encryption
 for the Masses'. Modifications and additions to that source code contained
 in this file are Copyright (c) TrueCrypt Foundation and are covered by the
 TrueCrypt License 2.2 the full text of which is contained in the file
 License.txt included in TrueCrypt binary and source code distribution
 packages. */

extern unsigned __int32 crc_32_tab[];

#define UPDC32(octet, crc)\
  (unsigned __int32)((crc_32_tab[(((unsigned __int32)(crc)) ^ ((unsigned char)(octet))) & 0xff] ^ (((unsigned __int32)(crc)) >> 8)))

unsigned __int32 crc32 (unsigned char *data, int length);
unsigned __int32 crc32int (unsigned __int32 *data);
BOOL crc32_selftests (void);
