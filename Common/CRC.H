/* Legal Notice: The source code contained in this file has been derived from
   the source code of Encryption for the Masses 2.02a, which is Copyright (c)
   1998-99 Paul Le Roux and which is covered by the 'License Agreement for
   Encryption for the Masses'. Modifications and additions to that source code
   contained in this file are Copyright (c) 2004-2005 TrueCrypt Foundation and
   Copyright (c) 2004 TrueCrypt Team, and are covered by TrueCrypt License 2.0
   the full text of which is contained in the file License.txt included in
   TrueCrypt binary and source code distribution archives.  */

extern unsigned __int32 crc_32_tab[];

#define UPDC32(octet, crc)\
  (unsigned __int32)((crc_32_tab[(((unsigned __int32)(crc)) ^ ((unsigned char)(octet))) & 0xff] ^ (((unsigned __int32)(crc)) >> 8)))

unsigned __int32 crc32 (unsigned char *data, int length);
unsigned __int32 crc32int (unsigned __int32 *data);
BOOL crc32_selftests (void);
