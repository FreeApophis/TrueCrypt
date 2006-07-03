/* Legal Notice: The source code contained in this file has been derived from
   the source code of Encryption for the Masses 2.02a, which is Copyright (c)
   1998-99 Paul Le Roux and which is covered by the 'License Agreement for
   Encryption for the Masses'. Modifications and additions to that source code
   contained in this file are Copyright (c) 2004-2006 TrueCrypt Foundation and
   Copyright (c) 2004 TrueCrypt Team, and are covered by TrueCrypt License 2.1
   the full text of which is contained in the file License.txt included in
   TrueCrypt binary and source code distribution archives.  */

#include "Tcdefs.h"
#include "Endian.h"


unsigned __int32 MirrorBytes32 (unsigned __int32 x)
{
	unsigned __int32 n = (unsigned __int8) x;
	n <<= 8; n |= (unsigned __int8) (x >> 8);
	n <<= 8; n |= (unsigned __int8) (x >> 16);
	return (n << 8) | (unsigned __int8) (x >> 24);
}


unsigned __int64 MirrorBytes64 (unsigned __int64 x)
{
	unsigned __int64 n = (unsigned __int8) x;
	n <<= 8; n |= (unsigned __int8) (x >> 8);
	n <<= 8; n |= (unsigned __int8) (x >> 16);
	n <<= 8; n |= (unsigned __int8) (x >> 24);
	n <<= 8; n |= (unsigned __int8) (x >> 32);
	n <<= 8; n |= (unsigned __int8) (x >> 40);
	n <<= 8; n |= (unsigned __int8) (x >> 48);
	return (n << 8) | (unsigned __int8) (x >> 56);
}


void
LongReverse (unsigned __int32 *buffer, unsigned byteCount)
{
	unsigned __int32 value;

	byteCount /= sizeof (unsigned __int32);
	while (byteCount--)
	{
		value = *buffer;
		value = ((value & 0xFF00FF00L) >> 8) | \
		    ((value & 0x00FF00FFL) << 8);
		*buffer++ = (value << 16) | (value >> 16);
	}
}
