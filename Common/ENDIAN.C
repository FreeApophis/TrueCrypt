/* The source code contained in this file has been derived from the source code
   of Encryption for the Masses 2.02a by Paul Le Roux. Modifications and
   additions to that source code contained in this file are Copyright (c) 2004-2005
   TrueCrypt Foundation and Copyright (c) 2004 TrueCrypt Team. Unmodified
   parts are Copyright (c) 1998-99 Paul Le Roux. This is a TrueCrypt Foundation
   release. Please see the file license.txt for full license details. */

#include "TCdefs.h"
#include "endian.h"

void
LongReverse (unsigned long *buffer, unsigned byteCount)
{
	unsigned long value;

	byteCount /= sizeof (unsigned long);
	while (byteCount--)
	{
		value = *buffer;
		value = ((value & 0xFF00FF00L) >> 8) | \
		    ((value & 0x00FF00FFL) << 8);
		*buffer++ = (value << 16) | (value >> 16);
	}
}
