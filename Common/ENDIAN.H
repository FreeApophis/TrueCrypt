/* The source code contained in this file has been derived from the source code
   of Encryption for the Masses 2.02a by Paul Le Roux. Modifications and
   additions to that source code contained in this file are Copyright (c) 2004
   TrueCrypt Team and Copyright (c) 2004 TrueCrypt Foundation. Unmodified
   parts are Copyright (c) 1998-99 Paul Le Roux. This is a TrueCrypt Foundation
   release. Please see the file license.txt for full license details. */

#define mputLong(memPtr,data) \
	*memPtr++ = ( unsigned char ) ( ( ( data ) >> 24 ) & 0xFF ), \
	*memPtr++ = ( unsigned char ) ( ( ( data ) >> 16 ) & 0xFF ), \
	*memPtr++ = ( unsigned char ) ( ( ( data ) >> 8 ) & 0xFF ), \
	*memPtr++ = ( unsigned char ) ( ( data ) & 0xFF )

#define mputWord(memPtr,data) \
	*memPtr++ = ( unsigned char ) ( ( ( data ) >> 8 ) & 0xFF ), \
	*memPtr++ = ( unsigned char ) ( ( data ) & 0xFF )

#define mputByte(memPtr,data)	\
	*memPtr++ = ( unsigned char ) data

#define mputBytes(memPtr,data,len)  \
	memcpy (memPtr,data,len); \
	memPtr += len;

/* Macros to read and write 16 and 32-bit quantities in a portable manner.
   These functions are implemented as macros rather than true functions as
   the need to adjust the memory pointers makes them somewhat painful to call
   in user code */

#define mgetLong(memPtr) 		\
	( memPtr += 4, ( ( unsigned long ) memPtr[ -4 ] << 24 ) | ( ( unsigned long ) memPtr[ -3 ] << 16 ) | \
	  ( ( unsigned long ) memPtr[ -2 ] << 8 ) | ( unsigned long ) memPtr[ -1 ] )

#define mgetWord(memPtr) 		\
	( memPtr += 2, ( unsigned short ) memPtr[ -2 ] << 8 ) | ( ( unsigned short ) memPtr[ -1 ] ) 

#define mgetByte(memPtr)		\
	( ( unsigned char ) *memPtr++ )


#define LITTLE_ENDIAN 1

/* Everything below this line is automatically updated by the -mkproto-tool- */

void LongReverse ( unsigned long *buffer , unsigned byteCount );
