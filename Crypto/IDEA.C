/* IDEA source code.  This code came from a number of sources, the original
   was written by Masayasu Kumagai <kumagai@mxc.meshnet.or.jp>, but was
   severely hacked for speed and portability on non-Intel machines using code
   from the book "PGP - Source Code and Internals", Phil Zimmermann, MIT
   Press 1995, ISBN 0-262-24039-4 (note that the equivalent code in Applied
   Cryptography has bugs and won't work properly).  Extra optimizations were
   contributed by Paulo Barreto <pbarreto@unisys.com.br>, everything was put
   together by Peter Gutmann <pgut001@cs.auckland.ac.nz> */

#include <string.h>
#include "idea.h"

#pragma warning( disable : 4244 )


/* Compute the multiplicative inverse of x mod 65537.  Slightly optimised
   version based on the "PGP - Source Code and Internals" code */

static word16 mulInv( word16 x )
	{
	word16 t0, t1;
	word16 q, y;

	if( x <= 1 )
		return x;		/* 0 and 1 are self-inverse */
	t1 = ( word16 ) ( 0x10001L / x );	/* Since x >= 2, this fits into 16 bits */
	y = ( word16 ) ( 0x10001L % x );
	if( y == 1 )
		return( ( word16 ) ( 1 - t1 ) );
	t0 = 1;
	do
		{
		q = x / y;
		x = x % y;
		t0 += q * t1;
		if( x == 1 )
			return( t0 );
		q = y / x;
		y = y % x;
		t1 += q * t0;
		}
	while( y != 1 );

	return( ( word16 ) ( 1 - t1 ) );
	}

/* Expand the 128-bit user key into the encryption and decryption keys */

void _cdecl ideaExpandKey( unsigned char const *userkey, word16 *eKey, word16 *dKey )
	{
	word16 *eKeyPtr = eKey;
	int i, j, k, p, r;

	/* Create the expanded encryption key */
	for( j = 0; j < 8; j++ )
		{
		eKey[ j ] = ( userkey[ 0 ] << 8 ) + userkey[ 1 ];
		userkey += 2;
		}
	for( i = 0; j < IDEA_KEYLEN; j++ )
		{
		i++;
		eKey[ i + 7 ] = ( eKey[ i & 7 ] << 9 ) | ( eKey[ i + 1 & 7 ] >> 7 );
		eKey += i & 8;
		i &= 7;
		}
	eKey = eKeyPtr;

	/* Create the decryption key from the encryption key */
	p = IDEA_KEYLEN;
	dKey[ p - 1 ] = mulInv( eKey[ 3 ] );
	dKey[ p - 2 ] = -( signed ) ( eKey[ 2 ] );
	dKey[ p - 3 ] = -( signed ) ( eKey[ 1 ] );
	dKey[ p - 4 ] = mulInv( eKey[ 0 ] );
	k = 4;
	p -= 4;
	for( r = IDEA_ROUNDS - 1; r > 0; r-- )
		{
		dKey[ p - 1 ] = eKey[ k + 1 ];
		dKey[ p - 2 ] = eKey[ k ];
		dKey[ p - 3 ] = mulInv( eKey[ k + 5 ] );
		dKey[ p - 4 ] = -( signed ) ( eKey[ k + 3 ] );
		dKey[ p - 5 ] = -( signed ) ( eKey[ k + 4 ] );
		dKey[ p - 6 ] = mulInv( eKey[ k + 2 ] );
		k += 6; p -= 6;
		}
	dKey[ p - 1 ] = eKey[ k + 1 ];
	dKey[ p - 2 ] = eKey[ k ];
	dKey[ p - 3 ] = mulInv( eKey[ k + 5 ] );
	dKey[ p - 4 ] = -( signed ) ( eKey[ k + 4 ] );
	dKey[ p - 5 ] = -( signed ) ( eKey[ k + 3 ] );
	dKey[ p - 6 ] = mulInv( eKey[ k + 2 ] );
	}

#ifndef __WIN32__

/* Compute x * y mod 65537, from "PGP - Source Code and Internals" */

#define mul( x, y ) \
	( ( t16 = ( y ) ) ? \
		( x ) ? \
			t32 = ( unsigned long ) x * t16, \
			x = ( word16 ) t32, \
			t16 = ( word16 ) ( t32 >> 16 ), \
			x = ( x - t16 ) + ( x < t16 ) \
		: ( x = 1 - t16 ) \
	: ( x = 1 - x ) )

#ifdef __TURBOC__
  #pragma warn -pia		/* Turn off warnings for dodgy code in mul() macro */
#endif /* __TURBOC__ */

/* The basic IDEA round */

#define ideaRound( count ) \
	mul( x1, key[ ( count * 6 ) ] ); \
	x2 += key[ ( count * 6 ) + 1 ]; \
	x3 += key[ ( count * 6 ) + 2 ]; \
	mul( x4, key[ ( count * 6 ) + 3 ] ); \
	\
	s3 = x3; \
	x3 ^= x1; \
	mul( x3, key[ ( count * 6 ) + 4 ] ); \
	s2 = x2; \
	x2 ^= x4; \
	x2 += x3; \
	mul( x2, key[ ( count * 6 ) + 5 ] ); \
	x3 += x2; \
	\
	x1 ^= x2;  x4 ^= x3; \
	x2 ^= s3;  x3 ^= s2;

/* Encrypt/decrypt a block of data with IDEA */

#if 0
void _cdecl ideaCrypt( unsigned char const *in, unsigned char *out, word16 const *key )
	{
	register word16 x1, x2, x3, x4, s2, s3;
	word16 *inPtr, *outPtr;
	register word16 t16;	/* Needed by mul() macro */
	register unsigned long t32;		/* Needed by mul() macro */

	inPtr = ( word16 * ) in;
	x1 = *inPtr++; x2 = *inPtr++;
	x3 = *inPtr++; x4 = *inPtr++;
#ifdef DATA_LITTLEENDIAN
	x1 = ( x1 >> 8 ) | ( x1 << 8 );
	x2 = ( x2 >> 8 ) | ( x2 << 8 );
	x3 = ( x3 >> 8 ) | ( x3 << 8 );
	x4 = ( x4 >> 8 ) | ( x4 << 8 );
#endif /* DATA_LITTLEENDIAN */

	/* Perform 8 rounds of encryption */
	ideaRound( 0 );
	ideaRound( 1 );
	ideaRound( 2 );
	ideaRound( 3 );
	ideaRound( 4 );
	ideaRound( 5 );
	ideaRound( 6 );
	ideaRound( 7 );

	/* final semiround: */
	mul( x1, key[ 48 ] );
	x3 += key[ 49 ];
	x2 += key[ 50 ];
	mul( x4, key[ 51 ] );

	outPtr = ( word16 * ) out;
#ifdef DATA_LITTLEENDIAN
	*outPtr++ = ( x1 >> 8 ) | ( x1 << 8 );
	*outPtr++ = ( x3 >> 8 ) | ( x3 << 8 );
	*outPtr++ = ( x2 >> 8 ) | ( x2 << 8 );
	*outPtr++ = ( x4 >> 8 ) | ( x4 << 8 );
#else
	*outPtr++ = x1; *outPtr++ = x3;
	*outPtr++ = x2; *outPtr++ = x4;
#endif /* DATA_LITTLEENDIAN */
	}
#ifdef __TURBOC__
  #pragma warn +pia
#endif /* __TURBOC__ */

#endif /* !__WIN32__ */
#endif


#if 0
#include <stdio.h>

void main( void )
	{
	unsigned char key[] = { 0x00, 0x01, 0x00, 0x02, 0x00, 0x03, 0x00, 0x04,
				   0x00, 0x05, 0x00, 0x06, 0x00, 0x07, 0x00, 0x08 };
	unsigned char plain[] = { 0x00, 0x00, 0x00, 0x01, 0x00, 0x02, 0x00, 0x03 };
	unsigned char cipher[] = { 0x11, 0xFB, 0xED, 0x2B, 0x01, 0x98, 0x6D, 0xE5 };
	unsigned char temp[ 8 ] = { 0 };
	unsigned short eKey[ 52 ], dKey[ 52 ];

	ideaExpandKey( key, eKey, dKey );
	ideaCrypt( plain, temp, eKey );
	if( memcmp( temp, cipher, 8 ) )
		puts( "Encrypt bang." );
	ideaCrypt( temp, temp, dKey );
	if( memcmp( temp, plain, 8 ) )
		puts( "Decrypt bang." );
	}
#endif /* 0 */
