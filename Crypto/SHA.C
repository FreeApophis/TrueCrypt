/* Implementation of NIST's Secure Hash Algorithm (FIPS 180) Lightly bummed
   for execution efficiency.

Jim Gillogly 3 May 1993

Copyright 1993, Dr. James J. Gillogly This code may be freely used in any
   application. */


#include <memory.h>
#include "sha.h"

#pragma intrinsic(memcpy)

#define f0(x,y,z) (z ^ (x & (y ^ z)))	/* Magic functions */
#define f1(x,y,z) (x ^ y ^ z)
#define f2(x,y,z) ((x & y) | (z & (x | y)))
#define f3(x,y,z) (x ^ y ^ z)

#define K0 0x5a827999		/* Magic constants */
#define K1 0x6ed9eba1
#define K2 0x8f1bbcdc
#define K3 0xca62c1d6

#define S(n, X) ((X << n) | (X >> (32 - n)))	/* Barrel roll */

#define r0(f, K) \
    temp = S(5, A) + f(B, C, D) + E + *p0++ + K; \
    E = D;  \
    D = C;  \
    C = S(30, B); \
    B = A;  \
    A = temp

#define r1_0(f, K) \
    temp = S(5, A) + f(B, C, D) + E + \
	   (*p0++ = *p1++ ^ *p2++ ^ *p3++ ^ *p4++) + K; \
    E = D;  \
    D = C;  \
    C = S(30, B); \
    B = A;  \
    A = temp

void
_cdecl ShaTransform0 (unsigned long *hash, unsigned long *data)	/* NIST original */
{
  unsigned long W[80];

  unsigned long *p0, *p1, *p2, *p3, *p4;
  unsigned long A, B, C, D, E, temp;

  unsigned long h0, h1, h2, h3, h4;

  h0 = hash[0];
  h1 = hash[1];
  h2 = hash[2];
  h3 = hash[3];
  h4 = hash[4];

  memcpy (W, data, 64);

  p0 = W;
  A = h0;
  B = h1;
  C = h2;
  D = h3;
  E = h4;

  r0 (f0, K0);
  r0 (f0, K0);
  r0 (f0, K0);
  r0 (f0, K0);
  r0 (f0, K0);
  r0 (f0, K0);
  r0 (f0, K0);
  r0 (f0, K0);
  r0 (f0, K0);
  r0 (f0, K0);
  r0 (f0, K0);
  r0 (f0, K0);
  r0 (f0, K0);
  r0 (f0, K0);
  r0 (f0, K0);
  r0 (f0, K0);

  p1 = &W[13];
  p2 = &W[8];
  p3 = &W[2];
  p4 = &W[0];

  r1_0 (f0, K0);
  r1_0 (f0, K0);
  r1_0 (f0, K0);
  r1_0 (f0, K0);
  r1_0 (f1, K1);
  r1_0 (f1, K1);
  r1_0 (f1, K1);
  r1_0 (f1, K1);
  r1_0 (f1, K1);
  r1_0 (f1, K1);
  r1_0 (f1, K1);
  r1_0 (f1, K1);
  r1_0 (f1, K1);
  r1_0 (f1, K1);
  r1_0 (f1, K1);
  r1_0 (f1, K1);
  r1_0 (f1, K1);
  r1_0 (f1, K1);
  r1_0 (f1, K1);
  r1_0 (f1, K1);
  r1_0 (f1, K1);
  r1_0 (f1, K1);
  r1_0 (f1, K1);
  r1_0 (f1, K1);
  r1_0 (f2, K2);
  r1_0 (f2, K2);
  r1_0 (f2, K2);
  r1_0 (f2, K2);
  r1_0 (f2, K2);
  r1_0 (f2, K2);
  r1_0 (f2, K2);
  r1_0 (f2, K2);
  r1_0 (f2, K2);
  r1_0 (f2, K2);
  r1_0 (f2, K2);
  r1_0 (f2, K2);
  r1_0 (f2, K2);
  r1_0 (f2, K2);
  r1_0 (f2, K2);
  r1_0 (f2, K2);
  r1_0 (f2, K2);
  r1_0 (f2, K2);
  r1_0 (f2, K2);
  r1_0 (f2, K2);
  r1_0 (f3, K3);
  r1_0 (f3, K3);
  r1_0 (f3, K3);
  r1_0 (f3, K3);
  r1_0 (f3, K3);
  r1_0 (f3, K3);
  r1_0 (f3, K3);
  r1_0 (f3, K3);
  r1_0 (f3, K3);
  r1_0 (f3, K3);
  r1_0 (f3, K3);
  r1_0 (f3, K3);
  r1_0 (f3, K3);
  r1_0 (f3, K3);
  r1_0 (f3, K3);
  r1_0 (f3, K3);
  r1_0 (f3, K3);
  r1_0 (f3, K3);
  r1_0 (f3, K3);
  r1_0 (f3, K3);

  h0 += A;
  h1 += B;
  h2 += C;
  h3 += D;
  h4 += E;

  hash[0] = h0;
  hash[1] = h1;
  hash[2] = h2;
  hash[3] = h3;
  hash[4] = h4;
}

