/*
 ---------------------------------------------------------------------------
 Copyright (c) 2003, Dr Brian Gladman, Worcester, UK.   All rights reserved.

 LICENSE TERMS

 The free distribution and use of this software in both source and binary
 form is allowed (with or without changes) provided that:

   1. distributions of this source code include the above copyright
      notice, this list of conditions and the following disclaimer;

   2. distributions in binary form include the above copyright
      notice, this list of conditions and the following disclaimer
      in the documentation and/or other associated materials;

   3. the copyright holder's name is not used to endorse products
      built using this software without specific written permission.

 ALTERNATIVELY, provided that this notice is retained in full, this product
 may be distributed under the terms of the GNU General Public License (GPL),
 in which case the provisions of the GPL apply INSTEAD OF those given above.

 DISCLAIMER

 This software is provided 'as is' with no explicit or implied warranties
 in respect of its properties, including, but not limited to, correctness
 and/or fitness for purpose.
 ---------------------------------------------------------------------------
 Issue Date: 31/01/2004
*/

/* Adapted for TrueCrypt by the TrueCrypt Foundation */

#ifndef _GCM_H
#define _GCM_H

#include "Tcdefs.h"

#if defined(__cplusplus)
extern "C"
{
#endif

#define CBLK_LEN   16  /* encryption block length */
#define CBLK_LEN8  8

typedef struct
{
    unsigned __int32 gf_t8k[CBLK_LEN * 2][16][CBLK_LEN / 4];
} GfCtx8k;

typedef struct
{
		unsigned __int32 gf_t4k[CBLK_LEN8 * 2][16][CBLK_LEN / 4];
} GfCtx4k64;

typedef struct
{
	/* union not used to support faster mounting */
    unsigned __int32 gf_t128[CBLK_LEN * 2 / 2][16][CBLK_LEN / 4];
    unsigned __int32 gf_t64[CBLK_LEN8 * 2][16][CBLK_LEN8 / 4];
} GfCtx;

typedef int  ret_type;

void GfMul128 (void *a, const void* b);
void GfMul128Tab(unsigned char a[16], GfCtx8k *ctx);
int Gf128Tab64Init (unsigned __int8 *a, GfCtx *ctx);
void Gf128MulBy64Tab (unsigned __int8 a[8], unsigned __int8 p[16], GfCtx *ctx);
int Gf64TabInit (unsigned __int8 *a, GfCtx *ctx);
void Gf64MulTab (unsigned char a[8], unsigned char p[8], GfCtx *ctx);
BOOL GfMulSelfTest ();

#if defined(__cplusplus)
}
#endif

#endif
