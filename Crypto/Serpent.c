// Except as noted below copyright in this code is held by Dr B.R. Gladman 
// but free direct or derivative use is permitted subject to acknowledgement
// of its origin and subject to any constraints placed on the use of the 
// algorithm by its designers (if such constraints may exist, this will be 
// indicated below).  
//
// Dr. B. R. Gladman (                            ). 25th January 2000.
//
// This is an implementation of Serpent, an encryption algorithm designed
// by Anderson, Biham and Knudsen and submitted as a candidate for the 
// Advanced Encryption Standard programme of the US National Institute of 
// Standards and Technology.  
//
// The designers of Serpent have not placed any constraints on the use of
// this algorithm. 
//
// The S box expressions used below are Copyright (C) 2000 Dag Arne Osvik.

/* Support for multithreaded operation added by TrueCrypt Foundation */

#include "serpent.h"

//static u4byte serpent_l_key[140];

#define sb0(r0,r1,r2,r3,r4) \
    __asm   {           \
    __asm   xor r3,r0   \
    __asm   mov r4,r1   \
    __asm   and r1,r3   \
    __asm   xor r4,r2   \
    __asm   xor r1,r0   \
    __asm   or  r0,r3   \
    __asm   xor r0,r4   \
    __asm   xor r4,r3   \
    __asm   xor r3,r2   \
    __asm   or  r2,r1   \
    __asm   xor r2,r4   \
    __asm   not r4      \
    __asm   or  r4,r1   \
    __asm   xor r1,r3   \
    __asm   xor r1,r4   \
    __asm   or  r3,r0   \
    __asm   xor r1,r3   \
    __asm   xor r4,r3   \
            }

#define ib0(r0,r1,r2,r3,r4) \
    __asm   {           \
    __asm   not r2      \
    __asm   mov r4,r1   \
    __asm    or r1,r0   \
    __asm   not r4      \
    __asm   xor r1,r2   \
    __asm   or  r2,r4   \
    __asm   xor r1,r3   \
    __asm   xor r0,r4   \
    __asm   xor r2,r0   \
    __asm   and r0,r3   \
    __asm   xor r4,r0   \
    __asm   or  r0,r1   \
    __asm   xor r0,r2   \
    __asm   xor r3,r4   \
    __asm   xor r2,r1   \
    __asm   xor r3,r0   \
    __asm   xor r3,r1   \
    __asm   and r2,r3   \
    __asm   xor r4,r2   \
            }

#define sb1(r0,r1,r2,r3,r4) \
    __asm   {           \
    __asm   not r0      \
    __asm   not r2      \
    __asm   mov r4,r0   \
    __asm   and r0,r1   \
    __asm   xor r2,r0   \
    __asm   or  r0,r3   \
    __asm   xor r3,r2   \
    __asm   xor r1,r0   \
    __asm   xor r0,r4   \
    __asm   or  r4,r1   \
    __asm   xor r1,r3   \
    __asm   or  r2,r0   \
    __asm   and r2,r4   \
    __asm   xor r0,r1   \
    __asm   and r1,r2   \
    __asm   xor r1,r0   \
    __asm   and r0,r2   \
    __asm   xor r0,r4   \
            }

#define ib1(r0,r1,r2,r3,r4) \
    __asm   {           \
    __asm   mov r4,r1   \
    __asm   xor r1,r3   \
    __asm   and r3,r1   \
    __asm   xor r4,r2   \
    __asm   xor r3,r0   \
    __asm   or  r0,r1   \
    __asm   xor r2,r3   \
    __asm   xor r0,r4   \
    __asm   or  r0,r2   \
    __asm   xor r1,r3   \
    __asm   xor r0,r1   \
    __asm   or  r1,r3   \
    __asm   xor r1,r0   \
    __asm   not r4      \
    __asm   xor r4,r1   \
    __asm   or  r1,r0   \
    __asm   xor r1,r0   \
    __asm   or  r1,r4   \
    __asm   xor r3,r1   \
            }

#define sb2(r0,r1,r2,r3,r4) \
    __asm   {           \
    __asm   mov r4,r0   \
    __asm   and r0,r2   \
    __asm   xor r0,r3   \
    __asm   xor r2,r1   \
    __asm   xor r2,r0   \
    __asm   or  r3,r4   \
    __asm   xor r3,r1   \
    __asm   xor r4,r2   \
    __asm   mov r1,r3   \
    __asm   or  r3,r4   \
    __asm   xor r3,r0   \
    __asm   and r0,r1   \
    __asm   xor r4,r0   \
    __asm   xor r1,r3   \
    __asm   xor r1,r4   \
    __asm   not r4      \
            }

#define ib2(r0,r1,r2,r3,r4) \
    __asm   {           \
    __asm   xor r2,r3   \
    __asm   xor r3,r0   \
    __asm   mov r4,r3   \
    __asm   and r3,r2   \
    __asm   xor r3,r1   \
    __asm   or  r1,r2   \
    __asm   xor r1,r4   \
    __asm   and r4,r3   \
    __asm   xor r2,r3   \
    __asm   and r4,r0   \
    __asm   xor r4,r2   \
    __asm   and r2,r1   \
    __asm   or  r2,r0   \
    __asm   not r3      \
    __asm   xor r2,r3   \
    __asm   xor r0,r3   \
    __asm   and r0,r1   \
    __asm   xor r3,r4   \
    __asm   xor r3,r0   \
            }

#define sb3(r0,r1,r2,r3,r4) \
    __asm   {           \
    __asm   mov r4,r0   \
    __asm   or  r0,r3   \
    __asm   xor r3,r1   \
    __asm   and r1,r4   \
    __asm   xor r4,r2   \
    __asm   xor r2,r3   \
    __asm   and r3,r0   \
    __asm   or  r4,r1   \
    __asm   xor r3,r4   \
    __asm   xor r0,r1   \
    __asm   and r4,r0   \
    __asm   xor r1,r3   \
    __asm   xor r4,r2   \
    __asm   or  r1,r0   \
    __asm   xor r1,r2   \
    __asm   xor r0,r3   \
    __asm   mov r2,r1   \
    __asm   or  r1,r3   \
    __asm   xor r1,r0   \
            }

#define ib3(r0,r1,r2,r3,r4) \
    __asm   {           \
    __asm   mov r4,r2   \
    __asm   xor r2,r1   \
    __asm   and r1,r2   \
    __asm   xor r1,r0   \
    __asm   and r0,r4   \
    __asm   xor r4,r3   \
    __asm   or  r3,r1   \
    __asm   xor r3,r2   \
    __asm   xor r0,r4   \
    __asm   xor r2,r0   \
    __asm   or  r0,r3   \
    __asm   xor r0,r1   \
    __asm   xor r4,r2   \
    __asm   and r2,r3   \
    __asm   or  r1,r3   \
    __asm   xor r1,r2   \
    __asm   xor r4,r0   \
    __asm   xor r2,r4   \
            }

#define sb4(r0,r1,r2,r3,r4) \
    __asm   {           \
    __asm   xor r1,r3   \
    __asm   not r3      \
    __asm   xor r2,r3   \
    __asm   xor r3,r0   \
    __asm   mov r4,r1   \
    __asm   and r1,r3   \
    __asm   xor r1,r2   \
    __asm   xor r4,r3   \
    __asm   xor r0,r4   \
    __asm   and r2,r4   \
    __asm   xor r2,r0   \
    __asm   and r0,r1   \
    __asm   xor r3,r0   \
    __asm   or  r4,r1   \
    __asm   xor r4,r0   \
    __asm   or  r0,r3   \
    __asm   xor r0,r2   \
    __asm   and r2,r3   \
    __asm   not r0      \
    __asm   xor r4,r2   \
            }

#define ib4(r0,r1,r2,r3,r4) \
    __asm   {           \
    __asm   mov r4,r2   \
    __asm   and r2,r3   \
    __asm   xor r2,r1   \
    __asm   or  r1,r3   \
    __asm   and r1,r0   \
    __asm   xor r4,r2   \
    __asm   xor r4,r1   \
    __asm   and r1,r2   \
    __asm   not r0      \
    __asm   xor r3,r4   \
    __asm   xor r1,r3   \
    __asm   and r3,r0   \
    __asm   xor r3,r2   \
    __asm   xor r0,r1   \
    __asm   and r2,r0   \
    __asm   xor r3,r0   \
    __asm   xor r2,r4   \
    __asm   or  r2,r3   \
    __asm   xor r3,r0   \
    __asm   xor r2,r1   \
            }

#define sb5(r0,r1,r2,r3,r4) \
    __asm   {           \
    __asm   xor r0,r1   \
    __asm   xor r1,r3   \
    __asm   not r3      \
    __asm   mov r4,r1   \
    __asm   and r1,r0   \
    __asm   xor r2,r3   \
    __asm   xor r1,r2   \
    __asm   or  r2,r4   \
    __asm   xor r4,r3   \
    __asm   and r3,r1   \
    __asm   xor r3,r0   \
    __asm   xor r4,r1   \
    __asm   xor r4,r2   \
    __asm   xor r2,r0   \
    __asm   and r0,r3   \
    __asm   not r2      \
    __asm   xor r0,r4   \
    __asm   or  r4,r3   \
    __asm   xor r2,r4   \
            }

#define ib5(r0,r1,r2,r3,r4) \
    __asm   {           \
    __asm   not r1      \
    __asm   mov r4,r3   \
    __asm   xor r2,r1   \
    __asm   or  r3,r0   \
    __asm   xor r3,r2   \
    __asm   or  r2,r1   \
    __asm   and r2,r0   \
    __asm   xor r4,r3   \
    __asm   xor r2,r4   \
    __asm   or  r4,r0   \
    __asm   xor r4,r1   \
    __asm   and r1,r2   \
    __asm   xor r1,r3   \
    __asm   xor r4,r2   \
    __asm   and r3,r4   \
    __asm   xor r4,r1   \
    __asm   xor r3,r0   \
    __asm   xor r3,r4   \
    __asm   not r4      \
            }

#define sb6(r0,r1,r2,r3,r4) \
    __asm   {           \
    __asm   not r2      \
    __asm   mov r4,r3   \
    __asm   and r3,r0   \
    __asm   xor r0,r4   \
    __asm   xor r3,r2   \
    __asm   or  r2,r4   \
    __asm   xor r1,r3   \
    __asm   xor r2,r0   \
    __asm   or  r0,r1   \
    __asm   xor r2,r1   \
    __asm   xor r4,r0   \
    __asm   or  r0,r3   \
    __asm   xor r0,r2   \
    __asm   xor r4,r3   \
    __asm   xor r4,r0   \
    __asm   not r3      \
    __asm   and r2,r4   \
    __asm   xor r2,r3   \
            }

#define ib6(r0,r1,r2,r3,r4) \
    __asm   {           \
    __asm   xor r0,r2   \
    __asm   mov r4,r2   \
    __asm   and r2,r0   \
    __asm   xor r4,r3   \
    __asm   not r2      \
    __asm   xor r3,r1   \
    __asm   xor r2,r3   \
    __asm   or  r4,r0   \
    __asm   xor r0,r2   \
    __asm   xor r3,r4   \
    __asm   xor r4,r1   \
    __asm   and r1,r3   \
    __asm   xor r1,r0   \
    __asm   xor r0,r3   \
    __asm   or  r0,r2   \
    __asm   xor r3,r1   \
    __asm   xor r4,r0   \
            }

#define sb7(r0,r1,r2,r3,r4) \
    __asm   {           \
    __asm   mov r4,r2   \
    __asm   and r2,r1   \
    __asm   xor r2,r3   \
    __asm   and r3,r1   \
    __asm   xor r4,r2   \
    __asm   xor r2,r1   \
    __asm   xor r1,r0   \
    __asm   or  r0,r4   \
    __asm   xor r0,r2   \
    __asm   xor r3,r1   \
    __asm   xor r2,r3   \
    __asm   and r3,r0   \
    __asm   xor r3,r4   \
    __asm   xor r4,r2   \
    __asm   and r2,r0   \
    __asm   not r4      \
    __asm   xor r2,r4   \
    __asm   and r4,r0   \
    __asm   xor r1,r3   \
    __asm   xor r4,r1   \
            }

#define ib7(r0,r1,r2,r3,r4) \
    __asm   {           \
    __asm   mov r4,r2   \
    __asm   xor r2,r0   \
    __asm   and r0,r3   \
    __asm   not r2      \
    __asm   or  r4,r3   \
    __asm   xor r3,r1   \
    __asm   or  r1,r0   \
    __asm   xor r0,r2   \
    __asm   and r2,r4   \
    __asm   xor r1,r2   \
    __asm   xor r2,r0   \
    __asm   or  r0,r2   \
    __asm   and r3,r4   \
    __asm   xor r0,r3   \
    __asm   xor r4,r1   \
    __asm   xor r3,r4   \
    __asm   or  r4,r0   \
    __asm   xor r3,r2   \
    __asm   xor r4,r2   \
            }

#define f_key(r0,r1,r2,r3)  \
    __asm   {               \
    __asm   mov r0,[esi]    \
    __asm   mov r1,[esi+4]  \
    __asm   mov r2,[esi+8]  \
    __asm   mov r3,[esi+12] \
            }

#define t_key(r0,r1,r2,r3)  \
    __asm   {               \
    __asm   mov [esi  ],r0  \
    __asm   mov [esi+4],r1  \
    __asm   mov [esi+8],r2  \
    __asm   mov [esi+12],r3 \
    __asm   add esi,16      \
            }

#define f_xor(r0,r1,r2,r3)  \
    __asm   {               \
    __asm   xor r0,[esi]    \
    __asm   xor r1,[esi+4]  \
    __asm   xor r2,[esi+8]  \
    __asm   xor r3,[esi+12] \
    __asm   add esi,16      \
            }

#define i_xor(r0,r1,r2,r3)  \
    __asm   {               \
    __asm   sub esi,16      \
    __asm   xor r0,[esi]    \
    __asm   xor r1,[esi+4]  \
    __asm   xor r2,[esi+8]  \
    __asm   xor r3,[esi+12] \
            }

// the linear transformation and its inverse    

#define rot(r0,r1,r2,r3,r4) \
    __asm   {           \
    __asm   rol r0,13   \
    __asm   rol r2,3    \
    __asm   mov r4,r0   \
    __asm   sal r4,3    \
    __asm   xor r3,r2   \
    __asm   xor r3,r4   \
    __asm   xor r1,r0   \
    __asm   xor r1,r2   \
    __asm   rol r1,1    \
    __asm   rol r3,7    \
    __asm   mov r4,r1   \
    __asm   xor r0,r1   \
    __asm   xor r0,r3   \
    __asm   sal r4,7    \
    __asm   xor r2,r3   \
    __asm   xor r2,r4   \
    __asm   rol r0,5    \
    __asm   rol r2,22   \
            }

#define irot(r0,r1,r2,r3,r4)    \
    __asm   {           \
    __asm   ror r2,22   \
    __asm   ror r0,5    \
    __asm   mov r4,r1   \
    __asm   sal r4,7    \
    __asm   xor r2,r3   \
    __asm   xor r2,r4   \
    __asm   xor r0,r1   \
    __asm   xor r0,r3   \
    __asm   ror r3,7    \
    __asm   mov r4,r0   \
    __asm   ror r1,1    \
    __asm   sal r4,3    \
    __asm   xor r3,r2   \
    __asm   xor r3,r4   \
    __asm   xor r1,r0   \
    __asm   xor r1,r2   \
    __asm   ror r2,3    \
    __asm   ror r0,13   \
            }

char* serpent_name(void)
{
    return "serpent";
}

// initialise the key schedule from the user supplied key   

#define k_loop                                                                  \
    f_key(eax,ebx,ecx,edx); sb3(eax,ebx,ecx,edx,edi); t_key(ebx,ecx,edx,edi);   \
    f_key(eax,ebx,ecx,edx); sb2(eax,ebx,ecx,edx,edi); t_key(ecx,edx,ebx,edi);   \
    f_key(eax,ebx,ecx,edx); sb1(eax,ebx,ecx,edx,edi); t_key(ecx,eax,edx,ebx);   \
    f_key(eax,ebx,ecx,edx); sb0(eax,ebx,ecx,edx,edi); t_key(ebx,edi,ecx,eax);   \
    f_key(eax,ebx,ecx,edx); sb7(eax,ebx,ecx,edx,edi); t_key(ecx,edi,edx,eax);   \
    f_key(eax,ebx,ecx,edx); sb6(eax,ebx,ecx,edx,edi); t_key(eax,ebx,edi,ecx);   \
    f_key(eax,ebx,ecx,edx); sb5(eax,ebx,ecx,edx,edi); t_key(ebx,edx,eax,ecx);   \
    f_key(eax,ebx,ecx,edx); sb4(eax,ebx,ecx,edx,edi); t_key(ebx,edi,eax,edx);

void serpent_set_key(const u1byte in_key[], const u4byte key_len, u1byte *serpent_l_key)
{
    __asm   mov edx,key_len
    __asm   cmp edx,256
    __asm   ja  short l3

#ifdef  __cplusplus
    __asm   mov ebx,this
    __asm   lea ebx,[ebx].l_key
#else
    __asm   mov ebx,serpent_l_key
#endif
    __asm   mov esi,in_key
    __asm   mov ecx,edx
    __asm   add ecx,31
    __asm   sar ecx,5
    __asm   je  short l0
    __asm   mov edi,ebx
    __asm   mov eax,ecx
    __asm   rep movsd
l0: __asm   cmp edx,256
    __asm   je  short l1
    __asm   mov ecx,8
    __asm   sub ecx,eax
    __asm   xor eax,eax
    __asm   rep stosd
    __asm   mov ecx,edx
    __asm   mov edx,1
    __asm   sal edx,cl
    __asm   sar ecx,5
    __asm   mov eax,edx
    __asm   dec eax
    __asm   and eax,[ebx+4*ecx]
    __asm   or  eax,edx
    __asm   mov [ebx+4*ecx],eax
l1: __asm   mov esi,ebx
    __asm   mov eax,0x9e3779b9
    __asm   mov ebx,eax
    __asm   xor eax,[esi+ 8]
    __asm   xor ebx,[esi+12]
    __asm   xor eax,[esi+16]
    __asm   xor ebx,[esi+20]
    __asm   xor eax,[esi+24]
    __asm   xor ebx,[esi+28]
    __asm   mov ecx,0
    __asm   push esi
l2: __asm   mov edx,[esi]
    __asm   xor edx,ecx
    __asm   xor edx,ebx
    __asm   ror edx,21
    __asm   mov [esi+32],edx
    __asm   xor eax,[esi+8]
    __asm   xor eax,edx
    __asm   add esi,4
    __asm   inc ecx
    __asm   mov edx,[esi]
    __asm   xor edx,ecx
    __asm   xor edx,eax
    __asm   ror edx,21
    __asm   mov [esi+32],edx
    __asm   xor ebx,[esi+8]
    __asm   xor ebx,edx
    __asm   add esi,4
    __asm   inc ecx
    __asm   cmp ecx,132
    __asm   jne l2
    __asm   pop esi
    __asm   add esi,4*8

    k_loop; 
    k_loop; 
    k_loop; 
    k_loop;
    f_key(eax,ebx,ecx,edx); 
    sb3(eax,ebx,ecx,edx,edi); 
    t_key(ebx,ecx,edx,edi);

l3: return;
}

// encrypt a block of text  

#define f_loop(a,b,c,d,t)   \
    f_xor(a,b,c,d); sb0(a,b,c,d,t); rot(b,t,c,a,d); \
    f_xor(b,t,c,a); sb1(b,t,c,a,d); rot(c,b,a,t,d); \
    f_xor(c,b,a,t); sb2(c,b,a,t,d); rot(a,t,b,d,c); \
    f_xor(a,t,b,d); sb3(a,t,b,d,c); rot(t,b,d,c,a); \
    f_xor(t,b,d,c); sb4(t,b,d,c,a); rot(b,a,t,c,d); \
    f_xor(b,a,t,c); sb5(b,a,t,c,d); rot(a,c,b,t,d); \
    f_xor(a,c,b,t); sb6(a,c,b,t,d); rot(a,c,d,b,t); \
    f_xor(a,c,d,b); sb7(a,c,d,b,t);  

void serpent_encrypt(const u1byte in_blk[16], u1byte out_blk[16], u1byte *serpent_l_key)
{
    __asm   mov esi,in_blk
    __asm   mov eax,[esi]
    __asm   mov ebx,[esi+4]
    __asm   mov ecx,[esi+8]
    __asm   mov edx,[esi+12]

#ifdef  __cplusplus
    __asm   mov esi,this
    __asm   lea esi,[esi].l_key + 4*8
#else
    __asm   mov esi,serpent_l_key
	__asm	add	esi,4*8
#endif

    f_loop(eax,ebx,ecx,edx,edi); rot(edx,edi,ebx,eax,ecx);
    f_loop(edx,edi,ebx,eax,ecx); rot(eax,ecx,edi,edx,ebx);
    f_loop(eax,ecx,edi,edx,ebx); rot(edx,ebx,ecx,eax,edi);
    f_loop(edx,ebx,ecx,eax,edi); f_xor(eax,edi,ebx,edx); 
    
    __asm   mov esi,out_blk
    __asm   mov [esi],eax
    __asm   mov [esi+4],edi
    __asm   mov [esi+8],ebx
    __asm   mov [esi+12],edx
}

// decrypt a block of text  

#define i_loop(a,b,c,d,t)                               \
                     ib7(a,b,c,d,t); i_xor(d,a,b,t);    \
    irot(d,a,b,t,c); ib6(d,a,b,t,c); i_xor(a,b,c,t);    \
    irot(a,b,c,t,d); ib5(a,b,c,t,d); i_xor(b,d,t,c);    \
    irot(b,d,t,c,a); ib4(b,d,t,c,a); i_xor(b,c,t,a);    \
    irot(b,c,t,a,d); ib3(b,c,t,a,d); i_xor(a,b,t,c);    \
    irot(a,b,t,c,d); ib2(a,b,t,c,d); i_xor(b,d,t,c);    \
    irot(b,d,t,c,a); ib1(b,d,t,c,a); i_xor(a,b,c,t);    \
    irot(a,b,c,t,d); ib0(a,b,c,t,d); i_xor(a,d,b,t);

void serpent_decrypt(const u1byte in_blk[16], u1byte out_blk[16], u1byte *serpent_l_key)
{
    __asm   mov esi,in_blk
    __asm   mov eax,[esi]
    __asm   mov ebx,[esi+4]
    __asm   mov ecx,[esi+8]
    __asm   mov edx,[esi+12]

#ifdef  __cplusplus
    __asm   mov esi,this
    __asm   lea esi,[esi].l_key + 4*140
#else
    __asm   mov esi,serpent_l_key
	__asm	add	esi,4*140
#endif

    i_xor(eax,ebx,ecx,edx);    i_loop(eax,ebx,ecx,edx,edi);
    irot(eax,edx,ebx,edi,ecx); i_loop(eax,edx,ebx,edi,ecx); 
    irot(eax,edi,edx,ecx,ebx); i_loop(eax,edi,edx,ecx,ebx); 
    irot(eax,ecx,edi,ebx,edx); i_loop(eax,ecx,edi,ebx,edx); 

    __asm   mov esi,out_blk
    __asm   mov [esi],eax
    __asm   mov [esi+4],ebx
    __asm   mov [esi+8],ecx
    __asm   mov [esi+12],edx
}
