#ifndef u4byte
typedef unsigned long	u4byte;
#endif
#ifndef u1byte
typedef unsigned char	u1byte;
#endif

#ifndef extract_byte
#define extract_byte(x,n)   ((u1byte)((x) >> (8 * n)))
#endif

#ifndef rotl
#include <stdlib.h>
#pragma intrinsic(_lrotr,_lrotl)
#define rotr(x,n) _lrotr(x,n)
#define rotl(x,n) _lrotl(x,n)
#endif

typedef struct
{
	u4byte *l_key;
	u4byte *s_key;
	u4byte *mk_tab;
	u4byte k_len;
} TwofishInstance;

#define TF_L_KEY_SIZE	(40*4)
#define TF_S_KEY_SIZE	(4*4)
#define TF_MK_TAB_SIZE	(4*4*256)
#define TWOFISH_KS		(sizeof(TwofishInstance) + TF_L_KEY_SIZE + TF_S_KEY_SIZE + TF_MK_TAB_SIZE)

u4byte * _cdecl twofish_set_key(TwofishInstance *instance, const u4byte in_key[], const u4byte key_len);
void _cdecl twofish_encrypt(TwofishInstance *instance, const u4byte in_blk[4], u4byte out_blk[]);
void _cdecl twofish_decrypt(TwofishInstance *instance, const u4byte in_blk[4], u4byte out_blk[4]);
