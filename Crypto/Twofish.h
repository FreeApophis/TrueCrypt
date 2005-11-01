#ifndef u4byte
#define u4byte	unsigned __int32
#endif
#ifndef u1byte
#define u1byte	unsigned char
#endif

#ifndef extract_byte
#define extract_byte(x,n)   ((u1byte)((x) >> (8 * n)))
#endif

#ifndef rotl

#ifdef _WIN32
#include <stdlib.h>
#pragma intrinsic(_lrotr,_lrotl)
#define rotr(x,n) _lrotr(x,n)
#define rotl(x,n) _lrotl(x,n)
#else
#define rotr(x,n) (((x)>>(n))|((x)<<(32-(n))))
#define rotl(x,n) (((x)<<(n))|((x)>>(32-(n))))
#endif

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
