#ifndef u4byte
typedef unsigned long	u4byte;
#endif
#ifndef u1byte
typedef unsigned char	u1byte;
#endif

char* serpent_name(void);
void _cdecl serpent_set_key(const u1byte in_key[], const u4byte key_len, u1byte *serpent_l_key);
void _cdecl serpent_decrypt(const u1byte in_blk[16], u1byte out_blk[16], u1byte *serpent_l_key);
void _cdecl serpent_encrypt(const u1byte in_blk[16], u1byte out_blk[16], u1byte *serpent_l_key);