void _cdecl serpent_set_key(const unsigned __int8 userKey[], int keylen, unsigned __int8 *ks);
void _cdecl serpent_encrypt(const unsigned __int8 *inBlock, unsigned __int8 *outBlock, unsigned __int8 *ks);
void _cdecl serpent_decrypt(const unsigned __int8 *inBlock,  unsigned __int8 *outBlock, unsigned __int8 *ks);
