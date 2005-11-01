#ifndef DICTIONARY_H
#define DICTIONARY_H

#include <windows.h>

#define DATA_POOL_CAPACITY 1000000

typedef struct
{
	char	*Key;
	int		IntKey;
	void	*Value;
} DictionaryEntry;

int AddDictionaryEntry (char *key, int intKey, void *value);
void *GetDictionaryValue (char *key);
void *GetDictionaryValueByInt (int intKey);
void *AddPoolData (void *data, size_t dataSize);
void ClearDictionaryPool ();

#endif
