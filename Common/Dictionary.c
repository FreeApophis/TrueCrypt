/* 
Copyright (c) 2004-2005 TrueCrypt Foundation. All rights reserved. 

Covered by TrueCrypt License 2.0 the full text of which is contained in the file
License.txt included in TrueCrypt binary and source code distribution archives. 
*/

#include "../Common/Dictionary.h"
#include <windows.h>

static DictionaryEntry StringDictionary[2048];
static int LastDictionaryEntry = -1;
static int MaxDictionaryEntry = sizeof (StringDictionary) / sizeof (DictionaryEntry) - 1;

static void *DataPool = NULL;
static size_t DataPoolSize = 0;

int AddDictionaryEntry (char *key, int intKey, void *value)
{
	int i;
	if (LastDictionaryEntry >= MaxDictionaryEntry) return -1;

	// Replace identical key if it exists
	for (i = 0; i <= LastDictionaryEntry; i++)
	{
		if ((StringDictionary[i].Key != NULL
			&& key != NULL
			&& strcmp (StringDictionary[i].Key, key) == 0)
			|| (key == NULL && StringDictionary[i].IntKey == intKey))
		{
			StringDictionary[i].Key = key;
			StringDictionary[i].IntKey = intKey;
			StringDictionary[i].Value = value;

			return i;
		}
	}

	LastDictionaryEntry++;

	StringDictionary[LastDictionaryEntry].Key = key;
	StringDictionary[LastDictionaryEntry].IntKey = intKey;
	StringDictionary[LastDictionaryEntry].Value = value;

	return LastDictionaryEntry;
}


void *GetDictionaryValue (char *key)
{
	int i;
	for (i = 0; i <= LastDictionaryEntry; i++)
	{
		if (StringDictionary[i].Key != NULL
			&& strcmp (StringDictionary[i].Key, key) == 0)
			return StringDictionary[i].Value;
	}

	return NULL;
}


void *GetDictionaryValueByInt (int intKey)
{
	int i;
	for (i = 0; i <= LastDictionaryEntry; i++)
	{
		if (StringDictionary[i].IntKey == intKey)
			return StringDictionary[i].Value;
	}

	return NULL;
}


void *AddPoolData (void *data, size_t dataSize)
{

	if (DataPoolSize + dataSize > DATA_POOL_CAPACITY) return NULL;

	if (DataPool == NULL)
	{
		DataPool = malloc (DATA_POOL_CAPACITY);
		if (DataPool == NULL) return NULL;
	}

	memcpy ((BYTE *)DataPool + DataPoolSize, data, dataSize);

	//if (wcschr((WCHAR *)((BYTE *)DataPool + DataPoolSize), '%') == 0)
	//	_wcsupr ((WCHAR *)((BYTE *)DataPool + DataPoolSize));
	//else
	//	((WCHAR *)((BYTE *)DataPool + DataPoolSize))[0] = L'*';

	DataPoolSize += dataSize;
	
	return (BYTE *)DataPool + DataPoolSize - dataSize;
}


void ClearDictionaryPool ()
{
	DataPoolSize = 0;
	LastDictionaryEntry = -1;
}