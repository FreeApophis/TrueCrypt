int ReadRegistryInt (char *subKey, char *name, int defaultValue);
char *ReadRegistryString (char *subKey, char *name, char *defaultValue, char *str, int maxLen);
DWORD ReadRegistryBytes (char *path, char *name, char *value, int maxLen);
void WriteRegistryInt (char *subKey, char *name, int value);
void WriteRegistryString (char *subKey, char *name, char *str);
BOOL WriteRegistryBytes (char *path, char *name, char *str, DWORD size);
void DeleteRegistryValue (char *subKey, char *name);
