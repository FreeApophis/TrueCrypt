int ReadRegistryInt (char *name, int defaultValue);
char *ReadRegistryString (char *name, char *defaultValue, char *str, int maxLen);
void WriteRegistryInt (char *name, int value);
void WriteRegistryString (char *name, char *str);