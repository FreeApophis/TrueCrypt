/* Copyright (C) 2004 TrueCrypt Team */

#include "TCdefs.h"

#define TC_REG_SUBKEY "Software\\TrueCrypt" 

int ReadRegistryInt (char *name, int defaultValue)
{
	HKEY hkey = 0;
	DWORD value, size = sizeof (DWORD);

	if (RegOpenKeyEx (HKEY_CURRENT_USER, TC_REG_SUBKEY,
		0, KEY_READ, &hkey) != ERROR_SUCCESS)
		return defaultValue;

	if (RegQueryValueEx (hkey, name, 0,	0, (LPBYTE) &value, &size) != ERROR_SUCCESS)
		value = defaultValue;

	RegCloseKey (hkey);
	return value;
}

char *ReadRegistryString (char *name, char *defaultValue, char *str, int maxLen)
{
	HKEY hkey = 0;
	char value[256];
	DWORD size = sizeof (value);

	strncpy (str, defaultValue, maxLen-1);

	ZeroMemory (value, sizeof value);
	if (RegOpenKeyEx (HKEY_CURRENT_USER, TC_REG_SUBKEY,
		0, KEY_READ, &hkey) == ERROR_SUCCESS)
		if (RegQueryValueEx (hkey, name, 0,	0, (LPBYTE) &value,	&size) == ERROR_SUCCESS)
			strncpy (str, value, maxLen-1);

	RegCloseKey (hkey);
	return str;
}

void WriteRegistryInt (char *name, int value)
{
	HKEY hkey = 0;
	DWORD disp;

	if (RegCreateKeyEx (HKEY_CURRENT_USER, TC_REG_SUBKEY,
		0, NULL, REG_OPTION_NON_VOLATILE, KEY_WRITE, NULL, &hkey, &disp) != ERROR_SUCCESS)
		return;

	RegSetValueEx (hkey, name, 0, REG_DWORD, (BYTE *) &value, sizeof value);
	RegCloseKey (hkey);
}

void WriteRegistryString (char *name, char *str)
{
	HKEY hkey = 0;
	DWORD disp;

	if (RegCreateKeyEx (HKEY_CURRENT_USER, TC_REG_SUBKEY,
		0, NULL, REG_OPTION_NON_VOLATILE, KEY_WRITE, NULL, &hkey, &disp) != ERROR_SUCCESS)
		return;

	RegSetValueEx (hkey, name, 0, REG_SZ, (BYTE *) str, strlen (str) + 1);
	RegCloseKey (hkey);
}
