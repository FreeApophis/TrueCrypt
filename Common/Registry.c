/* 
Copyright (c) 2004-2006 TrueCrypt Foundation. All rights reserved. 
Copyright (c) 2004 TrueCrypt Team. All rights reserved. 

Covered by TrueCrypt License 2.1 the full text of which is contained in the file
License.txt included in TrueCrypt binary and source code distribution archives. 
*/

#include "Tcdefs.h"
#include "Registry.h"

int ReadRegistryInt (char *subKey, char *name, int defaultValue)
{
	HKEY hkey = 0;
	DWORD value, size = sizeof (DWORD);

	if (RegOpenKeyEx (HKEY_CURRENT_USER, subKey,
		0, KEY_READ, &hkey) != ERROR_SUCCESS)
		return defaultValue;

	if (RegQueryValueEx (hkey, name, 0,	0, (LPBYTE) &value, &size) != ERROR_SUCCESS)
		value = defaultValue;

	RegCloseKey (hkey);
	return value;
}

char *ReadRegistryString (char *subKey, char *name, char *defaultValue, char *str, int maxLen)
{
	HKEY hkey = 0;
	char value[MAX_PATH*4];
	DWORD size = sizeof (value);

	strncpy (str, defaultValue, maxLen-1);

	ZeroMemory (value, sizeof value);
	if (RegOpenKeyEx (HKEY_CURRENT_USER, subKey,
		0, KEY_READ, &hkey) == ERROR_SUCCESS)
		if (RegQueryValueEx (hkey, name, 0,	0, (LPBYTE) &value,	&size) == ERROR_SUCCESS)
			strncpy (str, value, maxLen-1);

	RegCloseKey (hkey);
	return str;
}

DWORD ReadRegistryBytes (char *path, char *name, char *value, int maxLen)
{
	HKEY hkey = 0;
	DWORD size = maxLen;
	BOOL success = FALSE;

	if (RegOpenKeyEx (HKEY_CURRENT_USER, path, 0, KEY_READ, &hkey) != ERROR_SUCCESS)
		return 0;

	success = (RegQueryValueEx (hkey, name, 0,	0, (LPBYTE) value,	&size) == ERROR_SUCCESS);
	RegCloseKey (hkey);

	return success ? size : 0;
}

void WriteRegistryInt (char *subKey, char *name, int value)
{
	HKEY hkey = 0;
	DWORD disp;

	if (RegCreateKeyEx (HKEY_CURRENT_USER, subKey,
		0, NULL, REG_OPTION_NON_VOLATILE, KEY_WRITE, NULL, &hkey, &disp) != ERROR_SUCCESS)
		return;

	RegSetValueEx (hkey, name, 0, REG_DWORD, (BYTE *) &value, sizeof value);
	RegCloseKey (hkey);
}

void WriteRegistryString (char *subKey, char *name, char *str)
{
	HKEY hkey = 0;
	DWORD disp;

	if (RegCreateKeyEx (HKEY_CURRENT_USER, subKey,
		0, NULL, REG_OPTION_NON_VOLATILE, KEY_WRITE, NULL, &hkey, &disp) != ERROR_SUCCESS)
		return;

	RegSetValueEx (hkey, name, 0, REG_SZ, (BYTE *) str, strlen (str) + 1);
	RegCloseKey (hkey);
}

BOOL WriteRegistryBytes (char *path, char *name, char *str, DWORD size)
{
	HKEY hkey = 0;
	DWORD disp;
	BOOL res;

	if (RegCreateKeyEx (HKEY_CURRENT_USER, path,
		0, NULL, REG_OPTION_NON_VOLATILE, KEY_WRITE, NULL, &hkey, &disp) != ERROR_SUCCESS)
		return FALSE;

	res = RegSetValueEx (hkey, name, 0, REG_BINARY, (BYTE *) str, size);
	RegCloseKey (hkey);
	return res == ERROR_SUCCESS;
}

void DeleteRegistryValue (char *subKey, char *name)
{
	HKEY hkey = 0;

	if (RegOpenKeyEx (HKEY_CURRENT_USER, subKey, 0, KEY_WRITE, &hkey) != ERROR_SUCCESS)
		return;

	RegDeleteValue (hkey, name);
	RegCloseKey (hkey);
}