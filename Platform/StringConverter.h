/*
 Copyright (c) 2008 TrueCrypt Foundation. All rights reserved.

 Governed by the TrueCrypt License 2.4 the full text of which is contained
 in the file License.txt included in TrueCrypt binary and source code
 distribution packages.
*/

#ifndef TC_HEADER_Platform_StringConverter
#define TC_HEADER_Platform_StringConverter

#include <stdlib.h>
#include "PlatformBase.h"

namespace TrueCrypt
{
	class StringConverter
	{
	public:
		static wstring FromNumber (double number);
		static wstring FromNumber (int32 number);
		static wstring FromNumber (uint32 number);
		static wstring FromNumber (int64 number);
		static wstring FromNumber (uint64 number);
		static string GetTrailingNumber (const string &str);
		static string GetTypeName (const type_info &typeInfo);
		static wstring QuoteSpaces (const wstring &str);
		static vector <string> Split (const string &str, const string &separators = " \t\r\n", bool returnEmptyFields = false);
		static wstring ToExceptionString (const exception &ex);
		static uint32 ToUInt32 (const string &str);
		static uint32 ToUInt32 (const wstring &str);
		static uint64 ToUInt64 (const string &str);
		static uint64 ToUInt64 (const wstring &str);
		static string ToSingle (const wstring &str, bool noThrow = false);
		static wstring ToWide (const string &str, bool noThrow = false);
		static void ToWideBuffer (const wstring &str, wchar_t *buffer, size_t bufferSize);
		static string Trim (const string &str);

	private:
		StringConverter ();
	};
}

#endif // TC_HEADER_Platform_StringConverter
