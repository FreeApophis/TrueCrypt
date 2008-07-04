/*
 Copyright (c) 2008 TrueCrypt Foundation. All rights reserved.

 Governed by the TrueCrypt License 2.5 the full text of which is contained
 in the file License.txt included in TrueCrypt binary and source code
 distribution packages.
*/

#ifndef TC_HEADER_Main_UserInterfaceException
#define TC_HEADER_Main_UserInterfaceException

#include "Platform/Platform.h"

namespace TrueCrypt
{
	TC_EXCEPTION_DECL (UserInterfaceException, Exception);
	TC_EXCEPTION_DECL (MissingArgument, UserInterfaceException);
	TC_EXCEPTION_DECL (NoItemSelected, UserInterfaceException);
	TC_EXCEPTION_DECL (StringFormatterException, UserInterfaceException);
	TC_EXCEPTION_DECL (UserAbort, UserInterfaceException);

	struct ErrorMessage : public UserInterfaceException
	{
		ErrorMessage (const string &exceptionMessage, const wxString &errorMessage) : UserInterfaceException (exceptionMessage), Text (errorMessage) { }
		virtual ~ErrorMessage () throw () { }

		operator wstring () const { return wstring (Text); }
		operator wxString () const { return Text; }

	protected:
		wxString Text;
	};

#define throw_err(message) throw ErrorMessage (SRC_POS, (message))
}

#endif // TC_HEADER_Main_UserInterfaceException
