/*
 Copyright (c) 2008 TrueCrypt Foundation. All rights reserved.

 Governed by the TrueCrypt License 2.4 the full text of which is contained
 in the file License.txt included in TrueCrypt binary and source code
 distribution packages.
*/

#ifndef TC_HEADER_Platform_Finally
#define TC_HEADER_Platform_Finally

#include "PlatformBase.h"

// Execute defined code when leaving scope
#define finally_do(code) struct TC_JOIN(Finally,__LINE__) { TC_JOIN(~Finally,__LINE__) () { code } } TC_JOIN(finally,__LINE__)

// Execute defined code with argument 'finally_arg' when leaving scope 
#define finally_do_arg(argType, arg, code) struct TC_JOIN(Finally,__LINE__) \
{ \
	TC_JOIN(Finally,__LINE__) (argType a) : finally_arg (a) { } \
	TC_JOIN(~Finally,__LINE__) () { code } \
	argType finally_arg; \
} TC_JOIN(finally,__LINE__) (arg)

#define finally_do_arg2(argType, arg, argType2, arg2, code) struct TC_JOIN(Finally,__LINE__) \
{ \
	TC_JOIN(Finally,__LINE__) (argType a, argType2 a2) : finally_arg (a), finally_arg2 (a2) { } \
	TC_JOIN(~Finally,__LINE__) () { code } \
	argType finally_arg; \
	argType2 finally_arg2; \
} TC_JOIN(finally,__LINE__) (arg, arg2)

//#define finally_do_arg2(argType, arg, argType2, arg2, code) struct TC_JOIN(Finally,__LINE__) { argType finally_arg; TC_JOIN(Finally,__LINE__) (argType a) : finally_arg (a) { } TC_JOIN(~Finally,__LINE__) () { code } } TC_JOIN(finally,__LINE__) (arg)

#endif // TC_HEADER_Platform_Finally
