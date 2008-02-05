/*
 Copyright (c) 2008 TrueCrypt Foundation. All rights reserved.

 Governed by the TrueCrypt License 2.4 the full text of which is contained
 in the file License.txt included in TrueCrypt binary and source code
 distribution packages.
*/

#ifndef TC_HEADER_Platform_Thread
#define TC_HEADER_Platform_Thread

#ifdef TC_WINDOWS
#	include "System.h"
#	define TC_THREAD_PROC DWORD WINAPI
#else
#	include <pthread.h>
#	define TC_THREAD_PROC void*
#endif
#include "PlatformBase.h"
#include "Functor.h"
#include "SharedPtr.h"

namespace TrueCrypt
{
	class Thread
	{
	public:
#ifdef TC_WINDOWS
		typedef LPTHREAD_START_ROUTINE ThreadProcPtr;
#else
		typedef void* (*ThreadProcPtr) (void *);
#endif
		Thread () { };
		virtual ~Thread () { };

		void Start (ThreadProcPtr threadProc, void *parameter = nullptr);

		void Start (Functor *functor)
		{
			Start (Thread::FunctorEntry, (void *)functor);
		}

		static void Sleep (uint32 milliSeconds);

	protected:
		static TC_THREAD_PROC FunctorEntry (void *functorArg)
		{
			Functor *functor = (Functor *) functorArg;
			try
			{
				(*functor) ();
			}
			catch (...) { }

			delete functor;
			return 0;
		}

		static const size_t MinThreadStackSize = 1024 * 1024;

	private:
		Thread (const Thread &);
		Thread &operator= (const Thread &);
	};

}

#endif // TC_HEADER_Platform_Thread
