/*
 Copyright (c) 2008 TrueCrypt Foundation. All rights reserved.

 Governed by the TrueCrypt License 2.5 the full text of which is contained
 in the file License.txt included in TrueCrypt binary and source code
 distribution packages.
*/

#include "Platform/Exception.h"
#include "Platform/SyncEvent.h"
#include "Platform/SystemException.h"

namespace TrueCrypt
{
	SyncEvent::SyncEvent ()
	{
		int status = pthread_cond_init (&SystemSyncEvent, nullptr);
		if (status != 0)
			throw SystemException (SRC_POS, status);

		Signaled = false;
		Initialized = true;
	}

	SyncEvent::~SyncEvent ()
	{
		assert (Initialized);

		int status = pthread_cond_destroy (&SystemSyncEvent);
		if (status != 0)
			throw SystemException (SRC_POS, status);

		Initialized = false;
	}

	void SyncEvent::Signal ()
	{
		assert (Initialized);

		ScopeLock lock (EventMutex);

		Signaled = true;

		int status = pthread_cond_signal (&SystemSyncEvent);
		if (status != 0)
			throw SystemException (SRC_POS, status);
	}

	void SyncEvent::Wait ()
	{
		assert (Initialized);

		ScopeLock lock (EventMutex);

		while (!Signaled)
		{
			int status = pthread_cond_wait (&SystemSyncEvent, EventMutex.GetSystemHandle());
			if (status != 0)
				throw SystemException (SRC_POS, status);
		}
		
		Signaled = false;
	}
}
