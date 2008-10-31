/*
 Copyright (c) 2008 TrueCrypt Foundation. All rights reserved.

 Governed by the TrueCrypt License 2.6 the full text of which is contained
 in the file License.txt included in TrueCrypt binary and source code
 distribution packages.
*/

#ifndef TC_HEADER_Platform_Stream
#define TC_HEADER_Platform_Stream

#include "PlatformBase.h"
#include "Buffer.h"

namespace TrueCrypt
{
	class Stream
	{
	public:
		virtual ~Stream () { }
		virtual uint64 Read (const BufferPtr &buffer) = 0;
		virtual void ReadCompleteBuffer (const BufferPtr &buffer) = 0;
		virtual void Write (const ConstBufferPtr &data) = 0;

	protected:
		Stream () { };

	private:
		Stream (const Stream &);
		Stream &operator= (const Stream &);
	};
}

#endif // TC_HEADER_Platform_Stream
