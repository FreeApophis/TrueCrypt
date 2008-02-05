/*
 Copyright (c) 2008 TrueCrypt Foundation. All rights reserved.

 Governed by the TrueCrypt License 2.4 the full text of which is contained
 in the file License.txt included in TrueCrypt binary and source code
 distribution packages.
*/

#	define FSEEK _fseeki64
#	define FTELL _ftelli64

#include <stdio.h>
#include "File.h"

namespace TrueCrypt
{

	void File::Close ()
	{
		if_debug (ValidateState ());

		if (!SharedHandle)
			fclose (FileHandle);
		FileIsOpen = false;
	}

	void File::Delete ()
	{
		Close();
		Path.Delete();
	}

	uint32 File::GetDeviceSectorSize () const
	{
		return 512;
	}

	void File::Flush () const
	{
		if_debug (ValidateState ());
		throw_sys_sub_if (fflush (FileHandle) != 0, wstring (Path));
	}

	uint64 File::Length () const
	{
		uint64 current = FTELL (FileHandle);
		SeekEnd (0);
		uint64 length = FTELL (FileHandle);
		SeekAt (current);
		return length;
	}

	void File::Open (const FilePath &path, FileOpenMode mode, FileShareMode shareMode, FileOpenFlags flags)
	{
		mFileOpenFlags = flags;

		const wchar_t *fMode;

		switch (mode)
		{
		case CreateReadWrite:
			fMode = L"w+b";
			break;
				
		case CreateWrite:
			fMode = L"wb";
			break;

		case OpenRead:
			fMode = L"rb";
			break;
				
		case OpenWrite:
		case OpenReadWrite:
			fMode = L"r+b";
			break;

		default:
			throw ParameterIncorrect (SRC_POS);
		}

		FileHandle = _wfopen (wstring (path).c_str(), fMode);
		throw_sys_sub_if (FileHandle == nullptr, wstring (path));

		Path = path;
		FileIsOpen = true;
	}

	uint64 File::Read (const BufferPtr &buffer) const
	{
		if_debug (ValidateState ());

		uint64 bytesRead = fread (buffer, 1, buffer.Size(), FileHandle);
		throw_sys_sub_if (ferror (FileHandle) != 0, wstring (Path));

		return bytesRead;
	}

	uint64 File::ReadAt (const BufferPtr &buffer, uint64 position) const
	{
		if_debug (ValidateState ());
		
		SeekAt (position);
		return Read (buffer);
	}

	void File::SeekAt (uint64 position) const
	{
		if_debug (ValidateState());
		throw_sys_sub_if (FSEEK (FileHandle, position, SEEK_SET) != 0, wstring (Path));
	}

	void File::SeekEnd (int offset) const
	{
		if_debug (ValidateState ());
		throw_sys_sub_if (FSEEK (FileHandle, offset, SEEK_END) != 0, wstring (Path));
	}

	void File::Write (const ConstBufferPtr &buffer) const
	{
		if_debug (ValidateState ());
		uint64 bytesWritten = fwrite (buffer, 1, buffer.Size(), FileHandle);
		throw_sys_sub_if (bytesWritten != buffer.Size() || ferror (FileHandle) != 0, wstring (Path));
	}
	
	void File::WriteAt (const ConstBufferPtr &buffer, uint64 position) const
	{
		if_debug (ValidateState ());
		SeekAt (position);
		Write (buffer);
	}
}
