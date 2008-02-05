/*
 Copyright (c) 2008 TrueCrypt Foundation. All rights reserved.

 Governed by the TrueCrypt License 2.4 the full text of which is contained
 in the file License.txt included in TrueCrypt binary and source code
 distribution packages.
*/

#define _LARGEFILE_SOURCE	1
#define _FILE_OFFSET_BITS	64

#include <errno.h>
#ifdef TC_LINUX
#include <sys/mount.h>
#endif
#ifdef TC_BSD
#include <sys/disk.h>
#endif
#include <sys/file.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <utime.h>
#include "Platform/File.h"

namespace TrueCrypt
{
	void File::Close ()
	{
		ValidateState();

		if (!SharedHandle)
		{
			close (FileHandle);
			FileIsOpen = false;

			if ((mFileOpenFlags & File::PreserveTimestamps) && Path.IsFile())
			{
				struct utimbuf u;
				u.actime = AccTime;
				u.modtime = ModTime;
				throw_sys_sub_if (utime (string (Path).c_str(), &u) == -1, wstring (Path));
			}
		}
	}

	void File::Delete ()
	{
		Close();
		Path.Delete();
	}


	void File::Flush () const
	{
		ValidateState();
		throw_sys_sub_if (fsync (FileHandle) != 0, wstring (Path));
	}

	uint32 File::GetDeviceSectorSize () const
	{
		if (Path.IsDevice())
		{
#ifdef TC_LINUX
			int blockSize;
			throw_sys_sub_if (ioctl (FileHandle, BLKSSZGET, &blockSize) == -1, wstring (Path));
			return blockSize;

#elif defined (TC_MACOSX)
			uint32 blockSize;
			throw_sys_sub_if (ioctl (FileHandle, DKIOCGETBLOCKSIZE, &blockSize) == -1, wstring (Path));
			return blockSize;
#endif
		}

		return 512;
	}

	uint64 File::Length () const
	{
		ValidateState();

		// BSD does not support seeking to the end of a device
#ifdef TC_BSD
		if (Path.IsBlockDevice() || Path.IsCharacterDevice())
		{
#	ifdef TC_MACOSX
			uint32 blockSize;
			uint64 blockCount;
			throw_sys_sub_if (ioctl (FileHandle, DKIOCGETBLOCKSIZE, &blockSize) == -1, wstring (Path));
			throw_sys_sub_if (ioctl (FileHandle, DKIOCGETBLOCKCOUNT, &blockCount) == -1, wstring (Path));
			return blockCount * blockSize;
#	else
			uint64 mediaSize;
			throw_sys_sub_if (ioctl (FileHandle, DIOCGMEDIASIZE, &mediaSize) == -1, wstring (Path));
			return mediaSize;
#	endif
		}
#endif
		off_t current = lseek (FileHandle, 0, SEEK_CUR);
		throw_sys_sub_if (current == -1, wstring (Path));
		SeekEnd (0);
		uint64 length = lseek (FileHandle, 0, SEEK_CUR);
		SeekAt (current);
		return length;
	}

	void File::Open (const FilePath &path, FileOpenMode mode, FileShareMode shareMode, FileOpenFlags flags)
	{
#ifdef TC_LINUX
		int sysFlags = O_LARGEFILE;
#else
		int sysFlags = 0;
#endif

		switch (mode)
		{
		case CreateReadWrite:
			sysFlags |= O_CREAT | O_TRUNC | O_RDWR;
			break;
				
		case CreateWrite:
			sysFlags |= O_CREAT | O_TRUNC | O_WRONLY;
			break;

		case OpenRead:
			sysFlags |= O_RDONLY;
			break;

		case OpenWrite:
			sysFlags |= O_WRONLY;
			break;

		case OpenReadWrite:
			sysFlags |= O_RDWR;
			break;

		default:
			throw ParameterIncorrect (SRC_POS);
		}

		if ((flags & File::PreserveTimestamps) && path.IsFile())
		{
			struct stat statData;
			throw_sys_sub_if (stat (string (path).c_str(), &statData) == -1, wstring (path));
			AccTime = statData.st_atime;
			ModTime = statData.st_mtime;
		}

		FileHandle = open (string (path).c_str(), sysFlags, S_IRUSR | S_IWUSR);
		throw_sys_sub_if (FileHandle == -1, wstring (path));

		try
		{
			switch (shareMode)
			{
			case ShareNone:
				if (flock (FileHandle, LOCK_EX | LOCK_NB) == -1)
					throw_sys_sub_if (errno == EAGAIN, wstring (path));
				break;

			case ShareRead:
				if (flock (FileHandle, LOCK_SH | LOCK_NB) == -1)
					throw_sys_sub_if (errno == EAGAIN, wstring (path));
				break;

			case ShareReadWrite:
				if (flock (FileHandle, (mode == OpenRead ? LOCK_SH : LOCK_EX) | LOCK_NB) == -1)
					throw_sys_sub_if (errno == EAGAIN, wstring (path));
				flock (FileHandle, LOCK_UN | LOCK_NB);
				break;
			
			case ShareReadWriteIgnoreLock:
				break;

			default:
				throw ParameterIncorrect (SRC_POS);
			}
		}
		catch (...)
		{
			close (FileHandle);
			throw;
		}

		Path = path;
		mFileOpenFlags = flags;
		FileIsOpen = true;
	}

	uint64 File::Read (const BufferPtr &buffer) const
	{
		ValidateState();

		ssize_t bytesRead = read (FileHandle, buffer, buffer.Size());
		throw_sys_sub_if (bytesRead == -1, wstring (Path));

		return bytesRead;
	}

	uint64 File::ReadAt (const BufferPtr &buffer, uint64 position) const
	{
		ValidateState();
		
		ssize_t bytesRead = pread (FileHandle, buffer, buffer.Size(), position);
		throw_sys_sub_if (bytesRead == -1, wstring (Path));

		return bytesRead;
	}

	void File::SeekAt (uint64 position) const
	{
		ValidateState();
		throw_sys_sub_if (lseek (FileHandle, position, SEEK_SET) == -1, wstring (Path));
	}

	void File::SeekEnd (int offset) const
	{
		ValidateState();

		// BSD does not support seeking to the end of a device
#ifdef TC_BSD
		if (Path.IsBlockDevice() || Path.IsCharacterDevice())
		{
			SeekAt (Length() + offset);
			return;
		}
#endif

		throw_sys_sub_if (lseek (FileHandle, offset, SEEK_END) == -1, wstring (Path));
	}

	void File::Write (const ConstBufferPtr &buffer) const
	{
		ValidateState();
		throw_sys_sub_if (write (FileHandle, buffer, buffer.Size()) != buffer.Size(), wstring (Path));
	}
	
	void File::WriteAt (const ConstBufferPtr &buffer, uint64 position) const
	{
		ValidateState();
		throw_sys_sub_if (pwrite (FileHandle, buffer, buffer.Size(), position) != buffer.Size(), wstring (Path));
	}
}
