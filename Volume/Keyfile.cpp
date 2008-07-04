/*
 Copyright (c) 2008 TrueCrypt Foundation. All rights reserved.

 Governed by the TrueCrypt License 2.5 the full text of which is contained
 in the file License.txt included in TrueCrypt binary and source code
 distribution packages.
*/

#include "Platform/Serializer.h"
#include "Crc32.h"
#include "Keyfile.h"

namespace TrueCrypt
{
	void Keyfile::Apply (const BufferPtr &pool) const
	{
		if (Path.IsDirectory())
			throw ParameterIncorrect (SRC_POS);

		File file;
		file.Open (Path, File::OpenRead, File::ShareRead, File::PreserveTimestamps);

		Crc32 crc32;
		size_t poolPos = 0;
		uint64 totalLength = 0;
		uint64 readLength;

		SecureBuffer keyfileBuf (File::GetOptimalReadSize());

		while ((readLength = file.Read (keyfileBuf)) > 0)
		{
			for (size_t i = 0; i < readLength; i++)
			{
				uint32 crc = crc32.Process (keyfileBuf[i]);

				pool[poolPos++] += (byte) (crc >> 24);
				pool[poolPos++] += (byte) (crc >> 16);
				pool[poolPos++] += (byte) (crc >> 8);
				pool[poolPos++] += (byte) crc;

				if (poolPos >= pool.Size())
					poolPos = 0;

				if (++totalLength >= MaxProcessedLength)
					goto done;
			}
		}
done:
		if (totalLength < MinProcessedLength)
			throw InsufficientData (SRC_POS, Path);
	}

	shared_ptr <VolumePassword> Keyfile::ApplyListToPassword (shared_ptr <KeyfileList> keyfiles, shared_ptr <VolumePassword> password)
	{
		if (!password)
			password.reset (new VolumePassword);

		if (!keyfiles || keyfiles->size() < 1)
			return password;

		KeyfileList keyfilesExp;

		// Enumerate directories
		foreach (shared_ptr <Keyfile> keyfile, *keyfiles)
		{
			if (FilesystemPath (*keyfile).GetType() == FilesystemPathType::Directory)
			{
				foreach_ref (const FilePath &path, Directory::GetFilePaths (*keyfile))
				{
					keyfilesExp.push_back (make_shared <Keyfile> (path));
				}
			}
			else
			{
				keyfilesExp.push_back (keyfile);
			}
		}

		make_shared_auto (VolumePassword, newPassword);

		if (keyfilesExp.size() < 1)
		{
			newPassword->Set (*password);
		}
		else
		{
			SecureBuffer keyfilePool (VolumePassword::MaxSize);

			// Pad password with zeros if shorter than max length
			keyfilePool.Zero();
			keyfilePool.CopyFrom (ConstBufferPtr (password->DataPtr(), password->Size()));

			// Apply all keyfiles
			foreach_ref (const Keyfile &k, keyfilesExp)
			{
				k.Apply (keyfilePool);
			}

			newPassword->Set (keyfilePool);
		}

		return newPassword;
	}

	shared_ptr <KeyfileList> Keyfile::DeserializeList (shared_ptr <Stream> stream, const string &name)
	{
		shared_ptr <KeyfileList> keyfiles;
		Serializer sr (stream);
		
		if (!sr.DeserializeBool (name + "Null"))
		{
			keyfiles.reset (new KeyfileList);
			foreach (const wstring &k, sr.DeserializeWStringList (name))
				keyfiles->push_back (make_shared <Keyfile> (k));
		}
		return keyfiles;
	}

	void Keyfile::SerializeList (shared_ptr <Stream> stream, const string &name, shared_ptr <KeyfileList> keyfiles)
	{
		Serializer sr (stream);
		sr.Serialize (name + "Null", keyfiles == nullptr);
		if (keyfiles)
		{
			list <wstring> sl;

			foreach_ref (const Keyfile &k, *keyfiles)
				sl.push_back (FilesystemPath (k));

			sr.Serialize (name, sl);
		}
	}
}
