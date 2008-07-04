/*
 Copyright (c) 2008 TrueCrypt Foundation. All rights reserved.

 Governed by the TrueCrypt License 2.5 the full text of which is contained
 in the file License.txt included in TrueCrypt binary and source code
 distribution packages.
*/

#include "Volume/EncryptionTest.h"
#include "Volume/EncryptionModeXTS.h"
#include "Core.h"

#ifdef TC_UNIX
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#endif

#include "VolumeCreator.h"
#include "FatFormatter.h"

namespace TrueCrypt
{
	VolumeCreator::VolumeCreator ()
		: SizeDone (0)
	{
	}

	VolumeCreator::~VolumeCreator ()
	{
	}
	
	void VolumeCreator::Abort ()
	{
		AbortRequested = true;
	}

	void VolumeCreator::CheckResult ()
	{
		if (ThreadException)
			ThreadException->Throw();
	}

	void VolumeCreator::CreationThread ()
	{
		try
		{
			uint64 endOffset;
			uint64 filesystemSize = Layout->GetDataSize (HostSize);

			if (filesystemSize < 1)
				throw ParameterIncorrect (SRC_POS);

			DataStart = Layout->GetDataOffset (HostSize);
			WriteOffset = DataStart;
			endOffset = DataStart + Layout->GetDataSize (HostSize);

			VolumeFile->SeekAt (DataStart);

			// Create filesystem
			if (Options->Filesystem == VolumeCreationOptions::FilesystemType::FAT)
			{
				if (filesystemSize < TC_MIN_FAT_FS_SIZE || filesystemSize > TC_MAX_FAT_FS_SIZE)
					throw ParameterIncorrect (SRC_POS);

				struct WriteSectorCallback : public FatFormatter::WriteSectorCallback
				{
					WriteSectorCallback (VolumeCreator *creator) : Creator (creator), OutputBuffer (256 * 1024), OutputBufferWritePos (0) { }

					virtual bool operator() (const BufferPtr &sector)
					{
						OutputBuffer.GetRange (OutputBufferWritePos, sector.Size()).CopyFrom (sector);
						OutputBufferWritePos += sector.Size();

						if (OutputBufferWritePos >= OutputBuffer.Size())
							FlushOutputBuffer();

						return !Creator->AbortRequested;
					}

					void FlushOutputBuffer ()
					{
						if (OutputBufferWritePos > 0)
						{
							Creator->Options->EA->EncryptSectors (OutputBuffer.GetRange (0, OutputBufferWritePos),
								Creator->WriteOffset / SECTOR_SIZE, OutputBufferWritePos / SECTOR_SIZE, SECTOR_SIZE);

							Creator->VolumeFile->Write (OutputBuffer.GetRange (0, OutputBufferWritePos));

							Creator->WriteOffset += OutputBufferWritePos;
							Creator->SizeDone.Set (Creator->WriteOffset - Creator->DataStart);

							OutputBufferWritePos = 0;
						}
					}

					VolumeCreator *Creator;
					SecureBuffer OutputBuffer;
					size_t OutputBufferWritePos;
				};

				WriteSectorCallback sectorWriter (this);
				FatFormatter::Format (sectorWriter, filesystemSize, Options->FilesystemClusterSize);
				sectorWriter.FlushOutputBuffer();
			}

			if (!Options->Quick)
			{
				// Empty sectors are encrypted with different key to randomize plaintext
				Core->RandomizeEncryptionAlgorithmKey (Options->EA);

				SecureBuffer outputBuffer (256 * 1024);
				uint64 dataFragmentLength = outputBuffer.Size();

				while (!AbortRequested && WriteOffset < endOffset)
				{
					if (WriteOffset + dataFragmentLength > endOffset)
						dataFragmentLength = endOffset - WriteOffset;

					outputBuffer.Zero();
					Options->EA->EncryptSectors (outputBuffer, WriteOffset / SECTOR_SIZE, dataFragmentLength / SECTOR_SIZE, SECTOR_SIZE);
					VolumeFile->Write (outputBuffer, (size_t) dataFragmentLength);

					WriteOffset += dataFragmentLength;
					SizeDone.Set (WriteOffset - DataStart);
				}
			}

			SizeDone.Set (Options->Size);

			// Backup header
			SecureBuffer backupHeader (Layout->GetHeaderSize());

			SecureBuffer backupHeaderSalt (VolumeHeader::GetSaltSize());
			RandomNumberGenerator::GetData (backupHeaderSalt);

			Options->VolumeHeaderKdf->DeriveKey (HeaderKey, *PasswordKey, backupHeaderSalt);

			Layout->GetHeader()->EncryptNew (backupHeader, backupHeaderSalt, HeaderKey, Options->VolumeHeaderKdf);

			if (Options->Quick || Options->Type == VolumeType::Hidden)
				VolumeFile->SeekEnd (Layout->GetBackupHeaderOffset());

			VolumeFile->Write (backupHeader);

			if (Options->Type == VolumeType::Normal)
			{
				// Write random data to space reserved for hidden volume backup header
				Core->RandomizeEncryptionAlgorithmKey (Options->EA);
				Options->EA->Encrypt (backupHeader);

				VolumeFile->Write (backupHeader);
			}

			VolumeFile->Flush();
		}
		catch (Exception &e)
		{
			ThreadException.reset (e.CloneNew());
		}
		catch (exception &e)
		{
			ThreadException.reset (new ExternalException (SRC_POS, StringConverter::ToExceptionString (e)));
		}
		catch (...)
		{
			ThreadException.reset (new UnknownException (SRC_POS));
		}

		VolumeFile.reset();
		mProgressInfo.CreationInProgress = false;
	}

	void VolumeCreator::CreateVolume (shared_ptr <VolumeCreationOptions> options)
	{
		EncryptionTest::TestAll();
		RandomNumberGenerator::Start();

		{
#ifdef TC_UNIX
			UserId origDeviceOwner;
			origDeviceOwner.SystemId = (uid_t) -1;

			if (!Core->HasAdminPrivileges() && options->Path.IsDevice())
			{
				// Temporarily take ownership of the device to be formatted
				struct stat statData;
				throw_sys_if (stat (string (options->Path).c_str(), &statData) == -1);

				UserId owner;
				owner.SystemId = getuid();
				Core->SetFileOwner (options->Path, owner);
				origDeviceOwner.SystemId = statData.st_uid;
			}
			
			finally_do_arg2 (FilesystemPath, options->Path, UserId, origDeviceOwner,
				{
					if (finally_arg2.SystemId != (uid_t) -1)
						Core->SetFileOwner (finally_arg, finally_arg2);
				}
			);
#endif

			VolumeFile.reset (new File);
			VolumeFile->Open (options->Path,
				(options->Path.IsDevice() || options->Type == VolumeType::Hidden) ? File::OpenReadWrite : File::CreateReadWrite,
				File::ShareNone);

			HostSize = VolumeFile->Length();
		}

		try
		{
			// Test sector size
			if (options->Path.IsDevice() && VolumeFile->GetDeviceSectorSize() != SECTOR_SIZE)
				throw UnsupportedSectorSize (SRC_POS);

			// Volume layout
			switch (options->Type)
			{
			case VolumeType::Normal:
				Layout.reset (new VolumeLayoutV2Normal());
				break;

			case VolumeType::Hidden:
				Layout.reset (new VolumeLayoutV2Hidden());

				if (HostSize < TC_MIN_HIDDEN_VOLUME_HOST_SIZE)
					throw ParameterIncorrect (SRC_POS);
				break;

			default:
				throw ParameterIncorrect (SRC_POS);
			}

			// Volume header
			shared_ptr <VolumeHeader> header (Layout->GetHeader());
			SecureBuffer headerBuffer (Layout->GetHeaderSize());

			VolumeHeaderCreationOptions headerOptions;
			headerOptions.EA = options->EA;
			headerOptions.Kdf = options->VolumeHeaderKdf;
			headerOptions.Type = options->Type;

			if (options->Type == VolumeType::Hidden)
				headerOptions.VolumeDataStart = HostSize - Layout->GetHeaderSize() * 2 - options->Size;
			else
				headerOptions.VolumeDataStart = Layout->GetHeaderSize() * 2;

			headerOptions.VolumeDataSize = Layout->GetMaxDataSize (options->Size);

			if (headerOptions.VolumeDataSize < 1)
				throw ParameterIncorrect (SRC_POS);

			// Master data key
			MasterKey.Allocate (options->EA->GetKeySize() * 2);
			RandomNumberGenerator::GetData (MasterKey);
			headerOptions.DataKey = MasterKey;

			// PKCS5 salt
			SecureBuffer salt (VolumeHeader::GetSaltSize());
			RandomNumberGenerator::GetData (salt);
			headerOptions.Salt = salt;

			// Header key
			HeaderKey.Allocate (VolumeHeader::GetLargestSerializedKeySize());
			PasswordKey = Keyfile::ApplyListToPassword (options->Keyfiles, options->Password);
			options->VolumeHeaderKdf->DeriveKey (HeaderKey, *PasswordKey, salt);
			headerOptions.HeaderKey = HeaderKey;

			header->Create (headerBuffer, headerOptions);

			// Write new header
			if (Layout->GetHeaderOffset() >= 0)
				VolumeFile->SeekAt (Layout->GetHeaderOffset());
			else
				VolumeFile->SeekEnd (Layout->GetHeaderOffset());

			VolumeFile->Write (headerBuffer);

			if (options->Type == VolumeType::Normal)
			{
				// Write random data to space reserved for hidden volume header
				Core->RandomizeEncryptionAlgorithmKey (options->EA);
				options->EA->Encrypt (headerBuffer);

				VolumeFile->Write (headerBuffer);
			}

			// Data area keys
			options->EA->SetKey (MasterKey.GetRange (0, options->EA->GetKeySize()));
			shared_ptr <EncryptionMode> mode (new EncryptionModeXTS ());
			mode->SetKey (MasterKey.GetRange (options->EA->GetKeySize(), options->EA->GetKeySize()));
			options->EA->SetMode (mode);

			Options = options;
			AbortRequested = false;

			mProgressInfo.CreationInProgress = true;

			struct ThreadFunctor : public Functor
			{
				ThreadFunctor (VolumeCreator *creator) : Creator (creator) { }
				virtual void operator() ()
				{
					Creator->CreationThread ();
				}
				VolumeCreator *Creator;
			};

			Thread thread;
			thread.Start (new ThreadFunctor (this));
		}
		catch (...)
		{
			VolumeFile.reset();
			throw;
		}
	}

	VolumeCreator::KeyInfo VolumeCreator::GetKeyInfo () const
	{
		KeyInfo info;
		info.HeaderKey = HeaderKey;
		info.MasterKey = MasterKey;
		return info;
	}

	VolumeCreator::ProgressInfo VolumeCreator::GetProgressInfo ()
	{
		mProgressInfo.SizeDone = SizeDone.Get();
		return mProgressInfo;
	}
}
