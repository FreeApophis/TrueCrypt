/*
 Copyright (c) 2008 TrueCrypt Foundation. All rights reserved.

 Governed by the TrueCrypt License 2.4 the full text of which is contained
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
			WriteOffset = Layout->GetHeaderSize();
			uint64 EndOffset = Options->Size;
			VolumeFile->SeekAt (WriteOffset);

			if (Options->Filesystem == VolumeCreationOptions::FilesystemType::FAT)
			{
				struct WriteSectorCallback : public FatFormatter::WriteSectorCallback
				{
					WriteSectorCallback (VolumeCreator *creator) : Creator (creator) { }
					virtual bool operator() (const BufferPtr &sector)
					{
						Creator->Options->EA->EncryptSectors (sector, Creator->WriteOffset / sector.Size(), 1, sector.Size());
						Creator->VolumeFile->Write (sector);

						Creator->WriteOffset += sector.Size();
						Creator->SizeDone.Set (Creator->WriteOffset);

						return !Creator->AbortRequested;
					}
					VolumeCreator *Creator;
				};

				WriteSectorCallback fatWriter (this);
				FatFormatter::Format (fatWriter, Options->Size - Layout->GetHeaderSize(), Options->FilesystemClusterSize);
			}

			if (Options->Quick)
			{
				SizeDone.Set (EndOffset);
			}
			else
			{
				// Empty sectors are encrypted with different key to randomize plaintext
				SecureBuffer emptySectorsKey (Options->EA->GetKeySize());
				RandomNumberGenerator::GetData (emptySectorsKey);
				Options->EA->SetKey (emptySectorsKey);
				
				SecureBuffer emptySectorsModeKey (Options->EA->GetMode()->GetKeySize());
				RandomNumberGenerator::GetData (emptySectorsModeKey);
				Options->EA->GetMode()->SetKey (emptySectorsModeKey);

				SecureBuffer outputBuffer (256 * 1024);
				uint64 dataFragmentLength = outputBuffer.Size();

				while (!AbortRequested && WriteOffset < EndOffset)
				{
					if (WriteOffset + dataFragmentLength > EndOffset)
						dataFragmentLength = EndOffset - WriteOffset;

					outputBuffer.Zero();
					Options->EA->EncryptSectors (outputBuffer, WriteOffset / SECTOR_SIZE, dataFragmentLength / SECTOR_SIZE, SECTOR_SIZE);
					VolumeFile->Write (outputBuffer, (size_t) dataFragmentLength);

					WriteOffset += dataFragmentLength;
					SizeDone.Set (WriteOffset);
				}
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
			origDeviceOwner.SystemId = -1;

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
					if (finally_arg2.SystemId != -1)
						Core->SetFileOwner (finally_arg, finally_arg2);
				}
			);
#endif

			VolumeFile.reset (new File);
			VolumeFile->Open (options->Path, options->Path.IsDevice() ? File::OpenReadWrite : File::CreateReadWrite, File::ShareNone);
		}

		try
		{
			// Test sector size
			if (options->Path.IsDevice() && VolumeFile->GetDeviceSectorSize() != SECTOR_SIZE)
				throw UnsupportedSectorSize (SRC_POS);

			// Volume Layout
			Layout.reset (new VolumeLayoutV1Normal);

			switch (options->Type)
			{
			case VolumeType::Normal:
				Layout.reset (new VolumeLayoutV1Normal());
				break;

			case VolumeType::Hidden:
				Layout.reset (new VolumeLayoutV1Hidden());
				break;

			default:
				throw ParameterIncorrect (SRC_POS);
			}

			// Volume header
			VolumeHeader header (Layout->GetHeaderSize());
			SecureBuffer headerBuffer (Layout->GetHeaderSize());

			VolumeHeaderCreationOptions headerOptions;
			headerOptions.EA = options->EA;
			headerOptions.Kdf = options->VolumeHeaderKdf;
			headerOptions.Type = options->Type;
			headerOptions.VolumeSize = options->Size;

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
			shared_ptr <VolumePassword> password (Keyfile::ApplyListToPassword (options->Keyfiles, options->Password));
			options->VolumeHeaderKdf->DeriveKey (HeaderKey, *password, salt);
			headerOptions.HeaderKey = HeaderKey;

			header.Create (headerBuffer, headerOptions);

			// Write new header
			if (Layout->GetHeaderOffset() >= 0)
				VolumeFile->SeekAt (Layout->GetHeaderOffset());
			else
				VolumeFile->SeekEnd (Layout->GetHeaderOffset());

			VolumeFile->Write (headerBuffer);

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
