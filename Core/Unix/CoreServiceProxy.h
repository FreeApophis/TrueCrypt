/*
 Copyright (c) 2008 TrueCrypt Foundation. All rights reserved.

 Governed by the TrueCrypt License 2.6 the full text of which is contained
 in the file License.txt included in TrueCrypt binary and source code
 distribution packages.
*/

#ifndef TC_HEADER_Core_Windows_CoreServiceProxy
#define TC_HEADER_Core_Windows_CoreServiceProxy

#include "CoreService.h"
#include "Volume/VolumePasswordCache.h"

namespace TrueCrypt
{
	template <class T>
	class CoreServiceProxy : public T
	{
	public:
		CoreServiceProxy () { }
		virtual ~CoreServiceProxy () { }

		virtual void ChangePassword (shared_ptr <VolumePath> volumePath, bool preserveTimestamps, shared_ptr <VolumePassword> password, shared_ptr <KeyfileList> keyfiles, shared_ptr <VolumePassword> newPassword, shared_ptr <KeyfileList> newKeyfiles, shared_ptr <Pkcs5Kdf> newPkcs5Kdf = shared_ptr <Pkcs5Kdf> ()) const
		{
			CoreService::RequestChangePassword (volumePath, preserveTimestamps, Keyfile::ApplyListToPassword (keyfiles, password), shared_ptr <KeyfileList>(), Keyfile::ApplyListToPassword (newKeyfiles, newPassword), shared_ptr <KeyfileList>(), newPkcs5Kdf);
		}

		virtual void CheckFilesystem (shared_ptr <VolumeInfo> mountedVolume, bool repair) const
		{
			CoreService::RequestCheckFilesystem (mountedVolume, repair);
		}

		virtual void DismountFilesystem (const DirectoryPath &mountPoint, bool force) const
		{
			CoreService::RequestDismountFilesystem (mountPoint, force);
		}

		virtual shared_ptr <VolumeInfo> DismountVolume (shared_ptr <VolumeInfo> mountedVolume, bool ignoreOpenFiles = false, bool syncVolumeInfo = false)
		{
			shared_ptr <VolumeInfo> dismountedVolumeInfo = CoreService::RequestDismountVolume (mountedVolume, ignoreOpenFiles, syncVolumeInfo);

			VolumeEventArgs eventArgs (dismountedVolumeInfo);
			T::VolumeDismountedEvent.Raise (eventArgs);

			return dismountedVolumeInfo;
		}

		virtual uint64 GetDeviceSize (const DevicePath &devicePath) const
		{
			return CoreService::RequestGetDeviceSize (devicePath);
		}

#ifndef TC_LINUX
		virtual HostDeviceList GetHostDevices (bool pathListOnly = false) const
		{
			if (pathListOnly)
				return T::GetHostDevices (pathListOnly);
			else
				return CoreService::RequestGetHostDevices (pathListOnly);
		}
#endif
		virtual bool IsPasswordCacheEmpty () const { return VolumePasswordCache::IsEmpty(); }

		virtual shared_ptr <VolumeInfo> MountVolume (MountOptions &options)
		{
			shared_ptr <VolumeInfo> mountedVolume;
			// Cache password
			if (!VolumePasswordCache::IsEmpty()
				&& (!options.Password || options.Password->IsEmpty())
				&& (!options.Keyfiles || options.Keyfiles->empty()))
			{
				PasswordIncorrect passwordException;
				foreach (shared_ptr <VolumePassword> password, VolumePasswordCache::GetPasswords())
				{
					try
					{
						options.Password = password;
						mountedVolume = CoreService::RequestMountVolume (options);
						break;
					}
					catch (PasswordIncorrect &e)
					{
						passwordException = e;
					}
				}

				if (!mountedVolume)
					passwordException.Throw();
			}
			else
			{
				MountOptions newOptions = options;
				
				newOptions.Password = Keyfile::ApplyListToPassword (options.Keyfiles, options.Password);
				
				if (newOptions.Keyfiles)
					newOptions.Keyfiles->clear();

				mountedVolume = CoreService::RequestMountVolume (newOptions);

				if (options.CachePassword
					&& ((options.Password && !options.Password->IsEmpty()) || (options.Keyfiles && !options.Keyfiles->empty())))
				{
					VolumePasswordCache::Store (*Keyfile::ApplyListToPassword (options.Keyfiles, options.Password));
				}
			}

			VolumeEventArgs eventArgs (mountedVolume);
			T::VolumeMountedEvent.Raise (eventArgs);

			return mountedVolume;
		}

		virtual void SetAdminPasswordCallback (shared_ptr <GetStringFunctor> functor)
		{
			CoreService::SetAdminPasswordCallback (functor);
		}

		virtual void SetFileOwner (const FilesystemPath &path, const UserId &owner) const
		{
			CoreService::RequestSetFileOwner (path, owner);
		}

		virtual void WipePasswordCache () const
		{
			VolumePasswordCache::Clear();
		}
	};
}

#endif // TC_HEADER_Core_Windows_CoreServiceProxy
