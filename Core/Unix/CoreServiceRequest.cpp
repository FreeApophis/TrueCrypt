/*
 Copyright (c) 2008 TrueCrypt Foundation. All rights reserved.

 Governed by the TrueCrypt License 2.5 the full text of which is contained
 in the file License.txt included in TrueCrypt binary and source code
 distribution packages.
*/

#include <errno.h>
#include "CoreServiceRequest.h"
#include "Platform/SerializerFactory.h"

namespace TrueCrypt
{
	void CoreServiceRequest::Deserialize (shared_ptr <Stream> stream)
	{
		Serializer sr (stream);
		sr.Deserialize ("AdminPassword", AdminPassword);
		ApplicationExecutablePath = sr.DeserializeWString ("ApplicationExecutablePath");
		sr.Deserialize ("ElevateUserPrivileges", ElevateUserPrivileges);
		sr.Deserialize ("FastElevation", FastElevation);
	}

	void CoreServiceRequest::Serialize (shared_ptr <Stream> stream) const
	{
		Serializable::Serialize (stream);
		Serializer sr (stream);
		sr.Serialize ("AdminPassword", AdminPassword);
		sr.Serialize ("ApplicationExecutablePath", wstring (ApplicationExecutablePath));
		sr.Serialize ("ElevateUserPrivileges", ElevateUserPrivileges);
		sr.Serialize ("FastElevation", FastElevation);
	}
	
	// ChangePasswordRequest
	void ChangePasswordRequest::Deserialize (shared_ptr <Stream> stream)
	{
		Serializer sr (stream);
		CoreServiceRequest::Deserialize (stream);

		Keyfiles = Keyfile::DeserializeList (stream, "Keyfiles");
		NewKeyfiles = Keyfile::DeserializeList (stream, "NewKeyfiles");

		if (!sr.DeserializeBool ("NewPasswordNull"))
			NewPassword = Serializable::DeserializeNew <VolumePassword> (stream);
		else
			NewPassword.reset();

		if (!sr.DeserializeBool ("NewPkcs5KdfNull"))
			NewPkcs5Kdf = Pkcs5Kdf::GetAlgorithm (sr.DeserializeWString ("NewPkcs5Kdf"));
		else
			NewPkcs5Kdf.reset();

		if (!sr.DeserializeBool ("PasswordNull"))
			Password = Serializable::DeserializeNew <VolumePassword> (stream);
		else
			Password.reset();

		if (!sr.DeserializeBool ("PathNull"))
			Path.reset (new VolumePath (sr.DeserializeWString ("Path")));
		else
			Path.reset();

		sr.Deserialize ("PreserveTimestamps", PreserveTimestamps);
	}

	bool ChangePasswordRequest::RequiresElevation () const
	{
		if (Core->HasAdminPrivileges())
			return false;
		try
		{
			File file;
			file.Open (*Path);
			return false;
		}
		catch (SystemException &e)
		{
			if (e.GetErrorCode() == EACCES || e.GetErrorCode() == EPERM)
				return true;
			throw;
		}
	}

	void ChangePasswordRequest::Serialize (shared_ptr <Stream> stream) const
	{
		CoreServiceRequest::Serialize (stream);
		Serializer sr (stream);

		Keyfile::SerializeList (stream, "Keyfiles", Keyfiles);
		Keyfile::SerializeList (stream, "NewKeyfiles", NewKeyfiles);

		sr.Serialize ("NewPasswordNull", NewPassword == nullptr);
		if (NewPassword)
			NewPassword->Serialize (stream);

		sr.Serialize ("NewPkcs5KdfNull", NewPkcs5Kdf == nullptr);
		if (NewPkcs5Kdf)
			sr.Serialize ("NewPkcs5Kdf", NewPkcs5Kdf->GetName());

		sr.Serialize ("PasswordNull", Password == nullptr);
		if (Password)
			Password->Serialize (stream);

		sr.Serialize ("PathNull", Path == nullptr);
		if (Path)
			sr.Serialize ("Path", wstring (*Path));

		sr.Serialize ("PreserveTimestamps", PreserveTimestamps);
	}

	// CheckFilesystemRequest
	void CheckFilesystemRequest::Deserialize (shared_ptr <Stream> stream)
	{
		CoreServiceRequest::Deserialize (stream);
		Serializer sr (stream);
		MountedVolumeInfo = Serializable::DeserializeNew <VolumeInfo> (stream);
		sr.Deserialize ("Repair", Repair);
	}

	bool CheckFilesystemRequest::RequiresElevation () const
	{
		return !Core->HasAdminPrivileges();
	}

	void CheckFilesystemRequest::Serialize (shared_ptr <Stream> stream) const
	{
		CoreServiceRequest::Serialize (stream);
		Serializer sr (stream);
		MountedVolumeInfo->Serialize (stream);
		sr.Serialize ("Repair", Repair);
	}

	// DismountVolumeRequest
	void DismountVolumeRequest::Deserialize (shared_ptr <Stream> stream)
	{
		CoreServiceRequest::Deserialize (stream);
		Serializer sr (stream);
		sr.Deserialize ("IgnoreOpenFiles", IgnoreOpenFiles);
		sr.Deserialize ("SyncVolumeInfo", SyncVolumeInfo);
		MountedVolumeInfo = Serializable::DeserializeNew <VolumeInfo> (stream);
	}

	bool DismountVolumeRequest::RequiresElevation () const
	{
#ifdef TC_MACOSX
		return MountedVolumeInfo->Path.IsDevice();
#endif
		return !Core->HasAdminPrivileges();
	}

	void DismountVolumeRequest::Serialize (shared_ptr <Stream> stream) const
	{
		CoreServiceRequest::Serialize (stream);
		Serializer sr (stream);
		sr.Serialize ("IgnoreOpenFiles", IgnoreOpenFiles);
		sr.Serialize ("SyncVolumeInfo", SyncVolumeInfo);
		MountedVolumeInfo->Serialize (stream);
	}
	
	// GetDeviceSizeRequest
	void GetDeviceSizeRequest::Deserialize (shared_ptr <Stream> stream)
	{
		CoreServiceRequest::Deserialize (stream);
		Serializer sr (stream);
		Path = sr.DeserializeWString ("Path");
	}

	bool GetDeviceSizeRequest::RequiresElevation () const
	{
		return !Core->HasAdminPrivileges();
	}

	void GetDeviceSizeRequest::Serialize (shared_ptr <Stream> stream) const
	{
		CoreServiceRequest::Serialize (stream);
		Serializer sr (stream);
		sr.Serialize ("Path", wstring (Path));
	}

	// GetHostDevicesRequest
	void GetHostDevicesRequest::Deserialize (shared_ptr <Stream> stream)
	{
		CoreServiceRequest::Deserialize (stream);
		Serializer sr (stream);
		sr.Deserialize ("PathListOnly", PathListOnly);
	}

	bool GetHostDevicesRequest::RequiresElevation () const
	{
		return !Core->HasAdminPrivileges();
	}

	void GetHostDevicesRequest::Serialize (shared_ptr <Stream> stream) const
	{
		CoreServiceRequest::Serialize (stream);
		Serializer sr (stream);
		sr.Serialize ("PathListOnly", PathListOnly);
	}

	// ExitRequest
	void ExitRequest::Deserialize (shared_ptr <Stream> stream)
	{
		CoreServiceRequest::Deserialize (stream);
	}

	void ExitRequest::Serialize (shared_ptr <Stream> stream) const
	{
		CoreServiceRequest::Serialize (stream);
	}

	// MountVolumeRequest
	void MountVolumeRequest::Deserialize (shared_ptr <Stream> stream)
	{
		CoreServiceRequest::Deserialize (stream);
		Serializer sr (stream);
		DeserializedOptions = Serializable::DeserializeNew <MountOptions> (stream);
		Options = DeserializedOptions.get();
	}

	bool MountVolumeRequest::RequiresElevation () const
	{
#ifdef TC_MACOSX
		return Options->Path->IsDevice();
#endif
		return !Core->HasAdminPrivileges();
	}

	void MountVolumeRequest::Serialize (shared_ptr <Stream> stream) const
	{
		CoreServiceRequest::Serialize (stream);
		Serializer sr (stream);
		Options->Serialize (stream);
	}
	
	// SetFileOwnerRequest
	void SetFileOwnerRequest::Deserialize (shared_ptr <Stream> stream)
	{
		CoreServiceRequest::Deserialize (stream);
		Serializer sr (stream);
		
		uint64 owner;
		sr.Deserialize ("Owner", owner);
		Owner.SystemId = static_cast <uid_t> (owner);

		Path = sr.DeserializeWString ("Path");
	}

	bool SetFileOwnerRequest::RequiresElevation () const
	{
		return !Core->HasAdminPrivileges();
	}

	void SetFileOwnerRequest::Serialize (shared_ptr <Stream> stream) const
	{
		CoreServiceRequest::Serialize (stream);
		Serializer sr (stream);

		uint64 owner = Owner.SystemId;
		sr.Serialize ("Owner", owner);

		sr.Serialize ("Path", wstring (Path));
	}


	TC_SERIALIZER_FACTORY_ADD_CLASS (CoreServiceRequest);
	TC_SERIALIZER_FACTORY_ADD_CLASS (ChangePasswordRequest);
	TC_SERIALIZER_FACTORY_ADD_CLASS (CheckFilesystemRequest);
	TC_SERIALIZER_FACTORY_ADD_CLASS (DismountVolumeRequest);
	TC_SERIALIZER_FACTORY_ADD_CLASS (ExitRequest);
	TC_SERIALIZER_FACTORY_ADD_CLASS (GetDeviceSizeRequest);
	TC_SERIALIZER_FACTORY_ADD_CLASS (GetHostDevicesRequest);
	TC_SERIALIZER_FACTORY_ADD_CLASS (MountVolumeRequest);
	TC_SERIALIZER_FACTORY_ADD_CLASS (SetFileOwnerRequest);
}
