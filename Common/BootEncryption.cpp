/*
Copyright (c) 2008 TrueCrypt Foundation. All rights reserved.

Governed by the TrueCrypt License 2.4 the full text of which is contained
in the file License.txt included in TrueCrypt binary and source code
distribution packages.
*/

#include "Tcdefs.h"
#include "Platform/Finally.h"
#include "Platform/ForEach.h"
#include <Setupapi.h>
#include <devguid.h>
#include <io.h>
#include <shlobj.h>
#include <atlbase.h>
#include "BootEncryption.h"
#include "Boot/Windows/BootCommon.h"
#include "Common/Resource.h"
#include "Crc.h"
#include "Crypto.h"
#include "Dlgcode.h"
#include "Endian.h"
#include "Random.h"
#include "Registry.h"
#include "Volumes.h"

#ifdef VOLFORMAT
#include "Format/FormatCom.h"
#elif defined (TCMOUNT)
#include "Mount/MainCom.h"
#endif

namespace TrueCrypt
{
#if !defined (SETUP)

	class Elevator
	{
	public:
		static void CallDriver (DWORD ioctl, void *input, DWORD inputSize, void *output, DWORD outputSize)
		{
			Elevate();

			CComBSTR inputBstr;
			if (input && inputBstr.AppendBytes ((const char *) input, inputSize) != S_OK)
				throw ParameterIncorrect (SRC_POS);

			CComBSTR outputBstr;
			if (output && outputBstr.AppendBytes ((const char *) output, outputSize) != S_OK)
				throw ParameterIncorrect (SRC_POS);

			DWORD result = ElevatedComInstance->CallDriver (ioctl, inputBstr, &outputBstr);
			if (result != ERROR_SUCCESS)
			{
				SetLastError (result);
				throw SystemException();
			}
		}

		static void ReadWriteFile (BOOL write, BOOL device, const string &filePath, byte *buffer, uint64 offset, uint32 size, DWORD *sizeDone)
		{
			Elevate();

			CComBSTR bufferBstr;
			if (bufferBstr.AppendBytes ((const char *) buffer, size) != S_OK)
				throw ParameterIncorrect (SRC_POS);
			DWORD result = ElevatedComInstance->ReadWriteFile (write, device, CComBSTR (filePath.c_str()), &bufferBstr, offset, size, sizeDone);

			if (result != ERROR_SUCCESS)
			{
				SetLastError (result);
				throw SystemException();
			}

			if (!write)
				memcpy (buffer, (BYTE *) bufferBstr.m_str, size);
		}

		static void RegisterFilterDriver (bool registerDriver)
		{
			Elevate();

			DWORD result = ElevatedComInstance->RegisterFilterDriver (registerDriver ? TRUE : FALSE);
			if (result != ERROR_SUCCESS)
			{
				SetLastError (result);
				throw SystemException();
			}
		}

		static void Release ()
		{
			if (ElevatedComInstance)
			{
				ElevatedComInstance->Release();
				ElevatedComInstance = nullptr;
				CoUninitialize ();
			}
		}

		static void SetDriverServiceStartType (DWORD startType)
		{
			Elevate();

			DWORD result = ElevatedComInstance->SetDriverServiceStartType (startType);
			if (result != ERROR_SUCCESS)
			{
				SetLastError (result);
				throw SystemException();
			}
		}

	protected:
		static void Elevate ()
		{
			if (IsAdmin())
			{
				SetLastError (ERROR_ACCESS_DENIED);
				throw SystemException();
			}

			if (!ElevatedComInstance)
			{
				CoInitialize (NULL);
				ElevatedComInstance = GetElevatedInstance (GetActiveWindow() ? GetActiveWindow() : MainDlg);
			}
		}
		
#if defined (TCMOUNT)
		static ITrueCryptMainCom *ElevatedComInstance;
#elif defined (VOLFORMAT)
		static ITrueCryptFormatCom *ElevatedComInstance;
#endif
	};

#if defined (TCMOUNT)
	ITrueCryptMainCom *Elevator::ElevatedComInstance;
#elif defined (VOLFORMAT)
	ITrueCryptFormatCom *Elevator::ElevatedComInstance;
#endif

#else // SETUP
	
	class Elevator
	{
	public:
		static void CallDriver (DWORD ioctl, void *input, DWORD inputSize, void *output, DWORD outputSize) { throw ParameterIncorrect (SRC_POS); }
		static void ReadWriteFile (BOOL write, BOOL device, const string &filePath, byte *buffer, uint64 offset, uint32 size, DWORD *sizeDone) { throw ParameterIncorrect (SRC_POS); }
		static void RegisterFilterDriver (bool registerDriver) { throw ParameterIncorrect (SRC_POS); }
		static void Release () { }
		static void SetDriverServiceStartType (DWORD startType) { throw ParameterIncorrect (SRC_POS); }
	};

#endif // SETUP


	File::File (string path, bool readOnly, bool create) : Elevated (false), FileOpen (false)
	{
		Handle = CreateFile (path.c_str(),
			readOnly ? FILE_READ_DATA : FILE_READ_DATA | FILE_WRITE_DATA,
			FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, create ? CREATE_ALWAYS : OPEN_EXISTING,
			FILE_FLAG_RANDOM_ACCESS | FILE_FLAG_WRITE_THROUGH, NULL);

		try
		{
			throw_sys_if (Handle == INVALID_HANDLE_VALUE);
		}
		catch (SystemException &)
		{
			if (GetLastError() == ERROR_ACCESS_DENIED && IsUacSupported())
				Elevated = true;
			else
				throw;
		}

		FileOpen = true;
		FilePointerPosition = 0;
		IsDevice = false;
		Path = path;
	}

	void File::Close ()
	{
		if (FileOpen)
		{
			if (!Elevated)
				CloseHandle (Handle);

			FileOpen = false;
		}
	}

	DWORD File::Read (byte *buffer, DWORD size)
	{
		DWORD bytesRead;

		if (Elevated)
		{
			DWORD bytesRead;

			Elevator::ReadWriteFile (false, IsDevice, Path, buffer, FilePointerPosition, size, &bytesRead);
			FilePointerPosition += bytesRead;
			return bytesRead;
		}

		throw_sys_if (!ReadFile (Handle, buffer, size, &bytesRead, NULL));
		return bytesRead;
	}

	void File::SeekAt (int64 position)
	{
		if (Elevated)
		{
			FilePointerPosition = position;
		}
		else
		{
			LARGE_INTEGER pos;
			pos.QuadPart = position;
			throw_sys_if (!SetFilePointerEx (Handle, pos, NULL, FILE_BEGIN));
		}
	}

	void File::Write (byte *buffer, DWORD size)
	{
		DWORD bytesWritten;
		
		if (Elevated)
		{
			Elevator::ReadWriteFile (true, IsDevice, Path, buffer, FilePointerPosition, size, &bytesWritten);
			FilePointerPosition += bytesWritten;
			throw_sys_if (bytesWritten != size);
		}
		else
		{
			throw_sys_if (!WriteFile (Handle, buffer, size, &bytesWritten, NULL) || bytesWritten != size);
		}
	}

	void Show (HWND parent, const string &str)
	{
		MessageBox (parent, str.c_str(), NULL, 0);
	}


	Device::Device (string path, bool readOnly)
	{
		 FileOpen = false;
		 Elevated = false;

		Handle = CreateFile ((string ("\\\\.\\") + path).c_str(),
			readOnly ? FILE_READ_DATA : FILE_READ_DATA | FILE_WRITE_DATA,
			FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING,
			FILE_FLAG_RANDOM_ACCESS | FILE_FLAG_WRITE_THROUGH, NULL);

		try
		{
			throw_sys_if (Handle == INVALID_HANDLE_VALUE);
		}
		catch (SystemException &)
		{
			if (GetLastError() == ERROR_ACCESS_DENIED && IsUacSupported())
				Elevated = true;
			else
				throw;
		}

		FileOpen = true;
		FilePointerPosition = 0;
		IsDevice = true;
		Path = path;
	}


	BootEncryption::~BootEncryption ()
	{
		if (RescueIsoImage)
			delete RescueIsoImage;

		Elevator::Release();
	}


	void BootEncryption::CallDriver (DWORD ioctl, void *input, DWORD inputSize, void *output, DWORD outputSize)
	{
		try
		{
			DWORD bytesReturned;
			throw_sys_if (!DeviceIoControl (hDriver, ioctl, input, inputSize, output, outputSize, &bytesReturned, NULL));
		}
		catch (SystemException &)
		{
			if (GetLastError() == ERROR_ACCESS_DENIED && IsUacSupported())
				Elevator::CallDriver (ioctl, input, inputSize, output, outputSize);
			else
				throw;
		}
	}


	DWORD BootEncryption::GetDriverServiceStartType ()
	{
		DWORD startType;
		throw_sys_if (!ReadLocalMachineRegistryDword ("SYSTEM\\CurrentControlSet\\Services\\truecrypt", "Start", &startType));
		return startType;
	}


	void BootEncryption::SetDriverServiceStartType (DWORD startType)
	{
		if (!IsAdmin() && IsUacSupported())
		{
			Elevator::SetDriverServiceStartType (startType);
			return;
		}

		BOOL startOnBoot = (startType == SERVICE_BOOT_START);

		SC_HANDLE serviceManager = OpenSCManager (NULL, NULL, SC_MANAGER_ALL_ACCESS);
		throw_sys_if (!serviceManager);

		finally_do_arg (SC_HANDLE, serviceManager, { CloseServiceHandle (finally_arg); });

		SC_HANDLE service = OpenService (serviceManager, "truecrypt", SERVICE_CHANGE_CONFIG);
		throw_sys_if (!service);

		finally_do_arg (SC_HANDLE, service, { CloseServiceHandle (finally_arg); });

		throw_sys_if (!ChangeServiceConfig (service, SERVICE_NO_CHANGE, SERVICE_NO_CHANGE,
			startOnBoot ? SERVICE_ERROR_SEVERE : SERVICE_ERROR_NORMAL, NULL,
			startOnBoot ? "Filter" : NULL,
			NULL, NULL, NULL, NULL, NULL));

		// ChangeServiceConfig() rejects SERVICE_BOOT_START with ERROR_INVALID_PARAMETER
		throw_sys_if (!WriteLocalMachineRegistryDword ("SYSTEM\\CurrentControlSet\\Services\\truecrypt", "Start", startType));
	}


	void BootEncryption::ProbeRealSystemDriveSize ()
	{
		if (RealSystemDriveSizeValid)
			return;

		GetSystemDriveConfiguration();

		ProbeRealDriveSizeRequest request;
		_snwprintf (request.DeviceName, array_capacity (request.DeviceName), L"%hs", DriveConfig.DrivePartition.DevicePath.c_str());
		
		CallDriver (TC_IOCTL_PROBE_REAL_DRIVE_SIZE, &request, sizeof (request), &request, sizeof (request));
		DriveConfig.DrivePartition.Info.PartitionLength = request.RealDriveSize;

		RealSystemDriveSizeValid = TRUE;

		if (request.TimeOut)
			throw TimeOut (SRC_POS);
	}


	PartitionList BootEncryption::GetDrivePartitions (int driveNumber)
	{
		PartitionList partList;

		for (int partNumber = 0; partNumber < 64; ++partNumber)
		{
			stringstream partPath;
			partPath << "\\Device\\Harddisk" << driveNumber << "\\Partition" << partNumber;

			DISK_PARTITION_INFO_STRUCT diskPartInfo;
			_snwprintf (diskPartInfo.deviceName, array_capacity (diskPartInfo.deviceName), L"%hs", partPath.str().c_str());

			try
			{
				CallDriver (TC_IOCTL_GET_DRIVE_PARTITION_INFO, &diskPartInfo, sizeof (diskPartInfo), &diskPartInfo, sizeof (diskPartInfo));
			}
			catch (...)
			{
				continue;
			}

			Partition part;
			part.DevicePath = partPath.str();
			part.Number = partNumber;
			part.Info = diskPartInfo.partInfo;
			part.IsGPT = diskPartInfo.IsGPT;

			// Mount point
			wstringstream ws;
			ws << partPath.str().c_str();
			int driveNumber = GetDiskDeviceDriveLetter ((wchar_t *) ws.str().c_str());

			if (driveNumber >= 0)
			{
				part.MountPoint += (char) (driveNumber + 'A');
				part.MountPoint += ":";
			}
			partList.push_back (part);
		}

		return partList;
	}
	

	DISK_GEOMETRY BootEncryption::GetDriveGeometry (int driveNumber)
	{
		stringstream devName;
		devName << "\\Device\\Harddisk" << driveNumber << "\\Partition0";

		DISK_GEOMETRY geometry;
		throw_sys_if (!::GetDriveGeometry ((char *) devName.str().c_str(), &geometry));
		return geometry;
	}

	
	string BootEncryption::GetWindowsDirectory ()
	{
		char buf[MAX_PATH];
		if (GetSystemDirectory (buf, sizeof (buf)) > 0)
			return string (buf);

		return string();
	}
	

	uint16 BootEncryption::GetInstalledBootLoaderVersion ()
	{
		uint16 version;
		CallDriver (TC_IOCTL_GET_BOOT_LOADER_VERSION, NULL, 0, &version, sizeof (version));
		return version;
	}


	// Note that this does not require admin rights (it just requires the driver to be running)
	bool BootEncryption::IsBootLoaderOnDrive (char *devicePath)
	{
		try 
		{
			OPEN_TEST_STRUCT openTestStruct;
			DWORD dwResult;

			strcpy ((char *) &openTestStruct.wszFileName[0], devicePath);
			ToUNICODE ((char *) &openTestStruct.wszFileName[0]);

			openTestStruct.bDetectTCBootLoader = TRUE;

			return (DeviceIoControl (hDriver, TC_IOCTL_OPEN_TEST,
				   &openTestStruct, sizeof (OPEN_TEST_STRUCT),
				   NULL, 0,
				   &dwResult, NULL) == TRUE);
		}
		catch (...)
		{
			return false;
		}
	}


	BootEncryptionStatus BootEncryption::GetStatus ()
	{
		/* IMPORTANT: Do NOT add any potentially time-consuming operations to this function. */

		BootEncryptionStatus status;
		CallDriver (TC_IOCTL_GET_BOOT_ENCRYPTION_STATUS, NULL, 0, &status, sizeof (status));
		return status;
	}


	void BootEncryption::GetVolumeProperties (VOLUME_PROPERTIES_STRUCT *properties)
	{
		if (properties == NULL)
			throw ParameterIncorrect (SRC_POS);

		CallDriver (TC_IOCTL_GET_BOOT_DRIVE_VOLUME_PROPERTIES, NULL, 0, properties, sizeof (*properties));
	}


	bool BootEncryption::SystemDriveContainsPartitionType (byte type)
	{
		Device device (GetSystemDriveConfiguration().DevicePath, true);

		byte mbrBuf[SECTOR_SIZE];
		device.SeekAt (0);
		device.Read (mbrBuf, sizeof (mbrBuf));

		MBR *mbr = reinterpret_cast <MBR *> (mbrBuf);
		if (mbr->Signature != 0xaa55)
			throw ParameterIncorrect (SRC_POS);

		for (size_t i = 0; i < array_capacity (mbr->Partitions); ++i)
		{
			if (mbr->Partitions[i].Type == type)
				return true;
		}

		return false;
	}


	bool BootEncryption::SystemDriveContainsExtendedPartition ()
	{
		return SystemDriveContainsPartitionType (PARTITION_EXTENDED) || SystemDriveContainsPartitionType (PARTITION_XINT13_EXTENDED);
	}


	bool BootEncryption::SystemDriveIsDynamic ()
	{
		return SystemDriveContainsPartitionType (PARTITION_LDM);
	}


	SystemDriveConfiguration BootEncryption::GetSystemDriveConfiguration ()
	{
		if (DriveConfigValid)
			return DriveConfig;

		SystemDriveConfiguration config;

		string winDir = GetWindowsDirectory();

		// Scan all drives
		for (int driveNumber = 0; driveNumber < 32; ++driveNumber)
		{
			bool windowsFound = false;
			config.SystemLoaderPresent = false;

			PartitionList partitions = GetDrivePartitions (driveNumber);
			foreach (const Partition &part, partitions)
			{
				if (_access ((part.MountPoint + "\\bootmgr").c_str(), 0) == 0 || _access ((part.MountPoint + "\\ntldr").c_str(), 0) == 0)
					config.SystemLoaderPresent = true;

				if (!windowsFound && !part.MountPoint.empty() && winDir.find (part.MountPoint) == 0)
				{
					config.SystemPartition = part;
					windowsFound = true;
				}
			}

			if (windowsFound)
			{
				config.DriveNumber = driveNumber;

				stringstream ss;
				ss << "PhysicalDrive" << driveNumber;
				config.DevicePath = ss.str();

				config.DrivePartition = partitions.front();
				partitions.pop_front();
				config.Partitions = partitions;

				config.InitialUnallocatedSpace = 0x7fffFFFFffffFFFFull;
				config.TotalUnallocatedSpace = config.DrivePartition.Info.PartitionLength.QuadPart;

				foreach (const Partition &part, config.Partitions)
				{
					if (part.Info.StartingOffset.QuadPart < config.InitialUnallocatedSpace)
						config.InitialUnallocatedSpace = part.Info.StartingOffset.QuadPart;

					config.TotalUnallocatedSpace -= part.Info.PartitionLength.QuadPart;
				}

				DriveConfig = config;
				DriveConfigValid = TRUE;
				return DriveConfig;
			}
		}

		throw ParameterIncorrect (SRC_POS);
	}


	bool BootEncryption::SystemPartitionCoversWholeDrive ()
	{
		SystemDriveConfiguration config = GetSystemDriveConfiguration();

		return config.Partitions.size() == 1
			&& config.DrivePartition.Info.PartitionLength.QuadPart - config.SystemPartition.Info.PartitionLength.QuadPart < 64 * BYTES_PER_MB;
	}


	uint32 BootEncryption::GetChecksum (byte *data, size_t size)
	{
		uint32 sum = 0;

		while (size-- > 0)
		{
			sum += *data++;
			sum = _rotl (sum, 1);
		}

		return sum;
	}


	void BootEncryption::GetBootLoader (byte *buffer, size_t bufferSize, bool rescueDisk)
	{
		if (bufferSize < TC_BOOT_LOADER_AREA_SIZE - HEADER_SIZE)
			throw ParameterIncorrect (SRC_POS);

		ZeroMemory (buffer, bufferSize);

		int ea = 0;
		if (GetStatus().DriveMounted)
		{
			try
			{
				GetBootEncryptionAlgorithmNameRequest request;
				CallDriver (TC_IOCTL_GET_BOOT_ENCRYPTION_ALGORITHM_NAME, NULL, 0, &request, sizeof (request));

				if (_stricmp (request.BootEncryptionAlgorithmName, "AES") == 0)
					ea = AES;
				else if (_stricmp (request.BootEncryptionAlgorithmName, "Serpent") == 0)
					ea = SERPENT;
				else if (_stricmp (request.BootEncryptionAlgorithmName, "Twofish") == 0)
					ea = TWOFISH;
			}
			catch (...)
			{
				try
				{
					VOLUME_PROPERTIES_STRUCT properties;
					GetVolumeProperties (&properties);
					ea = properties.ea;
				}
				catch (...) { }
			}
		}
		else
		{
			if (SelectedEncryptionAlgorithmId == 0)
				throw ParameterIncorrect (SRC_POS);

			ea = SelectedEncryptionAlgorithmId;
		}

		int bootSectorId = IDR_BOOT_SECTOR;
		int bootLoaderId = IDR_BOOT_LOADER;

		switch (ea)
		{
		case AES:
			bootSectorId = IDR_BOOT_SECTOR_AES;
			bootLoaderId = IDR_BOOT_LOADER_AES;
			break;

		case SERPENT:
			bootSectorId = IDR_BOOT_SECTOR_SERPENT;
			bootLoaderId = IDR_BOOT_LOADER_SERPENT;
			break;

		case TWOFISH:
			bootSectorId = IDR_BOOT_SECTOR_TWOFISH;
			bootLoaderId = IDR_BOOT_LOADER_TWOFISH;
			break;
		}

		// Boot sector
		DWORD size;
		byte *bootSecResourceImg = MapResource ("BIN", bootSectorId, &size);
		if (!bootSecResourceImg || size != SECTOR_SIZE)
			throw ParameterIncorrect (SRC_POS);

		memcpy (buffer, bootSecResourceImg, size);

		if (rescueDisk)
			buffer[TC_BOOT_SECTOR_CONFIG_OFFSET] |= TC_BOOT_CFG_FLAG_RESCUE_DISK;
		
		if (nCurrentOS == WIN_VISTA_OR_LATER)
			buffer[TC_BOOT_SECTOR_CONFIG_OFFSET] |= TC_BOOT_CFG_FLAG_WINDOWS_VISTA_OR_LATER;

		// Decompressor
		byte *decompressor = MapResource ("BIN", IDR_BOOT_LOADER_DECOMPRESSOR, &size);
		if (!decompressor || size > TC_BOOT_LOADER_DECOMPRESSOR_SECTOR_COUNT * SECTOR_SIZE)
			throw ParameterIncorrect (SRC_POS);

		memcpy (buffer + SECTOR_SIZE, decompressor, size);

		// Compressed boot loader
		byte *bootLoader = MapResource ("BIN", bootLoaderId, &size);
		if (!bootLoader || size > TC_MAX_BOOT_LOADER_SECTOR_COUNT * SECTOR_SIZE)
			throw ParameterIncorrect (SRC_POS);

		memcpy (buffer + SECTOR_SIZE + TC_BOOT_LOADER_DECOMPRESSOR_SECTOR_COUNT * SECTOR_SIZE, bootLoader, size);

		// Boot loader and decompressor checksum
		*(uint16 *) (buffer + TC_BOOT_SECTOR_LOADER_LENGTH_OFFSET) = static_cast <uint16> (size);
		*(uint32 *) (buffer + TC_BOOT_SECTOR_LOADER_CHECKSUM_OFFSET) = GetChecksum (buffer + SECTOR_SIZE,
			TC_BOOT_LOADER_DECOMPRESSOR_SECTOR_COUNT * SECTOR_SIZE + size);

		// Backup of decompressor and boot loader
		if (size + TC_BOOT_LOADER_DECOMPRESSOR_SECTOR_COUNT * SECTOR_SIZE <= TC_BOOT_LOADER_BACKUP_SECTOR_COUNT * SECTOR_SIZE)
		{
			memcpy (buffer + SECTOR_SIZE + TC_BOOT_LOADER_BACKUP_SECTOR_COUNT * SECTOR_SIZE,
				buffer + SECTOR_SIZE, TC_BOOT_LOADER_BACKUP_SECTOR_COUNT * SECTOR_SIZE);

			buffer[TC_BOOT_SECTOR_CONFIG_OFFSET] |= TC_BOOT_CFG_FLAG_BACKUP_LOADER_AVAILABLE;
		}
		else if (bootLoaderId != IDR_BOOT_LOADER)
		{
			throw ParameterIncorrect (SRC_POS);
		}
	}


	void BootEncryption::InstallBootLoader ()
	{
		byte bootLoaderBuf[TC_BOOT_LOADER_AREA_SIZE - HEADER_SIZE];
		GetBootLoader (bootLoaderBuf, sizeof (bootLoaderBuf), false);

		// Write MBR
		Device device (GetSystemDriveConfiguration().DevicePath);
		byte mbr[SECTOR_SIZE];

		device.SeekAt (0);
		device.Read (mbr, sizeof (mbr));

		memcpy (mbr, bootLoaderBuf, TC_MAX_MBR_BOOT_CODE_SIZE);

		device.SeekAt (0);
		device.Write (mbr, sizeof (mbr));

		byte mbrVerificationBuf[SECTOR_SIZE];
		device.SeekAt (0);
		device.Read (mbrVerificationBuf, sizeof (mbr));

		if (memcmp (mbr, mbrVerificationBuf, sizeof (mbr)) != 0)
			throw ErrorException ("ERROR_MBR_PROTECTED");

		// Write boot loader
		device.SeekAt (SECTOR_SIZE);
		device.Write (bootLoaderBuf + SECTOR_SIZE, sizeof (bootLoaderBuf) - SECTOR_SIZE);
	}


	string BootEncryption::GetSystemLoaderBackupPath ()
	{
		char pathBuf[MAX_PATH];

		throw_sys_if (!SUCCEEDED (SHGetFolderPath (NULL, CSIDL_COMMON_APPDATA | CSIDL_FLAG_CREATE, NULL, 0, pathBuf)));
		
		string path = string (pathBuf) + "\\" TC_APP_NAME;
		CreateDirectory (path.c_str(), NULL);

		return path + '\\' + TC_SYS_BOOT_LOADER_BACKUP_NAME;
	}


#ifndef SETUP
	void BootEncryption::CreateRescueIsoImage (bool initialSetup, const string &isoImagePath)
	{
		BootEncryptionStatus encStatus = GetStatus();
		if (encStatus.SetupInProgress)
			throw ParameterIncorrect (SRC_POS);

		Buffer imageBuf (RescueIsoImageSize);
		
		byte *image = imageBuf.Ptr();
		memset (image, 0, RescueIsoImageSize);

		// Primary volume descriptor
		strcpy ((char *)image + 0x8000, "\001CD001\001");
		strcpy ((char *)image + 0x7fff + 41, "TrueCrypt Rescue Disk           ");
		*(uint32 *) (image + 0x7fff + 81) = RescueIsoImageSize / 2048;
		*(uint32 *) (image + 0x7fff + 85) = BE32 (RescueIsoImageSize / 2048);
		image[0x7fff + 121] = 1;
		image[0x7fff + 124] = 1;
		image[0x7fff + 125] = 1;
		image[0x7fff + 128] = 1;
		image[0x7fff + 130] = 8;
		image[0x7fff + 131] = 8;

		image[0x7fff + 133] = 10;
		image[0x7fff + 140] = 10;
		image[0x7fff + 141] = 0x14;
		image[0x7fff + 157] = 0x22;
		image[0x7fff + 159] = 0x18;

		// Boot record volume descriptor
		strcpy ((char *)image + 0x8801, "CD001\001EL TORITO SPECIFICATION");
		image[0x8800 + 0x47] = 0x19;

		// Volume descriptor set terminator
		strcpy ((char *)image + 0x9000, "\377CD001\001");

		// Path table
		image[0xA000 + 0] = 1;
		image[0xA000 + 2] = 0x18;
		image[0xA000 + 6] = 1;

		// Root directory
		image[0xc000 + 0] = 0x22;
		image[0xc000 + 2] = 0x18;
		image[0xc000 + 9] = 0x18;
		image[0xc000 + 11] = 0x08;
		image[0xc000 + 16] = 0x08;
		image[0xc000 + 25] = 0x02;
		image[0xc000 + 28] = 0x01;
		image[0xc000 + 31] = 0x01;
		image[0xc000 + 32] = 0x01;
		image[0xc000 + 34] = 0x22;
		image[0xc000 + 36] = 0x18;
		image[0xc000 + 43] = 0x18;
		image[0xc000 + 45] = 0x08;
		image[0xc000 + 50] = 0x08;
		image[0xc000 + 59] = 0x02;
		image[0xc000 + 62] = 0x01;
		*(uint32 *) (image + 0xc000 + 65) = 0x010101;

		// Validation entry
		image[0xc800] = 1;
		int offset = 0xc800 + 0x1c;
		image[offset++] = 0xaa;
		image[offset++] = 0x55;
		image[offset++] = 0x55;
		image[offset] = 0xaa;

		// Initial entry
		offset = 0xc820;
		image[offset++] = 0x88;
		image[offset++] = 2;
		image[0xc820 + 6] = 1;
		image[0xc820 + 8] = TC_CD_BOOT_LOADER_SECTOR;

		// TrueCrypt Boot Loader
		GetBootLoader (image + TC_CD_BOOTSECTOR_OFFSET, TC_BOOT_LOADER_AREA_SIZE, true);

		// Volume header
		if (initialSetup)
		{
			if (!RescueVolumeHeaderValid)
				throw ParameterIncorrect (SRC_POS);

			memcpy (image + TC_CD_BOOTSECTOR_OFFSET + TC_BOOT_VOLUME_HEADER_SECTOR_OFFSET, RescueVolumeHeader, HEADER_SIZE);
		}
		else
		{
			Device bootDevice (GetSystemDriveConfiguration().DevicePath, true);
			bootDevice.SeekAt (TC_BOOT_VOLUME_HEADER_SECTOR_OFFSET);
			bootDevice.Read (image + TC_CD_BOOTSECTOR_OFFSET + TC_BOOT_VOLUME_HEADER_SECTOR_OFFSET, HEADER_SIZE);
		}

		// Original system loader
		try
		{
			File sysBakFile (GetSystemLoaderBackupPath(), true);
			sysBakFile.Read (image + TC_CD_BOOTSECTOR_OFFSET + TC_ORIG_BOOT_LOADER_BACKUP_SECTOR_OFFSET, TC_BOOT_LOADER_AREA_SIZE);
			
			image[TC_CD_BOOTSECTOR_OFFSET + TC_BOOT_SECTOR_CONFIG_OFFSET] |= TC_BOOT_CFG_FLAG_RESCUE_DISK_ORIG_SYS_LOADER;
		}
		catch (Exception &e)
		{
			e.Show (ParentWindow);
			Warning ("SYS_LOADER_UNAVAILABLE_FOR_RESCUE_DISK");
		}
		
		RescueIsoImage = new byte[RescueIsoImageSize];
		if (!RescueIsoImage)
			throw bad_alloc();
		memcpy (RescueIsoImage, image, RescueIsoImageSize);

		if (!isoImagePath.empty())
		{
			File isoFile (isoImagePath, false, true);
			isoFile.Write (image, RescueIsoImageSize);
		}
	}
#endif

	bool BootEncryption::VerifyRescueDisk ()
	{
		if (!RescueIsoImage)
			throw ParameterIncorrect (SRC_POS);

		for (char drive = 'Z'; drive >= 'D'; --drive)
		{
			try
			{
				string path = "X:";
				path[0] = drive;

				Device driveDevice (path, true);
				size_t verifiedSectorCount = (TC_CD_BOOTSECTOR_OFFSET + TC_ORIG_BOOT_LOADER_BACKUP_SECTOR_OFFSET + TC_BOOT_LOADER_AREA_SIZE) / 2048;
				Buffer buffer ((verifiedSectorCount + 1) * 2048);

				DWORD bytesRead = driveDevice.Read (buffer.Ptr(), buffer.Size());
				if (bytesRead != buffer.Size())
					continue;

				if (memcmp (buffer.Ptr(), RescueIsoImage, buffer.Size()) == 0)
					return true;
			}
			catch (...) { }
		}

		return false;
	}


#ifndef SETUP

	void BootEncryption::CreateVolumeHeader (uint64 volumeSize, uint64 encryptedAreaStart, Password *password, int ea, int mode, int pkcs5)
	{
		PCRYPTO_INFO cryptoInfo = NULL;
		
		throw_sys_if (Randinit () != 0);
		throw_sys_if (VolumeWriteHeader (TRUE, (char *) VolumeHeader, ea, mode, password, pkcs5, NULL, 0, &cryptoInfo,
			volumeSize, 0, encryptedAreaStart, 0, FALSE) != 0);

		finally_do_arg (PCRYPTO_INFO*, &cryptoInfo, { crypto_close (*finally_arg); });

		// Initial rescue disk assumes encryption of the drive has been completed (EncryptedAreaLength == volumeSize)
		memcpy (RescueVolumeHeader, VolumeHeader, sizeof (RescueVolumeHeader));
		VolumeReadHeader (TRUE, (char *) RescueVolumeHeader, password, NULL, cryptoInfo);

		DecryptBuffer (RescueVolumeHeader + HEADER_ENCRYPTED_DATA_OFFSET, HEADER_ENCRYPTED_DATA_SIZE, cryptoInfo);

		if (GetHeaderField32 (RescueVolumeHeader, TC_HEADER_OFFSET_MAGIC) != 0x54525545)
			throw ParameterIncorrect (SRC_POS);

		byte *fieldPos = RescueVolumeHeader + TC_HEADER_OFFSET_ENCRYPTED_AREA_LENGTH;
		mputInt64 (fieldPos, volumeSize);
		
		EncryptBuffer (RescueVolumeHeader + HEADER_ENCRYPTED_DATA_OFFSET, HEADER_ENCRYPTED_DATA_SIZE, cryptoInfo);

		VolumeHeaderValid = true;
		RescueVolumeHeaderValid = true;
	}


	void BootEncryption::InstallVolumeHeader ()
	{
		if (!VolumeHeaderValid)
			throw ParameterIncorrect (SRC_POS);

		Device device (GetSystemDriveConfiguration().DevicePath);

		device.SeekAt (TC_BOOT_VOLUME_HEADER_SECTOR_OFFSET);
		device.Write ((byte *) VolumeHeader, sizeof (VolumeHeader));
	}


	// For synchronous operations use AbortSetupWait()
	void BootEncryption::AbortSetup ()
	{
		CallDriver (TC_IOCTL_ABORT_BOOT_ENCRYPTION_SETUP);
	}


	// For asynchronous operations use AbortSetup()
	void BootEncryption::AbortSetupWait ()
	{
		CallDriver (TC_IOCTL_ABORT_BOOT_ENCRYPTION_SETUP);

		BootEncryptionStatus encStatus = GetStatus();

		while (encStatus.SetupInProgress)
		{
			Sleep (TC_ABORT_TRANSFORM_WAIT_INTERVAL);
			encStatus = GetStatus();
		}
	}


	void BootEncryption::BackupSystemLoader ()
	{
		Device device (GetSystemDriveConfiguration().DevicePath, true);
	
		byte bootLoaderBuf[TC_BOOT_LOADER_AREA_SECTOR_COUNT * SECTOR_SIZE];

		device.SeekAt (0);
		device.Read (bootLoaderBuf, sizeof (bootLoaderBuf));

		// Prevent TrueCrypt loader from being backed up
		for (size_t i = 0; i < sizeof (bootLoaderBuf) - strlen (TC_APP_NAME); ++i)
		{
			if (memcmp (bootLoaderBuf + i, TC_APP_NAME, strlen (TC_APP_NAME)) == 0)
			{
				if (AskWarnNoYes ("TC_BOOT_LOADER_ALREADY_INSTALLED") == IDNO)
					throw UserAbort (SRC_POS);
				return;
			}
		}

		File backupFile (GetSystemLoaderBackupPath(), false, true);
		backupFile.Write (bootLoaderBuf, sizeof (bootLoaderBuf));
	}


	void BootEncryption::RestoreSystemLoader ()
	{
		byte bootLoaderBuf[TC_BOOT_LOADER_AREA_SECTOR_COUNT * SECTOR_SIZE];

		File backupFile (GetSystemLoaderBackupPath(), true);
		
		if (backupFile.Read (bootLoaderBuf, sizeof (bootLoaderBuf)) != sizeof (bootLoaderBuf))
			throw ParameterIncorrect (SRC_POS);

		Device device (GetSystemDriveConfiguration().DevicePath);

		// Preserve current partition table
		byte mbr[SECTOR_SIZE];
		device.SeekAt (0);
		device.Read (mbr, sizeof (mbr));
		memcpy (bootLoaderBuf + TC_MAX_MBR_BOOT_CODE_SIZE, mbr + TC_MAX_MBR_BOOT_CODE_SIZE, sizeof (mbr) - TC_MAX_MBR_BOOT_CODE_SIZE);

		device.SeekAt (0);
		device.Write (bootLoaderBuf, sizeof (bootLoaderBuf));
	}

#endif // SETUP

	void BootEncryption::RegisterFilterDriver (bool registerDriver)
	{
		if (!IsAdmin() && IsUacSupported())
		{
			Elevator::RegisterFilterDriver (registerDriver);
			return;
		}

		HKEY classRegKey = SetupDiOpenClassRegKey (&GUID_DEVCLASS_DISKDRIVE, KEY_READ | KEY_WRITE);
		throw_sys_if (classRegKey == INVALID_HANDLE_VALUE);
		finally_do_arg (HKEY, classRegKey, { RegCloseKey (finally_arg); });

		if (registerDriver && nCurrentOS == WIN_VISTA_OR_LATER)
		{
			// Attaching to the device stack after PartMgr on Vista causes all write IRPs sent to the lower device object to fail
			// with STATUS_ACCESS_DENIED. Therefore, our filter is placed in front of others already registered.
			size_t strSize = strlen ("truecrypt") + 1;
			byte regKeyBuf[65536];
			DWORD size = sizeof (regKeyBuf) - strSize;

			// SetupInstallFromInfSection() does not support prepending of values so we have to modify the registry directly
			strncpy ((char *) regKeyBuf, "truecrypt", sizeof (regKeyBuf));

			if (RegQueryValueEx (classRegKey, "UpperFilters", NULL, NULL, regKeyBuf + strSize, &size) != ERROR_SUCCESS)
				size = 1;

			throw_sys_if (RegSetValueEx (classRegKey, "UpperFilters", 0, REG_MULTI_SZ, regKeyBuf, strSize + size) != ERROR_SUCCESS);
		}
		else
		{
			char tempPath[MAX_PATH];
			GetTempPath (sizeof (tempPath), tempPath);
			string infFileName = string (tempPath) + "\\truecrypt_filter.inf";

			finally_do_arg (string, infFileName, { DeleteFile (finally_arg.c_str()); });
			File infFile (infFileName, false, true);

			string infTxt = "[truecrypt]\r\n" + string (registerDriver ? "Add" : "Del") + "Reg=truecrypt_reg\r\n\r\n"
				"[truecrypt_reg]\r\nHKR,,\"UpperFilters\",0x0001" + string (registerDriver ? "0008" : "8002") + ",\"truecrypt\"\r\n";

			infFile.Write ((byte *) infTxt.c_str(), infTxt.size());
			infFile.Close();

			HINF hInf = SetupOpenInfFile (infFileName.c_str(), NULL, INF_STYLE_OLDNT | INF_STYLE_WIN4, NULL);
			throw_sys_if (hInf == INVALID_HANDLE_VALUE);
			finally_do_arg (HINF, hInf, { SetupCloseInfFile (finally_arg); });

			throw_sys_if (!SetupInstallFromInfSection (ParentWindow, hInf, "truecrypt", SPINST_REGISTRY, classRegKey, NULL, 0, NULL, NULL, NULL, NULL));
		}
	}

#ifndef SETUP

	void BootEncryption::CheckRequirements ()
	{
		if (nCurrentOS == WIN_2000)
			throw ErrorException ("SYS_ENCRYPTION_UNSUPPORTED_ON_CURRENT_OS");

		if (IsNonInstallMode())
			throw ErrorException ("FEATURE_REQUIRES_INSTALLATION");

		SystemDriveConfiguration config = GetSystemDriveConfiguration ();

		if (config.SystemPartition.IsGPT)
			throw ErrorException ("GPT_BOOT_DRIVE_UNSUPPORTED");

		if (config.InitialUnallocatedSpace < TC_BOOT_LOADER_AREA_SIZE)
			throw ErrorException ("NO_SPACE_FOR_BOOT_LOADER");

		DISK_GEOMETRY geometry = GetDriveGeometry (config.DriveNumber);

		if (geometry.BytesPerSector != SECTOR_SIZE)
			throw ErrorException ("LARGE_SECTOR_UNSUPPORTED");

		if (!config.SystemLoaderPresent)
			throw ErrorException ("WINDOWS_NOT_ON_BOOT_DRIVE_ERROR");
	}


	void BootEncryption::Deinstall ()
	{
		BootEncryptionStatus encStatus = GetStatus();

		if (encStatus.DriveEncrypted || encStatus.DriveMounted)
			throw ParameterIncorrect (SRC_POS);

		SystemDriveConfiguration config = GetSystemDriveConfiguration ();

		if (encStatus.VolumeHeaderPresent)
		{
			// Verify CRC of header salt
			Device device (config.DevicePath, true);
			byte header[SECTOR_SIZE];

			device.SeekAt (TC_BOOT_VOLUME_HEADER_SECTOR_OFFSET);
			device.Read (header, sizeof (header));

			if (encStatus.VolumeHeaderSaltCrc32 != GetCrc32 ((byte *) header, PKCS5_SALT_SIZE))
				throw ParameterIncorrect (SRC_POS);
		}

		RegisterFilterDriver (false);
		SetDriverServiceStartType (SERVICE_SYSTEM_START);

		try
		{
			RestoreSystemLoader ();
		}
		catch (Exception &e)
		{
			e.Show (ParentWindow);
			throw ErrorException ("SYS_LOADER_RESTORE_FAILED");
		}
	}


	int BootEncryption::ChangePassword (Password *oldPassword, Password *newPassword, int pkcs5)
	{
		if (GetStatus().SetupInProgress)
			throw ParameterIncorrect (SRC_POS);

		SystemDriveConfiguration config = GetSystemDriveConfiguration ();

		char header[HEADER_SIZE];
		Device device (config.DevicePath);

		// Only one algorithm is currently supported
		if (pkcs5 != 0)
			throw ParameterIncorrect (SRC_POS);

		device.SeekAt (TC_BOOT_VOLUME_HEADER_SECTOR_OFFSET);
		device.Read ((byte *) header, sizeof (header));

		PCRYPTO_INFO cryptoInfo = NULL;
		
		int status = VolumeReadHeader (TRUE, header, oldPassword, &cryptoInfo, NULL);
		finally_do_arg (PCRYPTO_INFO, cryptoInfo, { if (finally_arg) crypto_close (finally_arg); });

		if (status != 0)
		{
			handleError (ParentWindow, status);
			return status;
		}

		// Change the PKCS-5 PRF if requested by user
		if (pkcs5 != 0)
			cryptoInfo->pkcs5 = pkcs5;

		throw_sys_if (Randinit () != 0);

		/* The header will be re-encrypted PRAND_DISK_WIPE_PASSES times to prevent adversaries from using 
		techniques such as magnetic force microscopy or magnetic force scanning tunnelling microscopy
		to recover the overwritten header. According to Peter Gutmann, data should be overwritten 22
		times (ideally, 35 times) using non-random patterns and pseudorandom data. However, as users might
		impatiently interupt the process (etc.) we will not use the Gutmann's patterns but will write the
		valid re-encrypted header, i.e. pseudorandom data, and there will be many more passes than Guttman
		recommends. During each pass we will write a valid working header. Each pass will use the same master
		key, and also the same header key, secondary key (XTS), etc., derived from the new password. The only
		item that will be different for each pass will be the salt. This is sufficient to cause each "version"
		of the header to differ substantially and in a random manner from the versions written during the
		other passes. */

		bool headerUpdated = false;
		int result = ERR_SUCCESS;

		try
		{
			for (int wipePass = 0; wipePass < PRAND_DISK_WIPE_PASSES; wipePass++)
			{
				PCRYPTO_INFO tmpCryptoInfo = NULL;

				status = VolumeWriteHeader (TRUE,
					header,
					cryptoInfo->ea,
					cryptoInfo->mode,
					newPassword,
					cryptoInfo->pkcs5,
					(char *) cryptoInfo->master_keydata,
					cryptoInfo->volume_creation_time,
					&tmpCryptoInfo,
					cryptoInfo->VolumeSize.Value,
					cryptoInfo->hiddenVolumeSize,
					cryptoInfo->EncryptedAreaStart.Value,
					cryptoInfo->EncryptedAreaLength.Value,
					wipePass < PRAND_DISK_WIPE_PASSES - 1);

				if (tmpCryptoInfo)
					crypto_close (tmpCryptoInfo);

				if (status != 0)
				{
					handleError (ParentWindow, status);
					return status;
				}

				device.SeekAt (TC_BOOT_VOLUME_HEADER_SECTOR_OFFSET);
				device.Write ((byte *) header, sizeof (header));
				headerUpdated = true;
			}
		}
		catch (Exception &e)
		{
			e.Show (ParentWindow);
			result = ERR_OS_ERROR;
		}

		if (headerUpdated)
		{
			ReopenBootVolumeHeaderRequest reopenRequest;
			reopenRequest.VolumePassword = *newPassword;
			finally_do_arg (ReopenBootVolumeHeaderRequest*, &reopenRequest, { burn (finally_arg, sizeof (*finally_arg)); });

			CallDriver (TC_IOCTL_REOPEN_BOOT_VOLUME_HEADER, &reopenRequest, sizeof (reopenRequest));
		}

		return result;
	}


	void BootEncryption::CheckEncryptionSetupResult ()
	{
		CallDriver (TC_IOCTL_GET_BOOT_ENCRYPTION_SETUP_RESULT);
	}


	void BootEncryption::Install ()
	{
		BootEncryptionStatus encStatus = GetStatus();
		if (encStatus.DriveMounted)
			throw ParameterIncorrect (SRC_POS);

		try
		{
			InstallBootLoader ();
			InstallVolumeHeader ();
			RegisterBootDriver ();

			// Prevent system log errors caused by rejecting crash dumps
			WriteLocalMachineRegistryDword ("System\\CurrentControlSet\\Control\\CrashControl", "CrashDumpEnabled", 0);
		}
		catch (Exception &)
		{
			try
			{
				RestoreSystemLoader ();
			}
			catch (Exception &e)
			{
				e.Show (ParentWindow);
			}

			throw;
		}
	}


	void BootEncryption::PrepareInstallation (bool systemPartitionOnly, Password &password, int ea, int mode, int pkcs5, const string &rescueIsoImagePath)
	{
		BootEncryptionStatus encStatus = GetStatus();
		if (encStatus.DriveMounted)
			throw ParameterIncorrect (SRC_POS);

		CheckRequirements ();

		SystemDriveConfiguration config = GetSystemDriveConfiguration();
		BackupSystemLoader ();

		uint64 volumeSize;
		uint64 encryptedAreaStart;

		if (systemPartitionOnly)
		{
			volumeSize = config.SystemPartition.Info.PartitionLength.QuadPart;
			encryptedAreaStart = config.SystemPartition.Info.StartingOffset.QuadPart;
		}
		else
		{
			volumeSize = config.DrivePartition.Info.PartitionLength.QuadPart - TC_BOOT_LOADER_AREA_SIZE;
			encryptedAreaStart = config.DrivePartition.Info.StartingOffset.QuadPart + TC_BOOT_LOADER_AREA_SIZE;
		}

		SelectedEncryptionAlgorithmId = ea;
		CreateVolumeHeader (volumeSize, encryptedAreaStart, &password, ea, mode, pkcs5);
		
		if (!rescueIsoImagePath.empty())
			CreateRescueIsoImage (true, rescueIsoImagePath);
	}
	

	void BootEncryption::StartDecryption ()
	{
		BootEncryptionStatus encStatus = GetStatus();

		if (!encStatus.DeviceFilterActive || !encStatus.DriveMounted || encStatus.SetupInProgress)
			throw ParameterIncorrect (SRC_POS);

		BootEncryptionSetupRequest request;
		ZeroMemory (&request, sizeof (request));
		
		request.SetupMode = SetupDecryption;

		CallDriver (TC_IOCTL_BOOT_ENCRYPTION_SETUP, &request, sizeof (request), NULL, 0);
	}


	void BootEncryption::StartEncryption (WipeAlgorithmId wipeAlgorithm)
	{
		BootEncryptionStatus encStatus = GetStatus();

		if (!encStatus.DeviceFilterActive || !encStatus.DriveMounted || encStatus.SetupInProgress)
			throw ParameterIncorrect (SRC_POS);

		BootEncryptionSetupRequest request;
		ZeroMemory (&request, sizeof (request));
		
		request.SetupMode = SetupEncryption;
		request.WipeAlgorithm = wipeAlgorithm;

		CallDriver (TC_IOCTL_BOOT_ENCRYPTION_SETUP, &request, sizeof (request), NULL, 0);
	}

#endif // !SETUP

	void BootEncryption::RegisterBootDriver (void)
	{
		SetDriverServiceStartType (SERVICE_BOOT_START);

		try
		{
			RegisterFilterDriver (false);
		}
		catch (...) { }

		RegisterFilterDriver (true);
	}


	bool BootEncryption::RestartComputer (void)
	{
		TOKEN_PRIVILEGES tokenPrivil; 
		HANDLE hTkn; 

		if (!OpenProcessToken (GetCurrentProcess (), TOKEN_QUERY|TOKEN_ADJUST_PRIVILEGES, &hTkn))
		{
			return false; 
		}

		LookupPrivilegeValue (NULL, SE_SHUTDOWN_NAME, &tokenPrivil.Privileges[0].Luid); 
		tokenPrivil.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED; 
		tokenPrivil.PrivilegeCount = 1;    

		AdjustTokenPrivileges (hTkn, false, &tokenPrivil, 0, (PTOKEN_PRIVILEGES) NULL, 0); 
		if (GetLastError() != ERROR_SUCCESS) 
			return false; 

		if (!ExitWindowsEx (EWX_REBOOT | EWX_FORCE, 
			SHTDN_REASON_MAJOR_OTHER | SHTDN_REASON_MINOR_OTHER | SHTDN_REASON_FLAG_PLANNED)) 
			return false; 

		return true;
	}
}
