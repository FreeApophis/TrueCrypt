/*
 Copyright (c) 2008 TrueCrypt Foundation. All rights reserved.

 Governed by the TrueCrypt License 2.4 the full text of which is contained
 in the file License.txt included in TrueCrypt binary and source code
 distribution packages.
*/

#ifndef TC_HEADER_Mount_BootEncryption
#define TC_HEADER_Mount_BootEncryption

#include "Tcdefs.h"
#include "Dlgcode.h"
#include "Platform/PlatformBase.h"

using namespace std;

namespace TrueCrypt
{
	struct Exception
	{
		virtual void Show (HWND parent) = 0;
	};

	struct SystemException : public Exception
	{
		SystemException () : ErrorCode (GetLastError()) { }

		void Show (HWND parent)
		{
			SetLastError (ErrorCode);
			handleWin32Error (parent);
		}

		DWORD ErrorCode;
	};

	struct ErrorException : public Exception
	{
		ErrorException (char *langId) : ErrLangId (langId) { }

		void Show (HWND parent)
		{
			::Error (ErrLangId);
		}

		char *ErrLangId;
	};

	struct ParameterIncorrect : public Exception
	{
		ParameterIncorrect (const char *srcPos) : SrcPos (srcPos) { }

		void Show (HWND parent)
		{
			string msgBody = "Parameter incorrect.\n\n\n(If you report a bug in connection with this, please include the following technical information in the bug report:\n" + string (SrcPos) + ")";
			MessageBox (parent, msgBody.c_str(), "TrueCrypt", MB_ICONERROR | MB_SETFOREGROUND | MB_TOPMOST);
		}

		const char *SrcPos;
	};

	struct TimeOut : public Exception
	{
		TimeOut (const char *srcPos) { }
		void Show (HWND parent) { MessageBox (parent, "Timeout", "TrueCrypt", MB_ICONERROR); }
	};

	struct UserAbort : public Exception
	{
		UserAbort (const char *srcPos) { }
		void Show (HWND parent) { }
	};

#define throw_sys_if(condition) do { if (condition) throw SystemException(); } while (false)


	class File
	{
	public:
		File () : FileOpen (false) { }
		File (string path, bool readOnly = false, bool create = false);
		~File () { Close(); }

		void Close ();
		DWORD Read (byte *buffer, DWORD size);
		void Write (byte *buffer, DWORD size);
		void SeekAt (int64 position);

	protected:
		bool Elevated;
		bool FileOpen;
		uint64 FilePointerPosition;
		HANDLE Handle;
		bool IsDevice;
		string Path;
	};


	class Device : public File
	{
	public:
		Device (string path, bool readOnly = false);
	};


	class Buffer
	{
	public:
		Buffer (size_t size) : DataSize (size)
		{
			DataPtr = new byte[size];
			if (!DataPtr)
				throw bad_alloc();
		}

		~Buffer () { delete DataPtr; }
		byte *Ptr () const { return DataPtr; }
		size_t Size () const { return DataSize; }

	protected:
		byte *DataPtr;
		size_t DataSize;
	};


	struct Partition
	{
		string DevicePath;
		PARTITION_INFORMATION Info;
		string MountPoint;
		int Number;
		BOOL IsGPT;
	};

	typedef list <Partition> PartitionList;

#pragma pack (push)
#pragma pack(1)

	struct PartitionEntryMBR
	{
		byte BootIndicator;

		byte StartHead;
		byte StartCylSector;
		byte StartCylinder;

		byte Type;

		byte EndHead;
		byte EndSector;
		byte EndCylinder;

		uint32 StartLBA;
		uint32 SectorCountLBA;
	};

	struct MBR
	{
		byte Code[446];
		PartitionEntryMBR Partitions[4];
		uint16 Signature;
	};

#pragma pack (pop)

	struct SystemDriveConfiguration
	{
		string DevicePath;
		int DriveNumber;
		Partition DrivePartition;
		int64 InitialUnallocatedSpace;
		PartitionList Partitions;
		Partition SystemPartition;
		int64 TotalUnallocatedSpace;
		bool SystemLoaderPresent;
	};

	class BootEncryption
	{
	public:
		BootEncryption (HWND parent)
			: DriveConfigValid (false),
			ParentWindow (parent),
			RealSystemDriveSizeValid (false),
			RescueIsoImage (nullptr),
			RescueVolumeHeaderValid (false),
			SelectedEncryptionAlgorithmId (0),
			VolumeHeaderValid (false)
		{
		}

		~BootEncryption ();

		void AbortSetup ();
		void AbortSetupWait ();
		void CallDriver (DWORD ioctl, void *input = nullptr, DWORD inputSize = 0, void *output = nullptr, DWORD outputSize = 0);
		int ChangePassword (Password *oldPassword, Password *newPassword, int pkcs5);
		void CheckEncryptionSetupResult ();
		void CheckRequirements ();
		void CreateRescueIsoImage (bool initialSetup, const string &isoImagePath);
		void Deinstall ();
		DWORD GetDriverServiceStartType ();
		uint16 GetInstalledBootLoaderVersion ();
		bool IsBootLoaderOnDrive (char *devicePath);
		BootEncryptionStatus GetStatus ();
		void GetVolumeProperties (VOLUME_PROPERTIES_STRUCT *properties);
		SystemDriveConfiguration GetSystemDriveConfiguration ();
		void Install ();
		void InstallBootLoader ();
		void PrepareInstallation (bool systemPartitionOnly, Password &password, int ea, int mode, int pkcs5, const string &rescueIsoImagePath);
		void ProbeRealSystemDriveSize ();
		void RegisterBootDriver ();
		void RegisterFilterDriver (bool registerDriver);
		bool RestartComputer (void);
		void SetDriverServiceStartType (DWORD startType);
		void StartDecryption ();
		void StartEncryption (WipeAlgorithmId wipeAlgorithm);
		bool SystemDriveContainsPartitionType (byte type);
		bool SystemDriveContainsExtendedPartition ();
		bool SystemPartitionCoversWholeDrive ();
		bool SystemDriveIsDynamic ();
		bool VerifyRescueDisk ();

	protected:
		static const uint32 RescueIsoImageSize = 1835008; // Size of ISO9660 image with bootable emulated 1.44MB floppy disk image

		void BackupSystemLoader ();
		void CreateVolumeHeader (uint64 volumeSize, uint64 encryptedAreaStart, Password *password, int ea, int mode, int pkcs5);
		string GetSystemLoaderBackupPath ();
		void GetBootLoader (byte *buffer, size_t bufferSize, bool rescueDisk);
		uint32 GetChecksum (byte *data, size_t size);
		DISK_GEOMETRY GetDriveGeometry (int driveNumber);
		PartitionList GetDrivePartitions (int driveNumber);
		string GetWindowsDirectory ();
		void RestoreSystemLoader ();
		void InstallVolumeHeader ();
		void UpdateSystemDriveConfiguration ();

		HWND ParentWindow;
		SystemDriveConfiguration DriveConfig;
		int SelectedEncryptionAlgorithmId;
		byte *RescueIsoImage;
		byte RescueVolumeHeader[HEADER_SIZE];
		byte VolumeHeader[HEADER_SIZE];
		bool DriveConfigValid;
		bool RealSystemDriveSizeValid;
		bool RescueVolumeHeaderValid;
		bool VolumeHeaderValid;
	};
}

#define TC_ABORT_TRANSFORM_WAIT_INTERVAL	10

#define TC_SYS_BOOT_LOADER_BACKUP_NAME "Original System Loader.bak"

#endif // TC_HEADER_Mount_BootEncryption
