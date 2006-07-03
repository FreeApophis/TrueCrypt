/* 
Copyright (c) 2004-2006 TrueCrypt Foundation. All rights reserved. 

Covered by TrueCrypt License 2.1 the full text of which is contained in the file
License.txt included in TrueCrypt binary and source code distribution archives. 
*/

#define TC_REQUIRED_MOUSE_EVENTS 5000
#define TC_REQUIRED_KEYSTROKES RNG_POOL_SIZE

#define TC_MAX_VOLUMES	256
#define TC_MAX_MINOR	256

#define TC_MAP_DEV "/dev/mapper/truecrypt"
#define TC_LOOP_DEV "/dev/loop"
#define TC_MICE_DEVICE "/dev/input/mice"
#define TC_SHARE_KERNEL "/usr/share/truecrypt/kernel"

#ifdef TC_MAX_PATH
#undef TC_MAX_PATH
#endif
#define TC_MAX_PATH 260
#define TC_MAX_PATH_STR "259"

#define error(fmt, args...) fprintf (stderr, "truecrypt: " fmt, ## args)

typedef struct
{
	int DeviceNumber;
	int DeviceMajor;
	int DeviceMinor;
	unsigned long long VolumeSize;
	char VolumePath[TC_MAX_PATH];
	int EA;
	int Mode;
	BOOL Hidden;
	unsigned long long ReadOnlyStart;
	unsigned long long ReadOnlyEnd;
	unsigned long long ModTime;
	unsigned long long AcTime;
	int Flags;
} MountListEntry;

static BOOL CheckAdminPrivileges ();
static void DropEffectiveUserId ();
static BOOL LockMemory ();
static BOOL WaitChild (BOOL quiet, char *execName);
static BOOL Execute (BOOL quiet, char *execName, ...);
static BOOL IsFile (char *path);
static BOOL IsBlockDevice (char *path);
static BOOL RestoreFileTime (char *path, time_t modTime, time_t acTime);
static BOOL LoadKernelModule ();
static BOOL UnloadKernelModule (BOOL quiet);
static BOOL CheckKernelModuleVersion (BOOL wait, BOOL quiet);
static void OpenMiceDevice ();
static BOOL GetMountList (BOOL force);
static BOOL IsVolumeMounted (char *volumePath);
static int GetFreeMapDevice ();
static BOOL DeleteLoopDevice (int loopDeviceNo);
static int AskSelection (int defaultChoice, int min, int max);
static BOOL AskYesNo (char *prompt, BOOL defaultNo);
static char *AskString (char *prompt, char *buf, int maxSize);
static void AskPassword (char *prompt, char *volumePath, Password *password);
static char *AskVolumePath (char *volumePath, char *prompt);
static BOOL AskKeyFiles (char *prompt, KeyFile **firstKeyFile);
static BOOL OpenVolume (char *volumePath, char *prompt, char *promptArg, BOOL secondaryPassword, PCRYPTO_INFO *cryptoInfo, unsigned long long *startSector, unsigned long long *totalSectors, time_t *modTime, time_t *acTime);
static char *EscapeSpaces (char *string);
static BOOL MountVolume (char *volumePath, char *mountPoint);
static void HexDump (unsigned __int8 *data, unsigned int length);
static uint64_t GetTimeUsec ();
static double GetTime ();
static BOOL RandFillPool ();
static BOOL ParseSize (char *string, unsigned long long *size);
static BOOL CreateVolume (char *hostPath);
static BOOL ChangePassword (char *volumePath);
static BOOL BackupVolumeHeaders (char *backupFile, char *volumePath);
static BOOL RestoreVolumeHeader (char *backupFile, char *volumePath);
static BOOL CreateKeyfile (char *path);
static time_t WindowsFileTime2UnixTime (uint64_t wTime);
static BOOL DumpVolumeProperties (char *volumePath);
static void DumpVersion (FILE *f);
static void DumpUsage (FILE *f);
static void DumpHelp ();
static BOOL DumpMountList (int devNo);
static BOOL DismountFileSystem (char *device);
static BOOL DismountVolume (int devNo);
static BOOL ToDeviceNumber (char *text, int *deviceNumber);

