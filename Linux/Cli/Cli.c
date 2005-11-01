/* 
Copyright (c) 2004-2005 TrueCrypt Foundation. All rights reserved. 

Covered by TrueCrypt License 2.0 the full text of which is contained in the file
License.txt included in TrueCrypt binary and source code distribution archives. 
*/

//FIXME remove stale dmsetup device
#define _LARGEFILE_SOURCE	1
#define _FILE_OFFSET_BITS	64

#include <getopt.h>
#include <inttypes.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <termios.h>
#include <time.h>
#include <unistd.h>
#include <utime.h>

#include "Tcdefs.h"
#include "Keyfiles.h"
#include "Volumes.h"
#include "Tests.h"
#include "Dm-target.h"

#define MAX_VOLUMES	256
#define MAX_MINOR 256

#undef MAX_PATH
#define MAX_PATH 260
#define MAX_PATH_STR "259"

#define TC_MAP_DEV "/dev/mapper/truecrypt"
#define LOOP_DEV "/dev/loop"

#define error(fmt, args...) fprintf (stderr, "truecrypt: " fmt, ## args)

typedef struct
{
	int DeviceNumber;
	int DeviceMajor;
	int DeviceMinor;
	uint64_t VolumeSize;
	char VolumePath[MAX_PATH];
	int EA;
	BOOL Hidden;
	uint64_t ReadOnlyStart;
	uint64_t ReadOnlyEnd;
	uint64_t ModTime;
	uint64_t AcTime;
	int Flags;
} MountListEntry;

static MountListEntry MountList[MAX_VOLUMES];
static BOOL MountListValid = FALSE;

static BOOL DisplayPassword = FALSE;
static char *Filesystem = NULL;
static char *MountOpts = NULL;
static int PasswordEntryTries = 3;
static Password CmdPassword;
static Password CmdPassword2;
static BOOL CmdPasswordValid = FALSE;

static BOOL CmdPassword2Valid = FALSE;
static int UseDeviceNumber = -1;
static BOOL ProtectHidden = FALSE;
static BOOL ReadOnly = FALSE;
static BOOL UpdateTime = FALSE;
static int Verbose = 0;

static BOOL	IsTerminal = FALSE;
static struct termios TerminalAttributes;
static Password password;
static KeyFile *FirstKeyFile;
static KeyFile *FirstProtVolKeyFile;


static void SecurityCleanup ()
{
	burn (&password, sizeof (password));
	burn (&CmdPassword, sizeof (CmdPassword));
	burn (&CmdPassword2, sizeof (CmdPassword2));
}


static void OnSignal (int signal)
{
	SecurityCleanup ();

	if (IsTerminal)
	{
		tcsetattr (0, TCSANOW, &TerminalAttributes);
		puts ("");
	}

	_exit (1);
}


static void OnExit ()
{
	SecurityCleanup ();
}


static BOOL WaitChild (BOOL quiet, char *execName)
{
	int status;
	if (wait (&status) == -1)
	{
		perror ("wait");
		return FALSE;
	}

	if (!WIFEXITED (status)
		|| (WIFEXITED (status) && WEXITSTATUS (status)))
	{
		if (!quiet && Verbose >= 3)
			error ("Error: %s returned %d\n", execName, WEXITSTATUS (status));
		return FALSE;
	}

	return TRUE;
}


BOOL Execute (BOOL quiet, char *execName, ...)
{
	int pid;
	va_list vl;
	va_start (vl, execName);

	pid = fork ();
	if (pid == -1)
	{
		perror ("fork");
		goto err;
	}
	else if (pid == 0)
	{
		char *args[32];
		int i = 1;

		SecurityCleanup ();

		if (Verbose >= 3)
			printf ("Executing %s", execName);

		args[0] = execName;
		while (i < 32 && (args[i] = (va_arg (vl, char *))))
		{
			if (Verbose >= 3)
				printf (" %s", args[i]);
			i++;
		}

		if (Verbose >= 3)
			puts ("");

		if (quiet)
		{
			// >/dev/null is safer than >&-
			int i = open ("/dev/null", 0);
			if (i == -1)
			{
				perror ("open /dev/null");
				_exit (1);
			}

			dup2 (i, STDOUT_FILENO);
			dup2 (i, STDERR_FILENO);
		}

		execvp (execName, args);

		fprintf (stderr, "%s ", execName);
		perror ("execlp");
		_exit (1);
	}

	if (!WaitChild (quiet, execName))
		goto err;

	va_end (vl);
	return TRUE;
err:
	va_end (vl);
	return FALSE;
}


static BOOL IsFile (char *path)
{
	struct stat st;
	if (stat (path, &st) != 0)
		return FALSE;

	return S_ISREG (st.st_mode);
}


static BOOL IsBlockDevice (char *path)
{
	struct stat st;
	if (stat (path, &st) != 0)
		return FALSE;

	return S_ISBLK (st.st_mode);
}


static BOOL RestoreFileTime (char *path, time_t modTime, time_t acTime)
{
	struct utimbuf t;

	t.actime = acTime;
	t.modtime = modTime;

	return utime (path, &t) != 0;
}


static BOOL LoadKernelModule ()
{
	char s[2048];	
	FILE *m;
	
	m = fopen ("/proc/modules", "r");
	if (m == NULL)
	{
		perror ("fopen /proc/modules");
		return FALSE;
	}

	while (fgets (s, sizeof (s), m))
	{
		if (strstr (s, "truecrypt ") == s)
		{
			fclose (m);
			return TRUE;
		}
	}

	fclose (m);

	if (!Execute (FALSE, "modprobe", "truecrypt", NULL))
	{
		error ("Failed to load TrueCrypt kernel module\n");
		return FALSE;
	}
	return TRUE;
}


static BOOL UnloadKernelModule (BOOL quiet)
{
	// rmmod is used instead of modprobe to prevent unload of dependencies
	return Execute (quiet, "rmmod", "truecrypt", NULL);
}


static BOOL CheckKernelModuleVersion (BOOL wait)
{
	FILE *p;
	int pfd[2];
	int pid, res;
	int i, dummy;
	char s[2048];
	int ver1 = 0, ver2 = 0, ver3 = 0;
	int tries = 10;

	do
	{
		pipe (pfd);
		pid = fork ();

		if (pid == -1)
		{
			perror ("fork");
			return FALSE;
		}
		else if (pid == 0)
		{
			SecurityCleanup ();

			dup2 (pfd[1], STDOUT_FILENO);
			close (pfd[0]);
			close (STDERR_FILENO);

			execlp ("dmsetup", "dmsetup", "targets", NULL);

			perror ("execlp dmsetup");
			_exit (1);
		}

		close (pfd[1]);
		p = fdopen (pfd[0], "r");
		if (p == NULL)
		{
			perror ("fdopen");
			return FALSE;
		}

		while (fgets (s, sizeof (s), p))
		{
			char name[32];

			if (sscanf (s, "%31s v%d.%d.%d", &name, &ver1, &ver2, &ver3) == 4
				&& strcmp (name, "truecrypt") == 0)
			{
				fclose (p);
				WaitChild (FALSE, "dmsetup");

				if (ver1 == VERSION_NUM1 && ver2 == VERSION_NUM2 && ver3 == VERSION_NUM3)
					return TRUE;

				error ("Incorrect version of kernel module loaded - version %s required\n", VERSION_STRING);
				UnloadKernelModule (TRUE);
				return FALSE;
			}
		}

		fclose (p);
		WaitChild (FALSE, "dmsetup");

		// Target registration may take some time
		if (wait)
			usleep (100 * 1000);
		else
			break;

	} while (tries--);

	error ("Kernel module not loaded\n");
	return FALSE;
}


static BOOL GetMountList ()
{
	FILE *p;
	int pfd[2];
	int pid, res;
	int i, dummy;

	if (MountListValid)
		return TRUE;

	MountList[0].DeviceNumber = -1;

	pipe (pfd);
	pid = fork ();

	if (pid == -1)
	{
		perror ("fork");
		goto err;
	}
	else if (pid == 0)
	{
		SecurityCleanup ();

		dup2 (pfd[1], STDOUT_FILENO);
		close (pfd[0]);
		close (STDERR_FILENO);

		execlp ("dmsetup", "dmsetup", "table", NULL);

		perror ("execlp dmsetup");
		_exit (1);
	}

	close (pfd[1]);
	p = fdopen (pfd[0], "r");
	if (p == NULL)
	{
		perror ("fdopen");
		goto err;
	}

	for (i = 0; i < MAX_VOLUMES; i++)
	{
		char s[2048];
		MountListEntry *e = &MountList[i];

		if (!fgets (s, sizeof (s), p))
			break;

		if (sscanf (s, "truecrypt%d: 0 %lld truecrypt %d 0 0 %d:%d %lld %lld %lld %lld %lld %d %" MAX_PATH_STR "s\n",
			&e->DeviceNumber,
			&e->VolumeSize,
			&e->EA,
			&e->DeviceMajor,
			&e->DeviceMinor,
			&e->Hidden,
			&e->ReadOnlyStart,
			&e->ReadOnlyEnd,
			&e->ModTime,
			&e->AcTime,
			&e->Flags,
			e->VolumePath) == 12)
		{
			e->Hidden = e->Hidden == 1 ? FALSE : TRUE;
			e->VolumeSize *= SECTOR_SIZE;
		}
		else
			i--;
	}

	MountList[i].DeviceNumber = -1;

	fclose (p);
	if (!WaitChild (TRUE, "dmsetup"))
		goto err;

	MountListValid = TRUE;
	return TRUE;

err:
	MountList[0].DeviceNumber = -1;
	return FALSE;
}


static BOOL IsVolumeMounted (char *volumePath)
{
	int i;
	if (!GetMountList ())
		return FALSE;

	for (i = 0; MountList[i].DeviceNumber != -1; i++)
		if (strcmp (volumePath, MountList[i].VolumePath) == 0)
			return TRUE;

	return FALSE;
}


static int GetFreeMapDevice ()
{
	FILE *p;
	char cmd[128];
	int n;

	if (!GetMountList ())
		return -1;

	for (n = 0; n < MAX_MINOR; n++)
	{
		int j = 0;
		while (MountList[j].DeviceNumber != -1)
		{
			if (MountList[j].DeviceNumber == n)
				break;
			j++;
		}

		if (MountList[j].DeviceNumber == -1)
			return n;
	}

	return -1;
}


static BOOL DeleteLoopDevice (int loopDeviceNo)
{
	char dev[32];
	BOOL r;

	sprintf (dev, LOOP_DEV "%d", loopDeviceNo);
	if (!IsBlockDevice (dev))
		sprintf (dev, LOOP_DEV "/%d", loopDeviceNo);

	r = Execute (FALSE, "losetup", "-d", dev, NULL);

	if (r && Verbose > 1)
		printf ("Detached %s\n", dev);

	return r;
}


static BOOL OpenVolume (char *volumePath, Password *password, PCRYPTO_INFO *cryptoInfo, uint64_t *startSector, uint64_t *totalSectors, time_t *modTime, time_t *acTime)
{
	char header[SECTOR_SIZE];
	uint64_t r;
	FILE *f = NULL;
	struct stat volumeStat;

	if (stat (volumePath, &volumeStat) != 0)
	{
		perror ("Cannot open volume");
		volumeStat.st_ctime = 0;
		goto err;
	}

	f = fopen (volumePath, "r");
	if (!f)
	{
		perror ("Cannot open volume");
		goto err;
	}

	// Normal header
	if (fread (header, 1, SECTOR_SIZE, f) != SECTOR_SIZE)
	{
		perror ("Cannot read volume header");
		goto err;
	}

	fseek (f, 0, SEEK_END);
	*totalSectors = ftello (f) / SECTOR_SIZE - 1;

	r = VolumeReadHeader (header, password, cryptoInfo);

	if (r != 0)
	{
		// Hidden header
		if (fseek (f, -HIDDEN_VOL_HEADER_OFFSET, SEEK_END) == -1
			|| fread (header, 1, SECTOR_SIZE, f) != SECTOR_SIZE)
		{
			perror ("Cannot read volume header");
			goto err;
		}

		r = VolumeReadHeader (header, password, cryptoInfo);

		if (r != 0)
		{
			if (IsTerminal)
				puts ("Incorrect password or not a TrueCrypt volume");
			else
				error ("Incorrect password or not a TrueCrypt volume\n");

			goto err;
		}

		*startSector = (ftello (f) 
			+ SECTOR_SIZE * 2 
			- (*cryptoInfo)->hiddenVolumeSize 
			- HIDDEN_VOL_HEADER_OFFSET) / SECTOR_SIZE;

		*totalSectors = (*cryptoInfo)->hiddenVolumeSize / SECTOR_SIZE;
	}
	else
		*startSector = 1;

	fclose (f);

	if (!UpdateTime)
		RestoreFileTime (volumePath, volumeStat.st_mtime, volumeStat.st_atime);

	*modTime = volumeStat.st_mtime;
	*acTime = volumeStat.st_atime;
	return TRUE;

err:
	*cryptoInfo = NULL;

	if (f)
		fclose (f);

	if (volumeStat.st_ctime != 0 && !UpdateTime)
		RestoreFileTime (volumePath, volumeStat.st_mtime, volumeStat.st_atime);

	return FALSE;
}


static void GetPassword (char *prompt, char *volumePath, Password *password)
{
	struct termios noEcho;

	if (tcgetattr (0, &TerminalAttributes) == 0)
	{
		IsTerminal = TRUE;
		noEcho = TerminalAttributes;

		if (!DisplayPassword)
		{
			noEcho.c_lflag &= ~ECHO;
			if (tcsetattr (0, TCSANOW, &noEcho) != 0)
				error ("Failed to turn terminal echo off\n");
		}

		printf (prompt, volumePath);
	}

	if (fgets (password->Text, sizeof (password->Text), stdin))
	{
		char *newl = strchr (password->Text, '\n');
		if (newl) newl[0] = 0;

		password->Length = strlen (password->Text);
	}
	else
		password->Length = 0;

	if (IsTerminal && !DisplayPassword)
	{
		tcsetattr (0, TCSANOW, &TerminalAttributes);
		puts ("");
	}
}


static BOOL MountVolume (char *volumePath, char *mountPoint)
{
	char hostDevice[MAX_PATH];
	char mapDevice[MAX_PATH];
	int loopDevNo = -1;
	PCRYPTO_INFO ci = NULL;
	uint64_t startSector, totalSectors;
	uint64_t readOnlyStartSector = 0, readOnlySectors = 0;
	int pfd[2];
	int pid, res, devNo;
	time_t modTime, acTime;
	FILE *f, *w;
	int flags;
	int i;
	int tries = PasswordEntryTries;

	if (!AutoTestAlgorithms ())
	{
		error ("Self-tests of algorithms FAILED!\n");
		return FALSE;
	}

	if (IsVolumeMounted (volumePath))
	{
		error ("Volume already mounted\n");
		return FALSE;
	}

	do
	{
		Password *pw = &password;

		if (!CmdPasswordValid)
			GetPassword ("Enter password for '%s': ", volumePath, &password);
		else
			pw = &CmdPassword;

		if (FirstKeyFile && !KeyFilesApply (pw, FirstKeyFile, !UpdateTime))
		{
			error ("Error while processing keyfiles\n");
			goto err;
		}

		if (OpenVolume (volumePath, pw, &ci, &startSector, &totalSectors, &modTime, &acTime))
			break;
		else
			totalSectors = 0;

	} while (!CmdPasswordValid && IsTerminal && --tries > 0);

	if (totalSectors == 0)
		goto err;

	// Hidden volume protection
	if (ProtectHidden)
	{
		PCRYPTO_INFO ciH = NULL;
		uint64_t startSectorH, totalSectorsH;

		tries = PasswordEntryTries;
		do
		{
			Password *pw = &password;

			if (!CmdPassword2Valid)
				GetPassword ("Enter hidden volume password: ", "", &password);
			else
				pw = &CmdPassword2;

			if (FirstProtVolKeyFile && !KeyFilesApply (pw, FirstProtVolKeyFile, !UpdateTime))
			{
				error ("Error while processing keyfiles\n");
				goto err;
			}

			if (OpenVolume (volumePath, pw, &ciH, &startSectorH, &totalSectorsH, &modTime, &acTime))
			{
				readOnlyStartSector = startSectorH;
				readOnlySectors = startSectorH + totalSectorsH;
				break;
			}

		} while (!CmdPassword2Valid && IsTerminal && --tries > 0);
		
		if (ciH)
			crypto_close (ciH);

		if (readOnlySectors == 0)
			goto err;
	}

	// Headers decrypted

	// Loopback
	if (IsFile (volumePath))
	{
		int i;

		for (i = 0; i < MAX_MINOR; i++)
		{
			snprintf (hostDevice, sizeof (hostDevice), LOOP_DEV "%d", i);

			if (!IsBlockDevice (hostDevice))
			{
				snprintf (hostDevice, sizeof (hostDevice), LOOP_DEV "/%d", i);
				if (!IsBlockDevice (hostDevice))
					continue;
			}

			if (Execute (TRUE, "losetup", hostDevice, volumePath, NULL))
				break;
		}

		if (i >= MAX_MINOR)
		{
			error ("No free loopback device available for file-hosted volume\n");
			goto err;
		}

		loopDevNo = i;

		if (Verbose > 1)
			printf ("Attached %s to %s\n", volumePath, hostDevice);

	}
	else
		strncpy (hostDevice, volumePath, sizeof (hostDevice));

	// Load kernel module
	if (!LoadKernelModule ())
		goto err;

	if (!CheckKernelModuleVersion (TRUE))
		goto err;

	// dmsetup
	devNo = UseDeviceNumber == -1 ? GetFreeMapDevice () : UseDeviceNumber;
	if (devNo == -1)
	{
		error ("Maximum number of volumes mounted\n");
		goto err;
	}

	sprintf (mapDevice, "truecrypt%d", devNo);

	pipe (pfd);
	pid = fork ();

	if (pid == -1)
	{
		perror ("fork");
		goto err;
	}
	else if (pid == 0)
	{
		SecurityCleanup ();

		close (pfd[1]);
		dup2 (pfd[0], STDIN_FILENO);

		execlp ("dmsetup", "dmsetup", "create", mapDevice, NULL);

		perror ("execlp dmsetup");
		_exit (1);
	}

	close (pfd[0]);
	w = fdopen (pfd[1], "a");
	if (w == NULL)
	{
		perror ("fdopen");
		goto err;
	}

	fprintf (w, "0 %lld truecrypt %d ", totalSectors, ci->ea);

	for (i = DISK_IV_SIZE; i < EAGetKeySize (ci->ea) + DISK_IV_SIZE; i++)
		fprintf (w, "%02x", ci->master_key[i]);

	fprintf (w, " ");

	for (i = 0; i < (int)sizeof (ci->iv); i++)
		fprintf (w, "%02x", ci->iv[i]);

	flags = 0;

	if (ReadOnly)
		flags |= FLAG_READ_ONLY;
	else if (ProtectHidden)
		flags |= FLAG_HIDDEN_VOLUME_PROTECTION;

	fprintf (w, " %s %lld %lld %lld %lld %lld %d %s\n",
		hostDevice,
		startSector,
		readOnlyStartSector,
		readOnlySectors,
		(uint64_t) modTime,
		(uint64_t) acTime,
		flags,
		volumePath);

	fclose (w);

	if (!WaitChild (FALSE, "dmsetup"))
	{
		Execute (TRUE, "dmsetup", "remove", mapDevice, NULL);
		goto err;
	}

	sprintf (mapDevice, TC_MAP_DEV "%d", devNo);

	if (Verbose >= 1)
		printf ("Mapped %s as %s\n", volumePath, mapDevice);

	// Mount
	if (mountPoint)
	{
		char fstype[64], opts[128];

		strcpy (fstype, "-t");
		if (Filesystem)
			strncat (fstype, Filesystem, sizeof (fstype) - 3);
		else
			strcat (fstype, "auto");

		strcpy (opts, ReadOnly ? "-oro" : "-orw");
		if (MountOpts)
		{
			strcat (opts, ",");
			strncat (opts, MountOpts, sizeof (opts) - 6);
		}

		if (!Execute (FALSE, "mount", fstype, opts, mapDevice, mountPoint, NULL))
		{
			error ("Mount failed\n");
			loopDevNo = -1;
			goto err;
		}

		if (Verbose >= 1)
			printf ("Mounted %s at %s\n", mapDevice, mountPoint);
	}

	crypto_close (ci);

	return TRUE;

err:
	if (ci)
		crypto_close (ci);

	if (loopDevNo != -1)
		DeleteLoopDevice (loopDevNo);

	UnloadKernelModule (TRUE);

	return FALSE;
}


static void DumpVersion (FILE *f)
{
	fprintf (f, 
"truecrypt %s\n\n"
"Copyright (C) 2004-2005 TrueCrypt Foundation. All Rights Reserved.\n\
Copyright (C) 1998-2000 Paul Le Roux. All Rights Reserved.\n\
Copyright (C) 2004 TrueCrypt Team. All Rights Reserved.\n\
Copyright (C) 1995-1997 Eric Young. All Rights Reserved.\n\
Copyright (C) 1999-2004 Dr. Brian Gladman. All Rights Reserved.\n\
Copyright (C) 2001 Markus Friedl. All Rights Reserved.\n\n"
	, VERSION_STRING);
}


static void DumpUsage (FILE *f)
{
	fprintf (f,
"Usage: truecrypt [OPTIONS] VOLUME_PATH [MOUNT_DIRECTORY]\n"
"   or: truecrypt [OPTIONS] -d | --dismount | -l | --list [MAPPED_VOLUME]\n"
"   or: truecrypt -h | --help | --test | -V | --version\n"
"\nCommands:\n"
" VOLUME_PATH                         Map volume\n"
" VOLUME_PATH MOUNT_DIRECTORY         Map and mount volume\n"
" -d, --dismount [MAPPED_VOLUME]      Dismount and unmap volume\n"
" -h, --help                          Display help\n"
" -l, --list [MAPPED_VOLUME]          List mapped volumes\n"
"     --test                          Test algorithms\n"
" -V, --version                       Display version information\n"
"\nOptions:\n"
"     --device-number NUMBER          Map volume as device number\n"
"     --display-password              Display password while typing\n"
"     --filesystem TYPE               Filesystem type to mount\n"
" -k, --keyfile FILE|DIR              Keyfile for volume\n"
" -K, --keyfile-protected FILE|DIR    Keyfile for protected volume\n"
" -p, --password PASSWORD             Password for volume\n"
"     --password-tries NUMBER         Password entry tries\n"
" -P, --protect-hidden                Protect hidden volume\n"
"     --update-time                   Do not preserve timestamps\n"
" -r, --read-only                     Map/Mount read-only\n"
"     --mount-options OPTIONS         Mount options\n"
" -v, --verbose                       Verbose output\n"
"\n MAPPED_VOLUME = DEVICE_NUMBER | DEVICE_NAME | MOUNT_POINT | VOLUME_PATH\n"
"For a detailed help use --help or see truecrypt(1) man page.\n"
);
}

static void DumpHelp ()
{
	fprintf (stdout,
"Manages encrypted TrueCrypt volumes, which can be mapped as virtual block\n"
"devices and used as any other standard block device. All data being read\n"
"from a mapped TrueCrypt volume is transparently decrypted and all data being\n"
"written to it is transparently encrypted.\n"
"\n"
"Usage: truecrypt [OPTIONS] VOLUME_PATH [MOUNT_DIRECTORY]\n"
"   or: truecrypt [OPTIONS] -d | --dismount | -l | --list [MAPPED_VOLUME]\n"
"   or: truecrypt -h | --help | --test | -V | --version\n"
"\n"
"Options:\n"
"\n"
"VOLUME_PATH [MOUNT_DIRECTORY]\n"
" Open a TrueCrypt volume specified by VOLUME_PATH and map it as a block device\n"
" /dev/mapper/truecryptN. N is the first available device number if not\n"
" otherwise specified with --device-number. The filesystem of the mapped volume\n"
" is mounted at MOUNT_DIRECTORY if specified.\n"
"\n"
"-d, --dismount [MAPPED_VOLUME]\n"
" Dismount and unmap mapped volumes. If MAPPED_VOLUME is not specified, all\n"
" volumes are dismounted and unmapped. See below for a description of\n"
" MAPPED_VOLUME.\n"
"\n"
"-l, --list [MAPPED_VOLUME]\n"
" Display a list of mapped volumes. If MAPPED_VOLUME is not specified, all\n"
" volumes are listed. By default, the list contains only volume path and mapped\n"
" device name pairs. A more detailed list can be enabled by verbose output\n"
" option (-v). See below for a description of MAPPED_VOLUME.\n"
"\n"
"MAPPED_VOLUME\n"
" Specifies a mapped or mounted volume. One of the following forms can be used:\n\n"
" 1) Path to the encrypted TrueCrypt volume.\n\n"
" 2) Mount directory of the volume's filesystem (if mounted).\n\n"
" 3) Device number of the mapped volume.\n\n"
" 4) Device name of the mapped volume.\n\n"
"\n"
"--device-number N\n"
" Use device number N when mapping a volume as a block device\n"
" /dev/mapper/truecryptN. Default is the first available device.\n"
"\n"
"--display-password\n"
" Display password characters while typing.\n"
"\n"
"--filesystem TYPE\n"
" Filesystem type to mount. The TYPE argument is passed to mount(8) command\n"
" with option -t. Default type is 'auto'.\n"
"\n"
"-h, --help\n"
" Display help information.\n"
"\n"
"-k, --keyfile FILE | DIRECTORY\n"
" Use specified keyfile to open a volume to be mapped. When a directory is\n"
" specified, all files inside it will be used (non-recursively). Additional\n"
" keyfiles can be specified with multiple -k options. See also option -K.\n"
"\n"
"-K, --keyfile-protected FILE | DIRECTORY\n"
" Use specified keyfile to open a hidden volume to be protected. See also\n"
" options -k and -P.\n"
"\n"
"--mount-options OPTIONS\n"
" Filesystem mount options. The OPTIONS argument is passed to mount(8)\n"
" command with option -o.\n"
" \n"
"-p, --password PASSWORD\n"
" Use specified password to open a volume. Additional passwords can be\n"
" specified with multiple -p options. An empty password can also be specified\n"
" (\"\" in most shells). Note that passing a password on the command line is\n"
" potentially insecure as the password may be visible in the process list\n"
" (see ps(1)) and/or stored in a command history file. \n"
" \n"
"--password-tries NUMBER\n"
" Prompt NUMBER of times for a password until the correct password is entered.\n"
" Default is to prompt three times.\n"
"\n"
"-P, --protect-hidden\n"
" Write-protect a hidden volume when mapping an outer volume. Before mapping the\n"
" outer volume, the user will be prompted for a password to open the hidden\n"
" volume. The size and position of the hidden volume is then determined and the\n"
" outer volume is mounted with all sectors belonging to the hidden volume\n"
" protected against write operations. When a write to the protected area is\n"
" prevented, the whole volume is switched to read-only mode. Verbose list command\n"
" (-vl) can be used to query the state of the hidden volume protection. Warning\n"
" message is displayed when a volume switched to read-only is being dismounted.\n"
" See also option -r.\n"
" \n"
"-r, --read-only\n"
" Map and/or mount a volume as read-only. Write operations to the volume may not\n"
" fail immediately due to the write buffering performed by the system, but the\n"
" physical write will still be prevented.\n"
" \n"
"--test\n"
" Test all internal algorithms used in the process of encryption and decryption.\n"
"\n"
"--update-time\n"
" Do not preserve access and modification timestamps of volume containers and\n"
" access timestamps of keyfiles. By default, timestamps are restored after\n"
" a volume is unmapped or after a keyfile is closed.\n"
"\n"
"-v, --verbose\n"
" Enable verbose output. Multiple -v options can be specified to increase the\n"
" level of verbosity.\n"
"\n"
"-V, --version\n"
" Display version information.\n"
"\n"
"Examples:\n"
"\n"
"truecrypt /root/volume.tc /mnt/tc\n"
" Map a volume /root/volume.tc and mount its filesystem at /mnt/tc.\n"
"\n"
"truecrypt -d\n"
" Dismount and unmap all mapped volumes.\n"
"  \n"
"truecrypt -d /root/volume.tc\n"
" Dismount and unmap a volume /root/volume.tc.\n"
"\n"
"truecrypt -d /mnt/tc\n"
" Dismount and unmap a volume mounted at /mnt/tc.\n"
"\n"
"truecrypt -vl\n"
" Display a detailed list of all mapped volumes.\n"
" \n"
"truecrypt --device-number=1 /dev/hdc1 && mkfs /dev/mapper/truecrypt1\n"
" Map a volume /dev/hdc1 and create a new filesystem on it.\n"
"\n"
"truecrypt -P /dev/hdc1 /mnt/tc\n"
" Map and mount outer volume /dev/hdc1 and protect hidden volume within it.\n"
"\n"
"truecrypt -p \"\" -p \"\" -k key1 -k key2 -K key_hidden -P volume.tc\n"
" Map outer volume ./volume.tc and protect hidden volume within it.\n"
" The outer volume is opened with keyfiles ./key1 and ./key2 and the\n"
" hidden volume with ./key_hidden. Passwords for both volumes are empty.\n"
"\n"
"Report bugs at <http://www.truecrypt.org/bugs>.\n"
	);
}

static BOOL DumpMountList (int devNo)
{
	int i;

	if (!CheckKernelModuleVersion (FALSE))
		return FALSE;

	if (!GetMountList ())
		return FALSE;

	for (i = 0; MountList[i].DeviceNumber != -1; i++)
	{
		MountListEntry *e = &MountList[i];

		if (devNo != -1 && e->DeviceNumber != devNo)
			continue;

		if (Verbose == 0)
		{
			printf (TC_MAP_DEV "%d %s\n",
				e->DeviceNumber,
				e->VolumePath);
		}
		else
		{
			char eaName[128];
			EAGetName (eaName, e->EA);

			printf (TC_MAP_DEV "%d:\n"
					" Volume: %s\n"
					" Type: %s\n"
					" Size: %lld bytes\n"
					" Encryption algorithm: %s\n"
					" Read-only: %s\n"
					" Hidden volume protected: %s\n\n",
				e->DeviceNumber,
				e->VolumePath,
				e->Hidden ? "Hidden" : "Normal",
				e->VolumeSize,
				eaName,
				(e->Flags & FLAG_READ_ONLY) ? "Yes" : "No",
				(e->Flags & FLAG_PROTECTION_ACTIVATED) ? "Yes - damage prevented" : (
					(e->Flags & FLAG_HIDDEN_VOLUME_PROTECTION) ? "Yes" : "No" )
				);
		}
	}

	return TRUE;
}


static BOOL EnumMountPoints (char *device, char *mountPoint)
{
	static FILE *m = NULL;

	if (device == NULL)
	{
		fclose (m);
		m = NULL;
		return TRUE;
	}

	if (m == NULL)
	{
		m = fopen ("/proc/mounts", "r");
		if (m == NULL)
		{
			perror ("fopen /proc/mounts");
			return FALSE;
		}
	}

	if (fscanf (m, "%" MAX_PATH_STR "s %" MAX_PATH_STR "s %*s %*s %*s %*s",
		device, mountPoint) != 2)
	{
		fclose (m);
		m = NULL;
		return FALSE;
	}

	return TRUE;
}


static BOOL DismountFileSystem (char *device)
{
	char mountedDevice[MAX_PATH], mountPoint[MAX_PATH];
	BOOL result = TRUE;

	while (EnumMountPoints (mountedDevice, mountPoint))
	{
		if (strcmp (mountedDevice, device) == 0)
		{
			if (!Execute (FALSE, "umount", mountPoint, NULL))
				result = FALSE;
			else if (Verbose >= 1)
				printf ("Dismounted %s\n", mountPoint);
		}
	}

	return result;
}


// devNo: -1 = Dismount all volumes
static BOOL DismountVolume (int devNo)
{
	char mapDevice[MAX_PATH];
	int nMountedVolumes = 0;
	int i;
	BOOL found = FALSE;
	BOOL status = TRUE;

	if (!CheckKernelModuleVersion (FALSE))
		return FALSE;

	if (!GetMountList ())
		return FALSE;

	if (devNo == -1 && MountList[0].DeviceNumber == -1)
	{
		error ("No volumes mounted\n");
		return FALSE;
	}

	// Flush write buffers before dismount if there are
	// mounted volumes with hidden volume protection 
	for (i = 0; MountList[i].DeviceNumber != -1; i++)
	{
		if (MountList[i].Flags & FLAG_HIDDEN_VOLUME_PROTECTION)
		{
			sync ();
			MountListValid = FALSE;
			GetMountList ();
			break;
		}
	}

	for (i = 0; MountList[i].DeviceNumber != -1; i++)
	{
		MountListEntry *e = &MountList[i];
		nMountedVolumes++;

		if (devNo == -1 || e->DeviceNumber == devNo)
		{
			BOOL dismounted = FALSE;
			found = TRUE;

			if (e->Flags & FLAG_PROTECTION_ACTIVATED)
				printf ("WARNING: Write to the hidden volume %s has been prevented!\n", e->VolumePath);

			sprintf (mapDevice, TC_MAP_DEV "%d", e->DeviceNumber);
			if (DismountFileSystem (mapDevice))
			{
				char name[32];
				sprintf (name, "truecrypt%d", e->DeviceNumber);
				dismounted = Execute (FALSE, "dmsetup", "remove", name, NULL);

				if (dismounted && IsFile (e->VolumePath))
				{
					if (!DeleteLoopDevice (e->DeviceMinor))
						status = FALSE;

					RestoreFileTime (e->VolumePath,
						UpdateTime ? time (NULL) : (time_t) e->ModTime,
						UpdateTime ? time (NULL) : (time_t) e->AcTime);
				}
			}

			if (!dismounted)
			{
				error ("Cannot dismount %s\n", mapDevice);
				status = FALSE;
			}
			else
			{
				nMountedVolumes--;
				if (Verbose >= 1)
					printf ("Unmapped %s\n", mapDevice);
			}

			if (devNo != -1)
				break;
		}
	}

	if (!found)
	{
		error (TC_MAP_DEV "%d not mounted\n", devNo);
		return FALSE;
	}

	if (nMountedVolumes == 0)
	{
		// Ignore errors as volumes may be mounted asynchronously
		UnloadKernelModule (TRUE);
	}

	return status;
}


// Convert a string to device number
// text: device number or name or mount point
BOOL ToDeviceNumber (char *text, int *deviceNumber)
{
	char mountedDevice[MAX_PATH], mountPoint[MAX_PATH];
	int i;

	if (sscanf (text, "%d", deviceNumber) == 1)
		return TRUE;

	if (sscanf (text, TC_MAP_DEV "%d", deviceNumber) == 1)
		return TRUE;

	while (EnumMountPoints (mountedDevice, mountPoint))
	{
		if (strcmp (mountPoint, text) == 0
			&& sscanf (mountedDevice, TC_MAP_DEV "%d", deviceNumber) == 1)
		{
			EnumMountPoints (NULL, NULL);
			return TRUE;
		}
	}

	if (!GetMountList ())
		return FALSE;

	for (i = 0; MountList[i].DeviceNumber != -1; i++)
	{
		MountListEntry *e = &MountList[i];
		if (e->DeviceNumber == -1)
			break;

		if (strcmp (text, e->VolumePath) == 0)
		{
			*deviceNumber = e->DeviceNumber;
			return TRUE;
		}
	}

	error ("%s not mounted\n", text);
	return FALSE;
}


int main(int argc, char **argv)
{
	char *volumePath = NULL;
	char *mountPoint = NULL;
	char volumePathBuf[MAX_PATH];
	int i, o;
	int optIndex = 0;

	struct option longOptions[] = {
		{"device-number", required_argument, 0, 0},
		{"dismount", optional_argument, 0, 'd'},
		{"display-password", 0, 0, 0},
		{"keyfile", required_argument, 0, 'k'},
		{"keyfile-protected", required_argument, 0, 'K'},
		{"filesystem", required_argument, 0, 0},
		{"list", 0, 0, 'l'},
		{"help", 0, 0, 'h'},
		{"mount-options", required_argument, 0, 0},
		{"password", required_argument, 0, 'l'},
		{"password-tries", required_argument, 0, 0},
		{"protect-hidden", 0, 0, 'P'},
		{"read-only", 0, 0, 'r'},
		{"test", 0, 0, 0},
		{"update-time", 0, 0, 0},
		{"verbose", 0, 0, 'v'},
		{"version", 0, 0, 'V'},
		{0, 0, 0, 0}
	};

	if (getuid () != 0 && geteuid () != 0)
	{
		error ("administrator (root) privileges required\n");
		return FALSE;
	}

	if (mlockall (MCL_FUTURE) != 0)
		perror ("Cannot prevent memory swapping: mlockall");

	signal (SIGHUP, OnSignal);
	signal (SIGINT, OnSignal);
	signal (SIGQUIT, OnSignal);
	signal (SIGABRT, OnSignal);
	signal (SIGPIPE, OnSignal);
	signal (SIGTERM, OnSignal);

	atexit (OnExit);

	while ((o = getopt_long (argc, argv, "dhk:K:lp:PrvV", longOptions, &optIndex)) != -1)
	{
		switch (o)
		{
		case 'd':
			// Dismount
			{
				int devNo;

				if (optind < argc)
				{
					if (!ToDeviceNumber (argv[optind++], &devNo))
						return 1;

					if (optind < argc)
						goto usage;
				}
				else
					devNo = -1;

				return DismountVolume (devNo) ? 0 : 1;
			}

		case 'l':
			// List
			{
				int devNo;

				if (optind < argc)
				{
					if (!ToDeviceNumber (argv[optind++], &devNo))
						return 1;

					if (optind < argc)
						goto usage;
				}
				else
					devNo = -1;

				return DumpMountList (devNo) ? 0 : 1;
			}

		case 'k':
		case 'K':
			// Keyfile
			{
				KeyFile *kf = malloc (sizeof (KeyFile));
				if (!kf)
				{
					perror ("malloc");
					return 1;
				}
				strncpy (kf->FileName, optarg, sizeof (kf->FileName));
				if (o == 'k')
					FirstKeyFile = KeyFileAdd (FirstKeyFile, kf);
				else
					FirstProtVolKeyFile = KeyFileAdd (FirstProtVolKeyFile, kf);
			}
			break;


		case 'p':
			// Password
			if (!CmdPasswordValid)
			{
				strncpy (CmdPassword.Text, optarg, sizeof (CmdPassword.Text));
				CmdPassword.Length = strlen (CmdPassword.Text);
				CmdPasswordValid = TRUE;
			}
			else if (!CmdPassword2Valid)
			{
				strncpy (CmdPassword2.Text, optarg, sizeof (CmdPassword2.Text));
				CmdPassword2.Length = strlen (CmdPassword2.Text);
				CmdPassword2Valid = TRUE;
			}
			break;

		case 'P':
			// Hidden volume protection
			ProtectHidden = TRUE;
			break;

		case 'r':
			ReadOnly = TRUE;
			break;

		case 'v':
			// Verbose
			Verbose++;
			break;

		case 'V':
			DumpVersion (stdout);
			return 0;

		case 'h':
			// Help
			DumpHelp ();
			return 0;

		case 0:
			if (strcmp ("display-password", longOptions[optIndex].name) == 0)
			{
				DisplayPassword = TRUE;
				break;
			}

			if (strcmp ("device-number", longOptions[optIndex].name) == 0)
			{
				if (sscanf (optarg, "%d", &UseDeviceNumber) == 1
					&& UseDeviceNumber >= 0)
					break;
				else
					goto usage;
			}

			if (strcmp ("filesystem", longOptions[optIndex].name) == 0)
			{
				Filesystem = optarg;
				break;
			}

			if (strcmp ("mount-options", longOptions[optIndex].name) == 0)
			{
				MountOpts = optarg;
				break;
			}

			if (strcmp ("password-tries", longOptions[optIndex].name) == 0)
			{
				if (sscanf (optarg, "%d", &PasswordEntryTries) == 1)
					break;
				else
					goto usage;
			}
			
			if (strcmp ("test", longOptions[optIndex].name) == 0)
			{
				if (AutoTestAlgorithms ())
				{
					printf ("Self-tests of all algorithms passed.\n");
					return 0;
				}

				printf ("Self-tests of algorithms FAILED!\n");
				return 1;
			}

			if (strcmp ("update-time", longOptions[optIndex].name) == 0)
			{
				UpdateTime = TRUE;
				break;
			}
			goto usage;

		default:
			goto usage;
		}
	}
	
	if (optind >= argc)
		goto usage;

	if (optind < argc)
		volumePath = argv[optind++];

	if (optind < argc)
		mountPoint = argv[optind++];

	if (optind < argc)
		goto usage;

	// Relative path => absolute
	if (volumePath[0] != '/')
	{
		char s[MAX_PATH];
		getcwd (s, sizeof (s));
		snprintf (volumePathBuf, sizeof (volumePathBuf), "%s/%s", s, volumePath);
		volumePath = volumePathBuf;
	}

	return MountVolume (volumePath, mountPoint) == FALSE;

usage:
	DumpUsage (stderr);

	return 1;
}
