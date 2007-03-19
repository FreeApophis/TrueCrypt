/*
 Copyright (c) TrueCrypt Foundation. All rights reserved.

 Covered by the TrueCrypt License 2.2 the full text of which is contained
 in the file License.txt included in TrueCrypt binary and source code
 distribution packages.
*/

#define _LARGEFILE_SOURCE	1
#define _FILE_OFFSET_BITS	64

#include <errno.h>
#include <getopt.h>
#include <inttypes.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/utsname.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <termios.h>
#include <time.h>
#include <unistd.h>
#include <utime.h>

#include "Tcdefs.h"
#include "Crc.h"
#include "Dm-target.h"
#include "Keyfiles.h"
#include "Fat.h"
#include "Format.h"
#include "Password.h"
#include "Progress.h"
#include "Random.h"
#include "Volumes.h"
#include "Tests.h"

#include "Cli.h"

static MountListEntry MountList[TC_MAX_VOLUMES];
static BOOL MountListValid = FALSE;

static FILE *MiceDevice = NULL;
static int MiceDeviceErrNo;

static BOOL DisplayKeys = FALSE;
static BOOL DisplayPassword = FALSE;
static BOOL DisplayProgress = TRUE;
static BOOL UserMount = FALSE;
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
static BOOL Interactive = FALSE;
static BOOL Overwrite = FALSE;
static int Verbose = 0;

static BOOL	IsTerminal = FALSE;
static struct termios TerminalAttributes;
static Password password;
static KeyFile *FirstKeyFile;
static KeyFile *FirstProtVolKeyFile;
static KeyFile *FirstNewKeyFile;
static BOOL NoKeyFiles = FALSE;
static BOOL NoNewKeyFiles = FALSE;

static unsigned long long VolumeSize;
static unsigned int ClusterSize = 0;
static int EA;
static int EAMode;
static int HashAlgorithm;
static char *Filesystem;
static int VolumeType = -1;
static BOOL Quick;
static char *RandomSource = NULL;

static uid_t RealUserId;
static gid_t RealGroupId;
static int LastExitStatus;


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


static BOOL CheckAdminPrivileges ()
{
	char *env;

	if (getuid () != 0 && geteuid () != 0)
	{
		error ("Administrator (root) privileges required\n");
		return FALSE;
	}

	if (getuid () != 0)
	{
		// Impersonate root to support execution of commands like mount
		setuid (0);

		// Allow execution of system binaries only
		setenv ("PATH", "/usr/sbin:/sbin:/usr/bin:/bin", 1);
	}

	return TRUE;
}


static void DropEffectiveUserId ()
{
	setuid (getuid ());
}


static BOOL LockMemory ()
{
	// Lock process memory
	if (mlockall (MCL_FUTURE) != 0)
	{
		perror ("Cannot prevent paging of memory to disk: mlockall");
		return FALSE;
	}

	return TRUE;
}


static BOOL WaitChild (BOOL quiet, char *execName)
{
	int status;
	if (wait (&status) == -1)
	{
		perror ("wait");
		return FALSE;
	}

	LastExitStatus = WEXITSTATUS (status);

	if (!WIFEXITED (status)
		|| (WIFEXITED (status) && WEXITSTATUS (status)))
	{
		if (!quiet && Verbose >= 3)
			error ("Error: %s returned %d\n", execName, WEXITSTATUS (status));
		return FALSE;
	}

	return TRUE;
}


static BOOL Execute (BOOL quiet, char *execName, ...)
{
	int pid;
	va_list vl;
	va_start (vl, execName);

	LastExitStatus = -1;

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

		fprintf (stderr, "(%s) ", execName);
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

	if (!Execute (TRUE, "modprobe", "truecrypt", NULL))
	{
		struct utsname u;
		char module[128];
		int r1, r2, r3;
		char *p;

		if (!Execute (TRUE, "modprobe", "dm-mod", NULL))
			Execute (TRUE, "modprobe", "dm", NULL);

		if (uname (&u) == 0 && sscanf (u.release, "%d.%d.%d", &r1, &r2, &r3) == 3)
		{
			sprintf (module, "%s/truecrypt.ko", TC_SHARE_KERNEL, r1, r2, r3);
			if (IsFile (module) && Execute (TRUE, "insmod", module, NULL))
				return TRUE;

			sprintf (module, "%s/truecrypt-%d.%d.%d.ko", TC_SHARE_KERNEL, r1, r2, r3);
			if (IsFile (module) && Execute (FALSE, "insmod", module, NULL))
				return TRUE;
		}

		Execute (FALSE, "modprobe", "truecrypt", NULL);
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


static BOOL CheckKernelModuleVersion (BOOL wait, BOOL quiet)
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

				if (ver1 == TC_VERSION_NUM1 && ver2 == TC_VERSION_NUM2 && ver3 == TC_VERSION_NUM3)
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

	if (!quiet)
		error ("Kernel module not loaded\n");

	return FALSE;
}


static void OpenMiceDevice ()
{
	if (!MiceDevice)
	{
		FILE *m;
		char s[2048];

		m = fopen ("/proc/bus/input/devices", "r");
		if (m != NULL)
		{
			BOOL found = FALSE;
			while (fgets (s, sizeof (s), m))
			{
				if (strstr (s, "mouse") || strstr (s, "Mouse") || strstr (s, "MOUSE"))
				{
					found = TRUE;
					break;
				}
			}

			fclose (m);
			if (!found)
				return;
		}

		MiceDevice = fopen (TC_MICE_DEVICE, "rb");
		MiceDeviceErrNo = errno;
	}
}


static BOOL GetMountList (BOOL force)
{
	FILE *p;
	int pfd[2];
	int pid, res;
	int i, dummy;

	if (!force && MountListValid)
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

	for (i = 0; i < TC_MAX_VOLUMES; i++)
	{
		int n = 0;
		char s[2048];
		MountListEntry *e = &MountList[i];

		if (!fgets (s, sizeof (s), p))
			break;

		if (sscanf (s, "truecrypt%d: 0 %llu truecrypt %d %d 0 0 %d:%d %llu %llu %llu %llu %llu %llu %d %n",
			&e->DeviceNumber,
			&e->VolumeSize,
			&e->EA,
			&e->Mode,
			&e->DeviceMajor,
			&e->DeviceMinor,
			&e->Hidden,
			&e->ReadOnlyStart,
			&e->ReadOnlyEnd,
			&e->UserId,
			&e->ModTime,
			&e->AcTime,
			&e->Flags,
			&n) >= 12 && n > 0)
		{
			int l;
			strncpy (e->VolumePath, s + n, sizeof (e->VolumePath));
			l = strlen (s + n);
			if (l > 0)
				e->VolumePath[l - 1] = 0;

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
	if (!GetMountList (FALSE))
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

	if (!GetMountList (FALSE))
		return -1;

	for (n = 0; n < TC_MAX_MINOR; n++)
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
	int i;

	sprintf (dev, TC_LOOP_DEV "%d", loopDeviceNo);
	if (!IsBlockDevice (dev))
		sprintf (dev, TC_LOOP_DEV "/%d", loopDeviceNo);

	for (i = 0; i < 10; i++)
	{
		r = Execute (TRUE, "losetup", "-d", dev, NULL);
		if (r)
			break;

		usleep (200 * 1000);
	}

	if (r && Verbose > 1)
		printf ("Detached %s\n", dev);

	if (!r)
		error ("Failed to detach %s\n", dev);

	return r;
}


static int AskSelection (int defaultChoice, int min, int max)
{
	int c;
	char s[10];

	while (1)
	{
		printf ("Select [%d]: ", defaultChoice);

		if (fgets (s, sizeof (s), stdin) && sscanf (s, "%d", &c) == 1)
		{
			if (c < min || c > max)
				continue;

			puts ("");
			return c;
		}

		if (s[0] != 0 && s[0] != '\n')
			continue;

		puts ("");
		return defaultChoice;
	}
}


static BOOL AskYesNo (char *prompt, BOOL defaultNo)
{
	char s[4];

	do
	{
		printf ("%s [%c/%c]: ", prompt, defaultNo ? 'y' : 'Y', defaultNo ? 'N' : 'n');
		fgets (s, sizeof(s), stdin);

		if (s[0] == 'y' || s[0] == 'Y')
			return TRUE;

		if (s[0] == 'n' || s[0] == 'N')
			return FALSE;

	} while (s[0] != '\n');

	return !defaultNo;
}


static char *AskString (char *prompt, char *buf, int maxSize)
{
	printf ("%s: ", prompt);

	if (fgets (buf, maxSize, stdin))
	{
		char *lf = strchr (buf, '\n');
		if (lf)
			lf[0] = 0;

		return buf;
	}

	return NULL;
}


static BOOL ValidatePassword (Password *password)
{
	int i;

	if (password->Length > MAX_PASSWORD)
	{
		error ("Maximum password length is %d characters\n", MAX_PASSWORD);
		return FALSE;
	}

	for (i = 0; i < password->Length; i++)
	{
		if (password->Text[i] >= 0x7f || password->Text[i] < 0x20)
		{
			error ("Password must be composed only of US-ASCII printable characters\n");
			return FALSE;
		}
	}

	return TRUE;
}


static void AskPassword (char *prompt, char *volumePath, Password *password)
{
	struct termios noEcho;
	char pw[2048];

	if (tcgetattr (0, &TerminalAttributes) == 0)
	{
		noEcho = TerminalAttributes;

		if (!DisplayPassword)
		{
			noEcho.c_lflag &= ~ECHO;
			if (tcsetattr (0, TCSANOW, &noEcho) != 0)
				error ("Failed to turn terminal echo off\n");
		}
	}

	while (TRUE)
	{
		char *newl;
		
		if (IsTerminal)
			printf (prompt, volumePath);

		if (!fgets (pw, sizeof (pw), stdin))
		{
			password->Length = 0;
			break;
		}

		newl = strchr (pw, '\n');
		if (newl) newl[0] = 0;

		strncpy ((char *)password->Text, pw, sizeof (password->Text));
		password->Length = strlen ((char *)password->Text);

		if (ValidatePassword (password))
			break;
	}

	burn(pw, sizeof (pw));

	if (IsTerminal && !DisplayPassword)
	{
		tcsetattr (0, TCSANOW, &TerminalAttributes);
		puts ("");
	}
}


static char *AskVolumePath (char *volumePath, char *prompt)
{
	static char path[TC_MAX_PATH];

	// Volume path
	while (!volumePath || !volumePath[0])
	{
		volumePath = AskString (prompt, path, sizeof (path));
	}

	return volumePath;
}


static BOOL AskKeyFiles (char *prompt, KeyFile **firstKeyFile)
{
	char path[TC_MAX_PATH];
	char lprompt[128];

	snprintf (lprompt, sizeof(lprompt), "%s [none]", prompt); 
	while (AskString (lprompt, path, sizeof (path)) && path[0] != 0)
	{
		KeyFile *kf = malloc (sizeof (KeyFile));
		if (!kf)
		{
			perror ("malloc");
			return FALSE;
		}
		strncpy (kf->FileName, path, sizeof (kf->FileName));
		*firstKeyFile = KeyFileAdd (*firstKeyFile, kf);

		snprintf (lprompt, sizeof(lprompt), "%s [finish]", prompt); 
	}

	return TRUE;
}


static BOOL OpenVolume (char *volumePath, char *prompt, char *promptArg, BOOL secondaryPassword, PCRYPTO_INFO *cryptoInfo, unsigned long long *startSector, unsigned long long *totalSectors, time_t *modTime, time_t *acTime)
{
	char header[SECTOR_SIZE];
	FILE *f = NULL;
	struct stat volumeStat;
	int tries = PasswordEntryTries;
	char msg[128];
	BOOL ret = FALSE;
	int r;

	memset (&volumeStat, 0, sizeof (volumeStat));
	if ((!UpdateTime || ReadOnly)
		&& IsFile (volumePath) && stat (volumePath, &volumeStat) != 0)
	{
		perror ("Cannot open volume");
		volumeStat.st_ctime = 0;
		goto err;
	}

	f = fopen (volumePath, "rb");
	if (!f)
	{
		perror ("Cannot open volume");
		goto err;
	}

	do
	{
		Password *pw = &password;

		if (!secondaryPassword && !CmdPasswordValid || (secondaryPassword && !CmdPassword2Valid))
			AskPassword (prompt, promptArg, &password);
		else
			pw = secondaryPassword ? &CmdPassword2 : &CmdPassword;

		if ((!secondaryPassword
				&& FirstKeyFile
				&& !KeyFilesApply (pw, FirstKeyFile, !UpdateTime))
			|| (secondaryPassword 
				&& FirstProtVolKeyFile
				&& !KeyFilesApply (pw, FirstProtVolKeyFile, !UpdateTime)))
		{
			error ("Error while processing keyfiles\n");
			goto err;
		}

		// Normal header
		fseek (f, 0, SEEK_SET);
		if (fread (header, 1, SECTOR_SIZE, f) != SECTOR_SIZE)
		{
			perror ("Cannot read volume header");
			goto err;
		}

		if (fseek (f, 0, SEEK_END) == -1)
		{
			perror ("Cannot determine volume size");
			goto err;
		}

		r = VolumeReadHeader (header, pw, cryptoInfo);

		if (r == 0)
		{
			*totalSectors = ftello (f) / SECTOR_SIZE - 1;
			*startSector = 1;
			ret = TRUE;
			break;
		}

		if (r == ERR_PASSWORD_WRONG)
		{
			// Hidden header
			if (fseek (f, -HIDDEN_VOL_HEADER_OFFSET, SEEK_END) == -1
				|| fread (header, 1, SECTOR_SIZE, f) != SECTOR_SIZE)
			{
				perror ("Cannot read hidden volume header");
				if (IsFile (volumePath))
					error ("Please check the filesystem supports files larger than 2GB.\n");
				goto err;
			}

			r = VolumeReadHeader (header, pw, cryptoInfo);

			if (r == 0)
			{
				*startSector = (ftello (f) 
					+ SECTOR_SIZE * 2 
					- (*cryptoInfo)->hiddenVolumeSize 
					- HIDDEN_VOL_HEADER_OFFSET) / SECTOR_SIZE;

				*totalSectors = (*cryptoInfo)->hiddenVolumeSize / SECTOR_SIZE;
				ret = TRUE;
				break;
			}
			
			if (r == ERR_PASSWORD_WRONG)
			{
				char s[128];

				sprintf (s, "Incorrect password %sor not a TrueCrypt volume."
					, (FirstKeyFile || FirstProtVolKeyFile) ? "and/or keyfile(s) " : "");

				if (IsTerminal)
				{
					puts (s);
					continue;
				}
				else
				{
					error ("%s\n", s);
					goto err;
				}
			}
		}

		// Report errors
		switch (r)
		{
		case ERR_NEW_VERSION_REQUIRED:
			strcpy (msg, "A newer version of TrueCrypt is required to open this volume."); 
			break;

		default:
			sprintf (msg, "Volume cannot be opened: Error %d", r);
			break;
		}

		if (IsTerminal)
			printf ("%s\n", msg);
		else
			error ("%s\n", msg);

		goto err;

	} while (IsTerminal
		&& --tries > 0
		&& ((!secondaryPassword && !CmdPasswordValid)
			|| (secondaryPassword && !CmdPassword2Valid)));

	fclose (f);

	if (!UpdateTime)
		RestoreFileTime (volumePath, volumeStat.st_mtime, volumeStat.st_atime);

	*modTime = volumeStat.st_mtime;
	*acTime = volumeStat.st_atime;

	return ret;

err:
	*cryptoInfo = NULL;

	if (f)
		fclose (f);

	if (volumeStat.st_ctime != 0 && !UpdateTime)
		RestoreFileTime (volumePath, volumeStat.st_mtime, volumeStat.st_atime);

	*totalSectors = 0;
	return FALSE;
}


static char *EscapeSpaces (char *string)
{
	static char escapedString[TC_MAX_PATH * 2];
	char *e = escapedString;
	char c;

	if (strlen (string) > TC_MAX_PATH)
		return NULL;

	while ((c = *string++))
	{
		if (c == ' ')
			*e++ = '\\';

		*e++ = c;
	}

	return escapedString;
}


static BOOL IsMountPointAvailable (char *mountPoint)
{
	char md[TC_MAX_PATH], mp[TC_MAX_PATH];

	while (EnumMountPoints (md, mp))
	{
		if (strcmp (mountPoint, mp) == 0)
		{
			EnumMountPoints (NULL, NULL);
			return FALSE;
		}
	}
	return TRUE;
}


static BOOL MountVolume (char *volumePath, char *mountPoint)
{
	char hostDevice[TC_MAX_PATH];
	char mapDevice[TC_MAX_PATH];
	int loopDevNo = -1;
	PCRYPTO_INFO ci = NULL;
	unsigned long long startSector, totalSectors;
	unsigned long long readOnlyStartSector = 0, readOnlySectors = 0;
	int pfd[2];
	int pid, res, devNo;
	time_t modTime, acTime;
	FILE *f, *w;
	int flags;
	int i;
	int tries = PasswordEntryTries;

#if DEBUG
	if (!AutoTestAlgorithms ())
	{
		error ("Self-tests of algorithms FAILED!\n");
		return FALSE;
	}
#endif

	if (IsVolumeMounted (volumePath))
	{
		error ("Volume already mapped\n");
		return FALSE;
	}

	if (mountPoint && !IsMountPointAvailable (mountPoint))
	{
		error ("Mount directory %s already in use\n", mountPoint);
		return FALSE;
	}

	if (!OpenVolume (volumePath, "Enter password for '%s': ", volumePath, FALSE,
		&ci, &startSector, &totalSectors, &modTime, &acTime))
		goto err;

	if (totalSectors == 0)
	{
		error ("Illegal volume size (0 bytes).\n");
		goto err;
	}

	// Hidden volume protection
	if (ProtectHidden)
	{
		PCRYPTO_INFO ciH = NULL;
		unsigned long long startSectorH, totalSectorsH;

		if (OpenVolume (volumePath, "Enter hidden volume password: ", "", TRUE,
			&ciH, &startSectorH, &totalSectorsH, &modTime, &acTime))
		{
			readOnlyStartSector = startSectorH;
			readOnlySectors = startSectorH + totalSectorsH;
		}
		
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

		for (i = 0; i < TC_MAX_MINOR; i++)
		{
			snprintf (hostDevice, sizeof (hostDevice), TC_LOOP_DEV "%d", i);

			if (!IsBlockDevice (hostDevice))
			{
				snprintf (hostDevice, sizeof (hostDevice), TC_LOOP_DEV "/%d", i);
				if (!IsBlockDevice (hostDevice))
					continue;
			}

			if (Execute (TRUE, "losetup", hostDevice, volumePath, NULL))
				break;
		}

		if (i >= TC_MAX_MINOR)
		{
			error ("Failed to assign loopback device for file-hosted volume\n");
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

	if (!CheckKernelModuleVersion (TRUE, FALSE))
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

	fprintf (w, "0 %llu truecrypt %d %d ", totalSectors, ci->ea, ci->mode);

	for (i = DISK_IV_SIZE; i < EAGetKeySize (ci->ea) + DISK_IV_SIZE; i++)
		fprintf (w, "%02x", ci->master_key[i]);

	fprintf (w, " ");

	for (i = 0; i < (int)sizeof (ci->iv); i++)
		fprintf (w, "%02x", ci->iv[i]);

	flags = 0;

	if (ReadOnly)
		flags |= TC_READ_ONLY;
	else if (ProtectHidden)
		flags |= TC_HIDDEN_VOLUME_PROTECTION;

	fprintf (w, " %s %llu %llu %llu %llu %llu %llu %d %s\n",
		hostDevice,
		startSector,
		readOnlyStartSector,
		readOnlySectors,
		(unsigned long long) RealUserId,
		(unsigned long long) modTime,
		(unsigned long long) acTime,
		flags,
		EscapeSpaces (volumePath));

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
		char fstype[64] = "-t";
		char opts[1024];

		if (Filesystem)
			strncat (fstype, Filesystem, sizeof (fstype) - 3);
		else
			strcat (fstype, "auto");

		strcpy (opts, ReadOnly ? "-oro" : "-orw");
		if (MountOpts)
		{
			strcat (opts, ",");
			strncat (opts, MountOpts, 256);
		}

		if (RealUserId != 0)
			strcat (opts, ",nosuid");

		if (UserMount)
		{
			// Set default uid and gid
			char s[64];
			sprintf (s, ",uid=%d,gid=%d,umask=077", RealUserId, RealGroupId);
			strcat (opts, s);
		}

		if (!Execute (FALSE, "mount", fstype, opts, mapDevice, mountPoint, NULL))
		{
			int devNo;
			error ("Mount failed\n");

			if (GetMountList (TRUE) && ToDeviceNumber (mapDevice, &devNo))
                DismountVolume (devNo);
			
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



static void HexDump (unsigned __int8 *data, unsigned int length)
{
	while (length--)
		printf ("%02x", (unsigned int) *data++);
}


static uint64_t GetTimeUsec ()
{
	struct timeval tv;
	gettimeofday (&tv, NULL);

	return (uint64_t)tv.tv_sec * 1000000 + tv.tv_usec;
}


static double GetTime ()
{
	struct timeval tv;
	gettimeofday (&tv, NULL);

	return (double)tv.tv_sec + (double)tv.tv_usec / 1000000;
}



static BOOL RandFillPool ()
{
	int i;

	if (Randinit () != 0)
	{
		error ("Error while initializing the TrueCrypt random number generator.\n");
		return FALSE;
	}

	FastPoll ();

	if (IsTerminal && !RandomSource)
	{
		puts ("TrueCrypt will now collect random data.");

		if (MiceDevice != NULL)
		{
			if (AskYesNo ("\nIs your mouse connected directly to computer where TrueCrypt is running?", FALSE))
			{
				// Mouse
				puts ("\nPlease move the mouse randomly until the required amount of data is captured...");
				for (i = 0; i <= TC_REQUIRED_MOUSE_EVENTS; i++)
				{
					unsigned char buf[sizeof (uint64_t)];

					printf ("\rMouse data captured: %d%%  ", i * 100 / TC_REQUIRED_MOUSE_EVENTS);
					fflush (stdout);

					if (fread (buf, 1, 1, MiceDevice) != 1)
					{
						perror ("Cannot read from " TC_MICE_DEVICE);
						goto keyboard;
					}
					RandaddBuf (buf, 1);

					*(uint64_t *)buf += GetTimeUsec ();

					/* The role of CRC-32 is merely to perform diffusion. Note that the output
					of CRC-32 is subsequently processed using a cryptographically secure hash
					algorithm. */
					RandAddInt (crc32 (buf, sizeof (buf)));
				}

				if (i >= TC_REQUIRED_MOUSE_EVENTS)
				{
					puts ("\n");
					return TRUE;
				}
			}
		}
		else if (MiceDeviceErrNo == EACCES)
		{
			if (IsTerminal)
			{
				
				puts ("\nTo enable mouse movements to be used as a source of random data,\n"
					"please do one of the following:\n"
					"- Run TrueCrypt under administrator (root) account.\n"
					"- Install TrueCrypt as set-euid root.\n"
					"- Add read permission to mouse device for all users (chmod o+r " TC_MICE_DEVICE ").");
			}
		}

keyboard:
		// Keyboard
		printf ("\nPlease type at least %d randomly chosen characters and then press Enter:\n", TC_REQUIRED_KEYSTROKES);

		i = 0;
		while (1)
		{
			char buf[TC_REQUIRED_KEYSTROKES * 8];
			int l;

			if (!fgets (buf, sizeof (buf), stdin))
				return FALSE;

			l = strlen (buf) - 1;

			if (l > 0)
			{
				RandaddBuf (buf, l);
				i += l;
			}

			if (i >= TC_REQUIRED_KEYSTROKES)
				break;

			printf ("\nCharacters remaining: %d\n", TC_REQUIRED_KEYSTROKES - i);
			fflush (stdout);
		}
		puts ("");
	}
	else if (RandomSource)
	{
		// File
		char buf[RNG_POOL_SIZE];
		FILE *f = NULL;
		int r;

		if (strcmp (RandomSource, "-") != 0)
		{
			f = fopen (RandomSource, "rb");
			if (!f)
			{
				perror ("Cannot open source of random data");
				return FALSE;
			}
		}

		if ((r = fread (buf, 1, sizeof (buf), f ? f : stdin)) < 1)
		{
			error ("Cannot read from source of random data");
			if (f)
				fclose (f);
			return FALSE;
		}

		if (f)
			fclose (f);
		RandaddBuf (buf, r);
	}
	else
	{
		error ("Source of random data required (use --random-source).\n");
		return FALSE;
	}

	return TRUE;
}


static unsigned __int64 TotalSectors, StartSector;
static double StartTime;
static double LastUpdateTime;

void InitProgressBar (__int64 totalSectors)
{
	LastUpdateTime = 0;
	StartTime = GetTime ();
	TotalSectors = (unsigned __int64) totalSectors;
}


BOOL UpdateProgressBar (__int64 sector)
{
	unsigned __int64 s = (unsigned __int64) sector - StartSector;
	double t = GetTime ();
	double elapsed = t - StartTime;
	unsigned __int64 bytesDone = (s + 1) * SECTOR_SIZE;
	unsigned __int64 bytesPerSec = bytesDone / (1 + elapsed);
	int timeRemain = (int)((TotalSectors  - s) / ((s + 1)/(elapsed + 1) + 1));

	if (DisplayProgress && IsTerminal && t - LastUpdateTime > 0.2)
	{
		printf ("\rDone: %.2f MB  Speed: %.2f MB/s  Left: %d:%02d:%02d  "
			, (double)bytesDone / 1024 / 1024
			, (double)bytesPerSec / 1024 / 1024
			, timeRemain / 3600
			, (timeRemain % 3600) / 60
			, (timeRemain % 3600) % 60);

		fflush (stdout);
		LastUpdateTime = t;
	}
}


static BOOL ParseSize (char *string, unsigned long long *size)
{
	if (sscanf (string, "%llu", size) == 1)
	{
		if (strchr (string, 'k') || strchr (string, 'K'))
			*size *= 1024;
		else if (strchr (string, 'M'))
			*size *= 1024 * 1024;
		else if (strchr (string, 'G'))
			*size *= 1024 * 1024 * 1024;

		*size &= ~0x1FF;

		return TRUE;
	}
	return FALSE;
}


static BOOL CreateVolume (char *hostPath)
{
	PCRYPTO_INFO ci = NULL;
	char header[HEADER_SIZE];
	char path[TC_MAX_PATH];
	char str[128];
	FILE *f;
	fatparams ft;
	Password *pw = &password;
	unsigned long long startSector, totalSectors, hostSize;
	BOOL hiddenVolume;
	BOOL deleteOnError = FALSE;
	BOOL ret = FALSE;
	int i, r = 0;

	OpenMiceDevice ();
	DropEffectiveUserId ();

	// Volume type
	switch (VolumeType)
	{
	case VOLUME_TYPE_NORMAL:
		hiddenVolume = FALSE;
		break;

	case VOLUME_TYPE_HIDDEN:
		hiddenVolume = TRUE;
		break;

	default:
		puts ("Volume type:\n 1) Normal\n 2) Hidden");
		hiddenVolume = AskSelection (1, 1, 2) == 2;
		break;
	}

	if (hiddenVolume)
		Quick = TRUE;

	// Host file or device
	hostPath = AskVolumePath (hostPath, hiddenVolume ? "Enter volume path" : "Enter file or device path for new volume");

	if (hiddenVolume)
	{
		if (!IsFile (hostPath) && !IsBlockDevice (hostPath))
		{
			error ("File or device %s does not exist. Hidden volume cannot be created.\n", hostPath);
			return FALSE;
		}
		f = fopen (hostPath, "r+b");
	}
	else 
	{
		if (!Overwrite
			&& IsFile (hostPath) 
			&& (!IsTerminal || !AskYesNo ("Volume already exists - overwrite?", TRUE)))
		{
			if (!IsTerminal)
				error ("Volume already exists.\n");
			return FALSE;
		}
		
		if (!Overwrite
			&& IsBlockDevice (hostPath) 
			&& (!IsTerminal || !AskYesNo ("WARNING: Data on device will be lost. Continue?", TRUE)))
		{
			return FALSE;
		}

		f = fopen (hostPath, "wb");
		deleteOnError = TRUE;
	}

	if (!f)
	{
		perror ("Cannot open file or device");
		return FALSE;
	}

	EAMode = LRW;

	// Filesystem
	if (!Filesystem)
	{
		puts ("Filesystem:\n 1) FAT\n 2) None");
		Filesystem = AskSelection (1, 1, 2) == 1 ? "FAT" : "None";
	}

	// Host file/device size
	if (fseek (f, 0, SEEK_END) == -1 || (hostSize = ftello (f)) == (unsigned __int64)-1)
	{
		perror ("Cannot determine host file/device size");
		goto err;
	}

	// Volume size
	if (IsBlockDevice (hostPath) && !hiddenVolume)
	{
		if (VolumeSize != 0)
		{
			error ("Volume size cannot be changed for device-hosted volumes.\n");
			goto err;
		}

		VolumeSize = hostSize;
	}
	else if (VolumeSize == 0)
	{
		while (!AskString ("Enter volume size (bytes - size/sizeK/sizeM/sizeG)", str, sizeof (str))
			|| !ParseSize (str, &VolumeSize)
			|| VolumeSize == 0);
		puts ("");
	}

	if (hiddenVolume && VolumeSize > hostSize - MIN_VOLUME_SIZE )
	{
		error ("Outer volume too small for the size specified.\n");
		goto err;
	}

	if (strcasecmp ("FAT", Filesystem) == 0)
	{
		if (VolumeSize < MIN_VOLUME_SIZE || VolumeSize > MAX_FAT_VOLUME_SIZE)
		{
			error ("Specified volume size cannot be used with FAT filesystem.\n");
			goto err;
		}
	}

	// Hash algorithm
	if (HashAlgorithm == 0)
	{
		puts ("Hash algorithm:");

		for (i = 1; i <= LAST_PRF_ID; i++)
			printf ("%2d) %s\n", i, HashGetName (i));

		HashAlgorithm = AskSelection (1, 1, LAST_PRF_ID);
	}

	// Encryption algorithm
	if (EA == 0)
	{
		int max = 0;
		puts ("Encryption algorithm:");

		for (i = EAGetFirst (); i != 0; i = EAGetNext (i))
		{
			if (EAGetFirstMode (i) == LRW)
			{
				printf ("%2d) %s\n", i, EAGetName (str, i));
				max = i;
			}
		}

		EA = AskSelection (1, EAGetFirst (), max);
	}

	// Password
	if (!CmdPasswordValid)
	{
		while (1)
		{
			AskPassword ("Enter password for new volume '%s': ", hostPath, &password);
			if (!DisplayPassword)
			{
				Password pv;
				AskPassword ("Re-enter password%s", ": ", &pv);
				if (password.Length != pv.Length || memcmp (password.Text, pv.Text, pv.Length))
				{
					puts ("Passwords do not match.\n");
					continue;
				}
			}
			break;
		}
		puts ("");
	}
	else
		pw = &CmdPassword;

	if (!NoKeyFiles && !FirstKeyFile)
	{
		AskKeyFiles ("Enter keyfile path", &FirstKeyFile);
		puts ("");
	}
	
	if (!FirstKeyFile && pw->Length == 0)
	{
		error ("Password cannot be empty when no keyfile is specified\n");
		goto err;
	}

	if (FirstKeyFile && !KeyFilesApply (pw, FirstKeyFile, !UpdateTime))
	{
		error ("Error while processing keyfiles\n");
		goto err;
	}

	if (!RandFillPool ())
		goto err;

	// Create volume header
	r = VolumeWriteHeader (header,
		EA,
		EAMode,
		pw,
		HashAlgorithm,
		0,
		0,
		&ci,
		hiddenVolume ? VolumeSize : 0,
		FALSE);
	
	if (r == ERR_CIPHER_INIT_WEAK_KEY)
	{
		error ("A weak or a potentially weak key has been generated. Please try again.\n");
		goto err;
	}

	if (r != 0)
	{
		error ("Volume header creation failed.\n");
		goto err;
	}

	totalSectors = VolumeSize / SECTOR_SIZE;
	ci->hiddenVolumeOffset = hostSize - VolumeSize - HIDDEN_VOL_HEADER_OFFSET;
	startSector = !hiddenVolume ? 1 : (ci->hiddenVolumeOffset / SECTOR_SIZE);

	if (DisplayKeys)
	{
		printf ("Master Key: ");
		HexDump (ci->master_key, EAGetKeySize (ci->ea));
		printf ("\nSecondary Key: ");
		HexDump (ci->iv, sizeof (ci->iv));
		puts ("\n");
	}

	// Write header
	if (hiddenVolume)
	{
		if (fseek (f, -HIDDEN_VOL_HEADER_OFFSET, SEEK_END) == -1)
		{
			perror ("Cannot seek to hidden volume header location");
			goto err;
		}
	}
	else
	{
		if (fseek (f, 0, SEEK_SET) == -1)
		{
			perror ("Cannot seek to volume header location");
			goto err;
		}
	}

	if (fwrite (header, 1, HEADER_SIZE, f) != HEADER_SIZE)
	{
		perror ("Cannot write volume header");
		goto err;
	}

	InitProgressBar (totalSectors - 1);
	StartSector = startSector;

	if (Quick && !hiddenVolume && IsFile (hostPath))
		Quick = FALSE;

	if (strcasecmp ("FAT", Filesystem) == 0)
	{
		if (hiddenVolume)
		{
			if (fseeko (f, startSector * SECTOR_SIZE, SEEK_SET) == -1)
			{
				perror ("Cannot seek to hidden volume data area");
				goto err;
			}
		}

		ft.num_sectors = (unsigned int) totalSectors - 1;
		ft.cluster_size = ClusterSize;
		memcpy (ft.volume_name, "NO NAME    ", 11);
		GetFatParams (&ft); 
		r = FormatFat (startSector, &ft, f, ci, Quick);
	}
	else if (!hiddenVolume)
	{
		r = FormatNoFs (startSector, totalSectors - 1, f, ci, Quick);
	}

	if (r == ERR_OS_ERROR)
	{
		perror ("Volume creation failed");
		goto err;
	}

	if (DisplayProgress && IsTerminal)
		puts ("\nVolume created.");

	ret = TRUE;

err:
	if (ci)
		crypto_close (ci);
	if (f)
		fclose (f);
	if (!ret && deleteOnError && IsFile (hostPath))
		remove (hostPath);
	Randfree ();
	return ret;
}


static BOOL ChangePassword (char *volumePath)
{
	char header[HEADER_SIZE];
	char path[TC_MAX_PATH];
	Password *pw = &password;
	PCRYPTO_INFO ci = NULL, ci2 = NULL;
	unsigned long long startSector, totalSectors;
	time_t modTime = 0, acTime;
	int wipePass, ret = FALSE;
	int fd = -1, r;
	FILE *f;

	// Volume path
	volumePath = AskVolumePath (volumePath, "Enter volume path");

	if (!NoKeyFiles && !FirstKeyFile)
		AskKeyFiles ("Enter current keyfile path", &FirstKeyFile);

	// Open volume
	if (!OpenVolume (volumePath, "Enter current password for '%s': ", volumePath, FALSE,
			&ci, &startSector, &totalSectors, &modTime, &acTime))
		return FALSE;

	puts ("");

	// New password and/or keyfile(s)
	if (!NoNewKeyFiles && !FirstNewKeyFile)
		AskKeyFiles ("Enter new keyfile path", &FirstNewKeyFile);

	if (!CmdPassword2Valid)
	{
		while (1)
		{
			AskPassword ("Enter new password for '%s': ", volumePath, &password);
			if (!DisplayPassword)
			{
				Password pv;
				AskPassword ("Re-enter new password%s", ": ", &pv);
				if (password.Length != pv.Length || memcmp (password.Text, pv.Text, pv.Length))
				{
					puts ("Passwords do not match.\n");
					continue;
				}
			}
			break;
		}

		puts ("");
	}
	else
		pw = &CmdPassword2;
	
	if (!FirstNewKeyFile && pw->Length == 0)
	{
		error ("Password cannot be empty when no keyfile is specified\n");
		goto err;
	}

	if (FirstNewKeyFile && !KeyFilesApply (pw, FirstNewKeyFile, !UpdateTime))
	{
		error ("Error while processing new keyfiles\n");
		goto err;
	}

	fd = open (volumePath, O_RDWR | O_SYNC);
	if (fd == -1)
	{
		perror ("Cannot open file or device");
		goto err;
	}

	OpenMiceDevice ();
	if (!RandFillPool ())
		goto err;

	f = fdopen (fd, "r+b");

	// Write a new volume header
	for (wipePass = 0; wipePass < DISK_WIPE_PASSES; wipePass++)
	{
		BOOL wipeMode = wipePass < DISK_WIPE_PASSES - 1;

		if (Verbose)
		{
			printf ("\rWriting header (pass %d)%s", wipePass, wipeMode ? "" : "\n");
			fflush (stdout);
		}

		r = VolumeWriteHeader (header,
			ci->ea,
			ci->mode,
			pw,
			HashAlgorithm == 0 ? ci->pkcs5 : HashAlgorithm,
			(char *)ci->master_key,
			ci->volume_creation_time,
			&ci2,
			ci->hiddenVolumeSize,
			wipeMode);

		if (r == ERR_CIPHER_INIT_WEAK_KEY)
		{
			error ("A weak or a potentially weak key has been generated. Please try again.\n");
			goto err;
		}

		if (r != 0)
		{
			error ("Volume header creation failed.\n");
			goto err;
		}

		crypto_close (ci2);
		ci2 = NULL;

		if (ci->hiddenVolumeSize)
		{
			if (fseek (f, -HIDDEN_VOL_HEADER_OFFSET, SEEK_END) == -1)
			{
				perror ("Cannot seek to hidden volume header location");
				goto err;
			}
		}
		else
		{
			if (fseek (f, 0, SEEK_SET) == -1)
			{
				perror ("Cannot seek to volume header location");
				goto err;
			}
		}

		if (fwrite (header, 1, HEADER_SIZE, f) != HEADER_SIZE)
		{
			perror ("Cannot write volume header");
			goto err;
		}

		fflush (f);
		fdatasync (fd);
	}

	if (Verbose)
		puts ("");

	printf ("Password %schanged.\n", FirstKeyFile && FirstNewKeyFile ? "and/or keyfile(s) " : "");

	if (!FirstKeyFile && FirstNewKeyFile)
		puts ("Keyfiles added.");

	if (FirstKeyFile && !FirstNewKeyFile)
		puts ("Keyfiles removed.");

	ret = TRUE;

err:
	if (ci)
		crypto_close (ci);
	if (fd != -1)
		close (fd);

	if (!UpdateTime && modTime != 0)
		RestoreFileTime (volumePath, modTime, acTime);

	Randfree ();
	return ret;
}


static BOOL BackupVolumeHeaders (char *backupFile, char *volumePath)
{
	char path[TC_MAX_PATH];
	char header[HEADER_SIZE * 2];
	FILE *f = NULL, *fb = NULL;
	struct stat volumeStat;
	int ret = FALSE;

	DropEffectiveUserId ();

	// Volume path
	volumePath = AskVolumePath (volumePath, "Enter volume path");
	
	if (strcmp (backupFile, volumePath) == 0)
	{
		error ("Volume path identical to backup file\n");
		goto err;
	}

	volumeStat.st_mtime = 0;
	if (IsFile (volumePath) && stat (volumePath, &volumeStat) != 0)
	{
		perror ("Cannot read volume's modification and access time");
		volumeStat.st_mtime = 0;
		goto err;
	}

	// Volume
	f = fopen (volumePath, "rb");
	if (!f)
	{
		perror ("Cannot open volume");
		goto err;
	}

	if (fread (header, 1, HEADER_SIZE, f) != HEADER_SIZE)
	{
		perror ("Cannot read volume header");
		goto err;
	}
	
	if (fseek (f, -HIDDEN_VOL_HEADER_OFFSET, SEEK_END) == -1)
	{
		perror ("Cannot seek to hidden volume header location");
		goto err;
	}

	if (fread (header + HEADER_SIZE, 1, HEADER_SIZE, f) != HEADER_SIZE)
	{
		perror ("Cannot read hidden volume header");
		goto err;
	}

	// Backup file
	fb = fopen (backupFile, "wb");
	if (!fb)
	{
		perror ("Cannot open backup file");
		goto err;
	}

	if (fwrite (header, 1, HEADER_SIZE * 2, fb) != HEADER_SIZE * 2)
	{
		perror ("Cannot write backup file");
		goto err;
	}

	ret = TRUE;

err:
	if (f)
		fclose (f);
	if (f)
		fclose (fb);

	if (!UpdateTime && volumeStat.st_mtime != 0)
		RestoreFileTime (volumePath, volumeStat.st_mtime, volumeStat.st_atime);

	return ret;
}


static BOOL RestoreVolumeHeader (char *backupFile, char *volumePath)
{
	char path[TC_MAX_PATH];
	char header[HEADER_SIZE];
	FILE *f = NULL, *fb = NULL;
	struct stat volumeStat;
	int ret = FALSE;
	BOOL hiddenVolume;

	DropEffectiveUserId ();

	// Backup file
	fb = fopen (backupFile, "rb");
	if (!fb)
	{
		perror ("Cannot open backup file");
		goto err;
	}

	// Volume path
	volumePath = AskVolumePath (volumePath, "Enter volume path");

	if (strcmp (backupFile, volumePath) == 0)
	{
		error ("Volume path identical to backup file\n");
		goto err;
	}

	// Volume type
	switch (VolumeType)
	{
	case VOLUME_TYPE_NORMAL:
		hiddenVolume = FALSE;
		break;

	case VOLUME_TYPE_HIDDEN:
		hiddenVolume = TRUE;
		Quick = TRUE;
		break;

	default:
		puts ("Restore header of:\n 1) Normal/Outer Volume\n 2) Hidden Volume");
		hiddenVolume = AskSelection (1, 1, 2) == 2;
		break;
	}

	volumeStat.st_mtime = 0;
	if (IsFile (volumePath) && stat (volumePath, &volumeStat) != 0)
	{
		perror ("Cannot read volume's modification and access time");
		volumeStat.st_mtime = 0;
		goto err;
	}

	f = fopen (volumePath, "r+b");
	if (!f)
	{
		perror ("Cannot open volume");
		goto err;
	}

	if (hiddenVolume)
	{

		if (fseek (fb, HEADER_SIZE, SEEK_SET) == -1)
		{
			perror ("Cannot seek to hidden volume header location in backup file");
			goto err;
		}

		if (fseek (f, -HIDDEN_VOL_HEADER_OFFSET, SEEK_END) == -1)
		{
			perror ("Cannot seek to hidden volume header location");
			goto err;
		}
	}

	if (fread (header, 1, HEADER_SIZE, fb) != HEADER_SIZE)
	{
		perror ("Cannot read backup file");
		goto err;
	}

	if (fwrite (header, 1, HEADER_SIZE, f) != HEADER_SIZE)
	{
		perror ("Cannot write volume header");
		goto err;
	}

	ret = TRUE;

err:
	if (f)
		fclose (f);
	if (f)
		fclose (fb);

	if (!UpdateTime && volumeStat.st_mtime != 0)
		RestoreFileTime (volumePath, volumeStat.st_mtime, volumeStat.st_atime);

	return ret;
}


static BOOL CreateKeyfile (char *path)
{
	uint8_t keyFile[MAX_PASSWORD];
	FILE *f = NULL;
	int ret = FALSE;

	OpenMiceDevice ();
	DropEffectiveUserId ();

	if (!Overwrite
		&& IsFile (path) 
		&& (!IsTerminal || !AskYesNo ("Keyfile already exists - overwrite?", TRUE)))
	{
		if (!IsTerminal)
			error ("Keyfile already exists.\n");
		return FALSE;
	}

	f = fopen (path, "wb");
	if (!f)
	{
		perror ("Cannot open file");
		goto err;
	}

	if (!RandFillPool ())
		goto err;

	if (!RandgetBytes (keyFile, sizeof (keyFile), FALSE))
		goto err;

	if (fwrite (keyFile, 1, sizeof (keyFile), f) != sizeof (keyFile))
	{
		perror ("Cannot write file");
		goto err;
	}

	puts ("Keyfile created.");
	ret = TRUE;

err:
	if (f)
		fclose (f);
	Randfree ();
	return ret;
}


static time_t WindowsFileTime2UnixTime (uint64_t wTime)
{
	return (time_t) (wTime / 1000LL / 1000 / 10 - 134774LL * 24 * 3600);
}


static BOOL DumpVolumeProperties (char *volumePath)
{
	unsigned long long startSector, totalSectors;
	time_t modTime = 0, acTime;
	PCRYPTO_INFO ci = NULL;
	BOOL ret = FALSE;
	char eaName[256], timeBuf[256], timeBuf2[256];
	int keySize;
	time_t volCTime, headerMTime;

	volumePath = AskVolumePath (volumePath, "Enter volume path");

	if (!NoKeyFiles && !FirstKeyFile)
		AskKeyFiles ("Enter keyfile path", &FirstKeyFile);

	if (!OpenVolume (volumePath, "Enter password for '%s': ", volumePath, FALSE,
		&ci, &startSector, &totalSectors, &modTime, &acTime))
		goto err;

	EAGetName (eaName, ci->ea);

	keySize = EAGetKeySize (ci->ea);	
	if (strcmp (eaName, "Triple DES") == 0)
		keySize -= 3; // Compensate for parity bytes

	volCTime = WindowsFileTime2UnixTime (ci->volume_creation_time);
	headerMTime = WindowsFileTime2UnixTime (ci->header_creation_time);

	printf ("%sVolume properties:\n"
		" Location: %s\n"
		" Size: %llu bytes\n"
		" Type: %s\n"
		" Encryption algorithm: %s\n"
		" Key size: %d bits\n"
		" Block size: %d bits\n"
		" Mode of operation: %s\n"
		" PKCS-5 PRF: %s\n"
		" PKCS-5 iteration count: %d\n"
		,
		CmdPasswordValid ? "" : "\n",
		volumePath,
		totalSectors * SECTOR_SIZE,
		ci->hiddenVolumeSize == 0 ? "Normal" : "Hidden",
		eaName,
		keySize * 8,
		CipherGetBlockSize (EAGetFirstCipher(ci->ea)) * 8,
		EAGetModeName (ci->ea, ci->mode, TRUE),
		get_pkcs5_prf_name (ci->pkcs5),
		ci->noIterations
		);

	memset (timeBuf, 0, sizeof (timeBuf));
	memset (timeBuf2, 0, sizeof (timeBuf2));
	
	if (ctime_r (&volCTime, timeBuf) == NULL || ctime_r (&headerMTime, timeBuf2) == NULL)
		goto err;

	printf (" Volume created: %s"
		" Header modified: %s",
		timeBuf, timeBuf2);

	ret = TRUE;
err:
	if (ci != NULL)
		crypto_close (ci);

	if (!UpdateTime && modTime != 0)
		RestoreFileTime (volumePath, modTime, acTime);

	return ret;
}


static void DumpVersion (FILE *f)
{
	fprintf (f, 
"truecrypt %s\n\n\
Released under the TrueCrypt Collective License 1.1\n\n\
Copyright (C) 2003-2007 TrueCrypt Foundation. All Rights Reserved.\n\
Copyright (C) 1998-2000 Paul Le Roux. All Rights Reserved.\n\
Copyright (C) 1999-2006 Dr. Brian Gladman. All Rights Reserved.\n\
Copyright (C) 1995-1997 Eric Young. All Rights Reserved.\n\
Copyright (C) 2001 Markus Friedl. All Rights Reserved.\n\n"
	, VERSION_STRING);
}


static void DumpUsage (FILE *f)
{
	fprintf (f,
"Usage: truecrypt [OPTIONS] VOLUME_PATH [MOUNT_DIRECTORY]\n"
"   or: truecrypt [OPTIONS] -i\n"
"   or: truecrypt [OPTIONS] -c | --create | -C | --change [VOLUME_PATH]\n"
"   or: truecrypt [OPTIONS] -d | --dismount | -l | --list [MAPPED_VOLUME]\n"
"   or: truecrypt [OPTIONS] --backup-headers | --restore-header FILE [VOLUME]\n"
"   or: truecrypt [OPTIONS] --properties [VOLUME_PATH]\n"
"   or: truecrypt [OPTIONS] --keyfile-create FILE\n"
"   or: truecrypt -h | --help | --test | -V | --version\n"
"\nCommands:\n"
" VOLUME_PATH                         Map volume\n"
" VOLUME_PATH MOUNT_DIRECTORY         Map and mount volume\n"
"     --backup-headers FILE [VOLUME]  Backup headers of VOLUME to FILE\n"
" -c, --create [VOLUME_PATH]          Create a new volume\n"
" -C, --change [VOLUME_PATH]          Change password/keyfile(s)\n"
" -d, --dismount [MAPPED_VOLUME]      Dismount and unmap volume\n"
" -h, --help                          Display detailed help\n"
"     --keyfile-create FILE           Create a new keyfile\n"
" -i, --interactive                   Map and mount volume interactively\n"
" -l, --list [MAPPED_VOLUME]          List mapped volumes\n"
"     --properties [VOLUME_PATH]      Display properties of volume\n"
"     --restore-header FILE [VOLUME]  Restore header of VOLUME from FILE\n"
"     --test                          Test algorithms\n"
" -V, --version                       Display program version and legal notices\n"
"\nOptions:\n"
"     --cluster SIZE                  Cluster size\n"
"     --display-keys                  Display encryption keys\n"
"     --display-password              Display password while typing\n"
"     --disable-progress              Disable progress display\n"
"     --encryption EA                 Encryption algorithm\n"
"     --filesystem TYPE               Filesystem type\n"
"     --hash HASH                     Hash algorithm\n"
" -k, --keyfile FILE|DIR              Keyfile for volume\n"
"     --keyfile-add FILE|DIR          New keyfile for volume\n"
" -K, --keyfile-protected FILE|DIR    Keyfile for protected volume\n"
" -M, --mount-options OPTIONS         Mount options\n"
" -N, --device-number NUMBER          Map volume as device number\n"
"     --overwrite                     Overwrite files without confirmation\n"
" -p, --password PASSWORD             Password for volume\n"
"     --password-tries NUMBER         Password entry tries\n"
" -P, --protect-hidden                Protect hidden volume\n"
"     --random-source FILE            Random number generator input file\n"
"     --quick                         Use quick format\n"
"     --update-time                   Do not preserve timestamps\n"
" -r, --read-only                     Map/Mount volume as read-only\n"
"     --size SIZE                     Volume size\n"
"     --type TYPE                     Volume type\n"
" -u, --user-mount                    Set default user and group ID on mount\n"
" -v, --verbose                       Verbose output\n"
"\n MAPPED_VOLUME = DEVICE_NUMBER | DEVICE_NAME | MOUNT_POINT | VOLUME_PATH\n"
"For a detailed help, use --help or see truecrypt(1) man page.\n"
"For more information, visit <http://www.truecrypt.org/docs/>.\n"
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
"   or: truecrypt [OPTIONS] -i\n"
"   or: truecrypt [OPTIONS] -c | --create | -C | --change [VOLUME_PATH]\n"
"   or: truecrypt [OPTIONS] -d | --dismount | -l | --list [MAPPED_VOLUME]\n"
"   or: truecrypt [OPTIONS] --backup-headers | --restore-header FILE [VOLUME]\n"
"   or: truecrypt [OPTIONS] --properties [VOLUME_PATH]\n"
"   or: truecrypt [OPTIONS] --keyfile-create FILE\n"
"   or: truecrypt -h | --help | --test | -V | --version\n"
"\n"
"Options:\n"
"\n"
"VOLUME_PATH [MOUNT_DIRECTORY]\n"
" Open a TrueCrypt volume specified by VOLUME_PATH and map it as a block device\n"
" /dev/mapper/truecryptN. N is the first available device number if not\n"
" otherwise specified with -N. Filesystem of the mapped volume is mounted at\n"
" MOUNT_DIRECTORY if specified. To open a hidden volume, specify its password\n"
" and/or keyfiles (the outer volume cannot be mapped at the same time).\n"
" See also EXAMPLES and options --display-password, --filesystem, -k, -M, -p, -P,\n"
" --password-tries, -r, -u, --update-time. Note that passing some of the options\n"
" may affect security (see options -i and -p for more information).\n"
"\n"
"--backup-headers BACKUP_FILE [VOLUME_PATH]\n"
" Backup headers of a volume specified by VOLUME_PATH to a file BACKUP_FILE.\n"
" Volume path is requested from user if not specified on command line. Both\n"
" normal/outer and hidden volume headers are stored in the backup file even\n"
" if there is no hidden volume within the volume (to preserve plausible\n"
" deniability). When restoring the volume header, it is possible to select\n"
" which header is to be restored. Note that this command drops effective user\n"
" ID. See also --restore-header.\n"
"\n"
"-c, --create [VOLUME_PATH]\n"
" Create a new volume. Most options are requested from user if not specified\n"
" on command line. Hidden volume can be created only in an existing file or\n"
" device. Size of the hidden volume should not exceed the free space of the\n"
" filesystem on the outer volume. Hidden volume protection (see option -P)\n"
" should be used to update the outer volume contents after the hidden volume\n"
" is created. WARNING: To prevent data corruption, you should follow the\n"
" instructions in the EXAMPLES section on how to create a hidden volume.\n"
" Note that this command drops effective user ID.\n"
" See also options --cluster, --disable-progress, --display-keys,\n"
" --encryption, -k, --filesystem, --hash, -p, --random-source, --quick, --size,\n"
" --type. Note that passing some of the options may affect security (see option\n"
" -p for more information).\n"
"\n"
"-C, --change [VOLUME_PATH]\n"
" Change a password and/or keyfile(s) of a volume. Volume path and passwords are\n"
" requested from user if not specified on command line. PKCS-5 PRF HMAC hash\n"
" algorithm can be changed with option --hash. See also options -k,\n"
" --keyfile-add, -p, --random-source, -v.\n"
"\n"
"-d, --dismount [MAPPED_VOLUME]\n"
" Dismount and unmap mapped volumes. If MAPPED_VOLUME is not specified, all\n"
" volumes are dismounted and unmapped. See below for a description of\n"
" MAPPED_VOLUME.\n"
"\n"
"-h, --help\n"
" Display help information.\n"
"\n"
"-i, --interactive\n"
" Map and mount a volume interactively. Options which may affect security are\n"
" requested from the user. See option -p for more information.\n"
"\n"
"-l, --list [MAPPED_VOLUME]\n"
" Display a list of mapped volumes. If MAPPED_VOLUME is not specified, all\n"
" volumes are listed. By default, the list contains only volume path and mapped\n"
" device name pairs. A more detailed list can be enabled by verbose output\n"
" option (-v). See below for a description of MAPPED_VOLUME.\n"
"\n"
"--keyfile-create FILE\n"
" Create a new keyfile using the random number generator. FILE argument specifies\n"
" the output file. Note that this command drops effective user ID.\n"
"\n"
"--properties [VOLUME_PATH]\n"
" Display properties of a volume specified by VOLUME_PATH.\n"
"\n"
"--restore-header BACKUP_FILE [VOLUME_PATH]\n"
" Restore header of a volume specified by VOLUME_PATH from a file BACKUP_FILE.\n"
" Volume path is requested from user if not specified on command line.\n"
" Type of the restored volume header (normal/hidden) is requested from user if\n"
" not specified with --type. Note that this command drops effective user ID.\n"
" See also --backup-headers.\n"
"\n"
"--test\n"
" Test all internal algorithms used in the process of encryption and decryption.\n"
"\n"
"-V, --version\n"
" Display program version and legal notices.\n"
"\n"
"MAPPED_VOLUME:\n"
" Specifies a mapped or mounted volume. One of the following forms can be used:\n\n"
" 1) Path to the encrypted TrueCrypt volume.\n\n"
" 2) Mount directory of the volume's filesystem (if mounted).\n\n"
" 3) Device number of the mapped volume.\n\n"
" 4) Device name of the mapped volume.\n\n"
"\n"
"--cluster SIZE\n"
" Use specified cluster size when creating a new volume. SIZE defines the number\n"
" of sectors per cluster.\n"
"\n"
"--disable-progress\n"
" Disable display of progress information during creation of a new volume.\n"
"\n"
"--display-keys\n"
" Display encryption keys generated during creation of a new volume.\n"
"\n"
"--display-password\n"
" Display password characters while typing.\n"
"\n"
"--encryption ENCRYPTION_ALGORITHM\n"
" Use specified encryption algorithm when creating a new volume.\n"
"\n"
"--filesystem TYPE\n"
" Filesystem type to mount. The TYPE argument is passed to mount(8) command\n"
" with option -t. Default type is 'auto'. When creating a new volume, this\n"
" option specifies the filesystem to be created on the new volume.\n"
"\n"
"--hash HASH\n"
" Use specified hash algorithm when creating a new volume or changing password\n"
" and/or keyfiles.\n"
"\n"
"-k, --keyfile FILE | DIRECTORY\n"
" Use specified keyfile to open a volume to be mapped (or when changing password\n"
" and/or keyfiles). When a directory is specified, all files inside it will be\n"
" used (non-recursively). Additional keyfiles can be specified with multiple -k\n"
" options. Empty keyfile (-k '') disables interactive requests for keyfiles\n"
" (e.g., when creating a new volume). See also option -K.\n"
"\n"
"-K, --keyfile-protected FILE | DIRECTORY\n"
" Use specified keyfile to open a hidden volume to be protected. This option\n"
" may be used only when mounting an outer volume with hidden volume protected.\n"
" See also options -k and -P.\n"
"\n"
"--keyfile-add FILE | DIRECTORY\n"
" Add specified keyfile to a volume when changing its password and/or keyfiles.\n"
" This option must be also used to keep all previous keyfiles asigned to a\n"
" volume. See EXAMPLES for more information.\n"
"\n"
"-M, --mount-options OPTIONS\n"
" Filesystem mount options. The OPTIONS argument is passed to mount(8)\n"
" command with option -o. This option can be specified only by an administrator.\n"
" See also options -r and -u.\n"
"\n"
"-N, --device-number N\n"
" Use device number N when mapping a volume as a block device\n"
" /dev/mapper/truecryptN. Default is the first available device.\n"
"\n"
"--overwrite\n"
" Overwrite files without prompting the user for confirmation.\n"
"\n"
"-p, --password PASSWORD\n"
" Use specified password to open a volume. Additional passwords can be\n"
" specified with multiple -p options. An empty password can also be specified\n"
" ('' in most shells). Note that passing a password on the command line is\n"
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
" outer volume is mapped with all sectors belonging to the hidden volume\n"
" protected against write operations. When a write to the protected area is\n"
" prevented, the whole volume is switched to read-only mode. Verbose list command\n"
" (-vl) can be used to query the state of the hidden volume protection. Warning\n"
" message is displayed when a volume switched to read-only is being dismounted.\n"
" See also options -r and -i.\n"
"\n"
"--quick\n"
" Use quick format when creating a new volume. This option can be used only\n"
" when creating a device-hosted volume. Quick format is always used when\n"
" creating a hidden volume.\n"
"\n"
"--random-source FILE\n"
" Use FILE as a source of random numbers. Standard input is used if '-' is\n"
" specified.\n"
"\n"
"-r, --read-only\n"
" Map and mount a volume as read-only. Write operations to the volume may not\n"
" fail immediately due to the write buffering performed by the system, but the\n"
" physical write will still be prevented.\n"
"\n"
"--size SIZE\n"
" Use specified size when creating a new volume. SIZE is defined as number of\n"
" bytes or, when a size suffix K/M/G is used, Kilobytes/Megabytes/Gigabytes.\n"
" Note that size must be a multiple of 512 bytes.\n"
"\n"
"--type TYPE\n"
" Use specified volume type when creating a new volume or restoring a volume\n"
" header. TYPE can be 'normal' or 'hidden'.\n"
"\n"
"-u, --user-mount\n"
" Set default user and group ID of the filesystem being mounted to the user and\n"
" group ID of the process which executed TrueCrypt. Some filesystems (e.g., FAT)\n"
" do not support Unix-style access control and, therefore, it is necessary to\n"
" supply a default user and group ID to the operating system when mounting them.\n"
" Note that Unix-style filesystems (e.g., ext2) do not support this option.\n"
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
"Examples:\n"
"\n"
"truecrypt /root/volume.tc /mnt/tc\n"
" Map a volume /root/volume.tc and mount its filesystem at directory /mnt/tc.\n"
"\n"
"truecrypt -u /dev/hda2 /mnt/tc\n"
" Map a volume /dev/hda2 (first ATA disk, primary partition 2) and mount its\n"
" filesystem at /mnt/tc. Default user-id is set, which is useful when mounting\n"
" a filesystem such as FAT under a non-admin user account.\n"
"\n"
"truecrypt -i\n"
" Map and mount a volume. Options are requested interactively.\n"
"\n"
"truecrypt -d\n"
" Dismount and unmap all mapped volumes.\n"
"\n"
"truecrypt -d /root/volume.tc\n"
" Dismount and unmap a volume /root/volume.tc.\n"
"\n"
"truecrypt -d /mnt/tc\n"
" Dismount and unmap a volume mounted at /mnt/tc.\n"
"\n"
"truecrypt -vl\n"
" Display a detailed list of all mapped volumes.\n"
" \n"
"truecrypt -N 1 /dev/hdc1 && mkfs /dev/mapper/truecrypt1\n"
" Map a volume /dev/hdc1 and create a new filesystem on it.\n"
"\n"
"truecrypt -P /dev/hdc1 /mnt/tc\n"
" Map and mount outer volume /dev/hdc1 and protect hidden volume within it.\n"
"\n"
"truecrypt -p '' -p '' -k key1 -k key2 -K key_hidden -P volume.tc\n"
" Map outer volume ./volume.tc and protect hidden volume within it.\n"
" The outer volume is opened with keyfiles ./key1 and ./key2 and the\n"
" hidden volume with ./key_hidden. Passwords for both volumes are empty.\n"
"\n"
"truecrypt -c\n"
" Create a new volume. Options are requested interactively."
"\n"
"truecrypt -c /dev/hda2\n"
" Create a new volume hosted at the second primary partition of the first\n"
" ATA disk.\n"
"\n"
"truecrypt -k keyfile --size 10M --encryption AES --hash SHA-1 -c vol.tc\n"
" Create a new volume. Options which are not specified on command line are\n"
" requested from the user.\n"
"\n"
"truecrypt --keyfile-add keyfile -C volume.tc\n"
" Change password and add a new keyfile to volume.\n"
"\n"
"truecrypt -k keyfile -C volume.tc\n"
" Change password and remove a keyfile from volume.\n"
"\n"
"truecrypt -k keyfile --keyfile-add keyfile -C volume.tc\n"
" Change password and keep previous keyfile.\n"
"\n"
"Creating a hidden volume without risking data corruption:\n"
" 1) Create an outer volume:\n"
"    truecrypt --type normal --size 100M -c volume.tc\n"
" 2) Create a hidden volume:\n"
"    truecrypt --type hidden --size 50M -c volume.tc\n"
" 3) Mount the outer volume with the hidden volume protected:\n"
"    truecrypt -P volume.tc /mnt/tc\n"
" 4) Copy files to the outer volume:\n"
"    cp outer_volume_file.txt /mnt/tc\n"
" 5) Dismount the outer volume:\n"
"    truecrypt -d volume.tc\n"
" 6) If a warning message has been displayed in 5), start again from 1). Either\n"
" a larger outer volume should be created in 1), or less data should be copied\n"
" to the outer volume in 4).\n"
"\n"
"Report bugs at <http://www.truecrypt.org/bugs/>.\n"
	);
}


static BOOL DumpMountList (int devNo)
{
	BOOL found = FALSE;
	int i;

	if (!CheckKernelModuleVersion (FALSE, TRUE)
		|| !GetMountList (FALSE)
		|| (devNo == -1 && MountList[0].DeviceNumber == -1))
	{
		error ("No volumes mapped\n");
		return FALSE;
	}

	for (i = 0; MountList[i].DeviceNumber != -1; i++)
	{
		MountListEntry *e = &MountList[i];

		if (devNo != -1 && e->DeviceNumber != devNo)
			continue;

		found = TRUE;

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
					" Size: %llu bytes\n"
					" Encryption algorithm: %s\n"
					" Mode of operation: %s\n"
					" Read-only: %s\n"
					" Hidden volume protected: %s\n\n",
				e->DeviceNumber,
				e->VolumePath,
				e->Hidden ? "Hidden" : "Normal",
				e->VolumeSize,
				eaName,
				EAGetModeName (e->EA, e->Mode, TRUE),
				(e->Flags & TC_READ_ONLY) ? "Yes" : "No",
				(e->Flags & TC_PROTECTION_ACTIVATED) ? "Yes - damage prevented" : (
					(e->Flags & TC_HIDDEN_VOLUME_PROTECTION) ? "Yes" : "No" )
				);
		}
	}

	if (!found)
	{
		error (TC_MAP_DEV "%d not mapped\n", devNo);
		return FALSE;
	}

	return TRUE;
}


static BOOL EnumMountPoints (char *device, char *mountPoint)
{
	static FILE *m = NULL;
	char mp[TC_MAX_PATH], *p;

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

	if (fscanf (m, "%" TC_MAX_PATH_STR "s %" TC_MAX_PATH_STR "s %*s %*s %*s %*s",
		device, mp) != 2)
	{
		fclose (m);
		m = NULL;
		return FALSE;
	}

	// Convert escaped characters
	p = mp;
	while (*p)
	{
		if (p[0] == '\\' && p[1] && p[2] && p[3])
		{
			char c;
			if (sscanf (p + 1, "%o", &c) == 1)
			{
				*mountPoint++ = c;
				p += 4;
				continue;
			}
		}
		*mountPoint++ = *p++;
	}
	*mountPoint = 0;

	return TRUE;
}


static BOOL DismountFileSystem (char *device)
{
	char mountedDevice[TC_MAX_PATH], mountPoint[TC_MAX_PATH];
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
	char mapDevice[TC_MAX_PATH];
	int nMountedVolumes = 0;
	int i;
	BOOL found = FALSE;
	BOOL status = TRUE;

	if (!CheckKernelModuleVersion (FALSE, TRUE)
		|| !GetMountList (FALSE)
		|| (devNo == -1 && MountList[0].DeviceNumber == -1))
	{
		error ("No volumes mapped\n");
		return FALSE;
	}

	// Flush write buffers before dismount if there are
	// mounted volumes with hidden volume protection 
	for (i = 0; MountList[i].DeviceNumber != -1; i++)
	{
		if (MountList[i].Flags & TC_HIDDEN_VOLUME_PROTECTION)
		{
			sync ();
			MountListValid = FALSE;
			GetMountList (FALSE);
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

			sprintf (mapDevice, TC_MAP_DEV "%d", e->DeviceNumber);

			if (RealUserId != 0 && e->UserId != RealUserId)
			{
				error ("Dismount denied: %s mapped by a different user\n", mapDevice);
				status = FALSE;
				continue;
			}

			if (e->Flags & TC_PROTECTION_ACTIVATED)
				printf ("WARNING: Write to the hidden volume %s has been prevented!\n", e->VolumePath);

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
						(UpdateTime || e->ModTime == 0) ? time (NULL) : (time_t) e->ModTime,
						(UpdateTime || e->AcTime == 0) ? time (NULL) : (time_t) e->AcTime);
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
		error (TC_MAP_DEV "%d not mapped\n", devNo);
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
static BOOL ToDeviceNumber (char *text, int *deviceNumber)
{
	char mountedDevice[TC_MAX_PATH], mountPoint[TC_MAX_PATH];
	int i;

	if (sscanf (text, "%d", deviceNumber) == 1)
		return TRUE;

	if (sscanf (text, TC_MAP_DEV "%d", deviceNumber) == 1)
		return TRUE;

	// Relative path => absolute
	if (text[0] != '/')
	{
		char s[TC_MAX_PATH];
		static char absolute[TC_MAX_PATH];

		getcwd (s, sizeof (s));
		snprintf (absolute, sizeof (absolute), "%s/%s", s, text);
		text = absolute;
	}

	while (EnumMountPoints (mountedDevice, mountPoint))
	{
		if (strcmp (mountPoint, text) == 0
			&& sscanf (mountedDevice, TC_MAP_DEV "%d", deviceNumber) == 1)
		{
			EnumMountPoints (NULL, NULL);
			return TRUE;
		}
	}

	if (!GetMountList (FALSE))
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


int main (int argc, char **argv)
{
	char *volumePath = NULL;
	char *mountPoint = NULL;
	char volumePathBuf[TC_MAX_PATH];
	int i, o;
	int optIndex = 0;
	FILE *f;

	struct option longOptions[] = {
		{"backup-headers", required_argument, 0, 0},
		{"cluster", required_argument, 0, 0},
		{"change", optional_argument, 0, 'C'},
		{"create", optional_argument, 0, 'c'},
		{"device-number", required_argument, 0, 'N'},
		{"dismount", optional_argument, 0, 'd'},
		{"disable-progress", 0, 0, 0},
		{"display-keys", 0, 0, 0},
		{"display-password", 0, 0, 0},
		{"encryption", required_argument, 0, 0},
		{"keyfile", required_argument, 0, 'k'},
		{"keyfile-add", required_argument, 0, 0},
		{"keyfile-protected", required_argument, 0, 'K'},
		{"filesystem", required_argument, 0, 0},
		{"interactive", 0, 0, 'i'},
		{"keyfile-create", required_argument, 0, 0},
		{"list", optional_argument, 0, 'l'},
		{"hash", required_argument, 0, 0},
		{"help", 0, 0, 'h'},
		{"mount-options", required_argument, 0, 'M'},
		{"overwrite", 0, 0, 0},
		{"password", required_argument, 0, 'p'},
		{"password-tries", required_argument, 0, 0},
		{"properties", optional_argument, 0, 0},
		{"protect-hidden", 0, 0, 'P'},
		{"quick", 0, 0, 0},
		{"random-source", required_argument, 0, 0},
		{"read-only", 0, 0, 'r'},
		{"restore-header", required_argument, 0, 0},
		{"size", required_argument, 0, 0},
		{"test", 0, 0, 0},
		{"type", required_argument, 0, 0},
		{"update-time", 0, 0, 0},
		{"user-mount", 0, 0, 'u'},
		{"verbose", 0, 0, 'v'},
		{"version", 0, 0, 'V'},
		{0, 0, 0, 0}
	};

	// Make sure pipes will not use file descriptors <= STDERR_FILENO
	f = fdopen (STDIN_FILENO, "r");
	if (f == NULL)
		open ("/dev/null", 0);

	f = fdopen (STDOUT_FILENO, "w");
	if (f == NULL)
		open ("/dev/null", 0);

	f = fdopen (STDERR_FILENO, "w");
	if (f == NULL)
		open ("/dev/null", 0);

	signal (SIGHUP, OnSignal);
	signal (SIGINT, OnSignal);
	signal (SIGQUIT, OnSignal);
	signal (SIGABRT, OnSignal);
	signal (SIGPIPE, OnSignal);
	signal (SIGTERM, OnSignal);

	LockMemory ();
	atexit (OnExit);

	RealUserId = getuid ();
	RealGroupId = getgid ();

	if (tcgetattr (0, &TerminalAttributes) == 0)
		IsTerminal = TRUE;

	while ((o = getopt_long (argc, argv, "c::C::d::hik:K:l::M:N:p:PruvV", longOptions, &optIndex)) != -1)
	{
		switch (o)
		{
		case 'c':
			{
				char *hostPath = NULL;
				if (optind < argc)
				{
					hostPath = argv[optind++];

					if (optind < argc)
						goto usage;
				}

				return CreateVolume (hostPath) ? 0 : 1;
			}

		case 'C':
			{
				char *hostPath = NULL;
				if (optind < argc)
				{
					hostPath = argv[optind++];

					if (optind < argc)
						goto usage;
				}

				return ChangePassword (hostPath) ? 0 : 1;
			}

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

				if (!CheckAdminPrivileges ())
					return 1;

				return DismountVolume (devNo) ? 0 : 1;
			}

		case 'i':
			Interactive = TRUE;
			if (optind < argc)
				goto usage;
			break;

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

				if (!CheckAdminPrivileges ())
					return 1;

				return DumpMountList (devNo) ? 0 : 1;
			}

		case 'k':
		case 'K':
			// Keyfile
			if (optarg[0] == 0)
			{
				NoKeyFiles = TRUE;
			}
			else
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

		case 'M':
			if (RealUserId != 0)
			{
				error ("--mount-options can be specified only by an administrator (see options -r, -u)\n");
				return 1;
			}

			MountOpts = optarg;
			break;
			
		case 'N':
			if (sscanf (optarg, "%d", &UseDeviceNumber) == 1 && UseDeviceNumber >= 0)
				break;
			goto usage;

		case 'p':
			// Password
			if (!CmdPasswordValid)
			{
				strncpy ((char *)CmdPassword.Text, optarg, sizeof (CmdPassword.Text));
				CmdPassword.Length = strlen ((char *)CmdPassword.Text);
				
				if (!ValidatePassword (&CmdPassword))
					return 1;

				CmdPasswordValid = TRUE;
			}
			else if (!CmdPassword2Valid)
			{
				strncpy ((char *)CmdPassword2.Text, optarg, sizeof (CmdPassword2.Text));

				CmdPassword2.Length = strlen ((char *)CmdPassword2.Text);
				if (!ValidatePassword (&CmdPassword2))
					return 1;

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
			
		case 'u':
			UserMount = TRUE;
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
			if (strcmp ("backup-headers", longOptions[optIndex].name) == 0)
			{
				char *volumePath = NULL;

				if (optind < argc)
					volumePath = argv[optind++];

				if (optind < argc)
					goto usage;

				if (BackupVolumeHeaders (optarg, volumePath))
				{
					printf ("Backup of volume headers succeeded.\n");
					return 0;
				}

				return 1;
			}

			if (strcmp ("cluster", longOptions[optIndex].name) == 0)
			{
				if (sscanf (optarg, "%d", &ClusterSize) != 1)
					goto usage;
				break;
			}

			if (strcmp ("display-keys", longOptions[optIndex].name) == 0)
			{
				DisplayKeys = TRUE;
				break;
			}

			if (strcmp ("display-password", longOptions[optIndex].name) == 0)
			{
				DisplayPassword = TRUE;
				break;
			}

			if (strcmp ("disable-progress", longOptions[optIndex].name) == 0)
			{
				DisplayProgress = FALSE;
				break;
			}

			if (strcmp ("encryption", longOptions[optIndex].name) == 0)
			{
				EA = EAGetByName (optarg);

				if (EA == 0)
					goto usage;
				break;
			}

			if (strcmp ("filesystem", longOptions[optIndex].name) == 0)
			{
				Filesystem = optarg;
				break;
			}

			if (strcmp ("hash", longOptions[optIndex].name) == 0)
			{
				HashAlgorithm = 0;
				for (i = 1; i <= LAST_PRF_ID; i++)
				{
					if (strcasecmp (optarg, HashGetName (i)) == 0)
					{
						HashAlgorithm = i;
						break;
					}
				}

				if (HashAlgorithm == 0)
					goto usage;

				break;
			}

			if (strcmp ("keyfile-add", longOptions[optIndex].name) == 0)
			{
				if (optarg[0] == 0)
				{
					NoNewKeyFiles = TRUE;
				}
				else
				{
					KeyFile *kf = malloc (sizeof (KeyFile));
					if (!kf)
					{
						perror ("malloc");
						return 1;
					}
					strncpy (kf->FileName, optarg, sizeof (kf->FileName));
					FirstNewKeyFile = KeyFileAdd (FirstNewKeyFile, kf);
				}
				break;
			}
			
			if (strcmp ("keyfile-create", longOptions[optIndex].name) == 0)
			{
				return CreateKeyfile (optarg) ? 0 : 1;
			}

			if (strcmp ("overwrite", longOptions[optIndex].name) == 0)
			{
				Overwrite = TRUE;
				break;
			}
			
			if (strcmp ("quick", longOptions[optIndex].name) == 0)
			{
				Quick = TRUE;
				break;
			}

			if (strcmp ("type", longOptions[optIndex].name) == 0)
			{
				if (strcasecmp (optarg, "normal") == 0)
					VolumeType = VOLUME_TYPE_NORMAL;
				else if (strcasecmp (optarg, "hidden") == 0)
					VolumeType = VOLUME_TYPE_HIDDEN;
				else
					goto usage;

				break;
			}

			if (strcmp ("password-tries", longOptions[optIndex].name) == 0)
			{
				if (sscanf (optarg, "%d", &PasswordEntryTries) == 1)
					break;
				else
					goto usage;
			}

			if (strcmp ("properties", longOptions[optIndex].name) == 0)
			{
				char *volumePath = NULL;

				if (optind < argc)
					volumePath = argv[optind++];

				if (optind < argc)
					goto usage;

				return DumpVolumeProperties (volumePath) ? 0 : 1;
			}
			
			if (strcmp ("random-source", longOptions[optIndex].name) == 0)
			{
				RandomSource = optarg;
				break;
			}

			if (strcmp ("restore-header", longOptions[optIndex].name) == 0)
			{
				char *volumePath = NULL;

				if (optind < argc)
					volumePath = argv[optind++];

				if (optind < argc)
					goto usage;

				if (RestoreVolumeHeader (optarg, volumePath))
				{
					printf ("Restore of volume header succeeded.\n");
					return 0;
				}

				return 1;
			}

			if (strcmp ("size", longOptions[optIndex].name) == 0)
			{
				if (!ParseSize (optarg, &VolumeSize))
					goto usage;
				break;
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
	
	if (!Interactive)
	{
		if (optind >= argc)
			goto usage;

		if (optind < argc)
			volumePath = argv[optind++];

		if (optind < argc)
			mountPoint = argv[optind++];

		if (optind < argc)
			goto usage;
	}

	if (!CheckAdminPrivileges ())
		return 1;

	if (Interactive)
	{
		static char mp[TC_MAX_PATH] = { 0 };

		// Volume path
		volumePath = AskVolumePath (volumePath, "Enter volume path");

		// Mount point
		mountPoint = AskString ("Enter mount directory [none]", mp, sizeof (mp));
		if (mp[0] == 0)
			mountPoint = NULL;

		ProtectHidden = AskYesNo ("Protect hidden volume?", TRUE);

		AskKeyFiles ("Enter keyfile path", &FirstKeyFile);

		if (ProtectHidden)
			AskKeyFiles ("Enter keyfile path for hidden volume", &FirstProtVolKeyFile);
	}

	// Relative path => absolute
	if (volumePath[0] != '/')
	{
		char s[TC_MAX_PATH];
		getcwd (s, sizeof (s));
		snprintf (volumePathBuf, sizeof (volumePathBuf), "%s/%s", s, volumePath);
		volumePath = volumePathBuf;
	}

	return MountVolume (volumePath, mountPoint) == FALSE;

usage:
	DumpUsage (stdout);

	return 1;
}
