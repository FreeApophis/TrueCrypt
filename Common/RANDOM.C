/* Legal Notice: The source code contained in this file has been derived from
   the source code of Encryption for the Masses 2.02a, which is Copyright (c)
   1998-99 Paul Le Roux and which is covered by the 'License Agreement for
   Encryption for the Masses'. Modifications and additions to that source code
   contained in this file are Copyright (c) 2004-2006 TrueCrypt Foundation and
   Copyright (c) 2004 TrueCrypt Team, and are covered by TrueCrypt License 2.1
   the full text of which is contained in the file License.txt included in
   TrueCrypt binary and source code distribution archives.  */

#include <stdlib.h>
#include <stdio.h>
#include <fcntl.h>
#include "Tcdefs.h"
#include "Crc.h"
#include "Random.h"
#include "Apidrvr.h"

unsigned __int8 buffer[RNG_POOL_SIZE];
unsigned char *pRandPool = NULL;
static BOOL bRandDidInit = FALSE;
int nRandIndex = 0, randPoolReadIndex = 0;
int HashFunction = DEFAULT_HASH_ALGORITHM;
BOOL bDidSlowPoll = FALSE;	/* We do the slow poll only once */
BOOL volatile bFastPollEnabled = TRUE;	/* Used to reduce CPU load when performing benchmarks */
BOOL volatile bRandmixEnabled = TRUE;	/* Used to reduce CPU load when performing benchmarks */

/* Macro to add a single byte to the pool */
#define RandaddByte(x) {\
	if (nRandIndex == RNG_POOL_SIZE) nRandIndex = 0;\
	pRandPool[nRandIndex] = (unsigned char) ((unsigned char)x + pRandPool[nRandIndex]); \
	if (nRandIndex % 8 == 0) Randmix();\
	nRandIndex++; \
	}

/* Macro to add four bytes to the pool */
#define RandaddInt32(x) RandAddInt((unsigned __int32)x);

void RandAddInt (unsigned __int32 x)
{
	RandaddByte(x); 
	RandaddByte((x >> 8)); 
	RandaddByte((x >> 16));
	RandaddByte((x >> 24));
}

#ifdef _WIN32

#include <tlhelp32.h>
#include "Dlgcode.h"

HHOOK hMouse = NULL;		/* Mouse hook for the random number generator */
HHOOK hKeyboard = NULL;		/* Keyboard hook for the random number generator */

/* Variables for thread control, the thread is used to gather up info about
   the system in in the background */
CRITICAL_SECTION critRandProt;	/* The critical section */
BOOL volatile bThreadTerminate = FALSE;	/* This variable is shared among thread's so its made volatile */

/* Network library handle for the SlowPoll function */
HANDLE hNetAPI32 = NULL;

// CryptoAPI
HCRYPTPROV hCryptProv;

#endif // _WIN32

/* Init the random number generator, setup the hooks, and start the thread */
int
Randinit ()
{
	if(bRandDidInit) return 0;

#ifdef _WIN32
	InitializeCriticalSection (&critRandProt);
#endif

	bRandDidInit = TRUE;

	pRandPool = (unsigned char *) TCalloc (RANDOMPOOL_ALLOCSIZE);
	if (pRandPool == NULL)
		goto error;
	else
		memset (pRandPool, 0, RANDOMPOOL_ALLOCSIZE);

#ifdef _WIN32
	VirtualLock (pRandPool, RANDOMPOOL_ALLOCSIZE);

	hKeyboard = SetWindowsHookEx (WH_KEYBOARD, (HOOKPROC)&KeyboardProc, NULL, GetCurrentThreadId ());
	if (hKeyboard == 0) handleWin32Error (0);

	hMouse = SetWindowsHookEx (WH_MOUSE, (HOOKPROC)&MouseProc, NULL, GetCurrentThreadId ());
	if (hMouse == 0)
	{
		handleWin32Error (0);
		goto error;
	}

	if (!CryptAcquireContext (&hCryptProv, NULL, NULL, PROV_RSA_FULL, 0)
		&& !CryptAcquireContext (&hCryptProv, NULL, NULL, PROV_RSA_FULL, CRYPT_NEWKEYSET))
	{
		hCryptProv = 0;
	}

	if (_beginthread (ThreadSafeThreadFunction, 8192, NULL) == -1)
		goto error;
#endif

	return 0;

error:
	Randfree ();
	return 1;
}

/* Close everything down, including the thread which is closed down by
   setting a flag which eventually causes the thread function to exit */
void
Randfree ()
{
	if (bRandDidInit == FALSE)
		return;

#ifdef _WIN32
	EnterCriticalSection (&critRandProt);

	if (hMouse != 0)
		UnhookWindowsHookEx (hMouse);
	if (hKeyboard != 0)
		UnhookWindowsHookEx (hKeyboard);

	bThreadTerminate = TRUE;

	LeaveCriticalSection (&critRandProt);

	for (;;)
	{
		Sleep (250);
		EnterCriticalSection (&critRandProt);
		if (bThreadTerminate == FALSE)
		{
			LeaveCriticalSection (&critRandProt);
			break;
		}
		LeaveCriticalSection (&critRandProt);
	}

	if (hNetAPI32 != 0)
	{
		FreeLibrary (hNetAPI32);
		hNetAPI32 = NULL;
	}

	if (hCryptProv)
	{
		CryptReleaseContext (hCryptProv, 0);
		hCryptProv = 0;
	}

	hMouse = NULL;
	hKeyboard = NULL;
	bThreadTerminate = FALSE;
	DeleteCriticalSection (&critRandProt);

#endif // _WIN32

	if (pRandPool != NULL)
	{
		burn (pRandPool, RANDOMPOOL_ALLOCSIZE);
		TCfree (pRandPool);
		pRandPool = NULL;
	}

	nRandIndex = 0;
	bRandDidInit = FALSE;
}


void RandSetHashFunction (int hash_algo_id)
{
	HashFunction = hash_algo_id;
}

int RandGetHashFunction (void)
{
	return HashFunction;
}

/* The random pool mixing function */
BOOL
Randmix ()
{
	if (bRandmixEnabled)
	{
		unsigned char hashOutputBuffer [MAX_DIGESTSIZE];
		WHIRLPOOL_CTX	wctx;
		RMD160_CTX		rctx;
		sha1_ctx		sctx;
		int poolIndex, digestIndex, digestSize;

		switch (HashFunction)
		{
		case SHA1:
			digestSize = SHA1_DIGESTSIZE;
			break;

		case RIPEMD160:
			digestSize = RIPEMD160_DIGESTSIZE;
			break;

		case WHIRLPOOL:
			digestSize = WHIRLPOOL_DIGESTSIZE;
			break;

		default:
			return FALSE;
		}

		for (poolIndex = 0; poolIndex < RNG_POOL_SIZE; poolIndex += digestSize)		
		{
			/* Compute the message digest of the entire pool using the selected hash function. */
			switch (HashFunction)
			{
			case SHA1:
				sha1_begin (&sctx);
				sha1_hash (pRandPool, RNG_POOL_SIZE, &sctx);
				sha1_end (hashOutputBuffer, &sctx);
				break;

			case RIPEMD160:
				RMD160Init(&rctx);
				RMD160Update(&rctx, pRandPool, RNG_POOL_SIZE);
				RMD160Final(hashOutputBuffer, &rctx);
				break;

			case WHIRLPOOL:
				WHIRLPOOL_init (&wctx);
				WHIRLPOOL_add (pRandPool, RNG_POOL_SIZE * 8, &wctx);
				WHIRLPOOL_finalize (&wctx, hashOutputBuffer);
				break;
			}

			/* XOR the resultant message digest to the pool at the poolIndex position. */
			for (digestIndex = 0; digestIndex < digestSize; digestIndex++)
			{
				pRandPool [poolIndex + digestIndex] ^= hashOutputBuffer [digestIndex];
			}
		}

		/* Prevent leaks */
		memset (hashOutputBuffer, 0, MAX_DIGESTSIZE);	
		switch (HashFunction)
		{
		case SHA1:
			memset (&sctx, 0, sizeof(sctx));		
			break;

		case RIPEMD160:
			memset (&rctx, 0, sizeof(rctx));		
			break;

		case WHIRLPOOL:
			memset (&wctx, 0, sizeof(wctx));		
			break;
		}
	}
	return TRUE;
}

/* Add a buffer to the pool */
void
RandaddBuf (void *buf, int len)
{
	int i;
	for (i = 0; i < len; i++)
	{
		RandaddByte (((unsigned char *) buf)[i]);
	}
}

#ifdef _WIN32
BOOL
RandpeekBytes (unsigned char *buf, int len)
{
	if (len > RNG_POOL_SIZE)
	{
		Error ("ERR_NOT_ENOUGH_RANDOM_DATA");	
		len = RNG_POOL_SIZE;
	}

	EnterCriticalSection (&critRandProt);
	memcpy (buf, pRandPool, len);
	LeaveCriticalSection (&critRandProt);

	return TRUE;
}
#endif


/* Get len random bytes from the pool (max. RNG_POOL_SIZE bytes per a single call) */
BOOL
RandgetBytes (unsigned char *buf, int len, BOOL forceSlowPoll)
{
	int i;
	BOOL ret = TRUE;

	if (HashFunction == 0)
		return FALSE;

#ifdef _WIN32
	EnterCriticalSection (&critRandProt);
#endif

	if (bDidSlowPoll == FALSE || forceSlowPoll)
	{
		if (!SlowPoll ())
			ret = FALSE;
		else
			bDidSlowPoll = TRUE;
	}

	if (!FastPoll ())
		ret = FALSE;

	/* There's never more than RNG_POOL_SIZE worth of randomess */
	if (len > RNG_POOL_SIZE)
	{
#ifdef _WIN32
		Error ("ERR_NOT_ENOUGH_RANDOM_DATA");	
		len = RNG_POOL_SIZE;
#else
		return FALSE;
#endif
	}

	// Requested number of bytes is copied from pool to output buffer,
	// pool is rehashed, and output buffer is XORed with new data from pool
	for (i = 0; i < len; i++)
	{
		buf[i] = pRandPool[randPoolReadIndex++];
		if (randPoolReadIndex == RNG_POOL_SIZE) randPoolReadIndex = 0;
	}

	/* Invert the pool */
	for (i = 0; i < RNG_POOL_SIZE / 4; i++)
	{
		((unsigned __int32 *) pRandPool)[i] = ~((unsigned __int32 *) pRandPool)[i];
	}

	// Mix the pool
	if (!FastPoll ())
		ret = FALSE;

	// XOR the current pool content into the output buffer to prevent pool state leaks
	for (i = 0; i < len; i++)
	{
		buf[i] ^= pRandPool[randPoolReadIndex++];
		if (randPoolReadIndex == RNG_POOL_SIZE) randPoolReadIndex = 0;
	}

#ifdef _WIN32
	LeaveCriticalSection (&critRandProt);
#endif
	return ret;
}

#ifdef _WIN32
/* Capture the mouse, and as long as the event is not the same as the last
   two events, add the crc of the event, and the crc of the time difference
   between this event and the last + the current time to the pool.
   The role of CRC-32 is merely to perform diffusion. Note that the output
   of CRC-32 is subsequently processed using a cryptographically secure hash
   algorithm. */
LRESULT CALLBACK
MouseProc (int nCode, WPARAM wParam, LPARAM lParam)
{
	static DWORD dwLastTimer;
	static unsigned __int32 lastCrc, lastCrc2;
	MOUSEHOOKSTRUCT *lpMouse = (MOUSEHOOKSTRUCT *) lParam;

	if (nCode < 0)
		return CallNextHookEx (hMouse, nCode, wParam, lParam);
	else
	{
		DWORD dwTimer = GetTickCount ();
		DWORD j = dwLastTimer - dwTimer;
		unsigned __int32 crc = 0L;
		int i;

		dwLastTimer = dwTimer;

		for (i = 0; i < sizeof (MOUSEHOOKSTRUCT); i++)
		{
			crc = UPDC32 (((unsigned char *) lpMouse)[i], crc);
		}

		if (crc != lastCrc && crc != lastCrc2)
		{
			unsigned __int32 timeCrc = 0L;

			for (i = 0; i < 4; i++)
			{
				timeCrc = UPDC32 (((unsigned char *) &j)[i], timeCrc);
			}

			for (i = 0; i < 4; i++)
			{
				timeCrc = UPDC32 (((unsigned char *) &dwTimer)[i], timeCrc);
			}

			EnterCriticalSection (&critRandProt);
			RandaddInt32 ((unsigned __int32) (crc + timeCrc));
			LeaveCriticalSection (&critRandProt);
		}
		lastCrc2 = lastCrc;
		lastCrc = crc;

	}
	return 0;
}

/* Capture the keyboard, as long as the event is not the same as the last two
   events, add the crc of the event to the pool along with the crc of the time
   difference between this event and the last. The role of CRC-32 is merely to
   perform diffusion. Note that the output of CRC-32 is subsequently processed
   using a cryptographically secure hash algorithm.  */
LRESULT CALLBACK
KeyboardProc (int nCode, WPARAM wParam, LPARAM lParam)
{
	static int lLastKey, lLastKey2;
	static DWORD dwLastTimer;
	int nKey = (lParam & 0x00ff0000) >> 16;
	int nCapture = 0;

	if (nCode < 0)
		return CallNextHookEx (hMouse, nCode, wParam, lParam);

	if ((lParam & 0x0000ffff) == 1 && !(lParam & 0x20000000) &&
	    (lParam & 0x80000000))
	{
		if (nKey != lLastKey)
			nCapture = 1;	/* Capture this key */
		else if (nKey != lLastKey2)
			nCapture = 1;	/* Allow for one repeat */
	}
	if (nCapture)
	{
		DWORD dwTimer = GetTickCount ();
		DWORD j = dwLastTimer - dwTimer;
		unsigned __int32 timeCrc = 0L;
		int i;

		dwLastTimer = dwTimer;
		lLastKey2 = lLastKey;
		lLastKey = nKey;

		for (i = 0; i < 4; i++)
		{
			timeCrc = UPDC32 (((unsigned char *) &j)[i], timeCrc);
		}

		for (i = 0; i < 4; i++)
		{
			timeCrc = UPDC32 (((unsigned char *) &dwTimer)[i], timeCrc);
		}

		EnterCriticalSection (&critRandProt);
		RandaddInt32 ((unsigned __int32) (crc32int(&lParam) + timeCrc));
		LeaveCriticalSection (&critRandProt);
	}

	return CallNextHookEx (hMouse, nCode, wParam, lParam);
}

/* This is the thread function which will poll the system for randomness */
void
ThreadSafeThreadFunction (void *dummy)
{
	if (dummy);		/* Remove unused parameter warning */

	for (;;)
	{
		EnterCriticalSection (&critRandProt);

		if (bThreadTerminate)
		{
			bThreadTerminate = FALSE;
			LeaveCriticalSection (&critRandProt);
			_endthread ();
		}
		else if (bFastPollEnabled)
		{
			FastPoll ();
		}

		LeaveCriticalSection (&critRandProt);

		Sleep (500);
	}
}

/* Type definitions for function pointers to call NetAPI32 functions */

typedef
  DWORD (WINAPI * NETSTATISTICSGET) (LPWSTR szServer, LPWSTR szService,
				     DWORD dwLevel, DWORD dwOptions,
				     LPBYTE * lpBuffer);
typedef
  DWORD (WINAPI * NETAPIBUFFERSIZE) (LPVOID lpBuffer, LPDWORD cbBuffer);
typedef
  DWORD (WINAPI * NETAPIBUFFERFREE) (LPVOID lpBuffer);

NETSTATISTICSGET pNetStatisticsGet = NULL;
NETAPIBUFFERSIZE pNetApiBufferSize = NULL;
NETAPIBUFFERFREE pNetApiBufferFree = NULL;

#endif	// _WIN32

/* This is the slowpoll function which gathers up network/hard drive
   performance data for the random pool */
BOOL SlowPoll (void)
{
	int i;
#ifdef _WIN32
	static int isWorkstation = -1;
	static int cbPerfData = 0x10000;
	HANDLE hDevice;
	LPBYTE lpBuffer;
	DWORD dwSize, status;
	LPWSTR lpszLanW, lpszLanS;
	int nDrive;

	/* Find out whether this is an NT server or workstation if necessary */
	if (isWorkstation == -1)
	{
		HKEY hKey;

		if (RegOpenKeyEx (HKEY_LOCAL_MACHINE,
		       "SYSTEM\\CurrentControlSet\\Control\\ProductOptions",
				  0, KEY_READ, &hKey) == ERROR_SUCCESS)
		{
			unsigned char szValue[32];
			dwSize = sizeof (szValue);

			isWorkstation = TRUE;
			status = RegQueryValueEx (hKey, "ProductType", 0, NULL,
						  szValue, &dwSize);

			if (status == ERROR_SUCCESS && _stricmp ((char *) szValue, "WinNT"))
				/* Note: There are (at least) three cases for
				   ProductType: WinNT = NT Workstation,
				   ServerNT = NT Server, LanmanNT = NT Server
				   acting as a Domain Controller */
				isWorkstation = FALSE;

			RegCloseKey (hKey);
		}
	}
	/* Initialize the NetAPI32 function pointers if necessary */
	if (hNetAPI32 == NULL)
	{
		/* Obtain a handle to the module containing the Lan Manager
		   functions */
		hNetAPI32 = LoadLibrary ("NETAPI32.DLL");
		if (hNetAPI32 != NULL)
		{
			/* Now get pointers to the functions */
			pNetStatisticsGet = (NETSTATISTICSGET) GetProcAddress (hNetAPI32,
							"NetStatisticsGet");
			pNetApiBufferSize = (NETAPIBUFFERSIZE) GetProcAddress (hNetAPI32,
							"NetApiBufferSize");
			pNetApiBufferFree = (NETAPIBUFFERFREE) GetProcAddress (hNetAPI32,
							"NetApiBufferFree");

			/* Make sure we got valid pointers for every NetAPI32
			   function */
			if (pNetStatisticsGet == NULL ||
			    pNetApiBufferSize == NULL ||
			    pNetApiBufferFree == NULL)
			{
				/* Free the library reference and reset the
				   static handle */
				FreeLibrary (hNetAPI32);
				hNetAPI32 = NULL;
			}
		}
	}

	/* Get network statistics.  Note: Both NT Workstation and NT Server
	   by default will be running both the workstation and server
	   services.  The heuristic below is probably useful though on the
	   assumption that the majority of the network traffic will be via
	   the appropriate service */
	lpszLanW = (LPWSTR) WIDE ("LanmanWorkstation");
	lpszLanS = (LPWSTR) WIDE ("LanmanServer");
	if (hNetAPI32 &&
	    pNetStatisticsGet (NULL,
			       isWorkstation ? lpszLanW : lpszLanS,
			       0, 0, &lpBuffer) == 0)
	{
		pNetApiBufferSize (lpBuffer, &dwSize);
		RandaddBuf ((unsigned char *) lpBuffer, dwSize);
		pNetApiBufferFree (lpBuffer);
	}

	/* Get disk I/O statistics for all the hard drives */
	for (nDrive = 0;; nDrive++)
	{
		DISK_PERFORMANCE diskPerformance;
		char szDevice[24];

		/* Check whether we can access this device */
		sprintf (szDevice, "\\\\.\\PhysicalDrive%d", nDrive);
		hDevice = CreateFile (szDevice, 0, FILE_SHARE_READ | FILE_SHARE_WRITE,
				      NULL, OPEN_EXISTING, 0, NULL);
		if (hDevice == INVALID_HANDLE_VALUE)
			break;


		/* Note: This only works if you have turned on the disk
		   performance counters with 'diskperf -y'.  These counters
		   are off by default */
		if (DeviceIoControl (hDevice, IOCTL_DISK_PERFORMANCE, NULL, 0,
				&diskPerformance, sizeof (DISK_PERFORMANCE),
				     &dwSize, NULL))
		{
			RandaddBuf ((unsigned char *) &diskPerformance, dwSize);
		}
		CloseHandle (hDevice);
	}

	// CryptoAPI
	for (i = 0; i < 100; i++)
	{
		if (hCryptProv && CryptGenRandom(hCryptProv, sizeof (buffer), buffer)) 
			RandaddBuf (buffer, sizeof (buffer));
	}

#else	// _WIN32

	// Read all bytes available in /dev/random up to buffer size
	int f = open ("/dev/random", O_RDONLY | O_NONBLOCK);
	if (f == -1)
	{
		perror ("Cannot open /dev/random");
		return FALSE;
	}

	i = read (f, buffer, sizeof (buffer));
	RandaddBuf (buffer, i);
	close (f);

	FastPoll ();

#endif	 // #else _WIN32

	burn(buffer, sizeof (buffer));
	Randmix();
	return TRUE;
}


/* This is the fastpoll function which gathers up info by calling various api's */
BOOL FastPoll (void)
{
	int nOriginalRandIndex = nRandIndex;
#ifdef _WIN32
	static BOOL addedFixedItems = FALSE;
	FILETIME creationTime, exitTime, kernelTime, userTime;
	DWORD minimumWorkingSetSize, maximumWorkingSetSize;
	LARGE_INTEGER performanceCount;
	MEMORYSTATUS memoryStatus;
	HANDLE handle;
	POINT point;

	/* Get various basic pieces of system information */
	RandaddInt32 (GetActiveWindow ());	/* Handle of active window */
	RandaddInt32 (GetCapture ());	/* Handle of window with mouse
					   capture */
	RandaddInt32 (GetClipboardOwner ());	/* Handle of clipboard owner */
	RandaddInt32 (GetClipboardViewer ());	/* Handle of start of
						   clpbd.viewer list */
	RandaddInt32 (GetCurrentProcess ());	/* Pseudohandle of current
						   process */
	RandaddInt32 (GetCurrentProcessId ());	/* Current process ID */
	RandaddInt32 (GetCurrentThread ());	/* Pseudohandle of current
						   thread */
	RandaddInt32 (GetCurrentThreadId ());	/* Current thread ID */
	RandaddInt32 (GetCurrentTime ());	/* Milliseconds since Windows
						   started */
	RandaddInt32 (GetDesktopWindow ());	/* Handle of desktop window */
	RandaddInt32 (GetFocus ());	/* Handle of window with kb.focus */
	RandaddInt32 (GetInputState ());	/* Whether sys.queue has any events */
	RandaddInt32 (GetMessagePos ());	/* Cursor pos.for last message */
	RandaddInt32 (GetMessageTime ());	/* 1 ms time for last message */
	RandaddInt32 (GetOpenClipboardWindow ());	/* Handle of window with
							   clpbd.open */
	RandaddInt32 (GetProcessHeap ());	/* Handle of process heap */
	RandaddInt32 (GetProcessWindowStation ());	/* Handle of procs
							   window station */
	RandaddInt32 (GetQueueStatus (QS_ALLEVENTS));	/* Types of events in
							   input queue */

	/* Get multiword system information */
	GetCaretPos (&point);	/* Current caret position */
	RandaddBuf ((unsigned char *) &point, sizeof (POINT));
	GetCursorPos (&point);	/* Current mouse cursor position */
	RandaddBuf ((unsigned char *) &point, sizeof (POINT));

	/* Get percent of memory in use, bytes of physical memory, bytes of
	   free physical memory, bytes in paging file, free bytes in paging
	   file, user bytes of address space, and free user bytes */
	memoryStatus.dwLength = sizeof (MEMORYSTATUS);
	GlobalMemoryStatus (&memoryStatus);
	RandaddBuf ((unsigned char *) &memoryStatus, sizeof (MEMORYSTATUS));

	/* Get thread and process creation time, exit time, time in kernel
	   mode, and time in user mode in 100ns intervals */
	handle = GetCurrentThread ();
	GetThreadTimes (handle, &creationTime, &exitTime, &kernelTime, &userTime);
	RandaddBuf ((unsigned char *) &creationTime, sizeof (FILETIME));
	RandaddBuf ((unsigned char *) &exitTime, sizeof (FILETIME));
	RandaddBuf ((unsigned char *) &kernelTime, sizeof (FILETIME));
	RandaddBuf ((unsigned char *) &userTime, sizeof (FILETIME));
	handle = GetCurrentProcess ();
	GetProcessTimes (handle, &creationTime, &exitTime, &kernelTime, &userTime);
	RandaddBuf ((unsigned char *) &creationTime, sizeof (FILETIME));
	RandaddBuf ((unsigned char *) &exitTime, sizeof (FILETIME));
	RandaddBuf ((unsigned char *) &kernelTime, sizeof (FILETIME));
	RandaddBuf ((unsigned char *) &userTime, sizeof (FILETIME));

	/* Get the minimum and maximum working set size for the current
	   process */
	GetProcessWorkingSetSize (handle, &minimumWorkingSetSize,
				  &maximumWorkingSetSize);
	RandaddInt32 (minimumWorkingSetSize);
	RandaddInt32 (maximumWorkingSetSize);

	/* The following are fixed for the lifetime of the process so we only
	   add them once */
	if (addedFixedItems == 0)
	{
		STARTUPINFO startupInfo;

		/* Get name of desktop, console window title, new window
		   position and size, window flags, and handles for stdin,
		   stdout, and stderr */
		startupInfo.cb = sizeof (STARTUPINFO);
		GetStartupInfo (&startupInfo);
		RandaddBuf ((unsigned char *) &startupInfo, sizeof (STARTUPINFO));
		addedFixedItems = TRUE;
	}
	/* The docs say QPC can fail if appropriate hardware is not
	   available. It works on 486 & Pentium boxes, but hasn't been tested
	   for 386 or RISC boxes */
	if (QueryPerformanceCounter (&performanceCount))
		RandaddBuf ((unsigned char *) &performanceCount, sizeof (LARGE_INTEGER));
	else
	{
		/* Millisecond accuracy at best... */
		DWORD dwTicks = GetTickCount ();
		RandaddBuf ((unsigned char *) &dwTicks, sizeof (dwTicks));
	}

	// CryptoAPI
	if (hCryptProv && CryptGenRandom(hCryptProv, sizeof (buffer), buffer)) 
		RandaddBuf (buffer, sizeof (buffer));

#else	// _WIN32

	// /dev/urandom

	int f = open ("/dev/urandom", 0);

	if (f == -1)
	{
		perror ("Cannot open /dev/urandom");
		return FALSE;
	}

	if (read (f, buffer, sizeof (buffer)) != sizeof (buffer))
	{
		perror ("Read from /dev/urandom failed");
		close (f);
		return FALSE;
	}

	close (f);
	RandaddBuf (buffer, sizeof (buffer));

#endif	// #else _WIN32

	/* Apply the pool mixing function */
	Randmix();

	/* Restore the original pool cursor position. If this wasn't done, mouse coordinates
	   could be written to a limited area of the pool, especially when moving the mouse
	   uninterruptedly. The severity of the problem would depend on the length of data
	   written by FastPoll (if it was equal to the size of the pool, mouse coordinates
	   would be written only to a particular 4-byte area, whenever moving the mouse
	   uninterruptedly). */
	nRandIndex = nOriginalRandIndex;

	return TRUE;
}

