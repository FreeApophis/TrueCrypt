/* Copyright (C) 2004 TrueCrypt Team, truecrypt.org
   This product uses components written by Paul Le Roux <pleroux@swprofessionals.com> */

#include "TCdefs.h"

#pragma VxD_LOCKED_CODE_SEG
#pragma VxD_LOCKED_DATA_SEG

#include "crypto.h"
#include "apidrvr.h"
#include "tc9x.h"
#include "queue.h"
#include "ifshook.h"

extern int bAllowFastShutdown;
extern cryptvol *cryptvols[];
extern char *transferbuffer;

extern ppIFSFileHookFunc IFSMgr_InstallFileSystemApiHook (pIFSFileHookFunc fcn);
extern int SHELLHookBroadcast (void *haddress, int ref);

ppIFSFileHookFunc prevhook = NULL;	/* address of previous IFS handler */
int threadid = -1;		/* Handle to the ring0 IO thread */
int nSemaphore = 0;		/* Sync object for the ring0 IO thread */
int terminatethread = 0;	/* Used when application reads disk drive.... */

int
HookProc (pIFSFunc fsdproc, int fcn, int drive, int flags, int cp, pioreq pir)
{
	int x, y;
	unsigned int fp;
	char *p;

	if (fcn < 2)		/* read or write */
	{
		if (pir->ir_data == (void *) transferbuffer)
		{
			y = pir->ir_options;
			pir->ir_options |= R0_MM_READ_WRITE;
			x = (**prevhook) (fsdproc, fcn, drive, flags, cp, pir);
			pir->ir_options = y;
			return x;
		}
		else
		{
			fp = pir->ir_pos;
			p = (char *) pir->ir_data;
			y = pir->ir_length;
			x = (**prevhook) (fsdproc, fcn, drive, flags, cp, pir);

			return x;

		}
	}

	return (**prevhook) (fsdproc, fcn, drive, flags, cp, pir);
}

int
BroadcastMon (int msg, int wparam, int lparam, int ref)
{
	cryptvol *cv;
	int c;

	if (msg == 0x16)	/* is it WM_ENDSESSION ? */
	{
		if (lparam < 0x80000000)	/* 0x80000000 is log off */
		{
			if (bAllowFastShutdown)
				return 1;

			for (c = 0; c < 8; c++)
			{
				cv = cryptvols[c];
				if (cv->booted)
				{
					return 0;
				}

			}


			OnSystemExit ();	/* only if NOT log off */
		}


	}

	if (msg == 0x11 && lparam < 0x80000000)	/* is it WM_QUERYENDSESSION ? */
	{
		if (bAllowFastShutdown)
			return 1;

		for (c = 0; c < 8; c++)
		{
			cv = cryptvols[c];
			if (cv->booted)
			{
				Post_message ("Please dismount all TC drives before attempting to shutdown Windows.", "TC drives still mounted!");
				return 0;	/* This will NOT stop
						   WM_ENDSESSION! */
			}
		}
	}


	return 1;
}

void
installhook (void)
{
	if (prevhook == NULL)
	{
		prevhook = IFSMgr_InstallFileSystemApiHook (HookProc);
		SHELLHookBroadcast (&BroadcastMon, 0);
	}
}

void
InstallTCThread (void)
{
	if (threadid == -1)
		threadid = installthread (&TCRing0Thread);
}


/* called when TC IO initially queued to wake up our ring 0 thread to handle
   the IO for us */

void
wakethread (void)
{
	Signal_Semaphore (nSemaphore);
}


/* called from broadcast handler */
void
killthread (void)
{
	if (threadid == -1)
		return;
	terminatethread = 1;
	Signal_Semaphore (nSemaphore);
}


/* This Ring 0 thread handles all TC IO, rather than schedule on global
   events which seem to cause trouble on Win98 */

void
TCRing0Thread (void)
{
	nSemaphore = Create_Semaphore (1);	/* task Sleep semaphore */

	while (1)
	{
		Wait_Semaphore (nSemaphore, BLOCK_THREAD_IDLE);
		if (terminatethread)
			break;
		DeQueueIOP ();
		if (terminatethread)
			break;	/* May have come in here too! */
	}

	threadid = -1;
	Destroy_Semaphore (nSemaphore);
}
