/* Copyright (C) 2004 TrueCrypt Team, truecrypt.org
   This product uses components written by Paul Le Roux <pleroux@swprofessionals.com> 
   Majority of this code originally Copyright (C) 1998/9 by Aman. Used with
   permission. Other parts originally Copyright (C) 1995 by Walter Oney used
   with implied permission. */

#include "TCdefs.h"

#pragma VxD_LOCKED_CODE_SEG
#pragma VxD_LOCKED_DATA_SEG

#include "crypto.h"
#include "fat.h"
#include "volumes.h"
#include "cache.h"
#include "apidrvr.h"
#include "tc9x.h"
#include "queue.h"

#include "ifshook.h"
#include "ifsmgr.inc"


#define NUMSLOTS        8	/* Only up to 8 volumes at a time */
#define MAXBLOCK        128	/* 64k  was 256.... */

#define MAX_MESSAGES    8	/* Max number of queued driver messages */

#define DEVICE_TYPE     0	/* We are a fixed disk (even files on
				   removables) */

#ifdef DEBUG
#define EXTRA_INFO 1
#endif

int halfseccount=0xc9;

char *transferbuffer = NULL;	/* IO transfer buffer */
char *appaccessbuffer = NULL;	/* win32 GUI IO buffer */
char *partitiontestbuffer = NULL;	/* Buffer for the MBR */
int dcbcount = 0;		/* DCB hack */
PDCB dcblist[128];		/* DCB hack */

PDCB dcb_boot;			/* Boot device */

extern DRP theDRP;		/* Device registration packet */

int bAllowFastShutdown = 0;

cryptvol cv1 =
{0, 0, 0, 0, 0, 0, 0, 0};

cryptvol cv2 =
{0, 0, 0, 0, 0, 0, 0, 0};

cryptvol cv3 =
{0, 0, 0, 0, 0, 0, 0, 0};

cryptvol cv4 =
{0, 0, 0, 0, 0, 0, 0, 0};

cryptvol cv5 =
{0, 0, 0, 0, 0, 0, 0, 0};

cryptvol cv6 =
{0, 0, 0, 0, 0, 0, 0, 0};

cryptvol cv7 =
{0, 0, 0, 0, 0, 0, 0, 0};

cryptvol cv8 =
{0, 0, 0, 0, 0, 0, 0, 0};

cryptvol *cryptvols[]=
{
	&cv1,
	&cv2,
	&cv3,
	&cv4,
	&cv5,
	&cv6,
	&cv7,
	&cv8
};

typedef struct MessageBox_t
{
	char *MessageHdr;
	char *MessageBody;
	int PostPlease;
} MessageBox;

MessageBox Msgs[MAX_MESSAGES];


VOID
OnAsyncRequest (PAEP aep)
{
	typedef USHORT (*PEF) (PAEP);

	static PEF evproc[AEP_MAX_FUNC + 1] =
	{(PEF) OnInitialize	/* 0 AEP_INITIALIZE */
	 ,NULL			/* 1 AEP_SYSTEM_CRIT_SHUTDOWN */
	 ,(PEF) OnBootComplete	/* 2 AEP_BOOT_COMPLETE */
	 ,(PEF) OnConfigDcb	/* 3 AEP_CONFIG_DCB */
	 ,(PEF) OnUnconfigDcb	/* 4 AEP_UNCONFIG_DCB */
	 ,NULL			/* 5 AEP_IOP_TIMEOUT */
	 ,NULL			/* 6 AEP_DEVICE_INQUIRY */
	 ,(PEF) OnHalfSec	/* 7 AEP_HALF_SEC */
	 ,NULL			/* 8 AEP_1_SEC */
	 ,NULL			/* 9 AEP_2_SECS */
	 ,NULL			/* 10 AEP_4_SECS */
	 ,NULL			/* 11 AEP_DBG_DOT_CMD */
	 ,NULL			/* 12 AEP_ASSOCIATE_DCB */
	 ,NULL			/* 13 AEP_REAL_MODE_HANDOFF */
	 ,(PEF) OnSystemExit	/* 14 AEP_SYSTEM_SHUTDOWN */
	 ,(PEF) OnUninitialize	/* 15 AEP_UNINITIALIZE */
	 ,NULL			/* 16 AEP_DCB_LOCK */
	 ,NULL			/* 17 AEP_MOUNT_VERIFY */
	 ,NULL			/* 18 AEP_CREATE_VRP */
	 ,NULL			/* 19 AEP_DESTROY_VRP */
	 ,NULL			/* 20 AEP_REFRESH_DRIVE */
	 ,NULL			/* 21 AEP_PEND_UNCONFIG_DCB */
	 ,NULL			/* 22 AEP_1E_VEC_UPDATE */
	 ,NULL			/* 23 AEP_CHANGE_RPM */
	};
	PEF proc;

	if (aep->AEP_func < arraysize (evproc) && (proc = evproc[aep->AEP_func]))
		aep->AEP_result = proc (aep);
	else
		aep->AEP_result = (USHORT) AEP_FAILURE;
}


USHORT
OnInitialize (PAEP_bi_init aep)
{
	/* allocate our (smaller) memory buffer..... */

	static int initalready = 0;

	if (initalready)
		return AEP_SUCCESS;

	initalready++;

	transferbuffer = (char *) _PageAllocate (50, PG_SYS, 0, 0, 0, MBYTE16, NULL, PAGEZEROINIT | PAGEFIXED | PAGECONTIG | PAGEUSEALIGN);
	partitiontestbuffer = (char *) transferbuffer + (265 * 512);
	appaccessbuffer = transferbuffer + (265 * 512);


	if (transferbuffer)
		return AEP_SUCCESS;

	return (USHORT) AEP_FAILURE;
}

USHORT
OnUninitialize (PAEP_bi_uninit aep)
{
	return AEP_SUCCESS;
}

/* asks us if we want to stay loaded or not. */

USHORT
OnBootComplete (PAEP_boot_done aep)
{
	installhook ();
	return AEP_SUCCESS;
}

USHORT
OnConfigDcb (PAEP_dcb_config aep)
{
	PDCB dcb = (PDCB) aep->AEP_d_c_dcb;
	if (!(dcb->DCB_cmn.DCB_device_flags & DCB_DEV_PHYSICAL))
	{
		return AEP_SUCCESS;
	}

	/* Sadly for SCSI some port drivers have not set apparent_blk_shift
	   up at this point.. if  ((dcb->DCB_cmn.DCB_apparent_blk_shift!=9)
	   && (dcb->DCB_cmn.DCB_device_type!=DCB_type_cdrom) ) return
	   AEP_SUCCESS; */

	if (dcbcount < 100)
	{
		if ((dcb->DCB_cmn.DCB_device_type == 0) || (dcb->DCB_cmn.DCB_device_type == DCB_type_cdrom))
		{
			if (cmpvend ((char *) &dcb->DCB_vendor_id, "JETICO", 6) != 0)
			{
				if (CheckDcbAlready (dcb))
					return AEP_SUCCESS;
				dcblist[dcbcount] = dcb;
				dcblist[dcbcount + 1] = NULL;
				dcbcount++;
			}
		}
	}


	if (dcb->DCB_cmn.DCB_device_type == 0)
		((IspInsertCalldown (dcb, OnRequest, (PDDB) aep->AEP_d_c_hdr.AEP_ddb, 0,
		    dcb->DCB_cmn.DCB_dmd_flags, aep->AEP_d_c_hdr.AEP_lgn)));

	return AEP_SUCCESS;
}

/* AEP_UNCONFIG_DCB informs us that the physical device represented by a DCB
   is going away */

USHORT
OnUnconfigDcb (PAEP_dcb_unconfig aep)
{
	return AEP_SUCCESS;
}

VOID
OnRequest (PIOP iop)
{
	DoCallDown (iop);	/* do normal unencryped disk stuff... */
}

int
cmpvend (char *a, char *b, int len)
{
	int n;
	for (n = 0; n < len; n++)
		if (a[n] != b[n])
			return 1;
	return 0;
}


int
CheckDcbAlready (PDCB dcb)
{
	int n;
	/* sometimes the same dcb is passed more than once, on some drivers!! */
	if (!dcbcount)
		return 0;

	for (n = 0; n < dcbcount; n++)
		if (dcblist[n] == dcb)
			return 1;

	return 0;
}

/* DoCallDown passes a request to the next lower layer. Note that the
   documentation about how to do this is totally wrong: you don't just add
   sizeof(DCB_cd_entry) to the calldown pointer, you follow a linked list
   from one calldown entry to the next. */

void
DoCallDown (PIOP iop)
{
	_asm
	{			/* call down to next layer */
		pushfd
		pushad
		mov ecx,[iop]
		mov eax,[ecx] IOP.IOP_calldown_ptr
		  mov eax,[eax] DCB_cd_entry.DCB_cd_next
		  mov[ecx] IOP.IOP_calldown_ptr, eax
		  push ecx
		  call[eax] DCB_cd_entry.DCB_cd_io_address
		  add esp, 4
		  popad
		  popfd
	}
}

  BOOL
OnSysDynamicDeviceInit ()
{
	cv1.cryptsectorfirst = 0x7fffffff;
	cv1.cryptsectorlast = 0;

	cv2.cryptsectorfirst = 0x7fffffff;
	cv2.cryptsectorlast = 0;

	cv3.cryptsectorfirst = 0x7fffffff;
	cv3.cryptsectorlast = 0;

	cv4.cryptsectorfirst = 0x7fffffff;
	cv4.cryptsectorlast = 0;

	cv5.cryptsectorfirst = 0x7fffffff;
	cv5.cryptsectorlast = 0;

	cv6.cryptsectorfirst = 0x7fffffff;
	cv6.cryptsectorlast = 0;

	cv7.cryptsectorfirst = 0x7fffffff;
	cv7.cryptsectorlast = 0;

	cv8.cryptsectorfirst = 0x7fffffff;
	cv8.cryptsectorlast = 0;

	IOS_Register (&theDRP);
	return TRUE;		/* stay resident no matter what IOS says */
}

BOOL
OnSysDynamicDeviceExit ()
{
	return TRUE;
}

DWORD
OnDeviceIoControl (PDIOCPARAMETERS p)
{
	installhook ();		/* make sure hook is installed */
	InstallTCThread ();

	/* select on IOCTL code */
	switch (p->dwIoControlCode)
	{

	case 0:		/* VWIN32 pinging us during CreateFile */
	case -1:		/* CloseHandle */
		break;

	case ALLOW_FAST_SHUTDOWN:
		{
			bAllowFastShutdown = 1;
			break;
		}

	case DRIVER_VERSION:
		{
			LONG *tmp = (LONG *) p->lpvInBuffer;
			LONG tmp2 = VERSION_NUM;

			if (tmp == NULL)
				return ERROR_GEN_FAILURE;

			memcpy (tmp, &tmp2, 4);
			break;
		}

	case WIPE_CACHE:
		WipeCache ();
		break;

	case CACHE_STATUS:
		return cacheEmpty ? ERROR_GEN_FAILURE : 0;

	case DISKIO:		/* Call to read and write sectors from
				   application */
		{
			DISKIO_STRUCT *dio = (DISKIO_STRUCT *) p->lpvInBuffer;
			int s;

			if (dio == NULL)
				return ERROR_GEN_FAILURE;

			s = AppAccessBlockDevice (dio->devicenum, dio->sectorstart, dio->sectorlen, dio->bufferad, dio->mode);
			dio->nReturnCode = s;

			break;
		}

	case OPEN_TEST:
		{
			OPEN_TEST_STRUCT *item = (OPEN_TEST_STRUCT *) p->lpvInBuffer;
			unsigned long *tmp = (void *) partitiontestbuffer;
			MOUNT_STRUCT mount;

			if (item == NULL)
				return ERROR_GEN_FAILURE;

			strcpy ((char *) mount.wszVolume, (char *) item->wszFileName);

			item->nReturnCode = ERR_BAD_DRIVE_LETTER;

			readallpartitions (&mount, TRUE);

			item->nReturnCode = mount.nReturnCode;

			item->secstart = tmp[0];
			item->seclast = tmp[1];
			item->device = tmp[2];

			break;
		}

	case MOUNT_LIST_N:
		{
			MOUNT_LIST_N_STRUCT *item = (MOUNT_LIST_N_STRUCT *) p->lpvInBuffer;
			cryptvol *cv;
			int c;

			if (item == NULL)
				return ERROR_GEN_FAILURE;

			item->nReturnCode = ERR_BAD_DRIVE_LETTER;

			for (c = 0; c < NUMSLOTS; c++)
			{
				cv = cryptvols[c];

				if ((cv->booted == 0) && (cv->physdevDCB == 0))
					continue;

				if (item->nDosDriveNo == cv->drive)
				{
					/* 16/9/99 This is safe as
					   item->wszVolume is >
					   cv->mounted_file_name */
					strcpy ((char *) item->wszVolume, cv->mounted_file_name);
					item->nReturnCode = 0;
					break;
				}
			}

			break;
		}

	case RELEASE_TIME_SLICE:
		ReleaseTimeSlice ();
		break;

	case MOUNT:
		{
			MOUNT_STRUCT *mount = (MOUNT_STRUCT *) p->lpvInBuffer;
			char tmp[9];

			if (mount == NULL)
				return ERROR_GEN_FAILURE;

#if EXTRA_INFO
			_Debug_Printf_Service ("MOUNT\n");
#endif

			memcpy (tmp, (char *) mount->wszVolume, 8);
			tmp[8] = 0;

			if (strcmp (tmp, "\\Device\\") == 0)
				readallpartitions (mount, FALSE);
			else
				mountdiskfileR0 (mount);

            if (mount->nReturnCode == 0 &&  bAllowFastShutdown == 1)
            {
                IFSMgr_PNPEvent (DBT_DEVICEARRIVAL, mount->nDosDriveNo, PNPT_VOLUME | DBTF_MEDIA );
            }


#if EXTRA_INFO
			_Debug_Printf_Service ("MOUNT end\n");
#endif

			break;
		}

	case UNMOUNT:
	case UNMOUNT_PENDING:
		{
			UNMOUNT_STRUCT *unmount = (UNMOUNT_STRUCT *) p->lpvInBuffer;
			cryptvol *cv;
			int c;

			if (unmount == NULL)
				return ERROR_GEN_FAILURE;

			unmount->nReturnCode = ERR_BAD_DRIVE_LETTER;

			for (c = 0; c < NUMSLOTS; c++)
			{
				cv = cryptvols[c];

				if ((cv->booted == 0) && (cv->physdevDCB == 0))
					continue;

				if (unmount->nDosDriveNo == cv->drive)
				{
					if (p->dwIoControlCode == UNMOUNT_PENDING)
					{
						if (closeCrDevice (cv, 0) != 0)
							unmount->nReturnCode = ERR_FILES_OPEN;
						else
							unmount->nReturnCode = 0;
					}
					else
					{
						if (closeCrDevice (cv, 1) != 0)
							unmount->nReturnCode = ERR_FILES_OPEN;
						else
							unmount->nReturnCode = 0;
					}

					break;
				}
			}

			break;
		}

	case MOUNT_LIST:
		{
			MOUNT_LIST_STRUCT *list = (MOUNT_LIST_STRUCT *) p->lpvInBuffer;
			cryptvol *cv;
			int c;

			if (list == NULL)
				return ERROR_GEN_FAILURE;

			list->ulMountedDrives = 0;

			for (c = 0; c < NUMSLOTS; c++)
			{
				int nDosDriveNo;

				cv = cryptvols[c];

				if ((cv->booted == 0) && (cv->physdevDCB == 0))
					continue;

				nDosDriveNo = cv->drive;

				list->ulMountedDrives |= 1 << nDosDriveNo;

				if (strlen (cv->mounted_file_name) < 64)
				{
					strcpy ((char *) list->wszVolume[nDosDriveNo], cv->mounted_file_name);
				}
				else
				{
					memcpy ((char *) list->wszVolume[nDosDriveNo], cv->mounted_file_name, 60);
					((char *) list->wszVolume[nDosDriveNo])[60] = '.';
					((char *) list->wszVolume[nDosDriveNo])[61] = '.';
					((char *) list->wszVolume[nDosDriveNo])[62] = '.';
					((char *) list->wszVolume[nDosDriveNo])[63] = 0;
				}

				list->cipher[nDosDriveNo] = cv->cryptoInfo->cipher;

				if(!cv->mountfilehandle)
					list->diskLength[nDosDriveNo] = (cv->cryptsectorlast - cv->cryptsectorfirst) * 512I64;
				else
					list->diskLength[nDosDriveNo] = 0;

				list->cipher[nDosDriveNo] = cv->cryptoInfo->cipher;

			}

			break;
		}

	case VOLUME_PROPERTIES:
		{
			VOLUME_PROPERTIES_STRUCT *prop = (VOLUME_PROPERTIES_STRUCT *) p->lpvInBuffer;
			cryptvol *cv;
			int c;

			if (prop == NULL)
				return ERROR_GEN_FAILURE;

			for (c = 0; c < NUMSLOTS; c++)
			{
				int nDosDriveNo;

				cv = cryptvols[c];

				if ((cv->booted == 0) && (cv->physdevDCB == 0))
					continue;

				nDosDriveNo = cv->drive;

				if (nDosDriveNo != prop->driveNo)
					continue;

				if (strlen (cv->mounted_file_name) < 64)
				{
					strcpy ((char *) prop->wszVolume, cv->mounted_file_name);
				}
				else
				{
					memcpy ((char *) prop->wszVolume, cv->mounted_file_name, 60);
					((char *) prop->wszVolume)[60] = '.';
					((char *) prop->wszVolume)[61] = '.';
					((char *) prop->wszVolume)[62] = '.';
					((char *) prop->wszVolume)[63] = 0;
				}

				prop->cipher = cv->cryptoInfo->cipher;

				if(!cv->mountfilehandle)
					prop->diskLength = (cv->cryptsectorlast - cv->cryptsectorfirst) * 512I64;
				else
					prop->diskLength = 0;

				prop->cipher = cv->cryptoInfo->cipher;
				prop->pkcs5 = cv->cryptoInfo->pkcs5;
				prop->pkcs5Iterations = cv->cryptoInfo->noIterations;
				prop->volumeCreationTime = cv->cryptoInfo->volume_creation_time;
				prop->headerCreationTime = cv->cryptoInfo->header_creation_time;

				return 0;
			}

			return ERROR_GEN_FAILURE;
		}


	default:
		return ERROR_INVALID_FUNCTION;

	}

	return 0;
}

BOOL
Kill_Drive (cryptvol * cv)
{
	BOOL result = FALSE;

	if (cv->booted != 0 || cv->physdevDCB != 0)
	{
		if ((cv->drive >= 0) && (cv->drive < 26))
		{
			result = IspDisassociateDcb (cv->drive);
			if (cv->mountfilehandle)
				R0_CloseFile (cv->mountfilehandle);

			if (result == TRUE)
			{
				PDCB dcb;

				if (!cv->mountfilehandle)
					unlockdrive (cv);	/* files to be handled
								   by win32 app. */

				crypto_close (cv->cryptoInfo);

				dcb = cv->ldcb;
				dcb->DCB_Port_Specific = 0;
				memset (cv, 0, sizeof (cryptvol));
				cv->cryptsectorfirst = 0x7fffffff;
			}
		}
	}

	return result;
}

int
closeCrDevice (cryptvol * cv, int mode)
{
	if (mode == 0)		/* pre flush volume call..... */
	{
		if (cv->drive != 0)
		{
			if (cv->booted <= 2)
			{
				_VolFlush (cv->drive, 0);	/* flush stuff out
								   before the
								   dismount... */
				//%% NotifyVolumeRemoval (cv->drive);
			}
			return 0;
		}
		else
			return 1;
	}
	else
	{
		if (Kill_Drive (cv) == TRUE)
			return 0;
		else
			return 0x42424242;
	}
}

int
installthread (void *t)
{
	int id;
	_asm
	{
		mov ecx, 4096
		  mov edi, 0
		  mov ebx,[t];
		xor esi, esi
	}

	  VxDCall (_VWIN32_CreateRing0Thread)
	_asm mov[id], eax
	  return id;
}

void
sectorcopy (char *dest, char *source, int num)
{
	_asm
	{
		pushad
		mov edi,[dest]
		mov esi,[source]
		mov ecx,[num]
		shl ecx, 9	/* *512 */
		  sar ecx, 4	/* 16 in pass... */
		  cpylp:
		  mov eax,[esi]
		mov ebx,[esi + 4]
		  mov[edi], eax
		  mov[edi + 4], ebx
		  mov eax,[esi + 8]
		mov ebx,[esi + 12]
		  mov[edi + 8], eax
		  mov[edi + 12], ebx
		  add edi, 16
		  add esi, 16
		  dec ecx
		  jnz cpylp
		  popad
	}
}

void
cryptproc (PIOP iop, cryptvol * cv)
{
	PDCB dcbx;
	unsigned int buffernum, totalsectors;
	unsigned int sectorstart, sectorcount;
	char *outbuffer, *bufadr, *buffercopy;
	_BlockDev_Scatter_Gather *sgd;

	dcbx = (PDCB) iop->IOP_physical_dcb;
	ior.IOR_status = 0;
	if (ior.IOR_func == IOR_WRITEV)
	{
		ior.IOR_status = IORS_INVALID_COMMAND;
		return;
	}

	sectorcount = ior.IOR_xfer_count;

	if (!sectorcount)
	{
		ior.IOR_status = 0;
		return;
	}

	if ((ior.IOR_func == IOR_READ) || (ior.IOR_func == IOR_WRITE))
	{
		if (iop->IOP_ior.IOR_flags & IORF_CHAR_COMMAND)
		{
			ior.IOR_status = IORS_INVALID_COMMAND;
			return;	/* Char command NOT supported or needed.... */
		}
	}
	else
	{
		ior.IOR_status = 0;
		if (!cv->mountfilehandle)
			DoCallDown (iop);
		return;
	}

	if (ior.IOR_func == IOR_READ)
	{
		sectorstart = ior.IOR_start_addr[0];
		sectorcount = ior.IOR_xfer_count;
		outbuffer = (char *) ior.IOR_buffer_ptr;	/* may be scatter gather
								   pointer... */
		if (ior.IOR_flags & IORF_SCATTER_GATHER)
		{
			sgd = (_BlockDev_Scatter_Gather *) outbuffer;
			while ((sectorcount = sgd->BD_SG_Count))
			{
				outbuffer = (char *) sgd->BD_SG_Buffer_Ptr;
				inblock (iop, outbuffer, sectorstart, sectorcount, cv);

				if (sectorstart == 0)
				{
					(unsigned char) outbuffer[0] = 0xeb;
					outbuffer[1] = 0x3c;
					(unsigned char) outbuffer[2] = 0x90;

					outbuffer[510] = 0x55;	/* boot sector
								   bodge...... */
					(unsigned char) outbuffer[511] = 0xAA;
				}

				sectorstart += sectorcount;
				++sgd;
			}
		}
		else
			/* linear buffer     */
		{
			inblock (iop, outbuffer, sectorstart, sectorcount, cv);

			/* The following code LIES to win98, who won't
			   otherwise mount disks created by earlier versions,
			   because the boot sector had stuff missing.  (fixed
			   now...) */
			if (sectorstart == 0)
			{
				(unsigned char) outbuffer[0] = 0xeb;
				outbuffer[1] = 0x3c;
				(unsigned char) outbuffer[2] = 0x90;
				outbuffer[510] = 0x55;
				(unsigned char) outbuffer[511] = 0xAA;
			}
		}
	}			/* end read op */
	else if (ior.IOR_func == IOR_WRITE)
	{
		if (cv->booted == 0)
		{
			ior.IOR_status = 0;
			return;
		}

		buffernum = 0;

		bufadr = transferbuffer;
		bufadr += (buffernum * (MAXBLOCK * 512));
		sectorstart = ior.IOR_start_addr[0];
		sectorcount = ior.IOR_xfer_count;
		outbuffer = (char *) ior.IOR_buffer_ptr;	/* may be scatter gather
								   pointer...; */
		totalsectors = 0;
		buffercopy = bufadr;

		if (ior.IOR_flags & IORF_SCATTER_GATHER)
		{
			sgd = (_BlockDev_Scatter_Gather *) outbuffer;
			while ((sectorcount = sgd->BD_SG_Count))
			{
				outbuffer = (char *) sgd->BD_SG_Buffer_Ptr;
				if ((totalsectors + sectorcount) <= MAXBLOCK)
				{
					sectorcopy (buffercopy, outbuffer, sectorcount);
					totalsectors += sectorcount;
					buffercopy += sectorcount * 512;
				}
				else
					/* write any previous buffer..... */
				{
					if (totalsectors)	/* was it too big to
								   start with ? */
					{
						outblock (iop, bufadr, sectorstart, totalsectors, cv, NULL);

						buffernum = 0;

						bufadr = transferbuffer;
						bufadr += (buffernum * (MAXBLOCK * 512));
						sectorstart += totalsectors;
						totalsectors = 0;
						buffercopy = bufadr;
						--sgd;	/* back to previous for
							   next pass..... */
					}
					else
					{	/* initial buffer was too
						   big, to start with! */
						outblock (iop, outbuffer, sectorstart, sectorcount, cv, bufadr);

						buffernum = 0;

						bufadr = transferbuffer;
						bufadr += (buffernum * (MAXBLOCK * 512));
						sectorstart += sectorcount;
						buffercopy = bufadr;
					}

				}
				++sgd;
			}	/* end while  */

			if (totalsectors)
				outblock (iop, bufadr, sectorstart, totalsectors, cv, NULL);	/* last one ? */
		}		/* end if scatter gather */
		else
			/* not scatter gather but is linear buffer */
		{

			outblock (iop, outbuffer, sectorstart, sectorcount, cv, bufadr);	/* get it to copy and do
												   large bit... */
		}
	}			/* end write op */

}

/* DoCallBack handles completion of an I/O request by calling the previous
   level's callback routine. */

void
DoCallBack (PIOP iop)
{
	_asm
	{			/* call back to previous layer */
		pushfd
		pushad
		mov ecx,[iop]
		sub[ecx] IOP.IOP_callback_ptr, size IOP_callback_entry
		mov eax,[ecx] IOP.IOP_callback_ptr
		push ecx
		call[eax] IOP_callback_entry.IOP_CB_address
		add esp, 4
		popad
		popfd

	}
}

VOID
partfilerequest (PIOP iop)
{
	PDCB dcb;
	cryptvol *cv;

	dcb = (PDCB) iop->IOP_physical_dcb;
	cv = (cryptvol *) dcb->DCB_Port_Specific;


	if ((cv != &cv1) && (cv != &cv2) && (cv != &cv3) && (cv != &cv4) && (cv != &cv5) && (cv != &cv6) && (cv != &cv7) && (cv != &cv8))
	{
		DoCallDown (iop);
		return;
	}

	if (cv->booted > 2)
	{
		ior.IOR_status = IORS_NOT_READY;	/* HW_FAILURE; */
		DoCallBack (iop);
		return;
	}

	if (ior.IOR_func == IOR_COMPUTE_GEOM)
	{
		dcb->DCB_actual_sector_cnt[0] = cv->cryptsectorlast - cv->cryptsectorfirst;
		dcb->DCB_actual_sector_cnt[0]++;
		dcb->DCB_actual_sector_cnt[1] = 0;
		dcb->DCB_actual_blk_size = 512;
		dcb->DCB_actual_head_cnt = 1;	/* number of heads */
		dcb->DCB_actual_cyl_cnt = 1;	/* number of cylinders */
		dcb->DCB_cmn.DCB_apparent_blk_shift = 9;
		dcb->DCB_cmn.DCB_TSD_Flags |= DCB_TSD_ACTUAL_PRE_SET;
		ior.IOR_status = IORS_SUCCESS;
		DoCallBack (iop);
		return;
	}

	if (ior.IOR_func == IOR_GEN_IOCTL)
	{
		iop->IOP_ior.IOR_ioctl_return = 01;
		ior.IOR_status = IORS_INVALID_PARM;	/* All the time now....  */
		DoCallBack (iop);
		return;
	}

	if ((ior.IOR_func == IOR_READ) || (ior.IOR_func == IOR_WRITE))
	{
		dcb = (PDCB) iop->IOP_physical_dcb;
		ior.IOR_status = IORS_CMD_IN_PROGRESS;	/* 0     */

		dcb->DCB_cmn.DCB_device_flags |= DCB_DEV_IO_ACTIVE;
		QueueMyIop (iop);
		return;
	}

	if ((ior.IOR_func == IOR_MEDIA_CHECK) || (ior.IOR_func == IOR_MEDIA_CHECK_RESET))
	{
		dcb = (PDCB) iop->IOP_original_dcb;

		ior.IOR_status = IORS_UNCERTAIN_MEDIA;	/* IORS_SUCCESS; */
		DoCallBack (iop);
		return;
	}

	ior.IOR_status = IORS_INVALID_COMMAND;
	DoCallBack (iop);
	return;
}

int
Add_Drive (PDCB dcb, cryptvol * cv, int prefdrive)
{
	int md = 0;
	PDCB ldcb;
	unsigned int flags;
	unsigned int dmdbits;
	ldcb = &cv->logicaldcb;
	cv->ldcb = ldcb;

#if EXTRA_INFO
	_Debug_Printf_Service ("Add_Drive\n");
#endif

	if (1)
	{
		ldcb = &cv->logicaldcb;
		flags = ldcb->DCB_cmn.DCB_device_flags;

		if (dcb)
			memcpy ((char *) ldcb, (char *) dcb, sizeof (DCB));

		ldcb->DCB_cmn.DCB_device_flags = flags;
		flags = dcb->DCB_cmn.DCB_device_flags;
		dmdbits = dcb->DCB_cmn.DCB_dmd_flags;
		dmdbits &= ~DCB_dmd_phys_sgd;
		cv->ldcb = ldcb;
		if (!cv->mountfilehandle)
			IspInsertCalldown (ldcb, partfilerequest, (PDDB) & cv->addb,
				 (USHORT) dcb->DCB_cmn.DCB_expansion_length,
					   dmdbits, (UCHAR) DRP_VSD_3);
		else
			IspInsertCalldown (ldcb, partfilerequest, (PDDB) & cv->addb, 0,
					   0, (UCHAR) DRP_VSD_3);

		ldcb->DCB_Port_Specific = (ULONG) cv;
		ldcb->DCB_cmn.DCB_physical_dcb = (ULONG) ldcb;
		ldcb->DCB_max_xfer_len = MAXBLOCK * 512;	/* 256*512 */

		if ((dcb->DCB_max_xfer_len < MAXBLOCK * 512) && (cv->mountfilehandle == 0))
			ldcb->DCB_max_xfer_len = dcb->DCB_max_xfer_len;

		if (!cv->mountfilehandle)
		{
			ldcb->DCB_max_sg_elements = dcb->DCB_max_sg_elements;	/* 1; */
			ldcb->DCB_cmn.DCB_expansion_length = dcb->DCB_cmn.DCB_expansion_length;
			ldcb->DCB_cmn.DCB_dmd_flags = dmdbits;
		}
		else
			ldcb->DCB_max_sg_elements = 17;

		ldcb->DCB_cmn.DCB_device_flags |= DCB_DEV_PHYSICAL;
		ldcb->DCB_cmn.DCB_device_flags2 = 0;
		ldcb->DCB_cmn.DCB_device_flags &= ~DCB_DEV_REMOVABLE;	/* support removable as
									   fixed... */
		ldcb->DCB_cmn.DCB_device_type = DEVICE_TYPE;
		ldcb->DCB_cmn.DCB_user_drvlet = (USHORT) md;
		ldcb->DCB_cmn.DCB_partition_type = 0;
		ldcb->DCB_cmn.DCB_Sstor_Host = 0;
		ldcb->DCB_actual_sector_cnt[0] = 0;
		ldcb->DCB_actual_sector_cnt[0]++;
		ldcb->DCB_actual_sector_cnt[1] = 0;
		ldcb->DCB_actual_blk_size = 512;
		ldcb->DCB_actual_head_cnt = 1;	/* number of heads */
		ldcb->DCB_actual_cyl_cnt = 1;	/* number of cylinders */
		ldcb->DCB_cmn.DCB_apparent_blk_shift = 9;
		ldcb->DCB_actual_spt = ldcb->DCB_actual_sector_cnt[0];
		ldcb->DCB_bdd.DCB_apparent_sector_cnt[0] = ldcb->DCB_actual_sector_cnt[0];
		ldcb->DCB_bdd.DCB_apparent_sector_cnt[1] = 0;
		ldcb->DCB_bdd.DCB_apparent_head_cnt = 1;
		ldcb->DCB_bdd.DCB_apparent_blk_size = 512;
		ldcb->DCB_bdd.DCB_apparent_cyl_cnt = 1;
		ldcb->DCB_bdd.DCB_apparent_spt = ldcb->DCB_actual_sector_cnt[0];
	}

	ldcb->DCB_cmn.DCB_drive_lttr_equiv = 0;
	ldcb->DCB_cmn.DCB_user_drvlet = 0;
	ldcb->DCB_cmn.DCB_device_type = DEVICE_TYPE;

	if (prefdrive != -1)
		md = IspDriveLetterPickPref (ldcb, (UCHAR) ISP_PDL_FL_USE_RANGE, (UCHAR) prefdrive);
	else
		md = (unsigned char) 255;


	if (md == 255)
		md = IspDriveLetterPick (ldcb, 0);

	ldcb->DCB_cmn.DCB_unit_number = (UCHAR) md;
	ldcb->DCB_cmn.DCB_vrp_ptr = 0;	/* clear the copied VRP pointer...... */
	ldcb->DCB_cmn.DCB_device_flags |= DCB_DEV_WRITEABLE;

	if (!(flags & DCB_DEV_WRITEABLE))
		ldcb->DCB_cmn.DCB_device_flags &= ~DCB_DEV_WRITEABLE;

	ldcb->DCB_cmn.DCB_drive_lttr_equiv = md;
	ldcb->DCB_cmn.DCB_user_drvlet = (UCHAR) md;
	ldcb->DCB_cmn.DCB_unit_number = (UCHAR) md;	/* 0;  */

	cv->drive = (ULONG) md;
	ldcb->DCB_cmn.DCB_TSD_Flags = DCB_TSD_APPARENT_PRE_SET | DCB_TSD_MBPB_PBR;
	ldcb->DCB_cmn.DCB_partition_type = 0;
	ldcb->DCB_cmn.DCB_device_flags &= ~DCB_DEV_TSD_PROCESSED;
	ldcb->DCB_cmn.DCB_Partition_Start = 0;
	ldcb->DCB_cmn.DCB_device_flags |= DCB_DEV_LOGICAL | DCB_DEV_MEDIA_CHANGED | DCB_DEV_UNCERTAIN_MEDIA;

	ldcb->DCB_cmn.DCB_cAssoc = 1;

	ldcb->DCB_cmn.DCB_user_drvlet = 0xFF;

#if EXTRA_INFO
	_Debug_Printf_Service ("Add_Drive end\n");
#endif

	if ((md <= 26) && (md > 1))
	{
		IspAssociateDcb (ldcb, (char) md, ISP_D_A_FL_NOSHELLMSG);

		cv->notifytime = 2;	/* 2 second to notify arrival of disk */

		return 0;
	}

	return 1;
}

#define FIRST_READ_SIZE SECTOR_SIZE

int
trymountfile (PDCB dcb, cryptvol * cv, MOUNT_STRUCT * mf)
{
	USHORT offset;
	USHORT size;
	PIOP myiop;
	PIOR myior;
	int mounted = 0;
	char *readBuffer = NULL;

	if (dcb->DCB_cmn.DCB_device_type == DCB_type_disk)
	{
		int status;

		offset = (USHORT) (dcb->DCB_cmn.DCB_expansion_length + FIELDOFFSET (IOP, IOP_ior));
		size = offset + sizeof (IOR) + dcb->DCB_max_sg_elements * sizeof (SGD);
		myiop = IspCreateIop (size, offset, ISP_M_FL_MUST_SUCCEED | ISP_M_FL_SMART_ALLOC | ISP_M_FL_INTERRUPT_TIME | ISP_M_FL_PERSISTENT_IOP);
		myior = &myiop->IOP_ior;
		myior->IOR_private_client = offset;

		readBuffer = TCalloc (FIRST_READ_SIZE);
		if (readBuffer == NULL)
			goto error;

		dophysblock (myiop, cv->cryptsectorfirst, FIRST_READ_SIZE / 512, readBuffer, cv, IOR_READ);

		status = VolumeReadHeaderCache (mf->bCache, readBuffer, mf->szPassword,
					 mf->nPasswordLen, &cv->cryptoInfo);

		if (status != 0)
		{
			memset (cv, 0, sizeof (cryptvol));
			cv->cryptsectorfirst = 0x7fffffff;
			mounted = 0;
			goto error;
		}
		else
			cv->booted = 1;

		if (Add_Drive (dcb, cv, mf->nDosDriveNo) == 0)
		{
			mounted = 1;
		}
		else
		{
			/* No Drive letter available */
			memset (cv, 0, sizeof (cryptvol));
			cv->cryptsectorfirst = 0x7fffffff;
			mounted = -1;
		}

	      error:
		if (readBuffer != NULL)
			TCfree (readBuffer);

		IspDeallocMem ((PVOID) ((DWORD) myior - myior->IOR_private_client));
		return mounted;
	}

	return mounted;
}

void
readnullfilesize (int hand)
{
	int bytes;
	char buffer[512];
	R0_ReadFile (FALSE, hand, 0, 0, buffer, &bytes);
}

void
mountdiskfileR0 (MOUNT_STRUCT * mf)
{
	DWORD hfile;
	DWORD action;
	int tmf;
	int code;
	cryptvol *cv;
	int c;
	int writeable = 1;
	PDCB dcb;
	int flag = 0;
	unsigned char openflag = 0x81;

	char *fname = (char *) mf->wszVolume;


	installhook ();		/* only installs if not done already... */

	for (c = 0; c < NUMSLOTS; c++)
	{
		cv = cryptvols[c];
		if (strcmp (fname, (char *) &cv->mounted_file_name) == 0)
		{
			flag = 3 + 128;	/* already present */
			goto done;
		}
	}

	if (writeable)
	{
		code = R0_OpenCreateFile (FALSE, ACCESS_READWRITE | SHARE_DENYREADWRITE,
		      0, ACTION_OPENEXISTING, 0x81, fname, &hfile, &action);	/* R0_NO_CACHE(UBYTE)
										   ((R0_NO_CACHE)>>8) */

		if (code != 0)
		{
			writeable = 0;
			code = R0_OpenCreateFile (FALSE, ACCESS_READONLY | SHARE_DENYREAD,
						  0, ACTION_OPENEXISTING, 0x81, fname, &hfile, &action);	/* R0_NO_CACHE(UBYTE)
														   ((R0_NO_CACHE)>>8) */
		}

		if (code == 0)
			readnullfilesize (hfile);
	}
	else
	{
		code = R0_OpenCreateFile (FALSE, ACCESS_READONLY | SHARE_DENYREAD,
		      0, ACTION_OPENEXISTING, 0x81, fname, &hfile, &action);	/* R0_NO_CACHE(UBYTE)
										   ((R0_NO_CACHE)>>8) */

		if (code == 0)
			readnullfilesize (hfile);
	}

	if (code != 0)
	{
		flag = 1;
		goto done;
	}

	for (c = 0; c < NUMSLOTS; c++)
	{
		cv = cryptvols[c];

		if ((cv->booted == 0) && (cv->physdevDCB == 0))
		{
			cv->filehostdcb = 0;
			cv->mountfilehandle = hfile;
			cv->physdevDCB = &cv->logicaldcb;
			cv->cryptsectorfirst = 0x00000000;
			cv->cryptsectorlast = 0x7ffffff0;
			dcb = (PDCB) cv->physdevDCB;
			flag = 2;

			if (writeable != 0)
				dcb->DCB_cmn.DCB_device_flags = DCB_DEV_WRITEABLE;

			/* clears cv set above if failed.... */
			tmf = trymountfile (dcb, cv, mf);

			if (tmf)
			{
				_asm cli
				  flag = 3;

				mf->nReturnCode = flag;

				if (tmf > 0)	/* if tmg is -ve then no
						   drive letter (already had
						   blue screen..) */
				{
					mf->nReturnCode = flag;

					cv->booted = 2;
					strcpy ((char *) &cv->mounted_file_name, fname);

					goto done;
				}
			}	/* trymountfile */

		}		/* if cv->.... */

		if (flag)
			break;	/* out of for loop */
	}


	R0_CloseFile (hfile);

      done:

	switch (flag)
	{
	case 3 + 128:
		mf->nReturnCode = ERR_VOL_ALREADY_MOUNTED;
		break;
	case 1:
		mf->nReturnCode = ERR_FILE_OPEN_FAILED;
		break;
	case 2:
		mf->nReturnCode = ERR_VOL_MOUNT_FAILED;
		break;
	case 3:
		if (tmf > 0)
		{
			mf->nReturnCode = 0;
			mf->nDosDriveNo = cv->drive;
		}
		else
			mf->nReturnCode = ERR_NO_FREE_DRIVES;
		break;
	case 0:
		mf->nReturnCode = ERR_NO_FREE_SLOTS;
		break;
	}
}


void
outblock (PIOP iop, char *outbuffer, int sectorstart, int sectorcount, cryptvol * cv, char *workbuff)
{
	int logsec = sectorstart + 1;	/* get logical volume sector. */

	char *sendbuffer;

	if (!sectorcount)
		return;

	do
	{
		if (sectorcount <= MAXBLOCK)
		{
			sendbuffer = outbuffer;

			/* if copyflag 0, then buffer already set by caller. */
			ior.IOR_status = 0;
			if (workbuff)
			{
				sectorcopy (workbuff, outbuffer, sectorcount);
				sendbuffer = workbuff;
			}

			writelogical (iop, logsec, sectorcount, sendbuffer, cv);

			sectorcount = 0;
			return;
		}
		else
		{
			sendbuffer = outbuffer;
			if (workbuff)
			{
				sectorcopy (workbuff, outbuffer, MAXBLOCK);
				sendbuffer = workbuff;
			}

			writelogical (iop, logsec, MAXBLOCK, sendbuffer, cv);
			logsec += MAXBLOCK;
			sectorcount -= MAXBLOCK;
			outbuffer += (MAXBLOCK * 512);
		}
	}
	while ((sectorcount > 0) && (ior.IOR_status < 16));
}

void
inblock (PIOP iop, char *outbuffer, int sectorstart, int sectorcount, cryptvol * cv)
{
	int logsec = sectorstart + 1;	/* get logical volume sector. */

	do
	{
		ior.IOR_status = 0;
		if (sectorcount < MAXBLOCK)
		{
			readlogical (iop, logsec, sectorcount, (char *) transferbuffer, cv);
			memcpy (outbuffer, transferbuffer, sectorcount * 512);
			sectorcount = 0;
			return;
		}
		else
		{
			readlogical (iop, logsec, MAXBLOCK, (char *) transferbuffer, cv);
			memcpy (outbuffer, transferbuffer, MAXBLOCK * 512);
			logsec += MAXBLOCK;
			sectorcount -= MAXBLOCK;
			outbuffer += (MAXBLOCK * 512);
		}
	}
	while ((sectorcount > 0) && (ior.IOR_status < 16));
}

int
doR0fileio (int sector, int numsectors, char *buffer, cryptvol * cv, int iorop)
{
	CLIENT_STRUCT sregs;	/* static */
	PVRP v;

	int res;
	int bytes;		/* static */


	if (iorop == IOR_READ)
	{
		if (numsectors)
		{
			SaveClientState ((CLIENT_STRUCT *) & sregs);

			res = R0_ReadFile (FALSE, cv->mountfilehandle, numsectors << 9, sector << 9, buffer, &bytes);

			RestoreClientState ((CLIENT_STRUCT *) & sregs);
		}

		return res;
	}			/* IOR read */

	res = 0;
	if (iorop == IOR_WRITE)
	{
		if (numsectors)
		{
			SaveClientState ((CLIENT_STRUCT *) & sregs);

			res = R0_WriteFile (FALSE, cv->mountfilehandle, numsectors * 512, sector * 512, buffer, &bytes);

			RestoreClientState ((CLIENT_STRUCT *) & sregs);
		}

		if (res)
		{
			if (res == 5)
				res = 0x13;	/* WHY ARE WE GETTING ACCESS
						   DENIED 005 ON CD RATHER
						   THAN WP ? */

			if (res == 0x13)
			{
				if (cv->booted >= 2)
				{
					v = (PVRP) cv->ldcb->DCB_cmn.DCB_vrp_ptr;
					if (v)
					{
						if ((v->VRP_event_flags & VRP_ef_write_protected) == 0)
						{
							v->VRP_event_flags |= VRP_ef_write_protected | VRP_ef_media_uncertain;
						}
					}
				}	/* cv->booted */
			}	/* res=13 */
		}		/* res= something */

		return res;
	}			/* IOR write */

	return 0;
}

int
MapDosError (int error)
{
	int e;

	if (error == 0x13)
		return (IORS_WRITE_PROTECT);

	e = IORS_NOT_READY;	/* IORS_HW_FAILURE;      */
	return e;
}

char fileerrorstr[]=
{
	"TC has encountered an error reading a host file which\n"
	"it is using for a currently open scrambled disk volume.\n\n"
	"You should immediately dismount the file using the TC mount\n"
   "application, correct the error, and re mount the disk image file.\n\n\n"
      "The related disk will be unavailable, until you do, and you should\n"
	"save your work elsewhere."
};

int
dophysblock2 (PIOP iop, int sector, int numsectors, char *buffr, cryptvol * cv, USHORT iorop)
{
	int rstatus = 0;	/* status return value.... */
	PIOP myiop;
	PIOR myior;

	_BlockDev_Scatter_Gather *sgd;

	PDCB mydcb = cv->physdevDCB;	/* (PDCB) iop->IOP_physical_dcb; */
	USHORT offset;
	USHORT size;

	if (cv->mountfilehandle)
	{
		if (cv->booted <= 2)
			rstatus = doR0fileio (sector, numsectors, buffr, cv, iorop);
		else
			rstatus = 23;

		if ((rstatus) && (rstatus != 0x13))
		{
			iop->IOP_timer = iop->IOP_timer_orig = 32000;
			rstatus = MapDosError (rstatus);

			if (cv->booted <= 2 && (cv->booted))
			{
				Post_message (fileerrorstr, "TC: Mounted file error");
				cv->booted = 256;
			}
		}

		iop->IOP_ior.IOR_status = rstatus;
		return rstatus;
	}

	/* End up here, if we are handling a disk partition rather than
	   container file */
	offset = (USHORT) (mydcb->DCB_cmn.DCB_expansion_length + FIELDOFFSET (IOP, IOP_ior));
	size = offset + sizeof (IOR) + (8 * sizeof (SGD));
	iop->IOP_timer = iop->IOP_timer_orig = 160;

	myiop = IspCreateIop (size, offset, ISP_M_FL_SMART_ALLOC);

	if (myiop == NULL)
	{

		iop->IOP_ior.IOR_status = IORS_MEMORY_ERROR;
		return IORS_MEMORY_ERROR;
	}

	myior = &myiop->IOP_ior;

	/* Be aware that Criteria routine reads it's dmd bits from THIS dcb! */

	myiop->IOP_original_dcb = (ULONG) mydcb;	/* iop->IOP_original_dcb;
							   (ULONG) mydcb;        */
	myiop->IOP_physical_dcb = (ULONG) mydcb->DCB_cmn.DCB_physical_dcb;
	if (cv->booted == 1)
		cv->booted = 2;	/* Irrelevant here.....    */
	myior->IOR_next = 0;
	myior->IOR_start_addr[1] = 0;
	myior->IOR_flags = IORF_VERSION_002;
	myior->IOR_private_client = offset;
	myior->IOR_req_vol_handle = mydcb->DCB_cmn.DCB_vrp_ptr;
	myior->IOR_sgd_lin_phys = (ULONG) (myior + 1);
	myior->IOR_num_sgds = 0;
	myior->IOR_vol_designtr = mydcb->DCB_cmn.DCB_unit_number;
	myior->IOR_func = iorop;
	myior->IOR_flags |= IORF_BYPASS_VOLTRK | IORF_HIGH_PRIORITY | IORF_SCATTER_GATHER | IORF_SYNC_COMMAND | IORF_DONT_CACHE;
	if (iorop == IOR_READ)
		myior->IOR_flags |= IORF_DATA_IN;
	if (iorop == IOR_WRITE)
		myior->IOR_flags |= IORF_DATA_OUT;
	myior->IOR_start_addr[0] = sector;
	myior->IOR_xfer_count = numsectors;
	sgd = (_BlockDev_Scatter_Gather *) myior->IOR_sgd_lin_phys;	/* scatter gather
									   array... */
	sgd->BD_SG_Buffer_Ptr = (ULONG) buffr;	/* Buffer in LOCKED ram,
						   below 16mbyte, 4K
						   boundary.. */
	sgd->BD_SG_Count = numsectors;
	myior->IOR_buffer_ptr = (ULONG) sgd;	/* Implement as Scatter
						   gather, with One block */
	sgd++;
	sgd->BD_SG_Buffer_Ptr = 0;
	sgd->BD_SG_Count = 0;
	sgd++;
	myior->IOR_sgd_lin_phys = (ULONG) sgd;
	rstatus = myior->IOR_status;
	sgd->BD_SG_Buffer_Ptr = 0;
	sgd->BD_SG_Count = 0;
	sgd++;
	sgd->BD_SG_Buffer_Ptr = 0;
	sgd->BD_SG_Count = 0;
	sgd++;
	sgd->BD_SG_Buffer_Ptr = 0;
	sgd->BD_SG_Count = 0;
	myiop->IOP_timer = 40;
	myiop->IOP_timer_orig = 40;
	/* Call criteria, to set phys SGDs physical addresses if needed..... */
	if (IlbIntIoCriteria (myiop))
		myior->IOR_flags |= IORF_DOUBLE_BUFFER;	/* Double buffer, will
							   also make no
							   difference */
	IlbInternalRequest (myiop, mydcb, OnRequest);
	rstatus = myior->IOR_status;
	iop->IOP_ior.IOR_status = rstatus;	/* myior->IOR_status; */
	IspDeallocMem ((PVOID) ((DWORD) myior - myior->IOR_private_client));
	return rstatus;
}

int
dophysblock (PIOP iop, int sector, int numsectors, char *buffr, cryptvol * cv, USHORT iorop)
{
	int s, c;

	for (c = 0; c < 3; c++)
	{
		s = dophysblock2 (iop, sector, numsectors, buffr, cv, iorop);
		if (s == IORS_SUCCESS_WITH_RETRY)
			return 0;
		if (!s)
			return 0;
	}

	return s;
}

void
readlogical (PIOP iop, int temp_block, int num_sectors, char *buffer, cryptvol * cv)
{
	int secNum;

	secNum = temp_block;

#if EXTRA_INFO
	_Debug_Printf_Service ("secNum=%d,num_sectors=%d\n", secNum, num_sectors);
#endif

	dophysblock (iop, secNum + cv->cryptsectorfirst, num_sectors, buffer, cv, IOR_READ);

#if EXTRA_INFO
	_Debug_Printf_Service ("0x%08x\n", *((int *) buffer));
#endif

	cv->cryptoInfo->decrypt_sector ((unsigned long *) buffer,
					(unsigned __int64) secNum, num_sectors,
					&cv->cryptoInfo->ks[0],
					cv->cryptoInfo->iv,
					cv->cryptoInfo->cipher);

#if EXTRA_INFO
	_Debug_Printf_Service ("0x%08x\n", *((int *) buffer));
#endif

}

void
writelogical (PIOP iop, int temp_block, int num_sectors, char *buffer, cryptvol * cv)
{
	int secNum;
	
	secNum = temp_block;

#if EXTRA_INFO
	_Debug_Printf_Service ("0x%08x\n", *((int *) buffer));
#endif

	cv->cryptoInfo->encrypt_sector ((unsigned long *) buffer,
					(unsigned __int64) secNum, num_sectors,
					&cv->cryptoInfo->ks[0],
					cv->cryptoInfo->iv,
					cv->cryptoInfo->cipher);

#if EXTRA_INFO
	_Debug_Printf_Service ("0x%08x\n", *((int *) buffer));
#endif

	dophysblock (iop, secNum + cv->cryptsectorfirst, num_sectors, buffer, cv, IOR_WRITE);
}


BOOL
OnSystemExit (void)
{
	/* Called when Win32 is about to die. We must close down the files,
	   for any files mounted as encrypted disks. this call seems to be
	   the only chance we get. the system pukes amd hangsif we don't.
	   Corrupt screen etc. nd refuses to shut down..... */

	cryptvol *cv;
	int c;

	for (c = 0; c < NUMSLOTS; c++)
	{
		cv = cryptvols[c];
		unlockdrive (cv);
		if (cv->mountfilehandle)
			R0_CloseFile (cv->mountfilehandle);
	}

	killthread ();
	return AEP_SUCCESS;
}

void
Post_message (char *msg, char *header)
{
	MessageBox *m;
	int n;

	for (n = 0; n < MAX_MESSAGES - 1; n++)
	{
		m = &Msgs[n];
		if (m->PostPlease == 0)
			break;

	}

	m->PostPlease = 1;
	m->MessageHdr = header;
	m->MessageBody = msg;
}

void
ProcessWinMessagesBlueScreen (void)
{
	MessageBox *m;
	int n;

	for (n = 0; n < MAX_MESSAGES; n++)
	{
		m = &Msgs[n];
		if (m->PostPlease)
		{
			ShellMessageNCB (0, m->MessageBody, m->MessageHdr);
			m->PostPlease = 0;
		}
	}
}

/* The code below gets called by the IOS *every* 0.5 seconds... */
USHORT 
OnHalfSec (PAEP_boot_done aep) /* dummy param */
{
#if 0
	cryptvol *cv;
        int c;
	int notified = 0;
#endif

	halfseccount++;

	ProcessWinMessagesBlueScreen ();

#if 0
        for (c = 0; c < 8; c++)
	{
		cv = cryptvols[c];

		if (cv->notifytime)
		{
			cv->notifytime--;
			if (cv->notifytime == 0)
			{
				cv->notifytime = 0x8000ffff;
				if (!notified) /* prevent multiple notifications */
				{
					notified++;
					SHELL_CallAtAppyTime ((APPY_CALLBACK) & drivearrived, 0, 0);
				}
			}

		}
	}
#endif

	return AEP_SUCCESS;
}


/* ------------------------------------partition support
   ------------------------------------------- */

/* go round every drive reading all the partitions.... */
void
readallpartitions (MOUNT_STRUCT * mf, BOOL bVerifyOnly)
{
	int c = 0;
	PDCB dcb;
	USHORT offset;
	USHORT size;
	PIOP myiop;
	PIOR myior;
	int x, disks, z;
	char *vol = (char *) mf->wszVolume;

	mf->nReturnCode = ERR_INVALID_DEVICE;	/* Assume failure */

	if (strlen ((char *) mf->wszVolume) < 28)
		return;

	x = vol[16] - '0';	/* Disk number starting from 0 */
	z = vol[27] - '0';	/* Partition number start from 1 */
	disks = 0;		/* Count of disks */

	if (x < 0 || z < 1)
		return;

#if EXTRA_INFO
	_Debug_Printf_Service ("readallpartitions\n");
#endif

	while (dcb = dcblist[++c])
	{
		if ((dcb->DCB_cmn.DCB_device_type == 0) && (dcb->DCB_cmn.DCB_apparent_blk_shift == 9))
		{
			if (x != disks++)
				continue;

			offset = (USHORT) (dcb->DCB_cmn.DCB_expansion_length + FIELDOFFSET (IOP, IOP_ior));
			size = offset + sizeof (IOR) + dcb->DCB_max_sg_elements * sizeof (SGD);
			myiop = IspCreateIop (size, offset, ISP_M_FL_MUST_SUCCEED | ISP_M_FL_SMART_ALLOC | ISP_M_FL_INTERRUPT_TIME | ISP_M_FL_PERSISTENT_IOP);
			myior = &myiop->IOP_ior;
			myior->IOR_private_client = offset;

			DiskRead (dcb, myiop, 0, 1, partitiontestbuffer, IOR_READ);	/* ;single read in case
											   of media change... */
			memset (partitiontestbuffer, 0, 512);

			if (!DiskRead (dcb, myiop, 0, 1, partitiontestbuffer, IOR_READ))	/* +32768  */
			{
				UsePartitionInfo (dcb, myiop, partitiontestbuffer, 0, 0, &z, mf, bVerifyOnly);	/* +32768 */
			}

			IspDeallocMem ((PVOID) ((DWORD) myior - myior->IOR_private_client));

		}
	}

#if EXTRA_INFO
	_Debug_Printf_Service ("readallpartitions end\n");
#endif

}


int
DiskRead (PDCB mydcb, PIOP myiop, unsigned int sector, unsigned int numsectors, char *buffr, USHORT iorop)
{
	int rstatus = 0;	/* status return value....  */
	unsigned long *errnl = (unsigned long *) buffr;	/* no load test... */
	PIOR myior;
	_BlockDev_Scatter_Gather *sgd;

	myior = &myiop->IOP_ior;
	myiop->IOP_original_dcb = (ULONG) mydcb;
	myiop->IOP_physical_dcb = (ULONG) mydcb->DCB_cmn.DCB_physical_dcb;
	myior->IOR_next = 0;
	myior->IOR_start_addr[1] = 0;
	myior->IOR_flags = IORF_VERSION_002;
	myior->IOR_req_vol_handle = mydcb->DCB_cmn.DCB_vrp_ptr;
	myior->IOR_sgd_lin_phys = (ULONG) (myior + 1);
	myior->IOR_num_sgds = 0;
	myior->IOR_vol_designtr = mydcb->DCB_cmn.DCB_unit_number;
	myior->IOR_func = iorop;
	myior->IOR_flags |= IORF_BYPASS_VOLTRK | IORF_HIGH_PRIORITY | IORF_SCATTER_GATHER | IORF_SYNC_COMMAND;
	if (iorop == IOR_READ)
	{
		myior->IOR_flags |= IORF_DATA_IN;
		memset (buffr, 0, numsectors * 512);
		errnl[0] = 0xACE01DE4;
		errnl[1] = 0xEDB0CD01;
		errnl[2] = 0x4caf3321;
		errnl[3] = 0xa35a32c4;
	}

	if (iorop == IOR_WRITE)
		myior->IOR_flags |= IORF_DATA_OUT;
	myior->IOR_start_addr[0] = sector;
	myior->IOR_xfer_count = numsectors;
	myior->IOR_buffer_ptr = (ULONG) buffr;

	sgd = (_BlockDev_Scatter_Gather *) myior->IOR_sgd_lin_phys;	/* scatter gather
									   array... */
	sgd->BD_SG_Buffer_Ptr = (ULONG) buffr;	/* Buffer in LOCKED ram,
						   below 16mbyte, 4K
						   boundary.. */
	sgd->BD_SG_Count = numsectors;
	myior->IOR_buffer_ptr = (ULONG) sgd;	/* Implement as Scatter
						   gather, with One block */
	sgd++;
	sgd->BD_SG_Buffer_Ptr = 0;
	sgd->BD_SG_Count = 0;

	sgd++;
	myior->IOR_sgd_lin_phys = (ULONG) sgd;
	rstatus = myior->IOR_status;

	myiop->IOP_timer = 40;
	myiop->IOP_timer_orig = 40;

	if (mydcb->DCB_cmn.DCB_Sstor_Host == FALSE)
	{
		if (IlbIntIoCriteria (myiop))
			myior->IOR_flags |= IORF_DOUBLE_BUFFER;
		IlbInternalRequest (myiop, mydcb, 0);
		rstatus = myior->IOR_status;

		if (iorop == IOR_READ)
		{
			/* checks for partion reads of simulated drives that
			   dont return either data or error.... */
			if ((errnl[0] == 0xACE01DE4) &&
			    (errnl[1] == 0xEDB0CD01) &&
			    (errnl[2] == 0x4caf3321) &&
			    (errnl[3] == 0xa35a32c4))

				rstatus = 16;

		}

		return rstatus;
	}

	return 16;


}

/* This routine finds partitions */

void
UsePartitionInfo (PDCB dcb, PIOP myiop, char *diskbuffer, unsigned int relative, int recursed, int *partnum,
		  MOUNT_STRUCT * mf, BOOL bVerifyOnly)
{
	/* Note that this is recursive..... */
	partitionrec *pr;
	char *c;
	char *ndb;
	int flag = 0;
	cryptvol *cv = NULL;

	unsigned int ComputedStartSector;
	unsigned int ComputedEndSector;
	unsigned int cyl;
	unsigned int cylsize;
	unsigned int headsize;

#if EXTRA_INFO
	_Debug_Printf_Service ("UsePartitionInfo\n");
#endif

	c = diskbuffer;
	ndb = c + 512;		/* next disk buffer */
	c += 0x1be;

	headsize = dcb->DCB_bdd.DCB_apparent_spt;
	cylsize = dcb->DCB_bdd.DCB_apparent_head_cnt;
	cylsize = cylsize * headsize;

	c = diskbuffer;
	c += 0x1be;
	pr = (partitionrec *) c;


	cyl = (pr->ss) & (128 + 64);
	cyl = cyl << 2;
	cyl += pr->sc;
	cyl *= cylsize;		/* 16065; */

	ComputedStartSector = pr->sh * headsize;	/* 63; */
	ComputedStartSector += (((pr->ss) & 63) - 1);
	ComputedStartSector += cyl;


	cyl = (pr->es) & (128 + 64);
	cyl = cyl << 2;
	cyl += pr->ec;
	cyl *= cylsize;		/* 16065; */

	ComputedEndSector = pr->eh * headsize;	/* 63 */
	ComputedEndSector += (((pr->es) & 63) - 1);
	ComputedEndSector += cyl;
	ComputedEndSector = ComputedEndSector - ComputedStartSector;
	ComputedEndSector += 1;	/* allow for inclusive sectors... */


	pr = (partitionrec *) c;

	if (pr->boot == 0x80)
		dcb_boot = dcb;

	if ((pr->system == 5) || (pr->system == 0xF))
	{
		if (!recursed)
			relative = pr->StartSector;
		else
			pr->StartSector += relative;


		memset (ndb, 0, 512);
		DiskRead (dcb, myiop, pr->StartSector, 1, ndb, IOR_READ);
		UsePartitionInfo (dcb, myiop, ndb, relative, pr->StartSector, partnum, mf, bVerifyOnly);	/* recursed, and also
														   offset */
	}
	else
	{
		if (recursed)
			pr->StartSector += recursed;

		if (--(*partnum) == 0)
		{
			if (bVerifyOnly == TRUE)
				flag = 1;
			else
				flag = tryvol (dcb, myiop, pr, mf, &cv);	/* partition 1 */
			goto error;
		}
	}

	pr++;

	if (pr->boot == 0x80)
		dcb_boot = dcb;

	if ((pr->system == 5) || (pr->system == 0xF))
	{
		if (!recursed)
			relative = pr->StartSector;
		else
			pr->StartSector += relative;

		memset (ndb, 0, 512);
		DiskRead (dcb, myiop, pr->StartSector, 1, ndb, IOR_READ);
		UsePartitionInfo (dcb, myiop, ndb, relative, pr->StartSector, partnum, mf, bVerifyOnly);	/* recursed, and also
														   offset */
	}
	else if (!recursed)
	{
		if (--(*partnum) == 0)
		{
			if (bVerifyOnly == TRUE)
				flag = 1;
			else
				flag = tryvol (dcb, myiop, pr, mf, &cv);	/* partition 2 */
			goto error;
		}
	}

	if (recursed)
		goto error;

	pr++;

	if (pr->boot == 0x80)
		dcb_boot = dcb;

	if ((pr->system == 5) || (pr->system == 0xF))
	{
		if (!recursed)
			relative = pr->StartSector;
		else
			pr->StartSector += relative;

		memset (ndb, 0, 512);
		DiskRead (dcb, myiop, pr->StartSector, 1, ndb, IOR_READ);
		UsePartitionInfo (dcb, myiop, ndb, relative, pr->StartSector, partnum, mf, bVerifyOnly);	/* recursed, and also
														   offset */
	}
	else if (!recursed)
	{
		if (--(*partnum) == 0)
		{
			if (bVerifyOnly == TRUE)
				flag = 1;
			else
				flag = tryvol (dcb, myiop, pr, mf, &cv);	/* partition 3 */
			goto error;
		}
	}

	pr++;

	if (pr->boot == 0x80)
		dcb_boot = dcb;

	if ((pr->system == 5) || (pr->system == 0xF))
	{
		if (!recursed)
			relative = pr->StartSector;
		else
			pr->StartSector += relative;

		memset (ndb, 0, 512);
		DiskRead (dcb, myiop, pr->StartSector, 1, ndb, IOR_READ);
		UsePartitionInfo (dcb, myiop, ndb, relative, pr->StartSector, partnum, mf, bVerifyOnly);	/* recursed, and also
														   offset */
	}
	else if (!recursed)
	{
		if (--(*partnum) == 0)
		{
			if (bVerifyOnly == TRUE)
				flag = 1;
			else
				flag = tryvol (dcb, myiop, pr, mf, &cv);	/* partition 4 */
			goto error;
		}
	}

      error:

#if EXTRA_INFO
	_Debug_Printf_Service ("UsePartitionInfo end\n");
#endif

	if (bVerifyOnly == TRUE)
	{
		if (flag == 1)
		{
			/* Return partition info in the 'diskbuffer' buffer */

			char *peek = (char *) &pr->system;
			unsigned long *tmp = (void *) partitiontestbuffer;
			unsigned long secstart, seclast;

			mf->nReturnCode = 0;

			peek -= 4;
			peek += 8;	/* point at starting sector... */
			secstart = *(unsigned long *) peek;
			peek += 4;

			seclast = (secstart + *(unsigned long *) peek);

			if (pr->boot == 0x80)
			{
				/* For safety reasons we return 0 length for
				   the boot device */
				seclast = secstart;
			}

			tmp[0] = secstart;
			tmp[1] = seclast;
			tmp[2] = (unsigned long) dcb;	/* device */

		}
	}
	else if (cv != NULL)
	{
		/* cv is only set by tryvol, flag is set only when cv is set */
		switch (flag)
		{
		case 0:
			mf->nReturnCode = ERR_VOL_MOUNT_FAILED;
			break;
		case 1:
			mf->nReturnCode = 0;
			mf->nDosDriveNo = cv->drive;
			strcpy (cv->mounted_file_name, (char *) mf->wszVolume);
			break;
		case -1:
			mf->nReturnCode = ERR_NO_FREE_DRIVES;
			break;
		}
	}
}

int
tryvol (PDCB dcb, PIOP myiop, partitionrec * pr, MOUNT_STRUCT * mf, cryptvol ** pcv)
{
	cryptvol *cv;
	char *readBuffer;
	int mounted = 0;

	readBuffer = TCalloc (FIRST_READ_SIZE);
	if (readBuffer == NULL)
		goto error;

	if (cv = checkpartition (myiop, pr))
	{
		if (cv->booted == 0)
		{
			int status;

			dophysblock (myiop, cv->cryptsectorfirst, FIRST_READ_SIZE / 512, readBuffer, cv, IOR_READ);

			status = VolumeReadHeaderCache (mf->bCache, readBuffer, mf->szPassword,
					 mf->nPasswordLen, &cv->cryptoInfo);

			if (status != 0)
			{
				memset (cv, 0, sizeof (cryptvol));
				cv->cryptsectorfirst = 0x7fffffff;
				mounted = 0;
				goto error;
			}
			else
				cv->booted = 1;

			if (Add_Drive (dcb, cv, mf->nDosDriveNo) == 0)
			{
				cv->filehostdcb = dcb;
				lockdrive (cv->filehostdcb, myiop, 1);
				mounted = 1;
			}
			else
			{
				/* No Drive letter available */
				memset (cv, 0, sizeof (cryptvol));
				cv->cryptsectorfirst = 0x7fffffff;
				mounted = -1;
			}
		}
	}
	else
	{
		/* If the checkpartition fails it could be because the
		   partitions is already mounted or because there are no free
		   slots */
		mounted = 0;
	}

      error:
	if (readBuffer != NULL)
		TCfree (readBuffer);

	*pcv = cv;

	return mounted;

}

struct cryptvol *
checkpartition (PIOP iop, partitionrec * pr)
{

	cryptvol *flag = 0;
	cryptvol *cv;
	PDCB dcb = (PDCB) iop->IOP_physical_dcb;

	char *peek = (char *) &pr->system;

	pr->system = 0x74;

	if (pr->system == 0x74)
	{
		if (cv = addcryptedpartition (iop, peek))
		{
			flag = cv;
		}
	}

	return flag;

}

int
cmppart (PDCB dcb, unsigned int secstart, cryptvol * cv)
{
	if (cv->physdevDCB != dcb)
		return 0;
	if (cv->cryptsectorfirst != secstart)
		return 0;
	return 1;
}

struct cryptvol *
addcryptedpartition (PIOP iop, char *peek)
{

	unsigned int secstart;
	unsigned int seclast;
	PDCB device;
	int d;
	peek -= 4;
	peek += 8;		/* point at starting sector... */
	secstart = *(unsigned long *) peek;
	peek += 4;

	seclast = (secstart + *(unsigned long *) peek);
	device = (PDCB) iop->IOP_physical_dcb;

	/* have we got it already ? */
	if (cmppart (device, secstart, (cryptvol *) & cv1))
		return NULL;
	if (cmppart (device, secstart, (cryptvol *) & cv2))
		return NULL;
	if (cmppart (device, secstart, (cryptvol *) & cv3))
		return NULL;
	if (cmppart (device, secstart, (cryptvol *) & cv4))
		return NULL;
	if (cmppart (device, secstart, (cryptvol *) & cv5))
		return NULL;
	if (cmppart (device, secstart, (cryptvol *) & cv6))
		return NULL;
	if (cmppart (device, secstart, (cryptvol *) & cv7))
		return NULL;
	if (cmppart (device, secstart, (cryptvol *) & cv8))
		return NULL;

	d = tryaddpart ((cryptvol *) & cv1, secstart, seclast, device);
	if (d == 1)
		return &cv1;
	if (d == 2)
		return 0;

	d = tryaddpart ((cryptvol *) & cv2, secstart, seclast, device);
	if (d == 1)
		return &cv2;
	if (d == 2)
		return 0;

	d = tryaddpart ((cryptvol *) & cv3, secstart, seclast, device);
	if (d == 1)
		return &cv3;
	if (d == 2)
		return 0;

	d = tryaddpart ((cryptvol *) & cv4, secstart, seclast, device);
	if (d == 1)
		return &cv4;
	if (d == 2)
		return 0;

	d = tryaddpart ((cryptvol *) & cv5, secstart, seclast, device);
	if (d == 1)
		return &cv5;
	if (d == 2)
		return 0;

	d = tryaddpart ((cryptvol *) & cv6, secstart, seclast, device);
	if (d == 1)
		return &cv6;
	if (d == 2)
		return 0;

	d = tryaddpart ((cryptvol *) & cv7, secstart, seclast, device);
	if (d == 1)
		return &cv7;
	if (d == 2)
		return 0;

	d = tryaddpart ((cryptvol *) & cv8, secstart, seclast, device);
	if (d == 1)
		return &cv8;
	if (d == 2)
		return 0;

	return NULL;
}

int
tryaddpart (cryptvol * cv, unsigned int secstart, unsigned int seclast, PDCB device)
{
	/* THIS if CAN NEVER BE TRUE because cmppart does this job before
	   this func is called */
	if ((cv->physdevDCB == device) && (cv->cryptsectorfirst == secstart))
		return (2);

	if (cv->physdevDCB == 0)
	{
		cv->physdevDCB = device;
		cv->cryptsectorfirst = secstart;
		cv->cryptsectorlast = seclast;

		return (1);
	}

	return (0);
}

int
unlockdrive (cryptvol * cv)
{
	PDCB dcb = cv->filehostdcb;	/* physdevDCB; */
	PIOP myiop;
	PIOR myior;
	USHORT offset;
	USHORT size;

	if (!dcb)
		return -1;

	offset = (USHORT) (dcb->DCB_cmn.DCB_expansion_length + FIELDOFFSET (IOP, IOP_ior));
	size = offset + sizeof (IOR) + dcb->DCB_max_sg_elements * sizeof (SGD);
	myiop = IspCreateIop (size, offset, ISP_M_FL_MUST_SUCCEED | ISP_M_FL_SMART_ALLOC | ISP_M_FL_INTERRUPT_TIME | ISP_M_FL_PERSISTENT_IOP);
	myior = &myiop->IOP_ior;
	myior->IOR_private_client = offset;
	lockdrive (dcb, myiop, 0);	/* unlock it! */
	IspDeallocMem ((PVOID) ((DWORD) myior - myior->IOR_private_client));
	return 1;
}

int
lockdrive (PDCB mydcb, PIOP myiop, int lockmode)
{
	PIOR myior;
	int rstatus;
	int iorop;

	if (!mydcb)
		return -1;

	if (lockmode)
		iorop = IOR_LOCK_MEDIA;
	else
		iorop = IOR_UNLOCK_MEDIA;

	if ((mydcb->DCB_cmn.DCB_device_flags & DCB_DEV_REMOVABLE) == 0)
		return -1;

	myior = &myiop->IOP_ior;
	myiop->IOP_original_dcb = (ULONG) mydcb;
	myiop->IOP_physical_dcb = (ULONG) mydcb->DCB_cmn.DCB_physical_dcb;
	myior->IOR_next = 0;
	myior->IOR_start_addr[1] = 0;
	myior->IOR_flags = IORF_VERSION_002;
	myior->IOR_req_vol_handle = 0;
	myior->IOR_vol_designtr = 0xff;
	myior->IOR_func = iorop;
	myior->IOR_flags |= IORF_BYPASS_VOLTRK | IORF_HIGH_PRIORITY | IORF_SYNC_COMMAND;
	myior->IOR_start_addr[0] = 0;
	myior->IOR_xfer_count = 0;
	myior->IOR_buffer_ptr = 0;

	myiop->IOP_timer = 40;
	myiop->IOP_timer_orig = 40;

	IlbInternalRequest (myiop, mydcb, 0);
	rstatus = myior->IOR_status;
	return rstatus;
}


/* the ring 0 code to allow win32 gui to access disk sectors */

int
AppAccessBlockDevice (unsigned int devicenum, unsigned int sectorstart, unsigned int sectorlen, char *buffer, int mode)
{
	PDCB dcb;
	USHORT offset;
	USHORT size;
	PIOP myiop;
	PIOR myior;
	int status;
	USHORT diskop;

	if (mode == 0)
		diskop = IOR_READ;
	else
		diskop = IOR_WRITE;

	if (devicenum < 128)
		dcb = dcblist[devicenum + 1];
	else
		dcb = (PDCB) devicenum;

	if (diskop == IOR_WRITE && dcb == dcb_boot)
	{
		if (sectorstart == 0)
		{
			return ERR_ACCESS_DENIED;
		}
	}

	offset = (USHORT) (dcb->DCB_cmn.DCB_expansion_length + FIELDOFFSET (IOP, IOP_ior));
	size = offset + sizeof (IOR) + dcb->DCB_max_sg_elements * sizeof (SGD);
	myiop = IspCreateIop (size, offset, ISP_M_FL_MUST_SUCCEED | ISP_M_FL_SMART_ALLOC | ISP_M_FL_INTERRUPT_TIME | ISP_M_FL_PERSISTENT_IOP);
	myior = &myiop->IOP_ior;
	myior->IOR_private_client = offset;

	if (diskop == IOR_WRITE)
		memcpy (appaccessbuffer, buffer, sectorlen * 512);

	status = DiskRead (dcb, myiop, sectorstart, sectorlen, appaccessbuffer, diskop);	/* mode later...... */

	if (diskop == IOR_READ)
		memcpy (buffer, appaccessbuffer, sectorlen * 512);

	IspDeallocMem ((PVOID) ((DWORD) myior - myior->IOR_private_client));

	if (status != 0)
	{
		if (mode == 0)
			status = ERR_VOL_READING;
		else
			status = ERR_VOL_WRITING;
	}

	return status;
}

/* This code informs Windows of a drives arrival, this code
  crashes windows 95 for some cd's; so it's currently never called */
 
void 
drivearrived (void)
{
	cryptvol *cv;
	int c;

	for (c = 0; c < 8; c++)
	{
		cv = cryptvols[c];

		if (cv->notifytime & 0x80000000)
		{
			cv->notifytime = 0;
    
			IFSMgr_PNPEvent (DBT_DEVICEARRIVAL, cv->drive, PNPT_VOLUME | DBTF_MEDIA );
		}
	}
}

