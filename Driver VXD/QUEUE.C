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

extern cryptvol *cryptvols[];

PIOP queuedIOP = 0;		/* Currently or to be processed iop ptr */

void
DeQueueIOP (void)
{
	PIOP iop;
	PIOP iop2;
	PDCB dcb;
	cryptvol *cv;

	iop = queuedIOP;

	if (!queuedIOP)
		return;		/* may happen in terminate thread (that this
				   runs on...) */

	iop = queuedIOP;

	while (1)
	{
		dcb = (PDCB) iop->IOP_physical_dcb;
		cv = (cryptvol *) dcb->DCB_Port_Specific;

		/* Note that in TC, it isn't necessary to clear IOR_next
		   Nothing further is called using this IOP */

		cryptproc (iop, cv);

		iop2 = (PIOP) iop->IOP_ior.IOR_next;
		queuedIOP = iop2;

		ior.IOR_status = 0;	/* IORS_CMD_IN_PROGRESS; 	 */

		dcb->DCB_cmn.DCB_device_flags &= ~DCB_DEV_IO_ACTIVE;
		DoCallBack (iop);

		if (!queuedIOP)
			break;

		iop = queuedIOP;
	}
}

void
QueueMyIop (PIOP iop)
{
	PIOP tempiop = queuedIOP;
	PIOP nextiop = 0;

	iop->IOP_ior.IOR_next = 0;	/* make sure */

	if (tempiop)
	{
		/* Add the current iop to the head of list */
		while (nextiop = (PIOP) tempiop->IOP_ior.IOR_next)
			tempiop = nextiop;
		tempiop->IOP_ior.IOR_next = (unsigned long) iop;
	}
	else
	{
		/* No current iop's so wake the thread up */
		queuedIOP = iop;
		wakethread ();
	}
}
