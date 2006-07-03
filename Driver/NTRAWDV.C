/* Legal Notice: The source code contained in this file has been derived from
   the source code of Encryption for the Masses 2.02a, which is Copyright (c)
   1998-99 Paul Le Roux and which is covered by the 'License Agreement for
   Encryption for the Masses'. Modifications and additions to that source code
   contained in this file are Copyright (c) 2004-2006 TrueCrypt Foundation and
   Copyright (c) 2004 TrueCrypt Team, and are covered by TrueCrypt License 2.1
   the full text of which is contained in the file License.txt included in
   TrueCrypt binary and source code distribution archives.  */

#include "TCdefs.h"
#include "Crypto.h"
#include "Fat.h"
#include "Volumes.h"

#include "Apidrvr.h"
#include "Ntdriver.h"
#include "Ntvol.h"
#include "Ntrawdv.h"

#pragma warning( disable : 4127 )

NTSTATUS
TCSendIRP_RawDevice (PDEVICE_OBJECT DeviceObject,
		      PEXTENSION Extension,
		      PVOID pUserBuffer,
		      ULONG uFlags,
		      UCHAR uMajorFunction,
		      PIRP Irp)
{
	PIO_STACK_LOCATION irpSp;
	PIO_STACK_LOCATION irpNextSp;
	NTSTATUS ntStatus;

	if (uFlags);		/* Remove compiler warning */

//	Dump ("Sending IRP...\n");

	irpSp = IoGetCurrentIrpStackLocation (Irp);
	irpNextSp = IoGetNextIrpStackLocation (Irp);

	irpSp->MajorFunction = uMajorFunction;
	irpSp->DeviceObject = DeviceObject;
	irpSp->FileObject = Extension->pfoDeviceFile;

	/* Copy our flags down one level, this is to get the proper
	   removable-media handling */
	irpNextSp->Flags = irpSp->Flags;

	/* Setup the lower drivers stack location */
	irpNextSp->MajorFunction = irpSp->MajorFunction;
	irpNextSp->MinorFunction = irpSp->MinorFunction;
	irpNextSp->DeviceObject = irpSp->DeviceObject;
	irpNextSp->FileObject = irpSp->FileObject;
	/* Copy over io parameters, this is a union, so it handles
	   deviceiocontrol & read/write */
	irpNextSp->Parameters.Read.Length = irpSp->Parameters.Read.Length;
	irpNextSp->Parameters.Read.ByteOffset = irpSp->Parameters.Read.ByteOffset;
	irpNextSp->Parameters.Read.Key = irpSp->Parameters.Read.Key;

	IoSetCompletionRoutine (Irp, TCCompletion, pUserBuffer, TRUE, TRUE, TRUE);
	ntStatus = IoCallDriver (Extension->pFsdDevice, Irp);

//	Dump ("IRP Sent!\n");
	return ntStatus;
}
