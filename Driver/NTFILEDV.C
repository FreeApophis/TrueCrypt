/* Copyright (C) 2004 TrueCrypt Foundation
   This product uses components written by Paul Le Roux <pleroux@swprofessionals.com> */

#include "TCdefs.h"
#include "crypto.h"
#include "fat.h"
#include "volumes.h"

#include "apidrvr.h"
#include "ntdriver.h"
#include "ntvol.h"
#include "ntfiledv.h"

#pragma warning( disable : 4127 )

TCSendIRP_FileDevice (PDEVICE_OBJECT DeviceObject,
		       PEXTENSION Extension,
		       PVOID pUserBuffer,
		       ULONG uFlags,
		       UCHAR uMajorFunction,
		       PIRP Irp)
{
	PIO_STACK_LOCATION irpOldSp;
	NTSTATUS ntStatus;
	PIRP NewIrp;

//	Dump ("Sending IRP...\n");

	NewIrp = IoAllocateIrp ((CCHAR) (Extension->pFsdDevice->StackSize + 1), FALSE);

	irpOldSp = IoGetCurrentIrpStackLocation (Irp);

	if (NewIrp != NULL)
	{
		PIO_STACK_LOCATION irpSp, irpNextSp;

		NewIrp->UserEvent = NULL;
		NewIrp->UserIosb = &Irp->IoStatus;

		/* Doc's say to copy the Tail.Overlay.Thread from the
		   original Irp but if I do this the user is not prompted on
		   media removed and other user conditions! */
		NewIrp->Tail.Overlay.Thread = PsGetCurrentThread ();
		NewIrp->Tail.Overlay.OriginalFileObject = Extension->pfoDeviceFile;
		NewIrp->RequestorMode = KernelMode;

		NewIrp->Flags = uFlags;

		NewIrp->AssociatedIrp.SystemBuffer = NULL;
		NewIrp->MdlAddress = NULL;
		NewIrp->UserBuffer = pUserBuffer;

		IoSetNextIrpStackLocation (NewIrp);

		irpSp = IoGetCurrentIrpStackLocation (NewIrp);
		irpNextSp = IoGetNextIrpStackLocation (NewIrp);

		irpSp->DeviceObject = DeviceObject;
		irpSp->FileObject = Extension->pfoDeviceFile;

		irpNextSp->MajorFunction = irpSp->MajorFunction = uMajorFunction;
		irpNextSp->MinorFunction = irpSp->MinorFunction = irpSp->MinorFunction;
		irpNextSp->DeviceObject = Extension->pFsdDevice;
		irpNextSp->FileObject = Extension->pfoDeviceFile;
		/* Copy our flags down one level, this is to get the proper
		   removable-media handling */
		irpNextSp->Flags = irpSp->Flags = irpOldSp->Flags;
		/* Copy over io parameters, this is a union, so it handles
		   deviceiocontrol & read/write */
		irpNextSp->Parameters.Read.Length = irpSp->Parameters.Read.Length = irpOldSp->Parameters.Read.Length;
		irpNextSp->Parameters.Read.ByteOffset = irpSp->Parameters.Read.ByteOffset = irpOldSp->Parameters.Read.ByteOffset;
		irpNextSp->Parameters.Read.Key = irpSp->Parameters.Read.Key = irpOldSp->Parameters.Read.Key;
	}
	else
	{
		TCfree (pUserBuffer);	/* Free the temp buffer we allocated
					   for the IRP */

		/* Complete the processing of the original Irp */
		return COMPLETE_IRP (DeviceObject, Irp, STATUS_INSUFFICIENT_RESOURCES, 0);
	}

	IoSetCompletionRoutine (NewIrp, TCCompletion, Irp, TRUE, TRUE, TRUE);

	ntStatus = IoCallDriver (Extension->pFsdDevice, NewIrp);
	//if (ntStatus == STATUS_PENDING)
	//{
	//	Dump ("Pending returned!\n");
	//}

//	Dump ("IRP Sent!\n");
	return ntStatus;
}
