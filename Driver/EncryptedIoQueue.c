/*
 Copyright (c) 2008 TrueCrypt Foundation. All rights reserved.

 Governed by the TrueCrypt License 2.4 the full text of which is contained
 in the file License.txt included in TrueCrypt binary and source code
 distribution packages.
*/

#include "TCdefs.h"
#include "Apidrvr.h"
#include "Ntdriver.h"
#include "EncryptedIoQueue.h"


static void DecrementOutstandingIoCount (EncryptedIoQueue *queue)
{
	if (InterlockedDecrement (&queue->OutstandingIoCount) == 0 && (queue->SuspendPending || queue->StopPending))
		KeSetEvent (&queue->NoOutstandingIoEvent, 0, FALSE);
}


static void OnItemCompleted (EncryptedIoQueueItem *item)
{
	DecrementOutstandingIoCount (item->Queue);
	
	if (item->Queue->IsFilterDevice)
		IoReleaseRemoveLock (&item->Queue->RemoveLock, item->OriginalIrp);

	if (NT_SUCCESS (item->Status))
	{
		if (item->Write)
			item->Queue->TotalBytesWritten += item->OriginalLength;
		else
			item->Queue->TotalBytesRead += item->OriginalLength;
	}

	TCfree (item);
}


static NTSTATUS CompleteOriginalIrp (EncryptedIoQueueItem *item, NTSTATUS status, ULONG_PTR information)
{
	//Dump ("Queue comp  offset=%I64d  status=%x  info=%p  out=%d\n", item->OriginalOffset, status, information, item->Queue->OutstandingIoCount - 1);
	TCCompleteDiskIrp (item->OriginalIrp, status, information);
	OnItemCompleted (item);
	return status;
}


static void AcquireFragmentBuffer (EncryptedIoQueue *queue, byte *buffer)
{
	NTSTATUS status = STATUS_INVALID_PARAMETER;

	if (buffer == queue->FragmentBufferA)
	{
		status = KeWaitForSingleObject (&queue->FragmentBufferAFreeEvent, Executive, KernelMode, FALSE, NULL);
	}
	else if (buffer == queue->FragmentBufferB)
	{
		status = KeWaitForSingleObject (&queue->FragmentBufferBFreeEvent, Executive, KernelMode, FALSE, NULL);
	}

	if (!NT_SUCCESS (status))
		TC_BUG_CHECK (status);
}


static void ReleaseFragmentBuffer (EncryptedIoQueue *queue, byte *buffer)
{
	if (buffer == queue->FragmentBufferA)
	{
		KeSetEvent (&queue->FragmentBufferAFreeEvent, 0, FALSE);
	}
	else if (buffer == queue->FragmentBufferB)
	{
		KeSetEvent (&queue->FragmentBufferBFreeEvent, 0, FALSE);
	}
	else
	{
		TC_BUG_CHECK (STATUS_INVALID_PARAMETER);
	}
}


static VOID CompletionThreadProc (PVOID threadArg)
{
	EncryptedIoQueue *queue = (EncryptedIoQueue *) threadArg;
	PLIST_ENTRY listEntry;
	EncryptedIoRequest *request;
	UINT64_STRUCT dataUnit;

	while (!queue->ThreadExitRequested)
	{
		if (!NT_SUCCESS (KeWaitForSingleObject (&queue->CompletionThreadQueueNotEmptyEvent, Executive, KernelMode, FALSE, NULL)))
			continue;

		if (queue->ThreadExitRequested)
			break;

		while ((listEntry = ExInterlockedRemoveHeadList (&queue->CompletionThreadQueue, &queue->CompletionThreadQueueLock)))
		{
			request = CONTAINING_RECORD (listEntry, EncryptedIoRequest, CompletionListEntry);

			if (request->EncryptedLength > 0)
			{
				ASSERT (request->EncryptedOffset + request->EncryptedLength <= request->Offset.QuadPart + request->Length);
				dataUnit.Value = (request->Offset.QuadPart + request->EncryptedOffset) / ENCRYPTION_DATA_UNIT_SIZE;
				DecryptDataUnits (request->Data + request->EncryptedOffset, &dataUnit, request->EncryptedLength / ENCRYPTION_DATA_UNIT_SIZE, queue->CryptoInfo);
			}

			if (request->CompleteOriginalIrp)
			{
				CompleteOriginalIrp (request->Item, request->Item->Status,
					NT_SUCCESS (request->Item->Status) ? request->Item->OriginalLength : 0);
			}

			TCfree (request);
		}
	}

	PsTerminateSystemThread (STATUS_SUCCESS);
}


static VOID IoThreadProc (PVOID threadArg)
{
	EncryptedIoQueue *queue = (EncryptedIoQueue *) threadArg;
	PLIST_ENTRY listEntry;
	EncryptedIoRequest *request;

	while (!queue->ThreadExitRequested)
	{
		if (!NT_SUCCESS (KeWaitForSingleObject (&queue->IoThreadQueueNotEmptyEvent, Executive, KernelMode, FALSE, NULL)))
			continue;

		if (queue->ThreadExitRequested)
			break;

		while ((listEntry = ExInterlockedRemoveHeadList (&queue->IoThreadQueue, &queue->IoThreadQueueLock)))
		{
			request = CONTAINING_RECORD (listEntry, EncryptedIoRequest, ListEntry);

			// IO request
			if (queue->IsFilterDevice)
			{
				if (request->Item->Write)
					request->Item->Status = TCWriteDevice (queue->LowerDeviceObject, request->Data, request->Offset, request->Length);
				else
					request->Item->Status = TCReadDevice (queue->LowerDeviceObject, request->Data, request->Offset, request->Length);
			}
			else
			{
				IO_STATUS_BLOCK ioStatus;

				if (request->Item->Write)
					request->Item->Status = ZwWriteFile (queue->HostFileHandle, NULL, NULL, NULL, &ioStatus, request->Data, request->Length, &request->Offset, NULL);
				else
					request->Item->Status = ZwReadFile (queue->HostFileHandle, NULL, NULL, NULL, &ioStatus, request->Data, request->Length, &request->Offset, NULL);
			}

			if (!request->Item->Write && NT_SUCCESS (request->Item->Status))
			{
				// Successful read completed
				if (!request->CompleteOriginalIrp)
					KeSetEvent (&request->Item->IoRequestCompletedEvent, 0, FALSE);

				// Copy fragment to original IRP buffer
				memcpy (request->OrigDataBufferFragment, request->Data, request->Length);
				ReleaseFragmentBuffer (queue, request->Data);
				request->Data = request->OrigDataBufferFragment;

				// Queue decryption to completion thread
				ExInterlockedInsertTailList (&queue->CompletionThreadQueue, &request->CompletionListEntry, &queue->CompletionThreadQueueLock);
				KeSetEvent (&queue->CompletionThreadQueueNotEmptyEvent, 0, FALSE);
			}
			else
			{
				ReleaseFragmentBuffer (queue, request->Data);

				if (request->CompleteOriginalIrp)
				{
					CompleteOriginalIrp (request->Item, request->Item->Status,
						NT_SUCCESS (request->Item->Status) ? request->Item->OriginalLength : 0);
				}
				else
				{
					KeSetEvent (&request->Item->IoRequestCompletedEvent, 0, FALSE);
				}

				TCfree (request);
			}
		}
	}

	PsTerminateSystemThread (STATUS_SUCCESS);
}


static NTSTATUS OnPassedIrpCompleted (PDEVICE_OBJECT filterDeviceObject, PIRP irp, EncryptedIoQueueItem *item)
{
	if (irp->PendingReturned)
		IoMarkIrpPending (irp);

	OnItemCompleted (item);
	return STATUS_CONTINUE_COMPLETION;
}


static VOID MainThreadProc (PVOID threadArg)
{
	EncryptedIoQueue *queue = (EncryptedIoQueue *) threadArg;
	PLIST_ENTRY listEntry;
	EncryptedIoQueueItem *item;
	NTSTATUS status;

	LARGE_INTEGER fragmentOffset;
	ULONG dataRemaining;
	PUCHAR activeFragmentBuffer = queue->FragmentBufferA;
	PUCHAR dataBuffer;
	EncryptedIoRequest *request;
	uint64 intersectStart;
	uint32 intersectLength;

	while (!queue->ThreadExitRequested)
	{
		if (!NT_SUCCESS (KeWaitForSingleObject (&queue->MainThreadQueueNotEmptyEvent, Executive, KernelMode, FALSE, NULL)))
			continue;

		while ((listEntry = ExInterlockedRemoveHeadList (&queue->MainThreadQueue, &queue->MainThreadQueueLock)))
		{
			item = CONTAINING_RECORD (listEntry, EncryptedIoQueueItem, ListEntry);

			if (queue->Suspended)
			{
				KeWaitForSingleObject (&queue->QueueResumedEvent, Executive, KernelMode, FALSE, NULL);
			}
			
			IoSetCancelRoutine (item->OriginalIrp, NULL);
			if (item->OriginalIrp->Cancel)
			{
				CompleteOriginalIrp (item, STATUS_CANCELLED, 0);
				continue;
			}

			// Pass the IRP if the drive is not encrypted
			if (queue->IsFilterDevice && (queue->EncryptedAreaStart == -1 || queue->EncryptedAreaEnd == -1))
			{

				IoCopyCurrentIrpStackLocationToNext (item->OriginalIrp);
				IoSetCompletionRoutine (item->OriginalIrp, OnPassedIrpCompleted, item, TRUE, TRUE, TRUE);
				IoCallDriver (queue->LowerDeviceObject, item->OriginalIrp);
				continue;
			}

			//Dump ("--- Queue %c %I64d  (%I64d)  %d  out=%d\n", item->Write ? 'W' : 'R', item->OriginalOffset.QuadPart, item->OriginalOffset.QuadPart / 1024 / 1024, item->OriginalLength, queue->OutstandingIoCount);

			// Validate offset and length
			if (item->OriginalLength == 0 || (item->OriginalLength & (ENCRYPTION_DATA_UNIT_SIZE - 1))
				|| (!queue->IsFilterDevice && item->OriginalOffset.QuadPart + item->OriginalLength > queue->VirtualDeviceLength))
			{
				CompleteOriginalIrp (item, STATUS_INVALID_PARAMETER, 0);
				continue;
			}

			if (!queue->IsFilterDevice)
			{
				// Hidden volume protection
				if (item->Write && queue->CryptoInfo->bProtectHiddenVolume)
				{
					// If there has already been a write operation denied in order to protect the
					// hidden volume (since the volume mount time)
					if (queue->CryptoInfo->bHiddenVolProtectionAction)	
					{
						// Do not allow writing to this volume anymore. This is to fake a complete volume
						// or system failure (otherwise certain kinds of inconsistency within the file
						// system could indicate that this volume has used hidden volume protection).
						CompleteOriginalIrp (item, STATUS_INVALID_PARAMETER, 0);
						continue;
					}

					// Verify that no byte is going to be written to the hidden volume area
					if (RegionsOverlap ((unsigned __int64) item->OriginalOffset.QuadPart + HEADER_SIZE,
						(unsigned __int64) item->OriginalOffset.QuadPart + HEADER_SIZE + item->OriginalLength - 1,
						queue->CryptoInfo->hiddenVolumeOffset,
						(unsigned __int64) queue->VirtualDeviceLength + HEADER_SIZE - (HIDDEN_VOL_HEADER_OFFSET - HEADER_SIZE) - 1))
					{
						queue->CryptoInfo->bHiddenVolProtectionAction = TRUE;

						// Deny this write operation to prevent the hidden volume from being overwritten
						CompleteOriginalIrp (item, STATUS_INVALID_PARAMETER, 0);
						continue;
					}
				}

				// Adjust the offset for host file or device
				if (queue->CryptoInfo->hiddenVolume)
					item->OriginalOffset.QuadPart += queue->CryptoInfo->hiddenVolumeOffset;
				else
					item->OriginalOffset.QuadPart += HEADER_SIZE; 
			}

			// Original IRP data buffer
			dataBuffer = (PUCHAR) MmGetSystemAddressForMdlSafe (item->OriginalIrp->MdlAddress, HighPagePriority);
			if (dataBuffer == NULL)
			{
				CompleteOriginalIrp (item, STATUS_INSUFFICIENT_RESOURCES, 0);
				continue;
			}

			// Divide data block to fragments to enable efficient overlapping of encryption and IO operations

			dataRemaining = item->OriginalLength;
			fragmentOffset = item->OriginalOffset;

			while (dataRemaining > 0)
			{
				BOOL isFirstFragment = fragmentOffset.QuadPart == item->OriginalOffset.QuadPart;
				BOOL isLastFragment = dataRemaining <= TC_ENC_IO_QUEUE_MAX_FRAGMENT_SIZE;
				
				ULONG dataFragmentLength = isLastFragment ? dataRemaining : TC_ENC_IO_QUEUE_MAX_FRAGMENT_SIZE;
				activeFragmentBuffer = (activeFragmentBuffer == queue->FragmentBufferA ? queue->FragmentBufferB : queue->FragmentBufferA);

				// Create IO request
				request = (EncryptedIoRequest *) TCalloc (sizeof (EncryptedIoRequest));
				if (!request)
				{
					CompleteOriginalIrp (item, STATUS_INSUFFICIENT_RESOURCES, 0);
					break;
				}

				request->Item = item;
				request->CompleteOriginalIrp = isLastFragment;
				request->Offset = fragmentOffset;
				request->Data = activeFragmentBuffer;
				request->OrigDataBufferFragment = dataBuffer;
				request->Length = dataFragmentLength;

				if (queue->IsFilterDevice)
				{
					// Get intersection of data fragment with encrypted area
					GetIntersection (fragmentOffset.QuadPart, dataFragmentLength, queue->EncryptedAreaStart, queue->EncryptedAreaEnd, &intersectStart, &intersectLength);

					request->EncryptedOffset = intersectStart - fragmentOffset.QuadPart;
					request->EncryptedLength = intersectLength;
				}
				else
				{
					request->EncryptedOffset = 0;
					request->EncryptedLength = dataFragmentLength;
				}

				AcquireFragmentBuffer (queue, activeFragmentBuffer);

				if (item->Write)
				{
					// Encrypt data
					memcpy (activeFragmentBuffer, dataBuffer, dataFragmentLength);

					if (request->EncryptedLength > 0)
					{
						UINT64_STRUCT dataUnit;
						ASSERT (request->EncryptedOffset + request->EncryptedLength <= request->Offset.QuadPart + request->Length);

						dataUnit.Value = (request->Offset.QuadPart + request->EncryptedOffset) / ENCRYPTION_DATA_UNIT_SIZE;
						EncryptDataUnits (activeFragmentBuffer + request->EncryptedOffset, &dataUnit, request->EncryptedLength / ENCRYPTION_DATA_UNIT_SIZE, queue->CryptoInfo);
					}
				}

				if (!isFirstFragment)
				{
					// Wait for completion of previous fragment IO

					status = KeWaitForSingleObject (&item->IoRequestCompletedEvent, Executive, KernelMode, FALSE, NULL);
					if (!NT_SUCCESS (status))
						TC_BUG_CHECK (status);

					if (!NT_SUCCESS (item->Status))
					{
						// If the previous fragment IO failed, stop processing remaining fragments and complete the IRP
						ReleaseFragmentBuffer (queue, activeFragmentBuffer);
						CompleteOriginalIrp (item, item->Status, 0);
						break;
					}
				}

				// Queue IO request
				ExInterlockedInsertTailList (&queue->IoThreadQueue, &request->ListEntry, &queue->IoThreadQueueLock);
				KeSetEvent (&queue->IoThreadQueueNotEmptyEvent, 0, FALSE);

				if (isLastFragment)
					break;

				dataRemaining -= TC_ENC_IO_QUEUE_MAX_FRAGMENT_SIZE;
				dataBuffer += TC_ENC_IO_QUEUE_MAX_FRAGMENT_SIZE;
				fragmentOffset.QuadPart += TC_ENC_IO_QUEUE_MAX_FRAGMENT_SIZE;
			}
		}
	}

	PsTerminateSystemThread (STATUS_SUCCESS);
}


NTSTATUS EncryptedIoQueueAddIrp (EncryptedIoQueue *queue, PIRP irp)
{
	EncryptedIoQueueItem *item;
	PIO_STACK_LOCATION origIrpSp = IoGetCurrentIrpStackLocation (irp);
	NTSTATUS status;

	InterlockedIncrement (&queue->OutstandingIoCount);
	if (queue->StopPending)
	{
		Dump ("STATUS_DEVICE_NOT_READY  out=%d\n", queue->OutstandingIoCount);
		status = STATUS_DEVICE_NOT_READY;
		goto err;
	}

	if (queue->IsFilterDevice)
	{
		status = IoAcquireRemoveLock (&queue->RemoveLock, irp);
		if (!NT_SUCCESS (status))
			goto err;
	}

	item = TCalloc (sizeof (EncryptedIoQueueItem));
	if (!item)
	{
		status = STATUS_INSUFFICIENT_RESOURCES;
		goto err;
	}

	memset (item, 0, sizeof (EncryptedIoQueueItem));

	switch (origIrpSp->MajorFunction)
	{
	case IRP_MJ_READ:
		item->Write = FALSE;
		item->OriginalOffset = origIrpSp->Parameters.Read.ByteOffset;
		item->OriginalLength = origIrpSp->Parameters.Read.Length;
		break;

	case IRP_MJ_WRITE:
		item->Write = TRUE;
		item->OriginalOffset = origIrpSp->Parameters.Write.ByteOffset;
		item->OriginalLength = origIrpSp->Parameters.Write.Length;
		break;

	default:
		TCfree (item);
		status = STATUS_INVALID_PARAMETER;
		goto err;
	}

	item->Queue = queue;
	item->OriginalIrp = irp;
	KeInitializeEvent (&item->IoRequestCompletedEvent, SynchronizationEvent, FALSE);

	IoMarkIrpPending (irp);

	//Dump ("Queue add %I64d %I64d  out=%d\n", item->OriginalOffset, item->OriginalLength, queue->OutstandingIoCount);

	ExInterlockedInsertTailList (&queue->MainThreadQueue, &item->ListEntry, &queue->MainThreadQueueLock);
	KeSetEvent (&queue->MainThreadQueueNotEmptyEvent, 0, FALSE);
	
	return STATUS_PENDING;

err:
	DecrementOutstandingIoCount (queue);
	return status;
}


NTSTATUS EncryptedIoQueueHoldWhenIdle (EncryptedIoQueue *queue, int64 timeout)
{
	NTSTATUS status;
	ASSERT (!queue->Suspended);

	queue->SuspendPending = TRUE;
	
	while (TRUE)
	{
		while (InterlockedExchangeAdd (&queue->OutstandingIoCount, 0) > 0)
		{
			LARGE_INTEGER waitTimeout;

			waitTimeout.QuadPart = timeout * -10000;
			status = KeWaitForSingleObject (&queue->NoOutstandingIoEvent, Executive, KernelMode, FALSE, timeout != 0 ? &waitTimeout : NULL);

			if (status == STATUS_TIMEOUT)
				status = STATUS_UNSUCCESSFUL;

			if (!NT_SUCCESS (status))
				return status;
		}

		KeClearEvent (&queue->QueueResumedEvent);
		queue->Suspended = TRUE;

		if (InterlockedExchangeAdd (&queue->OutstandingIoCount, 0) == 0)
			break;

		queue->Suspended = FALSE;
		KeSetEvent (&queue->QueueResumedEvent, 0, FALSE);

	}

	queue->SuspendPending = FALSE;
	//Dump ("Queue suspended  out=%d\n", queue->OutstandingIoCount);

	return STATUS_SUCCESS;
}


BOOL EncryptedIoQueueIsSuspended (EncryptedIoQueue *queue)
{
	return queue->Suspended;
}


BOOL EncryptedIoQueueIsRunning (EncryptedIoQueue *queue)
{
	return !queue->StopPending;
}


NTSTATUS EncryptedIoQueueResumeFromHold (EncryptedIoQueue *queue)
{
	ASSERT (queue->Suspended);
	
	queue->Suspended = FALSE;
	KeSetEvent (&queue->QueueResumedEvent, 0, FALSE);

	//Dump ("Queue resumed  out=%d\n", queue->OutstandingIoCount);

	return STATUS_SUCCESS;
}


NTSTATUS EncryptedIoQueueStart (EncryptedIoQueue *queue, PEPROCESS process)
{
	NTSTATUS status;
	queue->ThreadExitRequested = FALSE;

	KeInitializeEvent (&queue->NoOutstandingIoEvent, SynchronizationEvent, FALSE);
	KeInitializeEvent (&queue->QueueResumedEvent, SynchronizationEvent, FALSE);

	queue->FragmentBufferA = TCalloc (TC_ENC_IO_QUEUE_MAX_FRAGMENT_SIZE);
	if (!queue->FragmentBufferA)
		goto noMemory;

	queue->FragmentBufferB = TCalloc (TC_ENC_IO_QUEUE_MAX_FRAGMENT_SIZE);
	if (!queue->FragmentBufferB)
		goto noMemory;

	KeInitializeEvent (&queue->FragmentBufferAFreeEvent, SynchronizationEvent, TRUE);
	KeInitializeEvent (&queue->FragmentBufferBFreeEvent, SynchronizationEvent, TRUE);

	// Main thread
	InitializeListHead (&queue->MainThreadQueue);
	KeInitializeSpinLock (&queue->MainThreadQueueLock);
	KeInitializeEvent (&queue->MainThreadQueueNotEmptyEvent, SynchronizationEvent, FALSE);

	status = TCStartThread (MainThreadProc, queue, &queue->MainThread);
	if (!NT_SUCCESS (status))
		goto err;

	// IO thread
	InitializeListHead (&queue->IoThreadQueue);
	KeInitializeSpinLock (&queue->IoThreadQueueLock);
	KeInitializeEvent (&queue->IoThreadQueueNotEmptyEvent, SynchronizationEvent, FALSE);

	status = TCStartThreadInProcess (IoThreadProc, queue, &queue->IoThread, process);
	if (!NT_SUCCESS (status))
	{
		queue->ThreadExitRequested = TRUE;
		TCStopThread (queue->MainThread, &queue->MainThreadQueueNotEmptyEvent);
		goto err;
	}

	// Completion thread
	InitializeListHead (&queue->CompletionThreadQueue);
	KeInitializeSpinLock (&queue->CompletionThreadQueueLock);
	KeInitializeEvent (&queue->CompletionThreadQueueNotEmptyEvent, SynchronizationEvent, FALSE);

	status = TCStartThread (CompletionThreadProc, queue, &queue->CompletionThread);
	if (!NT_SUCCESS (status))
	{
		queue->ThreadExitRequested = TRUE;
		TCStopThread (queue->MainThread, &queue->MainThreadQueueNotEmptyEvent);
		TCStopThread (queue->IoThread, &queue->IoThreadQueueNotEmptyEvent);
		goto err;
	}

	queue->StopPending = FALSE;
	Dump ("Queue started\n");
	return STATUS_SUCCESS;

noMemory:
	status = STATUS_INSUFFICIENT_RESOURCES;

err:
	if (queue->FragmentBufferA)
		TCfree (queue->FragmentBufferA);
	if (queue->FragmentBufferB)
		TCfree (queue->FragmentBufferB);

	return status;
}


NTSTATUS EncryptedIoQueueStop (EncryptedIoQueue *queue)
{
	ASSERT (!queue->StopPending);
	queue->StopPending = TRUE;
	
	while (InterlockedExchangeAdd (&queue->OutstandingIoCount, 0) > 0)
	{
		KeWaitForSingleObject (&queue->NoOutstandingIoEvent, Executive, KernelMode, FALSE, NULL);
	}

	Dump ("Queue stopping  out=%d\n", queue->OutstandingIoCount);

	queue->ThreadExitRequested = TRUE;

	TCStopThread (queue->MainThread, &queue->MainThreadQueueNotEmptyEvent);
	TCStopThread (queue->IoThread, &queue->IoThreadQueueNotEmptyEvent);
	TCStopThread (queue->CompletionThread, &queue->CompletionThreadQueueNotEmptyEvent);

	TCfree (queue->FragmentBufferA);
	TCfree (queue->FragmentBufferB);

	Dump ("Queue stopped  out=%d\n", queue->OutstandingIoCount);
	return STATUS_SUCCESS;
}
