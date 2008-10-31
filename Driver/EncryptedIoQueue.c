/*
 Copyright (c) 2008 TrueCrypt Foundation. All rights reserved.

 Governed by the TrueCrypt License 2.6 the full text of which is contained
 in the file License.txt included in TrueCrypt binary and source code
 distribution packages.
*/

#include "TCdefs.h"
#include "Apidrvr.h"
#include "Ntdriver.h"
#include "DriveFilter.h"
#include "EncryptedIoQueue.h"
#include "EncryptionThreadPool.h"
#include "Volumes.h"


static void DecrementOutstandingIoCount (EncryptedIoQueue *queue)
{
	if (InterlockedDecrement (&queue->OutstandingIoCount) == 0 && (queue->SuspendPending || queue->StopPending))
		KeSetEvent (&queue->NoOutstandingIoEvent, IO_DISK_INCREMENT, FALSE);
}


static void OnItemCompleted (EncryptedIoQueueItem *item, BOOL freeItem)
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

	if (freeItem)
		TCfree (item);
}


static NTSTATUS CompleteOriginalIrp (EncryptedIoQueueItem *item, NTSTATUS status, ULONG_PTR information)
{
	//Dump ("Queue comp  offset=%I64d  status=%x  info=%p  out=%d\n", item->OriginalOffset, status, information, item->Queue->OutstandingIoCount - 1);
	
	TCCompleteDiskIrp (item->OriginalIrp, status, information);

	item->Status = status;
	OnItemCompleted (item, TRUE);

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
		KeSetEvent (&queue->FragmentBufferAFreeEvent, IO_DISK_INCREMENT, FALSE);
	}
	else if (buffer == queue->FragmentBufferB)
	{
		KeSetEvent (&queue->FragmentBufferBFreeEvent, IO_DISK_INCREMENT, FALSE);
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

	if (IsEncryptionThreadPoolRunning())
		KeSetPriorityThread (KeGetCurrentThread(), LOW_REALTIME_PRIORITY);

	while (!queue->ThreadExitRequested)
	{
		if (!NT_SUCCESS (KeWaitForSingleObject (&queue->CompletionThreadQueueNotEmptyEvent, Executive, KernelMode, FALSE, NULL)))
			continue;

		if (queue->ThreadExitRequested)
			break;

		while ((listEntry = ExInterlockedRemoveHeadList (&queue->CompletionThreadQueue, &queue->CompletionThreadQueueLock)))
		{
			request = CONTAINING_RECORD (listEntry, EncryptedIoRequest, CompletionListEntry);

			if (request->EncryptedLength > 0 && NT_SUCCESS (request->Item->Status))
			{
				ASSERT (request->EncryptedOffset + request->EncryptedLength <= request->Offset.QuadPart + request->Length);
				dataUnit.Value = (request->Offset.QuadPart + request->EncryptedOffset) / ENCRYPTION_DATA_UNIT_SIZE;

				if (queue->CryptoInfo->bPartitionInInactiveSysEncScope)
					dataUnit.Value += queue->CryptoInfo->FirstDataUnitNo.Value;
				else if (queue->RemapEncryptedArea)
					dataUnit.Value += queue->RemappedAreaDataUnitOffset;

				DecryptDataUnits (request->Data + request->EncryptedOffset, &dataUnit, request->EncryptedLength / ENCRYPTION_DATA_UNIT_SIZE, queue->CryptoInfo);
			}

			if (request->CompleteOriginalIrp)
			{
				CompleteOriginalIrp (request->Item, request->Item->Status,
					NT_SUCCESS (request->Item->Status) ? request->Item->OriginalLength : 0);
			}
			else
			{
				InterlockedDecrement (&request->Item->OutstandingRequestCount);
				KeSetEvent (&queue->RequestCompletedEvent, IO_DISK_INCREMENT, FALSE);
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

	KeSetPriorityThread (KeGetCurrentThread(), LOW_REALTIME_PRIORITY);

	if (!queue->IsFilterDevice && queue->SecurityClientContext)
	{
#ifdef DEBUG
		NTSTATUS status =
#endif
		SeImpersonateClientEx (queue->SecurityClientContext, NULL);
		ASSERT (NT_SUCCESS (status));
	}

	while (!queue->ThreadExitRequested)
	{
		if (!NT_SUCCESS (KeWaitForSingleObject (&queue->IoThreadQueueNotEmptyEvent, Executive, KernelMode, FALSE, NULL)))
			continue;

		if (queue->ThreadExitRequested)
			break;

		while ((listEntry = ExInterlockedRemoveHeadList (&queue->IoThreadQueue, &queue->IoThreadQueueLock)))
		{
			request = CONTAINING_RECORD (listEntry, EncryptedIoRequest, ListEntry);
			
			// Perform IO request if no preceding request of the item failed
			if (NT_SUCCESS (request->Item->Status))
			{
				if (queue->IsFilterDevice)
				{
					if (queue->RemapEncryptedArea && request->EncryptedLength > 0)
					{
						if (request->EncryptedLength != request->Length)
						{
							// Up to three subfragments may be required to handle a partially remapped fragment
							int subFragment;
							byte *subFragmentData = request->Data;

							for (subFragment = 0 ; subFragment < 3; ++subFragment)
							{
								LARGE_INTEGER subFragmentOffset;
								ULONG subFragmentLength;
								subFragmentOffset.QuadPart = request->Offset.QuadPart;

								switch (subFragment)
								{
								case 0:
									subFragmentLength = (ULONG) request->EncryptedOffset;
									break;

								case 1:
									subFragmentOffset.QuadPart += request->EncryptedOffset + queue->RemappedAreaOffset;
									subFragmentLength = request->EncryptedLength;
									break;

								case 2:
									subFragmentOffset.QuadPart += request->EncryptedOffset + request->EncryptedLength;
									subFragmentLength = (ULONG) (request->Length - (request->EncryptedOffset + request->EncryptedLength));
									break;
								}

								if (subFragmentLength > 0)
								{
									if (request->Item->Write)
										request->Item->Status = TCWriteDevice (queue->LowerDeviceObject, subFragmentData, subFragmentOffset, subFragmentLength);
									else
										request->Item->Status = TCReadDevice (queue->LowerDeviceObject, subFragmentData, subFragmentOffset, subFragmentLength);

									subFragmentData += subFragmentLength;
								}
							}
						}
						else
						{
							// Remap the fragment
							LARGE_INTEGER remappedOffset;
							remappedOffset.QuadPart = request->Offset.QuadPart + queue->RemappedAreaOffset;

							if (request->Item->Write)
								request->Item->Status = TCWriteDevice (queue->LowerDeviceObject, request->Data, remappedOffset, request->Length);
							else
								request->Item->Status = TCReadDevice (queue->LowerDeviceObject, request->Data, remappedOffset, request->Length);
						}
					}
					else
					{
						if (request->Item->Write)
							request->Item->Status = TCWriteDevice (queue->LowerDeviceObject, request->Data, request->Offset, request->Length);
						else
							request->Item->Status = TCReadDevice (queue->LowerDeviceObject, request->Data, request->Offset, request->Length);
					}
				}
				else
				{
					IO_STATUS_BLOCK ioStatus;

					if (request->Item->Write)
						request->Item->Status = ZwWriteFile (queue->HostFileHandle, NULL, NULL, NULL, &ioStatus, request->Data, request->Length, &request->Offset, NULL);
					else
						request->Item->Status = ZwReadFile (queue->HostFileHandle, NULL, NULL, NULL, &ioStatus, request->Data, request->Length, &request->Offset, NULL);

					if (NT_SUCCESS (request->Item->Status) && ioStatus.Information != request->Length)
						request->Item->Status = STATUS_END_OF_FILE;
				}
			}

			if (request->Item->Write)
			{
				ReleaseFragmentBuffer (queue, request->Data);

				if (request->CompleteOriginalIrp)
				{
					CompleteOriginalIrp (request->Item, request->Item->Status,
						NT_SUCCESS (request->Item->Status) ? request->Item->OriginalLength : 0);
				}
				else
				{
					InterlockedDecrement (&request->Item->OutstandingRequestCount);
					KeSetEvent (&queue->RequestCompletedEvent, IO_DISK_INCREMENT, FALSE);
				}

				TCfree (request);
			}
			else
			{
				if (NT_SUCCESS (request->Item->Status))
					memcpy (request->OrigDataBufferFragment, request->Data, request->Length);

				ReleaseFragmentBuffer (queue, request->Data);
				request->Data = request->OrigDataBufferFragment;

				ExInterlockedInsertTailList (&queue->CompletionThreadQueue, &request->CompletionListEntry, &queue->CompletionThreadQueueLock);
				KeSetEvent (&queue->CompletionThreadQueueNotEmptyEvent, IO_DISK_INCREMENT, FALSE);
			}
		}
	}

	PsTerminateSystemThread (STATUS_SUCCESS);
}


static NTSTATUS OnPassedIrpCompleted (PDEVICE_OBJECT filterDeviceObject, PIRP irp, EncryptedIoQueueItem *item)
{
	if (irp->PendingReturned)
		IoMarkIrpPending (irp);

	OnItemCompleted (item, TRUE);
	return STATUS_CONTINUE_COMPLETION;
}


static VOID MainThreadProc (PVOID threadArg)
{
	EncryptedIoQueue *queue = (EncryptedIoQueue *) threadArg;
	PLIST_ENTRY listEntry;
	EncryptedIoQueueItem *item;

	LARGE_INTEGER fragmentOffset;
	ULONG dataRemaining;
	PUCHAR activeFragmentBuffer = queue->FragmentBufferA;
	PUCHAR dataBuffer;
	EncryptedIoRequest *request;
	uint64 intersectStart;
	uint32 intersectLength;

	int mdlWaitTime;
	LARGE_INTEGER mdlWaitInterval;
	mdlWaitInterval.QuadPart = TC_ENC_IO_QUEUE_MEM_ALLOC_RETRY_DELAY * -10000;

	if (IsEncryptionThreadPoolRunning())
		KeSetPriorityThread (KeGetCurrentThread(), LOW_REALTIME_PRIORITY);

	while (!queue->ThreadExitRequested)
	{
		if (!NT_SUCCESS (KeWaitForSingleObject (&queue->MainThreadQueueNotEmptyEvent, Executive, KernelMode, FALSE, NULL)))
			continue;

		while ((listEntry = ExInterlockedRemoveHeadList (&queue->MainThreadQueue, &queue->MainThreadQueueLock)))
		{
			PIRP irp = CONTAINING_RECORD (listEntry, IRP, Tail.Overlay.ListEntry);
			PIO_STACK_LOCATION irpSp = IoGetCurrentIrpStackLocation (irp);
			
			if (queue->Suspended)
				KeWaitForSingleObject (&queue->QueueResumedEvent, Executive, KernelMode, FALSE, NULL);

			item = AllocateMemoryWithTimeout (sizeof (EncryptedIoQueueItem), TC_ENC_IO_QUEUE_MEM_ALLOC_RETRY_DELAY, TC_ENC_IO_QUEUE_MEM_ALLOC_TIMEOUT);
			if (!item)
			{
				EncryptedIoQueueItem stackItem;
				stackItem.Queue = queue;
				stackItem.OriginalIrp = irp;
				stackItem.Status = STATUS_INSUFFICIENT_RESOURCES;

				TCCompleteDiskIrp (irp, STATUS_INSUFFICIENT_RESOURCES, 0);
				OnItemCompleted (&stackItem, FALSE);
				continue;
			}

			item->Queue = queue;
			item->OriginalIrp = irp;
			item->OutstandingRequestCount = 0;
			item->Status = STATUS_SUCCESS;

			IoSetCancelRoutine (irp, NULL);
			if (irp->Cancel)
			{
				CompleteOriginalIrp (item, STATUS_CANCELLED, 0);
				continue;
			}

			switch (irpSp->MajorFunction)
			{
			case IRP_MJ_READ:
				item->Write = FALSE;
				item->OriginalOffset = irpSp->Parameters.Read.ByteOffset;
				item->OriginalLength = irpSp->Parameters.Read.Length;
				break;

			case IRP_MJ_WRITE:
				item->Write = TRUE;
				item->OriginalOffset = irpSp->Parameters.Write.ByteOffset;
				item->OriginalLength = irpSp->Parameters.Write.Length;
				break;

			default:
				CompleteOriginalIrp (item, STATUS_INVALID_PARAMETER, 0);
				continue;
			}

			// Pass the IRP if the drive is not encrypted
			if (queue->IsFilterDevice && (queue->EncryptedAreaStart == -1 || queue->EncryptedAreaEnd == -1))
			{
				IoCopyCurrentIrpStackLocationToNext (irp);
				IoSetCompletionRoutine (irp, OnPassedIrpCompleted, item, TRUE, TRUE, TRUE);
				IoCallDriver (queue->LowerDeviceObject, irp);
				continue;
			}

			// Validate offset and length
			if (item->OriginalLength == 0
				|| (item->OriginalLength & (ENCRYPTION_DATA_UNIT_SIZE - 1)) != 0
				|| (item->OriginalOffset.QuadPart & (ENCRYPTION_DATA_UNIT_SIZE - 1)) != 0
				|| (!queue->IsFilterDevice && item->OriginalOffset.QuadPart + item->OriginalLength > queue->VirtualDeviceLength))
			{
				CompleteOriginalIrp (item, STATUS_INVALID_PARAMETER, 0);
				continue;
			}

			//Dump ("--- Queue %c %I64d  (%I64d)  %d  out=%d\n", item->Write ? 'W' : 'R', item->OriginalOffset.QuadPart, item->OriginalOffset.QuadPart / 1024 / 1024, item->OriginalLength, queue->OutstandingIoCount);

			if (!queue->IsFilterDevice)
			{
				// Adjust the offset for host file or device
				if (queue->CryptoInfo->hiddenVolume)
					item->OriginalOffset.QuadPart += queue->CryptoInfo->hiddenVolumeOffset;
				else
					item->OriginalOffset.QuadPart += queue->CryptoInfo->volDataAreaOffset; 

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
					if (RegionsOverlap ((unsigned __int64) item->OriginalOffset.QuadPart,
						(unsigned __int64) item->OriginalOffset.QuadPart + item->OriginalLength - 1,
						queue->CryptoInfo->hiddenVolumeOffset,
						(unsigned __int64) queue->CryptoInfo->hiddenVolumeOffset + queue->CryptoInfo->hiddenVolumeProtectedSize - 1))
					{
						Dump ("Hidden volume protection triggered: write %I64d-%I64d (protected %I64d-%I64d)\n", item->OriginalOffset.QuadPart, item->OriginalOffset.QuadPart + item->OriginalLength - 1, queue->CryptoInfo->hiddenVolumeOffset, queue->CryptoInfo->hiddenVolumeOffset + queue->CryptoInfo->hiddenVolumeProtectedSize - 1);
						queue->CryptoInfo->bHiddenVolProtectionAction = TRUE;

						// Deny this write operation to prevent the hidden volume from being overwritten
						CompleteOriginalIrp (item, STATUS_INVALID_PARAMETER, 0);
						continue;
					}
				}
			}
			else if (item->Write && IsHiddenSystemRunning()
				&& (RegionsOverlap (item->OriginalOffset.QuadPart, item->OriginalOffset.QuadPart + item->OriginalLength - 1, SECTOR_SIZE, TC_BOOT_LOADER_AREA_SECTOR_COUNT * SECTOR_SIZE - 1)
				 || RegionsOverlap (item->OriginalOffset.QuadPart, item->OriginalOffset.QuadPart + item->OriginalLength - 1, GetBootDriveLength(), _I64_MAX)))
			{
				Dump ("Preventing write to boot loader or host protected area\n");
				CompleteOriginalIrp (item, STATUS_MEDIA_WRITE_PROTECTED, 0);
				continue;
			}

			// Original IRP data buffer
			mdlWaitTime = 0;
			while (TRUE)
			{
				dataBuffer = (PUCHAR) MmGetSystemAddressForMdlSafe (irp->MdlAddress, HighPagePriority);

				if (dataBuffer || mdlWaitTime >= TC_ENC_IO_QUEUE_MEM_ALLOC_TIMEOUT)
					break;

				KeDelayExecutionThread (KernelMode, FALSE, &mdlWaitInterval);
				mdlWaitTime += TC_ENC_IO_QUEUE_MEM_ALLOC_RETRY_DELAY;
			}

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
				BOOL isLastFragment = dataRemaining <= TC_ENC_IO_QUEUE_MAX_FRAGMENT_SIZE;
				
				ULONG dataFragmentLength = isLastFragment ? dataRemaining : TC_ENC_IO_QUEUE_MAX_FRAGMENT_SIZE;
				activeFragmentBuffer = (activeFragmentBuffer == queue->FragmentBufferA ? queue->FragmentBufferB : queue->FragmentBufferA);

				// Create IO request
				request = (EncryptedIoRequest *) AllocateMemoryWithTimeout (sizeof (EncryptedIoRequest), TC_ENC_IO_QUEUE_MEM_ALLOC_RETRY_DELAY, TC_ENC_IO_QUEUE_MEM_ALLOC_TIMEOUT);
				if (!request)
				{
					while (InterlockedExchangeAdd (&item->OutstandingRequestCount, 0) > 0)
						KeWaitForSingleObject (&queue->RequestCompletedEvent, Executive, KernelMode, FALSE, NULL);

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

						if (queue->CryptoInfo->bPartitionInInactiveSysEncScope)
							dataUnit.Value += queue->CryptoInfo->FirstDataUnitNo.Value;
						else if (queue->RemapEncryptedArea)
							dataUnit.Value += queue->RemappedAreaDataUnitOffset;
								
						EncryptDataUnits (activeFragmentBuffer + request->EncryptedOffset, &dataUnit, request->EncryptedLength / ENCRYPTION_DATA_UNIT_SIZE, queue->CryptoInfo);
					}
				}

				// Queue IO request
				InterlockedIncrement (&item->OutstandingRequestCount);

				ExInterlockedInsertTailList (&queue->IoThreadQueue, &request->ListEntry, &queue->IoThreadQueueLock);
				KeSetEvent (&queue->IoThreadQueueNotEmptyEvent, IO_DISK_INCREMENT, FALSE);

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

	//Dump ("Queue irp %p  out=%d\n", irp, queue->OutstandingIoCount);
	IoMarkIrpPending (irp);

	ExInterlockedInsertTailList (&queue->MainThreadQueue, &irp->Tail.Overlay.ListEntry, &queue->MainThreadQueueLock);
	KeSetEvent (&queue->MainThreadQueueNotEmptyEvent, IO_DISK_INCREMENT, FALSE);
	
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

			TCSleep (100);
			if (InterlockedExchangeAdd (&queue->OutstandingIoCount, 0) > 0)
				return STATUS_UNSUCCESSFUL;
		}

		KeClearEvent (&queue->QueueResumedEvent);
		queue->Suspended = TRUE;

		if (InterlockedExchangeAdd (&queue->OutstandingIoCount, 0) == 0)
			break;

		queue->Suspended = FALSE;
		KeSetEvent (&queue->QueueResumedEvent, IO_DISK_INCREMENT, FALSE);

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
	KeSetEvent (&queue->QueueResumedEvent, IO_DISK_INCREMENT, FALSE);

	//Dump ("Queue resumed  out=%d\n", queue->OutstandingIoCount);

	return STATUS_SUCCESS;
}


NTSTATUS EncryptedIoQueueStart (EncryptedIoQueue *queue)
{
	NTSTATUS status;
	queue->ThreadExitRequested = FALSE;

	KeInitializeEvent (&queue->NoOutstandingIoEvent, SynchronizationEvent, FALSE);
	KeInitializeEvent (&queue->RequestCompletedEvent, SynchronizationEvent, FALSE);
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

	status = TCStartThread (IoThreadProc, queue, &queue->IoThread);
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
