/*
 Copyright (c) 2008-2009 TrueCrypt Foundation. All rights reserved.

 Governed by the TrueCrypt License 2.7 the full text of which is contained
 in the file License.txt included in TrueCrypt binary and source code
 distribution packages.
*/

#ifndef TC_HEADER_DRIVER_ENCRYPTED_IO_QUEUE
#define TC_HEADER_DRIVER_ENCRYPTED_IO_QUEUE

#include "TCdefs.h"
#include "Apidrvr.h"

#if 0
#	define TC_TRACE_IO_QUEUE
#endif

#define TC_ENC_IO_QUEUE_MAX_FRAGMENT_SIZE (256 * 1024)

#define TC_ENC_IO_QUEUE_PREALLOCATED_ITEM_COUNT 8
#define TC_ENC_IO_QUEUE_PREALLOCATED_IO_REQUEST_COUNT 16

#define TC_ENC_IO_QUEUE_MEM_ALLOC_RETRY_DELAY 1
#define TC_ENC_IO_QUEUE_MEM_ALLOC_TIMEOUT 1000


typedef struct EncryptedIoQueueBufferStruct
{
	struct EncryptedIoQueueBufferStruct *NextBuffer;

	void *Address;
	ULONG Size;
	BOOL InUse;

} EncryptedIoQueueBuffer;


typedef struct
{
	PDEVICE_OBJECT DeviceObject;
	
	KMUTEX BufferPoolMutex;
	EncryptedIoQueueBuffer *FirstPoolBuffer;

	CRYPTO_INFO *CryptoInfo;
	
	// File-handle-based IO
	HANDLE HostFileHandle;
	int64 VirtualDeviceLength;
	SECURITY_CLIENT_CONTEXT *SecurityClientContext;

	// Filter device
	BOOL IsFilterDevice;
	PDEVICE_OBJECT LowerDeviceObject;
	int64 EncryptedAreaStart;
	int64 EncryptedAreaEnd;
	BOOL RemapEncryptedArea;
	int64 RemappedAreaOffset;
	int64 RemappedAreaDataUnitOffset;
	IO_REMOVE_LOCK RemoveLock;

	// Main tread
	PKTHREAD MainThread;
	LIST_ENTRY MainThreadQueue;
	KSPIN_LOCK MainThreadQueueLock;
	KEVENT MainThreadQueueNotEmptyEvent;

	// IO thread
	PKTHREAD IoThread;
	LIST_ENTRY IoThreadQueue;
	KSPIN_LOCK IoThreadQueueLock;
	KEVENT IoThreadQueueNotEmptyEvent;

	// Completion thread
	PKTHREAD CompletionThread;
	LIST_ENTRY CompletionThreadQueue;
	KSPIN_LOCK CompletionThreadQueueLock;
	KEVENT CompletionThreadQueueNotEmptyEvent;

	// Fragment buffers
	byte *FragmentBufferA;
	byte *FragmentBufferB;
	KEVENT FragmentBufferAFreeEvent;
	KEVENT FragmentBufferBFreeEvent;

	// Read-ahead buffer
	BOOL ReadAheadBufferValid;
	LARGE_INTEGER LastReadOffset;
	ULONG LastReadLength;
	LARGE_INTEGER ReadAheadOffset;
	ULONG ReadAheadLength;
	byte *ReadAheadBuffer;
	LARGE_INTEGER MaxReadAheadOffset;

	LONG OutstandingIoCount;
	KEVENT NoOutstandingIoEvent;
	LONG IoThreadPendingRequestCount;

	KEVENT RequestCompletedEvent;
	KEVENT PoolBufferFreeEvent;

	__int64 TotalBytesRead;
	__int64 TotalBytesWritten;

	volatile BOOL StartPending;
	volatile BOOL ThreadExitRequested;
	
	volatile BOOL Suspended;
	volatile BOOL SuspendPending;
	volatile BOOL StopPending;

	KEVENT QueueResumedEvent;

#ifdef TC_TRACE_IO_QUEUE
	LARGE_INTEGER LastPerformanceCounter;
#endif

}  EncryptedIoQueue;


typedef struct
{
	EncryptedIoQueue *Queue;
	PIRP OriginalIrp;
	BOOL Write;
	ULONG OriginalLength;
	LARGE_INTEGER OriginalOffset;
	LONG OutstandingRequestCount;
	NTSTATUS Status;

#ifdef TC_TRACE_IO_QUEUE
	LARGE_INTEGER OriginalIrpOffset;
#endif

} EncryptedIoQueueItem;


typedef struct
{
	EncryptedIoQueueItem *Item;

	BOOL CompleteOriginalIrp;
	LARGE_INTEGER Offset;
	ULONG Length;
	int64 EncryptedOffset;
	ULONG EncryptedLength;
	byte *Data;
	byte *OrigDataBufferFragment;

	LIST_ENTRY ListEntry;
	LIST_ENTRY CompletionListEntry;
} EncryptedIoRequest;


NTSTATUS EncryptedIoQueueAddIrp (EncryptedIoQueue *queue, PIRP irp);
BOOL EncryptedIoQueueIsRunning (EncryptedIoQueue *queue);
BOOL EncryptedIoQueueIsSuspended (EncryptedIoQueue *queue);
NTSTATUS EncryptedIoQueueResumeFromHold (EncryptedIoQueue *queue);
NTSTATUS EncryptedIoQueueStart (EncryptedIoQueue *queue);
NTSTATUS EncryptedIoQueueStop (EncryptedIoQueue *queue);
NTSTATUS EncryptedIoQueueHoldWhenIdle (EncryptedIoQueue *queue, int64 timeout);


#endif // TC_HEADER_DRIVER_ENCRYPTED_IO_QUEUE
