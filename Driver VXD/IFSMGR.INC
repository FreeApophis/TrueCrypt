/* IFSMGR.H -- Declarations for Installable File System Manager Calls
 Copyright (C) 1996 by Walter Oney
 All rights reserved

 Wrapper Modifications and extentions by Aman.
 */

#include "ifs.h"	/* Win 95 DDk one seems ok, but Oney has his own */
#define IFSMGRVERSION 0x22

/*
 IFSMgr services
 */

#ifndef IFSMgr_DEVICE_ID
#define IFSMgr_DEVICE_ID 0x0040
#endif

#ifndef Not_VxD

#undef IFSMgr_Service
#define IFSMgr_Service Declare_Service
#pragma warning(disable:4003)	/* not enough parameters */
#include <vmm.h>

#include <vtd.h>
Begin_Service_Table(IFSMgr)

IFSMgr_Service(IFSMgr_Get_Version)
IFSMgr_Service(IFSMgr_RegisterMount)
IFSMgr_Service(IFSMgr_RegisterNet)
IFSMgr_Service(IFSMgr_RegisterMailSlot)
IFSMgr_Service(IFSMgr_Attach)
IFSMgr_Service(IFSMgr_Detach)
IFSMgr_Service(IFSMgr_Get_NetTime)
IFSMgr_Service(IFSMgr_Get_DOSTime)
IFSMgr_Service(IFSMgr_SetupConnection)
IFSMgr_Service(IFSMgr_DerefConnection)
IFSMgr_Service(IFSMgr_ServerDOSCall)
IFSMgr_Service(IFSMgr_CompleteAsync)
IFSMgr_Service(IFSMgr_RegisterHeap)
IFSMgr_Service(IFSMgr_GetHeap)
IFSMgr_Service(IFSMgr_RetHeap)
IFSMgr_Service(IFSMgr_CheckHeap)
IFSMgr_Service(IFSMgr_CheckHeapItem)
IFSMgr_Service(IFSMgr_FillHeapSpare)
IFSMgr_Service(IFSMgr_Block)
IFSMgr_Service(IFSMgr_Wakeup)
IFSMgr_Service(IFSMgr_Yield)
IFSMgr_Service(IFSMgr_SchedEvent)
IFSMgr_Service(IFSMgr_QueueEvent)
IFSMgr_Service(IFSMgr_KillEvent)
IFSMgr_Service(IFSMgr_FreeIOReq)
IFSMgr_Service(IFSMgr_MakeMailSlot)
IFSMgr_Service(IFSMgr_DeleteMailSlot)
IFSMgr_Service(IFSMgr_WriteMailSlot)
IFSMgr_Service(IFSMgr_PopUp)
IFSMgr_Service(IFSMgr_printf)
IFSMgr_Service(IFSMgr_AssertFailed)
IFSMgr_Service(IFSMgr_LogEntry)
IFSMgr_Service(IFSMgr_DebugMenu)
IFSMgr_Service(IFSMgr_DebugVars)
IFSMgr_Service(IFSMgr_GetDebugString)
IFSMgr_Service(IFSMgr_GetDebugHexNum)
IFSMgr_Service(IFSMgr_NetFunction)
IFSMgr_Service(IFSMgr_DoDelAllUses)
IFSMgr_Service(IFSMgr_SetErrString)
IFSMgr_Service(IFSMgr_GetErrString)
IFSMgr_Service(IFSMgr_SetReqHook)
IFSMgr_Service(IFSMgr_SetPathHook)
IFSMgr_Service(IFSMgr_UseAdd)
IFSMgr_Service(IFSMgr_UseDel)
IFSMgr_Service(IFSMgr_InitUseAdd)
IFSMgr_Service(IFSMgr_ChangeDir)
IFSMgr_Service(IFSMgr_DelAllUses)
IFSMgr_Service(IFSMgr_CDROM_Attach)
IFSMgr_Service(IFSMgr_CDROM_Detach)
IFSMgr_Service(IFSMgr_Win32DupHandle)
IFSMgr_Service(IFSMgr_Ring0_FileIO)
IFSMgr_Service(IFSMgr_Win32_Get_Ring0_Handle)
IFSMgr_Service(IFSMgr_Get_Drive_Info)
IFSMgr_Service(IFSMgr_Ring0GetDriveInfo)
IFSMgr_Service(IFSMgr_BlockNoEvents)
IFSMgr_Service(IFSMgr_NetToDosTime)
IFSMgr_Service(IFSMgr_DosToNetTime)
IFSMgr_Service(IFSMgr_DosToWin32Time)
IFSMgr_Service(IFSMgr_Win32ToDosTime)
IFSMgr_Service(IFSMgr_NetToWin32Time)
IFSMgr_Service(IFSMgr_Win32ToNetTime)
IFSMgr_Service(IFSMgr_MetaMatch)
IFSMgr_Service(IFSMgr_TransMatch)
IFSMgr_Service(IFSMgr_CallProvider)
IFSMgr_Service(UniToBCS)
IFSMgr_Service(UniToBCSPath)
IFSMgr_Service(BCSToUni)
IFSMgr_Service(UniToUpper)
IFSMgr_Service(UniCharToOEM)
IFSMgr_Service(CreateBasis)
IFSMgr_Service(MatchBasisName)
IFSMgr_Service(AppendBasisTail)
IFSMgr_Service(FcbToShort)
IFSMgr_Service(ShortToFcb)
IFSMgr_Service(IFSMgr_ParsePath)
IFSMgr_Service(Query_PhysLock)
IFSMgr_Service(_VolFlush)
IFSMgr_Service(NotifyVolumeArrival)
IFSMgr_Service(NotifyVolumeRemoval)
IFSMgr_Service(QueryVolumeRemoval)
IFSMgr_Service(IFSMgr_FSDUnmountCFSD)
IFSMgr_Service(IFSMgr_GetConversionTablePtrs)
IFSMgr_Service(IFSMgr_CheckAccessConflict)
IFSMgr_Service(IFSMgr_LockFile)
IFSMgr_Service(IFSMgr_UnlockFile)
IFSMgr_Service(IFSMgr_RemoveLocks)
IFSMgr_Service(IFSMgr_CheckLocks)
IFSMgr_Service(IFSMgr_CountLocks)
IFSMgr_Service(IFSMgr_ReassignLockFileInst)
IFSMgr_Service(IFSMgr_UnassignLockList)
IFSMgr_Service(IFSMgr_MountChildVolume)
IFSMgr_Service(IFSMgr_UnmountChildVolume)
IFSMgr_Service(IFSMgr_SwapDrives)
IFSMgr_Service(IFSMgr_FSDMapFHtoIOREQ)
IFSMgr_Service(IFSMgr_FSDParsePath)
IFSMgr_Service(IFSMgr_FSDAttachSFT)
IFSMgr_Service(IFSMgr_GetTimeZoneBias)
IFSMgr_Service(IFSMgr_PNPEvent)
IFSMgr_Service(IFSMgr_RegisterCFSD)
IFSMgr_Service(IFSMgr_Win32MapExtendedHandleToSFT)
IFSMgr_Service(IFSMgr_DbgSetFileHandleLimit)
IFSMgr_Service(IFSMgr_Win32MapSFTToExtendedHandle)
IFSMgr_Service(IFSMgr_FSDGetCurrentDrive)
IFSMgr_Service(IFSMgr_InstallFileSystemApiHook)
IFSMgr_Service(IFSMgr_RemoveFileSystemApiHook)
IFSMgr_Service(IFSMgr_RunScheduledEvents)
IFSMgr_Service(IFSMgr_CheckDelResource)
IFSMgr_Service(IFSMgr_Win32GetVMCurdir)
IFSMgr_Service(IFSMgr_SetupFailedConnection)
IFSMgr_Service(_GetMappedErr)
IFSMgr_Service(ShortToLossyFcb)
IFSMgr_Service(IFSMgr_GetLockState)
IFSMgr_Service(BcsToBcs)
IFSMgr_Service(IFSMgr_SetLoopback)
IFSMgr_Service(IFSMgr_ClearLoopback)
IFSMgr_Service(IFSMgr_ParseOneElement)
IFSMgr_Service(BcsToBcsUpper)

End_Service_Table(IFSMgr)

#pragma warning(default:4003)

#endif /* Not_VxD */

/*
 Inline service function definitions:
*/

#ifndef Not_VxD
#pragma warning(disable:4035)	/* missing return value */

#undef NAKED
#define NAKED __declspec(naked)

DWORD VXDINLINE IFSMgr_Get_Version()
	{
	VxDCall(IFSMgr_Get_Version)
	_asm jnc okay
	_asm xor eax, eax
	_asm okay:
	}

#define NORMAL_FSD 0
#define DEFAULT_FSD 1

int VXDINLINE NAKED IFSMgr_RegisterCFSD(pIFSFunc fcn, UINT version, string_t* ppDeviceNames)
	{
	VxDJmp(IFSMgr_RegisterCFSD)
	}

/* Command codes in ir_flags for calls to mailslot procedure: */

#define MSLOT_CREATE 0
#define MSLOT_DELETE 1
#define MSLOT_WRITE 2

int VXDINLINE NAKED IFSMgr_RegisterMailSlot(pIFSFunc fcn, UINT version)
	{
	VxDJmp(IFSMgr_RegisterMailSlot)
	}

int VXDINLINE NAKED IFSMgr_RegisterMount(pIFSFunc fcn, UINT version, UINT defoption)
	{
	VxDJmp(IFSMgr_RegisterMount)
	}

int VXDINLINE NAKED IFSMgr_RegisterNet(pIFSFunc fcn, UINT version, UINT netid)
	{
	VxDJmp(IFSMgr_RegisterNet)
	}

#define DEBUG_FENCE_ON 1

#ifdef DEBUG
VOID VXDINLINE NAKED IFSMgr_RegisterHeap(pIFSFunc fcn, UINT flag)
	{
	VxDJmp(IFSMgr_RegisterHeap)
	}
#else
#define IFSMgr_RegisterHeapUser(a1,a2)
#endif

PVOID VXDINLINE NAKED IFSMgr_GetHeap(UINT size)
	{
	VxDJmp(IFSMgr_GetHeap)
	}

VOID VXDINLINE NAKED IFSMgr_RetHeap(PVOID p)
	{
	VxDJmp(IFSMgr_RetHeap)
	}

#ifdef DEBUG
#define CHECKHEAP(p) IFSMgr_CheckHeap(p, __FILE__, __LINE__);
#define CHECKHEAPITEM(p) IFSMgr_CheckHeapItem(p, __FILE__, __LINE__);
int VXDINLINE NAKED IFSMgr_CheckHeap(PVOID pmem, char* filename, UINT line)
	{
	VxDJmp(IFSMgr_CheckHeap)
	}
int VXDINLINE NAKED IFSMgr_CheckHeapItem(PVOID pmem, char* filename, UINT line)
	{
	VxDJmp(IFSMgr_CheckHeapItem)
	}
#else
#define CHECKHEAP(p)
#define CHECKHEAPITEM(p)
#define IFSMgr_CheckHeap(a1, a2, a3)
#define IFSMgr_CheckHeapItem(a1, a2, a3)
#endif

VOID VXDINLINE NAKED IFSMgr_FillHeapSpare()
	{
	VxDJmp(IFSMgr_FillHeapSpare)
	}

typedef DWORD nettime_t;		/* # seconds since 1/1/1970 */

typedef struct nettimex_t
	{
	DWORD dwSeconds;			/* # seconds since 1/1/1970 */
	DWORD dwMilliseconds;		/* milliseconds in last second */
	} nettimex_t;

typedef struct dostimex_t
	{
	WORD wTime;					/* time in DOS format */
	WORD wDate;					/* date in DOS format */
	DWORD dwMilliseconds;		/* # milliseconds in last 2-sec interval */
	} dostimex_t;

nettimex_t VXDINLINE NAKED IFSMgr_Get_NetTimeEx()
	{
	VxDJmp(IFSMgr_Get_NetTime)
	}

nettime_t VXDINLINE NAKED IFSMgr_Get_NetTime()
	{
	VxDJmp(IFSMgr_Get_NetTime)
	}

dostimex_t VXDINLINE NAKED IFSMgr_Get_DOSTimeEx()
	{
	VxDJmp(IFSMgr_Get_DOSTime)
	}

typedef dos_time dostime_t;

dostime_t VXDINLINE NAKED IFSMgr_Get_DOSTime()
	{
	VxDJmp(IFSMgr_Get_DOSTime)
	}

dostime_t VXDINLINE NAKED IFSMgr_NetToDosTime(DWORD nettime)
	{
	VxDJmp(IFSMgr_NetToDosTime)
	}

DWORD VXDINLINE NAKED IFSMgr_DosToNetTime(dostime_t dostime)
	{
	VxDJmp(IFSMgr_DosToNetTime)
	}

_FILETIME VXDINLINE NAKED IFSMgr_DosToWin32Time(dostime_t dostime)
	{
	VxDJmp(IFSMgr_DosToWin32Time)
	}

dostime_t VXDINLINE NAKED IFSMgr_Win32ToDosTime(_FILETIME win32time)
	{
	VxDJmp(IFSMgr_Win32ToDosTime)
	}

_FILETIME VXDINLINE NAKED IFSMgr_NetToWin32Time(DWORD nettime)
	{
	VxDJmp(IFSMgr_NetToWin32Time)
	}

DWORD VXDINLINE NAKED IFSMgr_Win32ToNetTime(_FILETIME win32time)
	{
	VxDJmp(IFSMgr_Win32ToNetTime)
	}

int VXDINLINE NAKED IFSMgr_GetTimeZoneBias()
	{
	VxDJmp(IFSMgr_GetTimeZoneBias)
	}

VOID VXDINLINE NAKED IFSMgr_SetupConnection(pioreq pir, UINT resopt, UINT restype)
	{
	VxDJmp(IFSMgr_SetupConnection)
	}

VOID VXDINLINE NAKED IFSMgr_DerefConnection(pioreq pir)
	{
	VxDJmp(IFSMgr_DerefConnection)
	}

typedef union tagDPL32
	{
	struct DPL32_DW 
		{
		DWORD DPL32_EAX;
		DWORD DPL32_EBX;
		DWORD DPL32_ECX;
		DWORD DPL32_EDX;
		DWORD DPL32_ESI;
		DWORD DPL32_EDI;
		DWORD DPL32_EBP;
		WORD  DPL32_UID;
		WORD  DPL32_PID;
		DWORD DPL32_DTA;
		BYTE  DPL32_FLAGS;
		BYTE  DPL32_PAD[3];
		};
	struct DPL32_W
		{
		WORD DPL32_AX, junk1;
		WORD DPL32_BX, junk2;
		WORD DPL32_CX, junk3;
		WORD DPL32_DX, junk4;
		WORD DPL32_SI, junk5;
		WORD DPL32_DI, junk6;
		WORD DPL32_BP, junk7;
		DWORD DPL32_PID32;
		};
	struct DPL32_B
		{
		BYTE DPL32_AL, APL32_AH;
		WORD junk8;
		BYTE DPL32_BL, APL32_BH;
		WORD junk9;
		BYTE DPL32_CL, APL32_CH;
		WORD junk10;
		BYTE DPL32_DL, APL32_DH;
		WORD junk11;
		};
	} DPL32, *PDPL32;

#define DPL32_USE_MASK		0x03
#define DPL32_USE_ANSI		0
#define DPL32_USE_OEM		1
#define DPL32_USE_UNICODE	2

#define DPL32_8_3_MATCHING	0x04

BOOL VXDINLINE IFSMgr_ServerDOSCall(HVM hVM, UINT fcn, PDPL32 dpl, PCRS pRegs)
	{
	_asm push ebp
	_asm mov ebx, hVM
	_asm mov ecx, fcn
	_asm mov esi, dpl
	_asm mov ebp, pRegs
	VxDCall(IFSMgr_ServerDOSCall)
	_asm pop ebp
	_asm cmc
	_asm sbb eax, eax
	}

typedef int (_cdecl *pMSFunc)(PVOID pdata, UINT len, BYTE lana);

int VXDINLINE NAKED IFSMgr_MakeMailSlot(pMSFunc fcn, path_t pmsname, PDWORD pmshand)
	{
	VxDJmp(IFSMgr_MakeMailSlot)
	}

int VXDINLINE NAKED IFSMgr_DeleteMailSlot(DWORD mshand)
	{
	VxDJmp(IFSMgr_DeleteMailSlot)
	}

int VXDINLINE NAKED IFSMgr_WriteMailSlot(path_t pmsname, char* pdata, WORD len, BYTE lana, string_t rname, PVOID xtra)
	{
	VxDJmp(IFSMgr_WriteMailSlot)
	}

int VXDINLINE NAKED IFSMgr_SetErrString(char* errstr, UINT errorcode, UINT table)
	{
	VxDJmp(IFSMgr_SetErrString)
	}

VXDINLINE NAKED PCHAR IFSMgr_GetErrString(UINT errorcode, UINT table)
	{
	VxDJmp(IFSMgr_GetErrString)
	}

typedef void (__cdecl *PPREAMBLE)(); 

VXDINLINE NAKED PPREAMBLE IFSMgr_SetReqHook(UINT request, PPREAMBLE preamble)
	{
	VxDJmp(IFSMgr_SetReqHook)
	}

typedef void (__cdecl *PPATHCHECKER)();

VXDINLINE NAKED PPATHCHECKER IFSMgr_SetPathHook(PPATHCHECKER fcn)
	{
	VxDJmp(IFSMgr_SetPathHook)
	}

#endif /* Not_VxD */

typedef struct _LM_GUID {
	WORD			guid_uid;		/* LM10 style user id */
	DWORD			guid_serial;	/* user record serial number */
	BYTE			guid_rsvd[10];	/* pad to 16 bytes */
	} _LM_GUID;

typedef struct use_info_2 {
	char            ui2_local[9];
	char            ui2_pad_1;
	char*			ui2_remote;
	char*			ui2_password;
	unsigned short  ui2_status;         
	short           ui2_asg_type;       
	unsigned short  ui2_refcount;       
	unsigned short  ui2_usecount;       
	unsigned short  ui2_res_type;       
	unsigned short  ui2_flags;          
	unsigned short  ui2_usrclass;       
	void*		    ui2_dirname;        
	struct _LM_GUID ui2_dfs_id;         
	} use_info_2, *puse_info_2;

#ifndef Not_VxD

int VXDINLINE NAKED IFSMgr_UseAdd(pioreq pir, int proId, netuse_info* pinfo)
	{
	VxDJmp(IFSMgr_UseAdd)
	}

int VXDINLINE NAKED IFSMgr_InitUseAdd(puse_info_2 pui2, int proId, int lana)
	{
	VxDJmp(IFSMgr_InitUseAdd)
	}

int VXDINLINE NAKED IFSMgr_UseDel(pioreq pir, int proId, netuse_info* pinfo)
	{
	VxDJmp(IFSMgr_UseDel)
	}

int VXDINLINE NAKED IFSMgr_DelAllUses(int proId, int force)
	{
	VxDJmp(IFSMgr_DelAllUses)
	}

VOID VXDINLINE NAKED IFSMgr_DoDelAllUses(pioreq pir)
	{
	VxDJmp(IFSMgr_DoDelAllUses)
	}

#if 0
int VXDLINLINE NAKED IFSMgr_FSDMapFHtoIOREQ(pioreq pir, WORD doshandle)
	{
	VxDJmp(IFSMgr_FSDMapFHtoIOREQ)
	}
#endif

int VXDINLINE NAKED IFSMgr_CheckDelResource(PVOID rh, int force, BOOL fDelFlag)
	{
	VxDJmp(IFSMgr_CheckDelResource)
	}

int VXDINLINE NAKED IFSMgr_SetupFailedConnection(pioreq pir, PDWORD pProId)
	{
	VxDJmp(IFSMgr_SetupFailedConnection)
	}

int VXDINLINE NAKED IFSMgr_SetLoopback(char* pszUNCPath, char* pszLocalPath)
	{
	VxDJmp(IFSMgr_SetLoopback)
	}

int VXDINLINE NAKED IFSMgr_ClearLoopback(char* pszUNCPath)
	{
	VxDJmp(IFSMgr_ClearLoopback)
	}

VOID VXDINLINE NAKED IFSMgr_Block(DWORD key)
	{
	VxDJmp(IFSMgr_Block)
	}

VOID VXDINLINE NAKED IFSMgr_BlockNoEvents(DWORD key)
	{
	VxDJmp(IFSMgr_BlockNoEvents)
	}

VOID VXDINLINE NAKED IFSMgr_Wakeup(DWORD key)
	{
	VxDJmp(IFSMgr_Wakeup)
	}

VOID VXDINLINE NAKED IFSMgr_Yield()
	{
	VxDJmp(IFSMgr_Yield)
	}

VOID VXDINLINE NAKED IFSMgr_SchedEvent(pevent pev, DWORD time)
	{
	VxDJmp(IFSMgr_SchedEvent)
	}

VOID VXDINLINE NAKED IFSMgr_QueueEvent(pevent pev)
	{
	VxDJmp(IFSMgr_QueueEvent)
	}

VOID VXDINLINE NAKED IFSMgr_KillEvent(pevent pev)
	{
	VxDJmp(IFSMgr_KillEvent)
	}

VOID VXDINLINE NAKED IFSMgr_FreeIOReq(pioreq pir)
	{
	VxDJmp(IFSMgr_FreeIOReq)
	}

VOID VXDINLINE NAKED IFSMgr_RunScheduledEvents()
	{
	VxDJmp(IFSMgr_RunScheduledEvents)
	}

UINT VXDINLINE NAKED IFSMgr_MetaMatch(string_t pUniPattern, string_t pUniName, int matchSem)
	{
	VxDJmp(IFSMgr_MetaMatch)
	}

int VXDINLINE NAKED IFSMgr_TransMatch(pioreq pir, srch_entry* pse, string_t pattern, _WIN32_FIND_DATA* pFindBuf)
	{
	VxDJmp(IFSMgr_TransMatch)
	}

UINT VXDINLINE NAKED UniToBCSPath(PBYTE pBCSPath, PathElement* pUniPath, UINT maxLength, int charSet)
	{
	VxDJmp(UniToBCSPath)
	}

UINT VXDINLINE NAKED UniToBCS(PBYTE pBCSPath, string_t pUniPath, UINT length, UINT maxLength, UINT charSet)
	{
	VxDJmp(UniToBCS)
	}

UINT VXDINLINE NAKED BCSToUni(string_t pUniStr, PBYTE pBCSStr, UINT length, int charSet)
	{
	VxDJmp(BCSToUni)
	}

UINT VXDINLINE NAKED BcsToBcs(PBYTE pDest, PBYTE pSrc, UINT dstCharSet, UINT srcCharSet, UINT MaxLen)
	{
	VxDJmp(BcsToBcs)
	}

UINT VXDINLINE NAKED UniCharToOEM(WORD uniChar)
	{
	VxDJmp(UniCharToOEM)
	}

UINT VXDINLINE NAKED UniToUpper(string_t pUniUpStr, string_t pUniStr, UINT length)
	{
	VxDJmp(UniToUpper)
	}

UINT VXDINLINE NAKED CreateBasis(string_t pBasisName, string_t pUniName, UINT length)
	{
	VxDJmp(CreateBasis)
	}

int VXDINLINE NAKED MatchBasisName(string_t pBasisName, string_t pName)
	{
	VxDJmp(MatchBasisName)
	}

int VXDINLINE NAKED AppendBasisTail(string_t pBasisName, int tail)
	{
	VxDJmp(AppendBasisTail)
	}

int VXDINLINE NAKED FcbToShort(string_t p83name, string_t pFCBName, int trailDot)
	{
	VxDJmp(FcbToShort)
	}

int VXDINLINE NAKED ShortToFcb(string_t pFCBName, string_t p83Name, UINT length)
	{
	VxDJmp(ShortToFcb)
	}

int VXDINLINE NAKED ShortToLossyFcb(string_t pFCBName, string_t p83Name, UINT length)
	{
	VxDJmp(ShortToLossyFcb)
	}

typedef struct _CONVTABLES
	{
	DWORD	ct_length;
	PDWORD	ct_UniToWinAnsiTbl;
	PDWORD	ct_UniToOemTbl;
	PDWORD	ct_WinAnsiToUniTbl;
	PDWORD	ct_OemToUniTable;
	PDWORD	ct_UniToUpperDeltaTbl;
	PDWORD	ct_UniToUpperTbl;
	} _CONVTABLES, *_PCONVTABLES;

_PCONVTABLES VXDINLINE NAKED IFSMgr_GetConversionTablePtrs()
	{
	VxDJmp(IFSMgr_GetConversionTablePtrs)
	}

int VXDINLINE NAKED IFSMgr_ParsePath(pioreq pir)
	{
	VxDJmp(IFSMgr_ParsePath)
	}

int VXDINLINE NAKED IFSMgr_FSDParsePath(pioreq pir)
	{
	VxDJmp(IFSMgr_FSDParsePath)
	}

int VXDINLINE NAKED IFSMgr_ParseOneElement(USHORT* pe_unichars)
	{
	VxDJmp(IFSMgr_ParseOneElement)
	}

int VXDINLINE NAKED IFSMgr_CheckAccessConflict(int fSortCompatibleDisable, fmode_t pfmode, int (*pfn)(fmode_t*, const void*), const void* FSDCookie)
	{
	VxDJmp(IFSMgr_CheckAccessConflict)
	}

int VXDINLINE NAKED IFSMgr_LockFile(void** ppFSDLockListHead, DWORD LockOffset, DWORD LockLength, DWORD LockOwner, PVOID pOpenFileInstance, DWORD fLockSemantics)
	{
	VxDJmp(IFSMgr_LockFile)
	}

int VXDINLINE NAKED IFSMgr_UnlockFile(void** ppFSDLockListHead, DWORD LockOffset, DWORD LockLength, DWORD LockOwner, PVOID pOpenFileInstance, DWORD fLockSemantics)
	{
	VxDJmp(IFSMgr_UnlockFile)
	}

VOID VXDINLINE NAKED IFSMgr_RemoveLocks(void** ppFSDLockListHead, DWORD LockOwner, PVOID pOpenFileInstance)
	{
	VxDJmp(IFSMgr_RemoveLocks)
	}

int VXDINLINE NAKED IFSMgr_CheckLocks(PVOID pFSDLockListHead, DWORD Offset, DWORD Length, DWORD Process, PVOID pOpenFileInstance, DWORD fOperation)
	{
	VxDJmp(IFSMgr_CheckLocks)
	}

int VXDINLINE NAKED IFSMgr_CountLocks(PVOID pFSDLockListHead, PVOID pOpenFileInstance)
	{
	VxDJmp(IFSMgr_CountLocks)
	}

VOID VXDINLINE NAKED IFSMgr_UnassignLockList(PVOID pFSDLockListHead)
	{
	VxDJmp(IFSMgr_UnassignLockList)
	}

VOID VXDINLINE NAKED IFSMgr_ReassignLockFileInst(PVOID pFSDLockListhead, PVOID pOldOpenFileInstance, PVOID pNewOpenFileInstance)
	{
	VxDJmp(IFSMgr_ReassignLockFileInst)
	}

VOID VXDINLINE NAKED NotifyVolumeArrival(UINT drive)
	{
	VxDJmp(NotifyVolumeArrival)
	}

int VXDINLINE NAKED QueryVolumeRemoval(UINT drive, int fDialog)
	{
	VxDJmp(QueryVolumeRemoval)
	}

VOID VXDINLINE NAKED NotifyVolumeRemoval(UINT drive)
	{
	VxDJmp(NotifyVolumeRemoval)
	}

int VXDINLINE NAKED IFSMgr_PNPEvent(UINT Message, UINT Resource, UINT Flags)
	{
	VxDJmp(IFSMgr_PNPEvent)
	}

int VXDINLINE NAKED _VolFlush(UINT Volume, int Flags)
	{
	VxDJmp(_VolFlush)
	}

VOID VXDINLINE NAKED IFSMgr_CompleteAsync(pioreq pir)
	{
	VxDJmp(IFSMgr_CompleteAsync)
	}

int VXDINLINE R0_OpenCreateFile(BOOL incontext, WORD modeflags, WORD attrib, BYTE action, BYTE flags, char* pathname, PDWORD phandle, PDWORD paction)
	{
	DWORD opcode = incontext ? R0_OPENCREAT_IN_CONTEXT : R0_OPENCREATFILE;
	DWORD result=0;
	_asm
		{
		pushad
		mov	eax, R0_OPENCREATFILE ;/* opcode */
		xor ebx,ebx
		xor ecx,ecx
		xor edx,edx
		mov bx, [modeflags]
		mov cx, [attrib]
		mov dl, [action]
		mov dh, [flags]
		mov esi, [pathname]
		}
	VxDCall(IFSMgr_Ring0_FileIO)
	_asm
		{
		jc	error
		mov ebx, [phandle]
		mov [ebx], eax
		mov ebx, [paction]
		mov [ebx], ecx
		xor eax, eax
		
	error:
		
		mov	[WORD PTR result], ax
		popad
	}
	return result;
	}

int VXDINLINE R0_ReadFile(BOOL incontext, DWORD handle, DWORD count, DWORD pos, PBYTE buffer, PDWORD nread)
	{
	DWORD opcode = incontext ? R0_READFILE_IN_CONTEXT : R0_READFILE;
	DWORD result=0;
	_asm
		{
		pushad
		mov	eax, R0_READFILE ; /* opcode */
		mov	ebx, [handle]
		mov ecx, [count]
		mov edx, [pos]
		mov esi, [buffer]
		}
	VxDCall(IFSMgr_Ring0_FileIO)
	_asm
		{
		jc	error
		mov ebx, [nread]
		mov [ebx], ecx
		xor eax, eax
	error:
		mov	[WORD PTR result], ax
		popad
		}
	return result;
	}

int VXDINLINE R0_WriteFile(BOOL incontext, DWORD handle, DWORD count, DWORD pos, const BYTE* buffer, PDWORD nwritten)
	{
	DWORD opcode = incontext ? R0_WRITEFILE_IN_CONTEXT : R0_WRITEFILE;
	DWORD result=0;
	_asm
		{
		pushad
		
		mov	eax, R0_WRITEFILE ; /* opcode */
		mov	ebx, [handle]
		mov ecx, [count]
		mov edx, [pos]
		mov esi, [buffer]
		}
	VxDCall(IFSMgr_Ring0_FileIO)
	_asm
		{
		jc	error
	
		mov ebx, nwritten
		mov [ebx], ecx
		xor eax, eax
	error:
		mov [WORD PTR result], ax
		popad
		}
	return result;
	}

int VXDINLINE R0_CloseFile(DWORD handle)
	{
	_asm
		{
		mov	eax, R0_CLOSEFILE
		mov ebx, [handle]
		}
	VxDCall(IFSMgr_Ring0_FileIO)
	_asm jc error
	_asm xor eax, eax
	_asm error:
	_asm movzx eax, ax
	}

int VXDINLINE R0_GetFileSize(DWORD handle, PDWORD psize)
	{
	_asm
		{
		mov	eax, R0_GETFILESIZE
		mov ebx, handle
		}
	VxDCall(IFSMgr_Ring0_FileIO)
	_asm
		{
		jc	error
		mov ebx, psize
		mov [ebx], eax
		xor	eax, eax
	error:
		movzx eax, ax
		}
	}

int VXDINLINE R0_FindFirstFile(WORD attrib, const char* pathname, _WIN32_FIND_DATA* fd, PDWORD phandle)
	{
	_asm
		{
		mov	eax, R0_FINDFIRSTFILE
		mov	esi, pathname
		mov edx, fd
		}
	VxDCall(IFSMgr_Ring0_FileIO)
	_asm
		{
		jc	error
		mov ebx, phandle
		mov [ebx], eax
		xor eax, eax
	error:
		movzx eax, ax
		}
	}

int VXDINLINE R0_FindNextFile(DWORD handle, _WIN32_FIND_DATA* fd)
	{
	_asm
		{
		mov	eax, R0_FINDNEXTFILE
		mov ebx, handle
		mov edx, fd
		}
	VxDCall(IFSMgr_Ring0_FileIO)
	_asm jc error
	_asm xor eax, eax
	_asm error:
	_asm movzx eax, ax
	}

int VXDINLINE R0_FindClose(DWORD handle)
	{
	_asm
		{
		mov	eax, R0_FINDCLOSEFILE
		mov ebx, handle
		}
	VxDCall(IFSMgr_Ring0_FileIO)
	_asm jc error
	_asm xor eax, eax
	_asm error:
	_asm movzx eax, ax
	}

int VXDINLINE R0_GetFileAttributes(const char* pathname, PWORD pattrib)
	{
	_asm
		{
		mov	eax, R0_FILEATTRIBUTES or GET_ATTRIBUTES
		mov esi, pathname
		}
	VxDCall(IFSMgr_Ring0_FileIO)
	_asm
		{
		jc	error
		mov ebx, pattrib
		mov word ptr [ebx], cx
		xor eax, eax
	error:
		movzx eax, ax
		}
	}

int VXDINLINE R0_SetFileAttributes(const char* pathname, WORD attrib)
	{
	_asm
		{
		mov	eax, R0_FILEATTRIBUTES or SET_ATTRIBUTES
		mov cx, attrib
		mov esi, pathname
		}
	VxDCall(IFSMgr_Ring0_FileIO)
	_asm jc error
	_asm xor eax, eax
	_asm error:
	_asm movzx eax, ax
	}

int VXDINLINE R0_RenameFile(const char* oldname, const char* newname)
	{
	_asm
		{
		mov	eax, R0_RENAMEFILE
		mov esi, oldname
		mov edx, newname
		}
	VxDCall(IFSMgr_Ring0_FileIO)
	_asm jc error
	_asm xor eax, eax
	_asm error:
	_asm movzx eax, ax
	}

int VXDINLINE R0_DeleteFile(const char* pathname, WORD attrib)
	{
	_asm
		{
		mov eax, R0_DELETEFILE
		mov cx, attrib
		mov esi, pathname
		}
	VxDCall(IFSMgr_Ring0_FileIO)
	_asm jc error
	_asm xor eax, eax
	_asm error:
	_asm movzx eax, ax
	}

int VXDINLINE R0_LockFile(DWORD handle, DWORD pid, DWORD dwOffset, DWORD dwLength)
	{
	_asm
		{
		mov eax, R0_LOCKFILE or LOCK_REGION
		mov ebx, handle
		mov ecx, pid
		mov edx, dwOffset
		mov esi, dwLength
		}
	VxDCall(IFSMgr_Ring0_FileIO)
	_asm jc error
	_asm xor eax, eax
	_asm error:
	_asm movzx eax, ax
	}

int VXDINLINE R0_UnlockFile(DWORD handle, DWORD pid, DWORD dwOffset, DWORD dwLength)
	{
	_asm
		{
		mov eax, R0_LOCKFILE or UNLOCK_REGION
		mov ebx, handle
		mov ecx, pid
		mov edx, dwOffset
		mov esi, dwLength
		}
	VxDCall(IFSMgr_Ring0_FileIO)
	_asm jc error
	_asm xor eax, eax
	_asm error:
	_asm movzx eax, ax
	}

int VXDINLINE R0_GetDiskFreeSpace(BYTE drive, PWORD pspc, PWORD pavl, PWORD psecsize, PWORD ptot)
	{
	_asm
		{
		mov	eax, R0_GETDISKFREESPACE
		mov dl, drive
		}
	VxDCall(IFSMgr_Ring0_FileIO)
	_asm
		{
		jc	error
		mov esi, pspc
		mov word ptr [esi], ax		; sectors per cluster
		mov esi, pavl
		mov word ptr [esi], bx		; available clusters
		mov esi, psecsize
		mov word ptr [esi], cx		; bytes per sector
		mov esi, ptot
		mov word ptr [esi], dx		; total clusters on disk
		xor eax, eax
	error:
		movzx eax, ax
		}
	}

int VXDINLINE R0_ReadAbsoluteDisk(BYTE drive, UINT nsectors, DWORD sector, PBYTE buffer)
	{
	_asm
		{
		mov	al, drive
		mov ah, R0_READABSOLUTEDISK shr 8
		mov ecx, nsectors
		mov edx, sector
		mov esi, buffer
		}
	VxDCall(IFSMgr_Ring0_FileIO)
	_asm jc error
	_asm xor eax, eax
	_asm error:
	_asm movzx eax, ax
	}

int VXDINLINE R0_WriteAbsoluteDisk(BYTE drive, UINT nsectors, DWORD sector, const BYTE* buffer)
	{
	_asm
		{
		mov	al, drive
		mov ah, R0_WRITEABSOLUTEDISK shr 8
		mov ecx, nsectors
		mov edx, sector
		mov esi, buffer
		}
	VxDCall(IFSMgr_Ring0_FileIO)
	_asm jc error
	_asm xor eax, eax
	_asm error:
	_asm movzx eax, ax
	}

int VXDINLINE IFSMgr_Ring0GetDriveInfo(UINT drive)
	{
	_asm mov edx, drive
	VxDCall(IFSMgr_Ring0_FileIO)
	_asm
		{
		jnc	noerror
		mov eax, -1
	noerror:
		}
	}






int VXDINLINE TimeSliceSleep(UINT time)
	{
	_asm mov eax, time
	VxDCall(Time_Slice_Sleep)
	
	}

int VXDINLINE GetVMMReenterCount()
{
    int v;
	_asm pushad
	
	_asm xor ecx,ecx
	VxDCall(Get_VMM_Reenter_Count)
    _asm mov [v],ecx
    _asm popad

	return v;
  
}


int VXDINLINE ReleaseTimeSlice()
	{
	VxDCall(Release_Time_Slice)
	}


//%%%
//int RestrictedEvent(unsigned int Proc,unsigned int refdata)
//	{
//	_asm
//	{
//
//	mov     eax, 0; 
//	mov     ebx, 0 ;Handle
//	;;mov     ecx, PEF_ALWAYS_SCHED|PEF_RING0_EVENT; 
//	mov     ecx, PEF_ALWAYS_SCHED|PEF_WAIT_CRIT;
//	mov     edx, [refdata]
//	mov     esi, [Proc]
//	mov     edi, 0
//	VxDCall (Call_Restricted_Event)
//	}
//	return 0; 
//	}


ShellMessageNCB(int flags,char * message,char *caption)
	{
	int handle;
	handle=Get_Sys_VM_Handle();

	_asm
	{
	 pushad

	 mov ebx, [handle]             ; virtual machine handle
	 mov eax, [flags]              ; message box flags
	 mov ecx, [message]   ; address of message text
	 mov edi, [caption]   ; address of caption text
	 mov esi, 0  ; address of callback
	 mov edx, 0      ; reference data for callback
	}

	VxDCall (SHELL_SYSMODAL_Message);
	_asm cli
	_asm popad
	}

ShellWinMessage(int flags,char * message,char *caption)
	{

	int handle;
	handle=Get_Sys_VM_Handle();

	_asm
	{
	pushad

	mov ebx, [handle]             ; virtual machine handle
	mov eax, [flags]              ; message box flags
	mov ecx, [message]   ; address of message text
	mov edi, [caption]   ; address of caption text
	mov esi, 0  ; address of callback
	mov edx, 0      ; reference data for callback
	}

	VxDCall (SHELL_Message);
	_asm jnc noerror
	ShellMessageNCB(flags,message,caption);

	_asm noerror:

	_asm cli
	_asm popad
	}


APPY_HANDLE VXDINLINE
SHELL_CallAtAppyTime(APPY_CALLBACK pfnAppyCallBack, DWORD dwRefData, DWORD flAppy, ...)
	{
    _asm    push    flAppy[4]
    _asm    push    flAppy
    _asm    push    dwRefData
    _asm    push    pfnAppyCallBack
    Touch_Register(eax)
    Touch_Register(ecx)
    Touch_Register(edx)
    VxDCall(_SHELL_CallAtAppyTime);
    _asm    add esp, 4*4
	}


int VXDINLINE
SHELLexec(int exec)
	{
	_asm    push    exec
	Touch_Register(eax)
	Touch_Register(ecx)
	Touch_Register(edx)
	VxDCall(_SHELL_ShellExecute);
	_asm    add esp, 4
	}
	
int SHELLHookBroadcast(void* haddress,int ref)
	{		
	_asm push ref
	_asm push haddress
	VxDCall (_SHELL_HookSystemBroadcast)
	_asm add esp,8
	}

int VXDINLINE WaitShTime(unsigned int time)
	{
	unsigned int timelow;
	unsigned int time2=0;
	_asm pushad

	Touch_Register(eax)
	Touch_Register(edx)

	VxDCall(VTD_Get_Real_Time)

	_asm mov [timelow],eax
	while (time2<time)
	{
	Touch_Register(eax)
	Touch_Register(edx)
	VxDCall(VTD_Get_Real_Time)   
	_asm sub eax,[timelow]
	_asm mov [time2],eax

	}

	_asm popad

	}


int VXDINLINE AdjustThreadPriority(UINT pb,UINT th)
	{
	_asm mov eax, pb
	_asm mov edi,th
	VxDCall(Adjust_Thread_Exec_Priority)
	
	}


ppIFSFileHookFunc IFSMgr_InstallFileSystemApiHook(pIFSFileHookFunc fcn)
	{
	ppIFSFileHookFunc p;
	_asm push fcn 
	_asm mov eax,fcn	/*  not sure which! */
	VxDCall(IFSMgr_InstallFileSystemApiHook)
	_asm add esp,4	
	_asm mov [p],eax
	return p;
	}

int VXDINLINE NAKED IFSMgr_RemoveFileSystemApiHook(pIFSFileHookFunc fcn)
	{
	VxDJmp(IFSMgr_RemoveFileSystemApiHook)
	}

int VXDINLINE NAKED IFSMgr_CDROM_Attach(DWORD drive, struct _VRP** pvrp, int fDoMount)
	{
	VxDJmp(IFSMgr_CDROM_Attach)
	}

int VXDINLINE NAKED IFSMgr_CDROM_Detach(DWORD Drive, struct _VRP* vrp)
	{
	VxDJmp(IFSMgr_CDROM_Detach)
	}

int VXDINLINE NAKED IFSMgr_FSDUnmountCFSD(DWORD rh)
	{
	VxDJmp(IFSMgr_FSDUnmountCFSD)
	}

int VXDINLINE NAKED IFSMgr_MountChildVolume(struct _VRP* vrp, DWORD drive)
	{
	VxDJmp(IFSMgr_MountChildVolume)
	}

int VXDINLINE NAKED IFSMgr_UnmountChildVolume(struct _VRP* vrp, DWORD drive)
	{
	VxDJmp(IFSMgr_UnmountChildVolume)
	}

int VXDINLINE NAKED IFSMgr_SwapDrives(struct _VRP* vrp, DWORD drive1, DWORD drive2)
	{
	VxDJmp(IFSMgr_SwapDrives)
	}

int VXDINLINE NAKED IFSMgr_FSDGetCurrentDrive(pioreq pir)
	{
	VxDJmp(IFSMgr_FSDGetCurrentDrive)
	}

int VXDINLINE NAKED _GetMappedErr(UINT Function, UINT ExtErr)
	{
	VxDJmp(_GetMappedErr)
	}

int VXDINLINE NAKED IFSMgr_GetLockState(DWORD drive, PDWORD pLockType, PDWORD pLockFlags, PDWORD pLockOwner)
	{
	VxDJmp(IFSMgr_GetLockState)
	}

BOOL VXDINLINE Query_PhysLock(DWORD unit)
	{
	_asm mov eax, unit
	VxDCall(Query_PhysLock)
	_asm sbb eax, eax			; CF set if process doesn't own volume lock, so return is -1 if unowned, 0 if owned
	}

VOID VXDINLINE NAKED IFSMgr_printf(const char* pfstr, ...)
	{
	VxDJmp(IFSMgr_printf)
	}

#ifdef DEBUG
#define IFSASSERT(x) if (!(x)) IFSMgr_AssertFailed(#x, __FILE__, __LINE__)
VOID VXDINLINE NAKED IFSMgr_AssertFailed(const char* msg, const char* pfname, DWORD line)
	{
	VxDJmp(IFSMgr_AssertFailed)
	}
VOID VXDINLINE NAKED IFSMgr_LogEntry(const char* name, DWORD info1, DWORD info2, int sdepth, DWORD mask)
	{
	VxDJmp(IFSMgr_LogEntry)
	}
DWORD VXDINLINE NAKED IFSMgr_DebugMenu(PVOID pm)
	{
	VxDJmp(IFSMgr_DebugMenu)
	}
DWORD VXDINLINE NAKED IFSMgr_DebugVars()
	{
	VxDJmp(IFSMgr_DebugVars)
	}
int VXDINLINE NAKED IFSMgr_GetDebugString(const char* prompt, char* buffer, UINT length)
	{
	VxDJmp(IFSMgr_GetDebugString)
	}
int VXDINLINE NAKED IFSMgr_GetDebugHexNum(const char* prompt, PDWORD phexval)
	{
	VxDJmp(IFSMgr_GetDebugHexNum)
	}
DWORD VXDINLINE NAKED IFSMgr_DbgSetFileHandleLimit(DWORD MaxHandles)
	{
	VxDJmp(IFSMgr_DbgSetFileHandleLimit)
	}
#else
#define IFSASSERT(x)
#define IFSMgr_Assert_Failed(a1, a2, a3)
#define IFSMgr_LogEntry(a1, a2, a3, a4, a5)
#define IFSMgr_DebugMenu(a1) NULL
#define IFSMgr_DebugVars() NULL
#define IFSMgr_GetDebugString(a1, a2, a3) 0
#define IFSMgr_GetDebugHexNum(a1, a2) 0
#define IFSMgr_DbgSetFileHandleLimit(a1) a1
#endif

#endif /* Not_VxD */

