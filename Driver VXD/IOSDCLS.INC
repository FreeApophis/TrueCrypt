/* IOSDCLS.H -- C-language declarations for IOS drivers
   Copyright (C) 1995 by Walter Oney
   All rights reserved
   */

#define WANTVXDWRAPS
#include <basedef.h>
#include <vmm.h>
	
#include <aep.h>
#include <blockdev.h>
#include <config.h>
#include <dcb.h>
#include <ddb.h>
#include <drp.h>
#include <dvt.h>
#include <ida.h>
#include <ilb.h>
#include <ior.h>
#include <iop.h>
#include <irs.h>
#include <isp.h>
#include <ivt.h>
#include <sgd.h>
#include <vrp.h>

#undef _IRS_H      /* suppress extra IOS_Requestor_Service in VXDWRAPS */
#include <vxdwraps.h>

/* Some annoying inconsistencies in typedef spelling: */

typedef pIOP PIOP;
typedef pDDB PDDB;

/*
IOS.H is useless for C-language users, so do what it should have done:
*/

#define IOS_DEVICE_ID	0x0010

#define IOS_Service Declare_Service
#pragma warning(disable:4003)   /* not enough parameters */

Begin_Service_Table(IOS)

IOS_Service(IOS_Get_Version, LOCAL)
IOS_Service(IOS_BD_Register_Device)
IOS_Service(IOS_Find_Int13_Drive)
IOS_Service(IOS_Get_Device_List)
IOS_Service(IOS_SendCommand)
IOS_Service(IOS_BD_Command_Complete)
IOS_Service(IOS_Synchronous_Command)
IOS_Service(IOS_Register)
IOS_Service(IOS_Requestor_Service)
IOS_Service(IOS_Exclusive_Access)
IOS_Service(IOS_Send_Next_Command)
IOS_Service(IOS_Set_Async_Time_Out)
IOS_Service(IOS_Signal_Semaphore_No_Switch)
IOS_Service(IOSIdleStatus)
IOS_Service(IOSMapIORSToI24)
IOS_Service(IOSMapIORSToI21)

#ifdef INITLOG
IOS_Service(PrintLog)
#endif

End_Service_Table(IOS)

#pragma warning(default:4003)

#define IOSEA_LOCK_THREAD (1 << 8)

#ifndef Not_VxD
#pragma warning(disable:4035)   /* missing return value */
#define NAKED __declspec(naked)





VXDINLINE VOID IOS_SendCommand(PIOR ior, PDCB bdd)
{
	_asm mov esi, ior
	_asm mov edi, bdd
	VxDCall(IOS_SendCommand)
}

VXDINLINE VOID IOS_BD_Command_Complete(PIOR ior)
{
	_asm mov esi, ior
	VxDCall(IOS_BD_Command_Complete)
}



VXDINLINE VOID IOS_Register(PDRP drp)
{
	_asm push drp
	VxDCall(IOS_Register)
	_asm add esp,4
}



/*
 Interfaces to routines via IOS linkage block (ILB).
 THESE DEFINITIONS ASSUME YOU HAVE AN ILB NAMED "theILB"
 */

#ifndef FIELDOFFSET
	#define FIELDOFFSET(type, field) ((DWORD)(&((type *)0)->field))
#endif

extern ILB theILB;

VXDINLINE PIOP NAKED IlbDequeueIop(PDCB dcb)
{
	_asm jmp [theILB.ILB_dequeue_iop]
}

VXDINLINE VOID NAKED IlbDprintf(char *ctl, ...)
{
	_asm jmp [theILB.ILB_dprintf_rtn]
}

VXDINLINE VOID NAKED IlbEnqueueIop(PIOP iop, PDCB dcb)
{
	_asm jmp [theILB.ILB_enqueue_iop]
}

VXDINLINE DWORD NAKED IlbIntIoCriteria(PIOP iop)
{
	_asm jmp [theILB.ILB_int_io_criteria_rtn]
}

VXDINLINE VOID IlbInternalRequest(PIOP iop, PDCB dcb, PVOID calldown)
{
	_asm pushad   ;added
 	
	_asm mov edi, iop
	_asm mov ebx, dcb
	_asm mov edx, calldown
        /* (* (VOID (*)()) theILB.ILB_internal_request)(); */
    _asm call [theILB.ILB_internal_request]

    _asm popad   ;added
}

VXDINLINE DWORD NAKED IlbIoCriteria(PIOR ior)
{
	_asm jmp [theILB.ILB_io_criteria_rtn]
}

VXDINLINE DWORD NAKED IlbService(PVOID isp)     /* really has (PISP) arg */
{
	_asm jmp [theILB.ILB_service_rtn]
}

VXDINLINE VOID NAKED IlbWait10thSec()
{
	_asm jmp [theILB.ILB_Wait_10th_Sec]
}

/*
 IOS Service Request wrappers. These avoid the baroque nonsense of explicitly
 filling in the appropriate packet structure. TANSTAAFL, but at least it's
 less typing in the program!
 */

VXDINLINE PVOID IspAllocMem(USHORT size, USHORT type, UCHAR flags)
{
	ISP_mem_alloc isp = {{ISP_ALLOC_MEM, 0}, size, 0, type, flags};
	IlbService(&isp);
	if (isp.ISP_mem_a_hdr.ISP_result == 0)
		return (PVOID) isp.ISP_mem_ptr;
	return NULL;
}

VXDINLINE BOOL IspAssociateDcb(PDCB dcb, CHAR drive, UCHAR flags)
{
	ISP_dcb_associate isp = {{ISP_ASSOCIATE_DCB, 0}, (ULONG) dcb, drive, flags};
	IlbService(&isp);
	return isp.ISP_d_a_hdr.ISP_result == 0;
}

VXDINLINE BOOL IspBroadcastAep(PAEP aep)
{
	ISP_AEP_BROADCAST isp = {{ISP_BROADCAST_AEP, 0}, aep};
	IlbService(&isp);
	return isp.ISP_baep_hdr.ISP_result == 0;
}

VXDINLINE PDCB IspCreateDcb(USHORT size)
{
	ISP_dcb_create isp = {{ISP_CREATE_DCB, 0}, size};
	IlbService(&isp);
	if (isp.ISP_dcb_hdr.ISP_result == 0)
		return (PDCB) isp.ISP_dcb_ptr;
	return NULL;
}

VXDINLINE PDDB IspCreateDdb(USHORT size, UCHAR flags)
{
	ISP_ddb_create isp = {{ISP_CREATE_DDB, 0}, size, 0, flags};
	IlbService(&isp);
	if (isp.ISP_ddb_hdr.ISP_result == 0)
		return (PDDB) isp.ISP_ddb_ptr;
	return NULL;
}





VXDINLINE PIOP IspCreateIop(USHORT size, ULONG delta, UCHAR flags)
{
	ISP_IOP_alloc isp = {{ISP_CREATE_IOP, 0}, size, delta, 0, flags};
	IlbService(&isp);
	if ( (isp.ISP_i_c_hdr.ISP_result == 0) && (isp.ISP_IOP_ptr!=NULL))
                return (PIOP) (isp.ISP_IOP_ptr + delta - FIELDOFFSET(IOP, IOP_ior)); /* ptr is to memory block, NOT the IOP (?!) */
	return NULL;
}





VXDINLINE PIOR IspCreateIor(USHORT size, ULONG delta, UCHAR flags)
{
	ISP_IOP_alloc isp = {{ISP_CREATE_IOP, 0}, size, delta, 0, flags};
	IlbService(&isp);
	if (isp.ISP_i_c_hdr.ISP_result == 0)
                return (PIOR) (isp.ISP_IOP_ptr + delta); /* ptr is to memory block, NOT the IOP (?!) */
	return NULL;
}

VXDINLINE BOOL IspDeallocDdb(PDDB ddb)
{
	ISP_DDB_DEALLOC isp = {{ISP_DEALLOC_DDB, 0}, (ULONG) ddb, theILB.ILB_dvt};
	IlbService(&isp);
	return isp.ISP_ddb_d_hdr.ISP_result == 0;
}

VXDINLINE BOOL IspDeallocMem(PVOID p)
{
	ISP_mem_dealloc isp = {{ISP_DEALLOC_MEM, 0}, (ULONG) p};
	IlbService(&isp);
	return isp.ISP_mem_da_hdr.ISP_result == 0;
}

VXDINLINE BOOL IspDeleteLdmEntry(ULONG drive)
{
	ISP_FIND_LDM isp = {{ISP_DELETE_LDM_ENTRY, 0}, drive};
	IlbService(&isp);
	return isp.ISP_fldm_hdr.ISP_result == 0;
}

VXDINLINE BOOL IspDestroyDcb(PDCB dcb)
{
	ISP_DCB_DESTROY isp = {{ISP_DESTROY_DCB, 0}, (ULONG) dcb};
	IlbService(&isp);
        return isp.ISP_ddb_d_hdr.ISP_result == 0; /* not a typo! it's really spelled "ddb_d_hdr" instead of "dcb_d_hdr" */
}

VXDINLINE BOOL IspDeviceArrived(PDCB dcb, ULONG flags)
{
	ISP_DEV_ARRIVED isp = {{ISP_DEVICE_ARRIVED, 0}, dcb, flags};
	IlbService(&isp);
	return isp.ISP_d_arrived_hdr.ISP_result == 0;
}

VXDINLINE BOOL IspDeviceRemoved(PDCB dcb, ULONG flags)
{
	ISP_DEV_REMOVED isp = {{ISP_DEVICE_REMOVED, 0}, dcb, flags};
	IlbService(&isp);
	return isp.ISP_d_removed_hdr.ISP_result == 0;
}

VXDINLINE BOOL IspDisassociateDcb(ULONG drive)
{
        /*    {{function     result}  ULONG}   */
        ISP_DISASSOC_DCB isp = {{ISP_DISASSOCIATE_DCB, 0}, drive};
	IlbService(&isp);
	return isp.ISP_dis_dcb_hdr.ISP_result == 0;
}

VXDINLINE UCHAR IspDriveLetterPick(PDCB dcb, UCHAR flags)
{
	ISP_pick_drive_letter isp = {{ISP_DRIVE_LETTER_PICK, 0}, dcb, {0, 0}, flags};
	IlbService(&isp);
	if (isp.ISP_p_d_l_hdr.ISP_result == 0)
		return isp.ISP_p_d_l_letter[0];
	return 0;
}

VXDINLINE UCHAR IspDriveLetterPickPref(PDCB dcb, UCHAR flags,UCHAR preffered)
{
	
	ISP_pick_drive_letter isp = {{ISP_DRIVE_LETTER_PICK, 0}, dcb, {0, 0}, flags};
        isp.ISP_p_d_l_letter[0]=preffered; /* +'A'; */
        isp.ISP_p_d_l_letter[1]=preffered+1; /* 'A'; */
	IlbService(&isp);
	if (isp.ISP_p_d_l_hdr.ISP_result == 0)
		return isp.ISP_p_d_l_letter[0];
	return 255;
}




VXDINLINE PVOID IspFindLdmEntry(ULONG drive)
{
	ISP_FIND_LDM isp = {{ISP_DELETE_LDM_ENTRY, 0}, drive};
	if (isp.ISP_fldm_hdr.ISP_result == 0)
		return isp.ISP_fldm_pldm;
	return NULL;
}

VXDINLINE PDCB IspGetDcb(ULONG drive)
{
	ISP_dcb_get isp = {{ISP_GET_DCB, 0}, 0, drive};
	IlbService(&isp);
	if (isp.ISP_g_d_hdr.ISP_result == 0)
		return (PDCB) isp.ISP_g_d_dcb;
	return NULL;
}

VXDINLINE PDCB IspGetFirstNextDcb(PDCB dcb, BYTE type)
{
	ISP_GET_FRST_NXT_DCB isp = {{ISP_GET_FIRST_NEXT_DCB, 0}, (ULONG) dcb, 0, type};
	IlbService(&isp);
	if (isp.ISP_gfnd_hdr.ISP_result == 0)
		return (PDCB) isp.ISP_gfnd_found_dcb;
	return NULL;
}

VXDINLINE BOOL IspInsertCalldown(PDCB dcb, VOID (*calldown)(PIOP), PDDB ddb, USHORT expand, DWORD demand, UCHAR loadgroup)
{
	ISP_calldown_insert isp = {{ISP_INSERT_CALLDOWN, 0}, (ULONG) dcb, (PVOID) calldown, (ULONG) ddb, expand, demand, loadgroup};
	IlbService(&isp);
	return isp.ISP_i_cd_hdr.ISP_result == 0;
}

VXDINLINE ULONG IspQueryMatchingDcbs(PDCB dcb)
{
	ISP_QUERY_MATCH isp = {{ISP_QUERY_MATCHING_DCBS, 0}, dcb};
	IlbService(&isp);
	if (isp.ISP_q_match_hdr.ISP_result == 0)
		return isp.ISP_q_match_drives;
	return 0;
}

VXDINLINE BOOL IspRegistryRead(PDCB dcb, char* keyname, PDWORD ptype, PDWORD psize, PVOID buffer)
{
	ISP_read_registry isp = {{ISP_REGISTRY_READ, 0}, dcb, keyname, ptype, psize, buffer};
	IlbService(&isp);
	return isp.ISP_r_r_hdr.ISP_result == 0;
}

VXDINLINE BOOL IspQueryRemoveDcb(PDCB dcb, ULONG flags)
{
	ISP_QUERY_REMOVE isp = {{ISP_QUERY_REMOVE_DCB, 0}, dcb, flags};
	IlbService(&isp);
	return isp.ISP_q_remove_hdr.ISP_result == 0;
}



VXDINLINE BOOL SaveClientState(CLIENT_STRUCT * s)
{


	_asm push edi
	_asm mov edi,[s]

	VxDCall (Save_Client_State)

	_asm pop edi

	return FALSE;
}



VXDINLINE BOOL RestoreClientState(CLIENT_STRUCT * s)
{


	_asm push esi
	_asm mov esi,[s]

	VxDCall (Restore_Client_State)

	_asm pop esi

	return FALSE;
}


#pragma warning(default:4035)
#endif /* Not_VxD */

