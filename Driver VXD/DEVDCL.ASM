;    DEVDCL.ASM -- Device declaration and control proc for IOS VxDs
;    Copyright (C) 1995 by Walter Oney
;    All rights reserved


	 .386p
	 include vmm.inc
	 include drp.inc
	 include ilb.inc

	 extrn _OnAsyncRequest:near

         VxD_IDATA_SEG
	 public _theDRP

_theDRP  DRP   <EyeCatcher,DRP_MISC_PD OR DRP_VSD_3 , offset32 _OnAsyncRequest, \
               offset32 _theILB, 'TRUCRYPT VSD', 0, DRP_FC_HALF_SEC , 0>


VxD_IDATA_ENDS

VxD_LOCKED_DATA_SEG
	 public _theILB
_theILB  ILB   <>			       ; I/O subsystem linkage block
VxD_LOCKED_DATA_ENDS

Declare_Virtual_Device TRUCRYPT, 1, 0, TRUCRYPT_control,\
		       Undefined_Device_ID, Undefined_Init_Order,,,_theDRP

Begin_Control_Dispatch TRUCRYPT
Control_Dispatch Sys_Dynamic_Device_Init, _OnSysDynamicDeviceInit, cCall
Control_Dispatch Sys_Dynamic_Device_Exit, _OnSysDynamicDeviceExit, cCall
Control_Dispatch W32_DeviceIoControl,	  _OnDeviceIoControl, cCall, <esi>,PRESERVE_FLAGS,
End_Control_Dispatch   TRUCRYPT



	 end

