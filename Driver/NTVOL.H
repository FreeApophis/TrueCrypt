/* Copyright (C) 2004 TrueCrypt Foundation
   This product uses components written by Paul Le Roux <pleroux@swprofessionals.com> */

/* Everything below this line is automatically updated by the -mkproto-tool- */

NTSTATUS TCOpenVolume ( PDEVICE_OBJECT DeviceObject , PEXTENSION Extension , MOUNT_STRUCT *mount , PWSTR pwszMountVolume , BOOL bRawDevice );
void TCCloseVolume ( PDEVICE_OBJECT DeviceObject , PEXTENSION Extension );
NTSTATUS TCCompletion ( PDEVICE_OBJECT DeviceObject , PIRP Irp , PVOID pUserBuffer );
NTSTATUS TCReadWrite ( PDEVICE_OBJECT DeviceObject , PEXTENSION Extension , PIRP Irp );
NTSTATUS TCSendDeviceIoControlRequest ( PDEVICE_OBJECT DeviceObject , PEXTENSION Extension , ULONG IoControlCode , char *OutputBuffer , int OutputBufferSize );
NTSTATUS COMPLETE_IRP ( PDEVICE_OBJECT DeviceObject , PIRP Irp , NTSTATUS IrpStatus , ULONG IrpInformation );
