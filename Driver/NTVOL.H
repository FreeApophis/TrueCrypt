/* Legal Notice: The source code contained in this file has been derived from
   the source code of Encryption for the Masses 2.02a, which is Copyright (c)
   1998-99 Paul Le Roux and which is covered by the 'License Agreement for
   Encryption for the Masses'. Modifications and additions to that source code
   contained in this file are Copyright (c) 2004-2006 TrueCrypt Foundation and
   Copyright (c) 2004 TrueCrypt Team, and are covered by TrueCrypt License 2.1
   the full text of which is contained in the file License.txt included in
   TrueCrypt binary and source code distribution archives.  */

NTSTATUS TCOpenVolume ( PDEVICE_OBJECT DeviceObject , PEXTENSION Extension , MOUNT_STRUCT *mount , PWSTR pwszMountVolume , BOOL bRawDevice );
void TCCloseVolume ( PDEVICE_OBJECT DeviceObject , PEXTENSION Extension );
NTSTATUS TCCompletion ( PDEVICE_OBJECT DeviceObject , PIRP Irp , PVOID pUserBuffer );
NTSTATUS TCReadWrite ( PDEVICE_OBJECT DeviceObject , PEXTENSION Extension , PIRP Irp );
NTSTATUS TCSendDeviceIoControlRequest ( PDEVICE_OBJECT DeviceObject , PEXTENSION Extension , ULONG IoControlCode , char *OutputBuffer , int OutputBufferSize );
NTSTATUS COMPLETE_IRP ( PDEVICE_OBJECT DeviceObject , PIRP Irp , NTSTATUS IrpStatus , ULONG_PTR IrpInformation );
static void RestoreTimeStamp ( PEXTENSION Extension );