/* The source code contained in this file has been derived from the source code
   of Encryption for the Masses 2.02a by Paul Le Roux. Modifications and
   additions to that source code contained in this file are Copyright (c) 2004
   TrueCrypt Team and Copyright (c) 2004 TrueCrypt Foundation. Unmodified
   parts are Copyright (c) 1998-99 Paul Le Roux. This is a TrueCrypt Foundation
   release. Please see the file license.txt for full license details. */

/* Everything below this line is automatically updated by the -mkproto-tool- */

BOOL UnmountAllVolumes ( HWND hwndDlg , DWORD *os_error , int *err );
BOOL UnmountVolume ( int nDosDriveNo , DWORD *os_error , int *err );
BOOL DismountVolume ( char *lpszVolMountName , DWORD *os_error , int *err );
BOOL DoDeviceClose ( int slot , int *err );
int ioctllock ( unsigned int nDrive , int permissions , int function );
int locklogdrive ( int drivenum , int mode );
int ld ( char *d , int mode );
BOOL CloseSlot ( int slot , int brutal , int *err );
int EjectStop ( char Driveletter , BOOL function );
