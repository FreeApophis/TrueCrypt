/* Copyright (C) 2004 TrueCrypt Foundation
   This product uses components written by Paul Le Roux <pleroux@swprofessionals.com> */

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
