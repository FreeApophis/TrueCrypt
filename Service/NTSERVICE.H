/* The source code contained in this file has been derived from the source code
   of Encryption for the Masses 2.02a by Paul Le Roux. Modifications and
   additions to that source code contained in this file are Copyright (c) 2004
   TrueCrypt Team and Copyright (c) 2004 TrueCrypt Foundation. Unmodified
   parts are Copyright (c) 1998-99 Paul Le Roux. This is a TrueCrypt Foundation
   release. Please see the file license.txt for full license details. */

#define SZSERVICENAME        "TrueCryptService"
#define SZSERVICEDISPLAYNAME "TrueCrypt Service"
#define SZDEPENDENCIES       ""

/* Everything below this line is automatically updated by the -mkproto-tool- */

void WINAPI service_main ( DWORD dwArgc , LPSTR *lpszArgv );
void WINAPI service_ctrl ( DWORD dwCtrlCode );
BOOL ReportStatusToSCMgr ( DWORD dwCurrentState , DWORD dwWin32ExitCode , DWORD dwWaitHint );
void AddToMessageLog ( LPSTR lpszMsg );
LPSTR GetLastErrorText ( LPSTR lpszBuf , DWORD dwSize );
void ServiceStart ( DWORD dwArgc , LPTSTR *lpszArgv );
void ServiceStop ( void );
void handleWin32Error ( HWND dummy );
