/* Copyright (C) 2004 TrueCrypt Foundation
   This product uses components written by Paul Le Roux <pleroux@swprofessionals.com> */

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
