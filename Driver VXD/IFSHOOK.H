/* Copyright (C) 2004 TrueCrypt Team, truecrypt.org
   This product uses components written by Paul Le Roux <pleroux@swprofessionals.com> */

/* Everything below this line is automatically updated by the -mkproto-tool- */

int HookProc ( pIFSFunc fsdproc , int fcn , int drive , int flags , int cp , pioreq pir );
int BroadcastMon ( int msg , int wparam , int lparam , int ref );
void installhook ( void );
void InstallTCThread ( void );
void wakethread ( void );
void killthread ( void );
void TCRing0Thread ( void );
