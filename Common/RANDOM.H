/* The source code contained in this file has been derived from the source code
   of Encryption for the Masses 2.02a by Paul Le Roux. Modifications and
   additions to that source code contained in this file are Copyright (c) 2004-2005
   TrueCrypt Foundation and Copyright (c) 2004 TrueCrypt Team. Unmodified
   parts are Copyright (c) 1998-99 Paul Le Roux. This is a TrueCrypt Foundation
   release. Please see the file license.txt for full license details. */

/* Everything below this line is automatically updated by the -mkproto-tool- */

_inline void _RandaddLong ( unsigned long x );
int Randinit ( void );
void Randfree ( void );
void RandSetHashFunction ( int hash );
void Randmix ( void );
void RandaddBuf ( void *buf , int len );
void RandpeekBytes ( unsigned char *buf , int len );
void RandgetBytes ( unsigned char *buf , int len, BOOL forceSlowPoll );
LRESULT CALLBACK MouseProc ( int nCode , WPARAM wParam , LPARAM lParam );
LRESULT CALLBACK KeyboardProc ( int nCode , WPARAM wParam , LPARAM lParam );
void ThreadSafeThreadFunction ( void *dummy );
void SlowPollWinNT ( void );
void SlowPollWin9x ( void );
void FastPoll ( void );
