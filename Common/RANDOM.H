/* Copyright (C) 2004 TrueCrypt Team, truecrypt.org
   This product uses components written by Paul Le Roux <pleroux@swprofessionals.com> */

/* Everything below this line is automatically updated by the -mkproto-tool- */

_inline void _RandaddLong ( unsigned long x );
int Randinit ( void );
void Randfree ( void );
void Randmix ( void );
void RandaddBuf ( void *buf , int len );
void RandpeekBytes ( char *buf , int len );
void RandgetBytes ( char *buf , int len );
LRESULT CALLBACK MouseProc ( int nCode , WPARAM wParam , LPARAM lParam );
LRESULT CALLBACK KeyboardProc ( int nCode , WPARAM wParam , LPARAM lParam );
void ThreadSafeThreadFunction ( void *dummy );
void SlowPollWinNT ( void );
void SlowPollWin9x ( void );
void FastPoll ( void );
