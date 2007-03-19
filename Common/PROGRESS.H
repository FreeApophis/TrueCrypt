/*
 Legal Notice: The source code contained in this file has been derived from
 the source code of Encryption for the Masses 2.02a, which is Copyright (c)
 Paul Le Roux and which is covered by the 'License Agreement for Encryption
 for the Masses'. Modifications and additions to that source code contained
 in this file are Copyright (c) TrueCrypt Foundation and are covered by the
 TrueCrypt License 2.2 the full text of which is contained in the file
 License.txt included in TrueCrypt binary and source code distribution
 packages. */

#ifdef __cplusplus
extern "C" {
#endif

void InitProgressBar ( __int64 totalSecs );
BOOL UpdateProgressBar ( __int64 nSecNo );
BOOL UpdateProgressBarProc (__int64 nSecNo);

#ifdef __cplusplus
}
#endif
