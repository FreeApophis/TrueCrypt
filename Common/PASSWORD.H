/*
 Legal Notice: The source code contained in this file has been derived from
 the source code of Encryption for the Masses 2.02a, which is Copyright (c)
 Paul Le Roux and which is covered by the 'License Agreement for Encryption
 for the Masses'. Modifications and additions to that source code contained
 in this file are Copyright (c) TrueCrypt Foundation and are covered by the
 TrueCrypt License 2.3 the full text of which is contained in the file
 License.txt included in TrueCrypt binary and source code distribution
 packages. */

#ifndef PASSWORD_H
#define PASSWORD_H 1

// User text input limits
#define MIN_PASSWORD			1		// Minimum password length
#define MAX_PASSWORD			64		// Maximum password length

#define PASSWORD_LEN_WARNING	12		// Display a warning when a password is shorter than this

#ifdef __cplusplus
extern "C" {
#endif

typedef struct
{
	int Length;
	unsigned char Text[MAX_PASSWORD + 1];
} Password;

#if defined(_WIN32) && !defined(NT4_DRIVER)

void VerifyPasswordAndUpdate ( HWND hwndDlg , HWND hButton , HWND hPassword , HWND hVerify , char *szPassword , char *szVerify, BOOL keyFilesEnabled );
BOOL CheckPasswordLength (HWND hwndDlg, HWND hwndItem);		
BOOL CheckPasswordCharEncoding (HWND hPassword, Password *ptrPw);			
int ChangePwd (char *lpszVolume, Password *oldPassword, Password *newPassword, int pkcs5, HWND hwndDlg);

#endif

#ifdef __cplusplus
}
#endif

#endif
