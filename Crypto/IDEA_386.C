/***********************************************************************
 * idea_386.c - intel i386 assembler code for IDEA block cipher        *
 *                                                                     *
 * IDEA(International Data Encryption Algorithm) is a secret-key block *
 * cipher algorithm which encrypt/decrypt 64-bit data size, using 128- *
 * bit key size. The patent of IDEA is held by Ascom Systec Ltd.       *
 *                                                                     *
 *                         This program is written by Masayasu Kumagai.*
 *                                  (E-Mail: kumagai@mxc.meshnet.or.jp)*
 ***********************************************************************/

#include "idea.h"

void
ideaCrypt( unsigned char const *input, unsigned char *output, word16 const *key )
{
	_asm {
//%%%%	PUSH		EBP
	PUSH		EAX
	PUSH		EBX
	PUSH		ECX
	PUSH		EDX
	PUSH		ESI
	PUSH		EDI
	MOV			ESI, input
#if 0
	MOV			AX, word ptr [ESI + 0]
	MOV			EBX, dword ptr [ESI + 2]
	ROL			EAX, 16
	MOV			AX, word ptr [ESI + 6]
#else
	mov			ax, word ptr [esi + 6]
	mov 		ebx, dword ptr [esi + 2]
	shl			eax, 16
	bswap		ebx
	mov			ax, word ptr [esi + 0]
	bswap		eax
	rol			ebx, 16
#endif
	MOV			DX, 8
	MOV			ESI, key
_LOOP:
	ROL			EDX, 16
	ADD			BX, word ptr [ESI + 2]
	ROL			EBX, 16
	ADD			BX, word ptr [ESI + 4]
	MOV			DI, AX
	MUL			word ptr [ESI + 6]
	SUB			AX, DX
	JZ			_PROD_0_1
	ADC			AX, 0
_RET_1:
	ROL			EAX, 16
	MOV			DI, AX
	MUL			word ptr [ESI + 0]
	SUB			AX, DX
	JZ			_PROD_0_2
	ADC			AX, 0
_RET_2:
	MOV			ECX, EAX
	XOR			EAX, EBX
	MOV			DI, AX
	MUL			word ptr [ESI + 8]
	SUB			AX, DX
	JZ			_PROD_0_3
	ADC			AX, 0
_RET_3:
	MOV			DX, AX
	ROL			EAX, 16
	ADD			AX, DX
	MOV			DI, AX
	MUL			word ptr [ESI + 10]
	SUB			AX, DX
	JZ			_PROD_0_4
	ADC			AX, 0
_RET_4:
	MOV			DX, AX
	ROL			EAX, 16
	ADD			AX, DX
	ROL			EAX, 16
	XOR			EBX, EAX
	XOR			EAX, ECX
	ROL			EAX, 16
	ADD			ESI, 12
	ROL			EDX, 16
	DEC			DX
	JNZ			_LOOP
	ADD			BX, word ptr [ESI + 4]
	ROL			EBX, 16
	ADD			BX, word ptr [ESI + 2]
	MOV			DI, AX
	MUL			word ptr [ESI + 6]
	SUB			AX, DX
	JZ			_PROD_0_5
	ADC			AX, 0
_RET_5:
	ROL			EAX, 16
	MOV			DI, AX
	MUL			word ptr [ESI + 0]
	SUB			AX, DX
	JZ			_PROD_0_6
	ADC			AX, 0
_RET_6:
	JMP			_SKIP
_PROD_0_1:
	INC			AX
	SUB			AX, word ptr [ESI + 6]
	SUB			AX, DI
	JMP			_RET_1
_PROD_0_2:
	INC			AX
	SUB			AX, word ptr [ESI + 0]
	SUB			AX, DI
	JMP			_RET_2
_PROD_0_3:
	INC			AX
	SUB			AX, word ptr [ESI + 8]
	SUB			AX, DI
	JMP			_RET_3
_PROD_0_4:
	INC			AX
	SUB			AX, word ptr [ESI + 10]
	SUB			AX, DI
	JMP			_RET_4
_PROD_0_5:
	INC			AX
	SUB			AX, word ptr [ESI + 6]
	SUB			AX, DI
	JMP			_RET_5
_PROD_0_6:
	INC			AX
	SUB			AX, word ptr [ESI + 0]
	SUB			AX, DI
	JMP			_RET_6
_SKIP:
	MOV			EDI, output
#if 0
	MOV			word ptr [EDI + 0], AX
	MOV			dword ptr [EDI + 2], EBX
	ROL			EAX, 16
	MOV			word ptr [EDI + 6], AX
#else
	bswap		eax
	bswap		ebx
	mov			word ptr [edi + 6 ], ax
	rol			ebx, 16
	shr			eax, 16
	mov			dword ptr [edi + 2], ebx
	mov			word ptr [edi + 0], ax
#endif
	POP			EDI
	POP			ESI
	POP			EDX
	POP			ECX
	POP			EBX
	POP			EAX
//%%%%%	POP			EBP
	}
}
