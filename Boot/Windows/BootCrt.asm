;
; Copyright (c) 2008 TrueCrypt Foundation. All rights reserved.
;
; Governed by the TrueCrypt License 2.4 the full text of which is contained
; in the file License.txt included in TrueCrypt binary and source code
; distribution packages.
;

.MODEL tiny, C
.386

INCLUDE BootDefs.i

EXTERNDEF main:NEAR

_TEXT SEGMENT
ORG TC_BOOT_LOADER_OFFSET

start:
	call main
	jmp $

_TEXT ENDS
END start
