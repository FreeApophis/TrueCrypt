;
; Copyright (c) 2008 TrueCrypt Foundation. All rights reserved.
;
; Governed by the TrueCrypt License 2.4 the full text of which is contained
; in the file License.txt included in TrueCrypt binary and source code
; distribution packages.
;

.MODEL tiny
.386
_TEXT SEGMENT

INCLUDE BootDefs.i

ORG 7C00h ; Boot sector offset

start:
	; BIOS executes boot sector from 0:7C00 or 7C0:0000 (default CD boot loader address).
	; Far jump to the next instruction ensures the offset matches the ORG directive.
	db 0EAh				; jmp 0:main
	dw main, 0

	db 'TrueCrypt'
	
main:	
	xor ax, ax
	mov ds, ax
	
	lea si, intro_msg
	call print
	
	mov ax, TC_BOOT_LOADER_SEGMENT
	mov es, ax ; Default load segment

	; Check available memory
	cmp word ptr [ds:413h], TC_BOOT_LOADER_SEGMENT / 1024 * 16 + TC_BOOT_MEMORY_REQUIRED
	jge clear_memory
	
	; Insufficient memory
	mov ax, TC_BOOT_LOADER_LOWMEM_SEGMENT
	mov es, ax

	; Ensure clear BSS section
clear_memory:
	xor al, al
	mov di, TC_BOOT_LOADER_OFFSET
	mov cx, TC_BOOT_MEMORY_REQUIRED * 1024 - 1
	cld
	rep stosb
	
	; Read boot loader
	mov bx, TC_BOOT_LOADER_OFFSET
	mov ch, 0           ; Cylinder
	mov dh, 0           ; Head
	mov cl, 2           ; Sector
	mov al, TC_BOOT_LOADER_AREA_SECTOR_COUNT - 2
						; DL = drive number passed from BIOS
	mov ah, 2
	int 13h
	jnc exec_loader
	
	lea si, read_error_msg
	call print
	jmp $
	
	; Execute boot loader
exec_loader:

	; DH = boot sector flags
	mov dh, byte ptr [start + TC_BOOT_SECTOR_CONFIG_OFFSET]
	
	mov ax, es
	mov ds, ax
	cli
	mov ss, ax
	mov sp, TC_BOOT_MEMORY_REQUIRED * 1024 - 4
	sti
	
	mov word ptr [cs:jump_seg], es
	
	db 0EAh				 ; jmp TC_BOOT_LOADER_SEGMENT:TC_BOOT_LOADER_OFFSET
	dw TC_BOOT_LOADER_OFFSET
jump_seg:
	dw TC_BOOT_LOADER_SEGMENT

	; Print string
print:
	xor bx, bx
	mov ah, 0eh
	
@@:	lodsb
	test al, al
	jz print_end
	
	int 10h
	jmp @B

print_end:
	ret
	
intro_msg db 13, 10, "TrueCrypt Boot Loader", 13, 10, 0
read_error_msg db "Disk read error", 13, 10, 7, 0

	db 508 - ($ - start) dup (0)
	dw 0, 0AA55h		; Boot sector signature

_TEXT ENDS
END start
