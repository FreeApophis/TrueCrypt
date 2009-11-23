
!if "$(TC_ARCH)" == "x86"
TC_OBJ_FORMAT = win32
!else
TC_OBJ_FORMAT = win64
!endif

"$(OBJ_PATH)\$(O)\Aes_$(TC_ARCH).obj": Aes_$(TC_ARCH).asm
	nasm.exe -Xvc -f $(TC_OBJ_FORMAT) -Ox -D DLL_EXPORT -o "$@" -l "$(OBJ_PATH)\$(O)\Aes_$(TC_ARCH).lst" Aes_$(TC_ARCH).asm