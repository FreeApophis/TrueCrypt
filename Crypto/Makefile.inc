
!if "$(TC_ARCH)" == "x86"
TC_OBJ_FORMAT = win32
!else
TC_OBJ_FORMAT = win64
!endif

"$(OBJ_PATH)\$(O)\Aes_$(TC_ARCH).obj": Aes_$(TC_ARCH).asm
	yasm.exe -Xvc -f $(TC_OBJ_FORMAT) -D DLL_EXPORT -o "$@" Aes_$(TC_ARCH).asm
