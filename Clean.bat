pause
cd common
del *.aps *.tmp

cd ..\crypto
del *.tmp
rd /s /q release debug

cd ..\driver
del *.aps *.tmp
rd /s /q release debug

cd "..\driver vxd"
del *.aps *.tmp
rd /s /q release debug

cd ..\format
del *.aps *.tmp
rd /s /q release debug

cd ..\mount
del *.aps *.tmp
rd /s /q release debug

cd ..\service
del *.aps *.tmp
rd /s /q release debug

cd ..\setup
del *.aps *.tmp
rd /s /q release debug

cd ..\release
del *.exe *.sys *.vxd
cd ..\release\setup files
del *.exe *.sys *.vxd

cd ..\..
del *.ncb *.suo
del /A:H *.ncb *.suo
pause