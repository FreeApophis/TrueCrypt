pause
cd common
del *.aps *.tmp

cd ..\crypto
del *.tmp
rd /s /q release debug

cd ..\driver
del *.aps *.tmp
rd /s /q release release64 debug debug64

cd ..\format
del *.aps *.tmp
rd /s /q release debug

cd ..\mount
del *.aps *.tmp
rd /s /q release debug

cd ..\setup
del *.aps *.tmp
rd /s /q release debug

cd ..\release
del *.exe *.sys
cd ..\release\setup files
del *.exe *.sys

cd ..\..
del *.ncb *.suo
del /A:H *.ncb *.suo
pause