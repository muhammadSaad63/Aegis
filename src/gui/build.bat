@echo off
rem run this from a Visual Studio "x86 Native Tools Command Prompt" (needs ml.exe, rc.exe & link.exe)
ml /nologo /c /coff gui.asm
if errorlevel 1 goto done
rc /nologo gui.rc
if errorlevel 1 goto done
link /nologo /subsystem:windows /entry:main gui.obj gui.res
:done
