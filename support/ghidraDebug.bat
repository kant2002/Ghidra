:: Ghidra debug launch

@echo off
setlocal

:: Maximum heap memory size
:: Default for Windows 32-bit is 768M and 64-bit is 1024M
:: Raising the value too high may cause a silent failure where
:: Ghidra fails to launch.
:: Uncomment MAXMEM setting if non-default value is needed

::set MAXMEM=768M

:: debug launch mode can be changed to one of the following:
::    debug, debug-suspend
set LAUNCH_MODE=debug

:: set debug port
set DEBUG_PORT=18001

:: DEBUG_PORT set via environment for launch.bat

call "%~dp0launch.bat" %LAUNCH_MODE% Ghidra "%MAXMEM%" "" ghidra.GhidraRun %*
