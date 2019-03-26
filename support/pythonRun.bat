:: Ghidra python launch

@echo off

setlocal EnableDelayedExpansion

:: Maximum heap memory size
:: Default for Windows 32-bit is 768M and 64-bit is 1024M
:: Raising the value too high may cause a silent failure where
:: Ghidra fails to launch.
:: Uncomment MAXMEM setting if non-default value is needed
::set MAXMEM=768M

:: launch mode can be changed to one of the following:
::    fg, debug, debug-suspend
set LAUNCH_MODE=fg

:: set debug port for debug mode if used
set DEBUG_PORT=13002

:: Limit the # of garbage collection and JIT compiler threads in case many headless
:: instances are run in parallel.  By default, Java will assign one thread per core
:: which does not scale well on servers with many cores.
set VMARG_LIST=-XX:ParallelGCThreads=2
set VMARG_LIST=%VMARG_LIST% -XX:CICompilerCount=2

:: store current path
set filepath=%~dp0

call "%filepath%launch.bat" %LAUNCH_MODE% Ghidra-Python "%MAXMEM%" "%VMARG_LIST%" ghidra.python.PythonRun %params%
