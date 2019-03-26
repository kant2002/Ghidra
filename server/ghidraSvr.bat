@echo off
setlocal enabledelayedexpansion

rem Find the script directory
rem %~dsp0 is location of current script under NT
set _REALPATH=%~dp0

set APP_NAME=ghidraSvr
set APP_LONG_NAME=Ghidra Server

set MODULE_DIR=Ghidra\Features\GhidraServer

set WRAPPER_NAME=yajsw-stable-12.12

if exist "%_REALPATH%..\Ghidra\" goto normal

rem NOTE: If adjusting JAVA command assignment - do not attempt to add parameters (e.g., -d64, -version:1.7, etc.)

rem Development Environment
set GHIDRA_HOME=%_REALPATH%..\..\..\..
set WRAPPER_CONF=%_REALPATH%..\..\Common\server\server.conf
set WRAPPER_HOME=%GHIDRA_HOME%\%MODULE_DIR%\build\data\%WRAPPER_NAME%
set CLASSPATH_FRAG=%GHIDRA_HOME%\%MODULE_DIR%\build\dev-meta\classpath.frag
set LS_CPATH=%GHIDRA_HOME%\GhidraBuild\LaunchSupport\bin

goto :lab1

:normal
set GHIDRA_HOME=%_REALPATH%..
set WRAPPER_CONF=%_REALPATH%server.conf
set WRAPPER_HOME=%GHIDRA_HOME%\%MODULE_DIR%\data\%WRAPPER_NAME%
set CLASSPATH_FRAG=%GHIDRA_HOME%\%MODULE_DIR%\data\classpath.frag
set LS_CPATH=%GHIDRA_HOME%\support\LaunchSupport.jar

:lab1

if not exist "%WRAPPER_HOME%\" (
	set ERROR_MSG=%WRAPPER_HOME% not found
	echo !ERROR_MSG!
	echo !ERROR_MSG! >> %GHIDRA_HOME%\wrapper.log
	exit /B 1
)

:: Make sure some kind of java is on the path.  It's required to run the LaunchSupport program.
java -version >nul 2>nul
if not %ERRORLEVEL% == 0 (
	set ERROR_MSG=Java runtime not found.  Please refer to the Ghidra Installation Guide's Troubleshooting section.
	echo !ERROR_MSG!
	echo !ERROR_MSG! >> %GHIDRA_HOME%\wrapper.log
	exit /B 1
)

:: Get the java that will be used to launch GhidraServer
set JAVA_HOME=
for /f "delims=*" %%i in ('java -cp "%LS_CPATH%" LaunchSupport "%GHIDRA_HOME%" -java_home') do set JAVA_HOME=%%i
if "%JAVA_HOME%" == "" (
	set ERROR_MSG=Failed to find a supported Java runtime.  Please refer to the Ghidra Installation Guide's Troubleshooting section.
	echo !ERROR_MSG!
	echo !ERROR_MSG! >> %GHIDRA_HOME%\wrapper.log
	exit /B 1
)
set JAVA=%JAVA_HOME%\bin\java.exe

set OS_NAME=win32
"%JAVA%" -version 2>&1 | findstr /I " 64-Bit " >NUL
if errorlevel 0 (
	set OS_NAME=win64
)

set OS_DIR=%GHIDRA_HOME%\%MODULE_DIR%\os\%OS_NAME%

set IS_ADMIN=NO
whoami /groups | findstr "S-1-16-12288 " >NUL
if errorlevel 0 (
	set IS_ADMIN=YES
)

set OPTION=%1
if "%OPTION%"=="" (
	set OPTION=console
)

:: set DEBUG=-Xdebug -Xnoagent -Djava.compiler=NONE -Xrunjdwp:transport=dt_socket,server=y,suspend=y,address=*:18888

if "%OPTION%"=="console" (
	start "%APP_LONG_NAME%" "%JAVA%" %DEBUG% -jar "%WRAPPER_HOME%/wrapper.jar" -c "%WRAPPER_CONF%"
	echo Use Ctrl-C in Ghidra Console to terminate...
	
) else if "%OPTION%"=="status" (
	"%JAVA%" -jar "%WRAPPER_HOME%/wrapper.jar" -q "%WRAPPER_CONF%"

) else if "%OPTION%"=="start" (
	if "%IS_ADMIN%"=="NO" goto :adminFail
	"%JAVA%" %DEBUG% -jar "%WRAPPER_HOME%/wrapper.jar" -t "%WRAPPER_CONF%"

) else if "%OPTION%"=="stop" (
	if "%IS_ADMIN%"=="NO" goto :adminFail
	"%JAVA%" -jar "%WRAPPER_HOME%/wrapper.jar" -p "%WRAPPER_CONF%"

) else if "%OPTION%"=="restart" (
	if "%IS_ADMIN%"=="NO" goto :adminFail
	"%JAVA%" -jar "%WRAPPER_HOME%/wrapper.jar" -p "%WRAPPER_CONF%"
	"%JAVA%" -jar "%WRAPPER_HOME%/wrapper.jar" -t "%WRAPPER_CONF%"

) else if "%OPTION%"=="install" (
	if "%IS_ADMIN%"=="NO" goto :adminFail
	"%JAVA%" -jar "%WRAPPER_HOME%/wrapper.jar" -i "%WRAPPER_CONF%"
	"%JAVA%" -jar "%WRAPPER_HOME%/wrapper.jar" -t "%WRAPPER_CONF%"
	
) else if "%OPTION%"=="uninstall" (
	if "%IS_ADMIN%"=="NO" goto :adminFail
	"%JAVA%" -jar "%WRAPPER_HOME%/wrapper.jar" -r "%WRAPPER_CONF%"

) else (
	echo Usage: %0 { console ^| start ^| stop ^| restart ^| status }
	echo.
)

goto :eof

:adminFail
echo Command option "%OPTION%" must be run as an Administrator (using Administrator CMD shell - see svrREADME.txt)
echo.

:eof
