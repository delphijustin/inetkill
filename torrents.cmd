@echo off
if "%1"=="" goto help
if "%2"=="" goto help
echo [%date% - %time%] - Scanning...
set oldstatus=null
set oldstatus=%errorlevel%
:loop
call detect-torrent.cmd
set newstatus=%errorlevel%
if not "%newstatus%"=="%oldstatus%" goto change%newstatus%
:update
set oldstatus=%newstatus%
goto loop
:change0
echo [%date% - %time%] No clients were found running
rundll32.exe inetkill.dll,%1Gateway
goto update
:change1
echo [%date% - %time%] First client has started
rundll32.exe inetkill.dll,%2Gateway
goto update
:help
echo Usage: %0 [not_found_action] [found_action]
echo Actions:
echo kill	Enables the internet kill switch
echo restore	Disables the internet kill switch
echo toggle	Toggles the internet kill switch
echo NULL	Does nothing
echo.
echo ACTIONS ARE CASE-SENSITIVE! AND YOU MUST USE ALL PARAMETERS!
pause