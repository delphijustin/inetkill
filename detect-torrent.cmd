@echo off
goto begin
************************************************************
This script detects some of the popular torrent clients that
are running at the time this script was executed.
It sets the errorlevel to 1 if detected

I would like to thank nirsoft.net for client list
************************************************************
:begin
if not "%1"=="" goto next
call %0 Ares.exe Azureus.exe BaiduYunGuanjia.exe BitComet.exe bittorrent.exe ChilliTorrent.exe deluge.exe fdm.exe flashget.exe FreeOpener.exe FrostWire.exe hiderun.exe iLivid.exe iMesh.exe LimeWire.exe mediaget.exe qbittorrent.exe Spark.exe tixati.exe torch.exe uTorrent-2-0-Beta.exe uTorrent.exe uTorrentPortable.exe BiglyBT.exe
exit /B %ERRORLEVEL%
:next
if "%1"=="" exit /B 0
tasklist.exe|find /I "%1">nul
if "%ERRORLEVEL%"=="0" exit /B 1
shift
goto next