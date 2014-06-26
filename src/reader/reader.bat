@echo off
@echo "Tiawps sessionkey reader Build 18414 5.4.8"

SET PATH=%~dp0
REM Switch to drive
%PATH:~0,2%

cd %PATH%

tiawps_reader.exe 15484476 1288
PAUSE
