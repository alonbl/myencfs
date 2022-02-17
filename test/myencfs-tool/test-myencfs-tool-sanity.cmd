@echo off
setlocal

set code=1

if "%MYENCFS_TOOL%" == "" set MYENCFS_TOOL=myencfs-tool

set C=%RANDOM%
:RLOOP
set RND=%RANDOM%
if "%C%" == "%RND%" goto RLOOP

set TMPDIR=%TEMP%\myencfs-%RND%.tmp

mkdir "%TMPDIR%\key-store"
mkdir "%TMPDIR%\base-pt1"
mkdir "%TMPDIR%\base-pt2"
mkdir "%TMPDIR%\base-ct"

echo 01234567890123456789001234567890 > "%TMPDIR%\key-store\id1"
echo test > "%TMPDIR%\base-pt1\file1.dat"

"%MYENCFS_TOOL%" encrypt --key-store="%TMPDIR%\key-store" --key-id=id1 --base-pt="%TMPDIR%\base-pt1" --base-ct="%TMPDIR%\base-ct" --name=file1.dat
if %errorlevel% neq 0 goto cleanup

"%MYENCFS_TOOL%" decrypt --key-store="%TMPDIR%\key-store" --base-pt="%TMPDIR%\base-pt2" --base-ct="%TMPDIR%\base-ct" --name=file1.dat
if %errorlevel% neq 0 goto cleanup

set code=0

:cleanup

rmdir /q /s "%TMPDIR%" > nul:

exit /b %code%
