@echo off
rem ---------------------------------------------------------------------------
rem  HERO installer
rem
rem  This opens HERO's own setup window. Nothing is installed until you click
rem  Install there, and Windows will then ask for administrator permission once
rem  -- that prompt is HERO registering its guardian service, which has to run
rem  as LocalSystem to see every process on the machine.
rem
rem  HERO itself does NOT run as administrator afterwards. The tray app ships
rem  asInvoker on purpose: a tool that triggers a UAC prompt at every logon
rem  teaches you to click through prompts, which is a net security loss.
rem ---------------------------------------------------------------------------

rem  Run from inside a zip viewer, this file can see nothing beside it: Explorer
rem  extracts only the one file being opened, to a temporary folder. Say so,
rem  rather than launching a HERO.exe that is not there and showing nothing.
if not exist "%~dp0HERO.exe" (
  echo.
  echo   HERO.exe is not next to this file.
  echo.
  echo   Extract the WHOLE zip to a folder first, then run "Install HERO.cmd"
  echo   from inside that folder.
  echo.
  pause
  exit /b 1
)

start "" "%~dp0HERO.exe" --setup
