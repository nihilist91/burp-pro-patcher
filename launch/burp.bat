@echo off
cd /d "%~dp0.."
start "" javaw -noverify -Xmx4g -jar burpsuite_pro.jar
