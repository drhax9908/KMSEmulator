@echo off
cd /D %~dp0
REM Delete Precompiled Headers
FOR /D /R %%X IN (ipch*) DO RD /S /Q "%%X"

REM Delete obj Folders
FOR /D /R %%X IN (obj*) DO RD /S /Q "%%X"

REM Delete Debug Folders
FOR /D /R %%X IN (Debug*) DO RD /S /Q "%%X"

REM Delete Static Library Binary Folders
RD /S /Q "%~dp0KMS Client Library\bin"
RD /S /Q "%~dp0KMS Server Library\bin"
RD /S /Q "%~dp0KMS Stub Library\bin"

REM Delete EXP Files
DEL /f /s /q *.exp

REM Delete LIB Files
DEL /f /s /q *.lib

REM Delete PDB Files
DEL /f /s /q *.pdb

REM Delete SDF Files
DEL /f /s /q *.sdf