@echo off

set ASMJIT_CURRENT_DIR=%CD%
set ASMJIT_BUILD_DIR="build_vs2013_x86"

mkdir ..\%ASMJIT_BUILD_DIR%
cd ..\%ASMJIT_BUILD_DIR%
cmake .. -G"Visual Studio 12" -DASMJIT_BUILD_TEST=1
cd %ASMJIT_CURRENT_DIR%
