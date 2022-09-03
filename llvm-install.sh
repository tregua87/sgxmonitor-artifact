#!/bin/bash

# LLVM+Clang for me

SGXMONITORSRC=/workspace/sgxmonitor-src

cd /llvm-project 
git checkout d4c50f7326a063e073b380c4a7a5c10dd02a5e5d 
cp $SGXMONITORSRC/docker/sgx-monitor.patch .
git apply sgx-monitor.patch
mkdir build
cd build
cmake -G "Unix Makefiles" -DLLVM_ENABLE_PROJECTS="clang" ../llvm
make