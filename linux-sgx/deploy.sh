#!/bin/bash

#echo "Uninstall"
#sudo /opt/intel/sgxpsw/uninstall.sh
#sudo /opt/intel/sgxsdk/uninstall.sh

echo "Compile"
make sdk || { echo "make sdk failed!"; exit 1; }
make psw || { echo "make psw failed!"; exit 1; }
make sdk_install_pkg || { echo "make sdk_install_pkg failed!"; exit 1; }
make psw_install_pkg || { echo "make pws_install_pkg failed!"; exit 1; }

echo "Install"
# sudo cp ./build/linux/libsgx_urts.so /opt/intel/sgxsdk/lib64/
printf "no\n/opt/intel/\n" | ./linux/installer/bin/sgx_linux_x64_sdk_2.6.100.51363.bin
./linux/installer/bin/sgx_linux_x64_psw_2.6.100.51363.bin  --no-start-aesm || { echo "error but continue"; }

# HOW TO START AESM -- to be included in the entry point
# cd /opt/intel/sgxpsw/aesm/ && LD_LIBRARY_PATH=. ./aesm_service --no-daemon &> /dev/null  &

# cp ./build/linux/libsgx_urts.so /opt/intel/sgxsdk/lib64/

# echo "Set environment"
# source /opt/intel/sgxsdk/environment