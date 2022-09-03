#!/bin/bash

echo "Uninstall"
#sudo /opt/intel/sgxpsw/uninstall.sh
/opt/intel/sgxsdki/uninstall.sh || { echo "nothing to uninstall"; }

echo "Compile"
make || { echo "make failed!"; exit 1; }
#make psw_install_pkg || { echo "make pws_install_pkg failed!"; exit 1; }
make sdk_install_pkg || { echo "make sdk_install_pkg failed!"; exit 1; }

echo "Install"
#sudo cp ./build/linux/libsgx_urts.so /opt/intel/sgxsdk/lib64/
printf "no\n/opt/intel/\n" | ./linux/installer/bin/sgx_linux_x64_sdk_2.6.100.51363.bin
#sudo ./linux/installer/bin/sgx_linux_x64_psw_2.6.100.51363.bin
#sudo cp ./build/linux/libsgx_urts.so /opt/intel/sgxsdk/lib64/

echo "Set environment"
source /opt/intel/sgxsdki/environment

# USE VARIABLES INSTEAD OF ABSOLUTE PATHS?! nooooo... :P
cp -r /opt/intel/sgxsdki/lib64/* $SGXMONITOR_PATH/sgxsdki/lib64/

