#!/bin/bash


export DEBIAN_FRONTEND=noninteractive 

export LLVM_PATH "/opt/llvm-project/"
export SGXMONITOR_PATH "/opt/sgxmonitor-src"
export ROPGADGET_PATH "/opt/ROPgadget"

sudo apt-get update && apt -y install cmake git clang build-essential libssl-dev neovim curl wget
sudo apt-get install -y build-essential ocaml ocamlbuild automake autoconf libtool wget python libssl-dev git cmake perl
sudo apt-get install -y libssl-dev libcurl4-openssl-dev protobuf-compiler libprotobuf-dev debhelper cmake reprepro unzip lsb-release
sudo apt-get install -y postgresql postgresql-server-dev-all nasm

# Install LLVM the version I need
sudo git clone https://github.com/llvm/llvm-project.git

pushd ${LLVM_PATH}
sudo git checkout d4c50f7326a063e073b380c4a7a5c10dd02a5e5d 
COPY ./docker/sgx-monitor.patch .
sudo git apply sgx-monitor.patch
sudo mkdir build
sudo cd build; \
    cmake -G "Unix Makefiles" -DLLVM_ENABLE_PROJECTS="clang" ../llvm; \
    make
popd

cp -r . ${SGXMONITOR_PATH}

# standard SDK
pushd ${SGXMONITOR_PATH}/linux-sgx
sudo ./download_prebuilt.sh
sudo ./deploy.sh
popd

# instrumented SDK
pushd ${SGXMONITOR_PATH}/linux-sgx-i
sudo ./download_prebuilt.sh
sudo ./deploy.sh
popd

# for Python
sudo apt -y install python3-pip python3
sudo apt -y remove python3-setuptools
sudo pip3 install capstone==4.0.2 setuptools 
sudo pip3 install angr==9.2.6 
sudo pip3 install timeout_decorator bloom_filter

# back to root
pushd /opt/
sudo git clone https://github.com/JonathanSalwan/ROPgadget.git
popd
pushd ${ROPGADGET_PATH}
sudo git checkout 0dc14e7ba8eb7ee1a96330e5061c0651ca63bf66
popd

sudo apt-get update
sudo apt-get install -y python-dev libsdl-image1.2-dev libsdl-mixer1.2-dev \
    libsdl-ttf2.0-dev libsdl1.2-dev libsmpeg-dev python-numpy \
    subversion libportmidi-dev ffmpeg libswscale-dev libavformat-dev \
    libavcodec-dev libfreetype6-dev

# before doesn't work
sudo pip3 install psycopg2
sudo pip3 install matplotlib

sudo apt-get install -y openjdk-8-jdk jq cloc
sudo pip3 install prettytable

# last thing, back to sgxmonitor_src
cd ${SGXMONITOR_PATH}