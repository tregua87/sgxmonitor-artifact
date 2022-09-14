FROM ubuntu:18.04 as base

ARG DEBIAN_FRONTEND=noninteractive 

ENV LLVM_PATH "/llvm-project/"
ENV SGXMONITOR_PATH "/sgxmonitor-src"
ENV ROPGADGET_PATH "/ROPgadget"

RUN apt-get update && apt -y install cmake git clang build-essential libssl-dev neovim curl wget
RUN apt-get install -y build-essential ocaml ocamlbuild automake autoconf libtool wget python libssl-dev git cmake perl
RUN apt-get install -y libssl-dev libcurl4-openssl-dev protobuf-compiler libprotobuf-dev debhelper cmake reprepro unzip lsb-release
RUN apt-get install -y postgresql postgresql-server-dev-all nasm

# Install LLVM the version I need
RUN git clone https://github.com/llvm/llvm-project.git

WORKDIR ${LLVM_PATH}
RUN git checkout d4c50f7326a063e073b380c4a7a5c10dd02a5e5d 
COPY ./docker/sgx-monitor.patch .
RUN git apply sgx-monitor.patch
RUN mkdir build
RUN cd build; \
    cmake -G "Unix Makefiles" -DLLVM_ENABLE_PROJECTS="clang" ../llvm; \
    make

COPY . ${SGXMONITOR_PATH}

# standard SDK
WORKDIR ${SGXMONITOR_PATH}/linux-sgx
RUN ./download_prebuilt.sh
RUN ./deploy.sh

# instrumented SDK
WORKDIR ${SGXMONITOR_PATH}/linux-sgx-i
RUN ./download_prebuilt.sh
RUN ./deploy.sh

# for Python
RUN apt -y install python3-pip python3
RUN apt -y remove python3-setuptools
RUN pip3 install capstone==4.0.2 setuptools 
RUN pip3 install angr==9.2.6 
RUN pip3 install timeout_decorator bloom_filter

# back to root
WORKDIR /
RUN git clone https://github.com/JonathanSalwan/ROPgadget.git
WORKDIR ${ROPGADGET_PATH}
RUN git checkout 0dc14e7ba8eb7ee1a96330e5061c0651ca63bf66

RUN apt-get update
RUN apt-get install -y python-dev libsdl-image1.2-dev libsdl-mixer1.2-dev \
    libsdl-ttf2.0-dev libsdl1.2-dev libsmpeg-dev python-numpy \
    subversion libportmidi-dev ffmpeg libswscale-dev libavformat-dev \
    libavcodec-dev libfreetype6-dev

# before doesn't work
RUN pip3 install psycopg2
RUN pip3 install matplotlib

RUN apt-get install -y openjdk-8-jdk jq

RUN pip3 install prettytable

# last thing, back to sgxmonitor_src
WORKDIR ${SGXMONITOR_PATH}