FROM ubuntu:18.04 as base

ENV LLVM_PATH "/llvm-project/"
ENV SGXMONITOR_PATH "/sgxmonitor-src"
ENV ROPGADGET_PATH "/ROPgadget"

RUN apt update && apt -y install cmake git clang build-essential libssl-dev neovim curl wget
RUN apt install -y build-essential ocaml ocamlbuild automake autoconf libtool wget python libssl-dev git cmake perl
RUN apt install -y libssl-dev libcurl4-openssl-dev protobuf-compiler libprotobuf-dev debhelper cmake reprepro unzip lsb-release

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
RUN pip3 install capstone setuptools 
RUN pip3 install angr==9.2.6 
RUN pip3 install timeout_decorator bloom_filter

# back to root
WORKDIR /
RUN git clone https://github.com/JonathanSalwan/ROPgadget.git
WORKDIR ${ROPGADGET_PATH}
RUN git checkout 0dc14e7ba8eb7ee1a96330e5061c0651ca63bf66


# last thing, back to sgxmonitor_src
WORKDIR ${SGXMONITOR_PATH}