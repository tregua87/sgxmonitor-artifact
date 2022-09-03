#
# Copyright (C) 2011-2019 Intel Corporation. All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions
# are met:
#
#   * Redistributions of source code must retain the above copyright
#     notice, this list of conditions and the following disclaimer.
#   * Redistributions in binary form must reproduce the above copyright
#     notice, this list of conditions and the following disclaimer in
#     the documentation and/or other materials provided with the
#     distribution.
#   * Neither the name of Intel Corporation nor the names of its
#     contributors may be used to endorse or promote products derived
#     from this software without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
# "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
# LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
# A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
# OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
# SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
# LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
# DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
# THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
# (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
# OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
#
#

######## SGX SDK Settings ########

CC=$(LLVM_PATH)/build/bin/clang
CXX=$(LLVM_PATH)/build/bin/clang++

SGX_SDK ?= /opt/intel/sgxsdk
SGX_MODE ?= HW
SGX_ARCH ?= x64
SGX_DEBUG ?= 1

Monitor_Name = MonitorLocal.o

ifeq ($(shell getconf LONG_BIT), 32)
	SGX_ARCH := x86
else ifeq ($(findstring -m32, $(CXXFLAGS)), -m32)
	SGX_ARCH := x86
endif

ifeq ($(SGX_ARCH), x86)
	SGX_COMMON_FLAGS := -m32
	SGX_LIBRARY_PATH_I := /opt/intel/sgxsdki/lib64
	SGX_LIBRARY_PATH := $(SGX_SDK)/lib
	SGX_ENCLAVE_SIGNER := $(SGX_SDK)/bin/x86/sgx_sign
	SGX_EDGER8R := $(SGX_SDK)/bin/x86/sgx_edger8r
else
	SGX_COMMON_FLAGS := -m64
	SGX_LIBRARY_PATH_I := /opt/intel/sgxsdki/lib64
	SGX_LIBRARY_PATH := $(SGX_SDK)/lib64
	SGX_ENCLAVE_SIGNER := $(SGX_SDK)/bin/x64/sgx_sign
	SGX_EDGER8R := $(SGX_SDK)/bin/x64/sgx_edger8r
endif

ifeq ($(SGX_DEBUG), 1)
ifeq ($(SGX_PRERELEASE), 1)
$(error Cannot set SGX_DEBUG and SGX_PRERELEASE at the same time!!)
endif
endif

ifeq ($(SGX_DEBUG), 1)
        SGX_COMMON_FLAGS += -O0 -g
else
        SGX_COMMON_FLAGS += -O2
endif

SGX_COMMON_FLAGS += -Wall -Wextra -Winit-self -Wpointer-arith -Wreturn-type \
                    -Waddress -Wsequence-point -Wformat-security \
                    -Wmissing-include-dirs -Wfloat-equal -Wundef -Wshadow $(Signed_EnclaveM_Name)\
                    -Wcast-align -Wcast-qual -Wconversion -Wredundant-decls
SGX_COMMON_CFLAGS := $(SGX_COMMON_FLAGS) -Wjump-misses-init -Wstrict-prototypes -Wunsuffixed-float-constants
SGX_COMMON_CXXFLAGS := $(SGX_COMMON_FLAGS) -Wnon-virtual-dtor -std=c++11

Monitor_Include_Paths := -IInclude -I../../inc -I$(SGX_SDK)/include

Monitor_C_Flags := -fPIC -Wno-attributes $(Monitor_Include_Paths)

######## Enclave Settings ########

ifneq ($(SGX_MODE), HW)
	Trts_Library_Name := sgx_trts_sim
	Service_Library_Name := sgx_tservice_sim
else
	Trts_Library_Name := sgx_trts
	Service_Library_Name := sgx_tservice
endif
Crypto_Library_Name := sgx_tcrypto

EnclaveM_Cpp_Files := EnclaveM/Enclave.cpp
EnclaveM_Include_Paths := -IInclude -I../../inc -IEnclaveM -I$(SGX_SDK)/include -I$(SGX_SDK)/include/tlibc -I$(SGX_SDK)/include/libcxx

EnclaveM_C_Flags := $(EnclaveM_Include_Paths) -nostdinc -fvisibility=hidden -fpie -ffunction-sections -fdata-sections

ifeq ($(CC_BELOW_4_9), 1)
	EnclaveM_C_Flags += -fstack-protector
else
	EnclaveM_C_Flags += -fstack-protector-strong
endif

# Enable the security flags
Enclave_Security_Link_Flags := -Wl,-z,relro,-z,now,-z,noexecstack

EnclaveM_Cpp_Flags := $(EnclaveM_C_Flags) -nostdinc++


EnclaveM_Link_Flags := $(Enclave_Security_Link_Flags) \
	    -Wl,--no-undefined -nostdlib -nodefaultlibs -nostartfiles -L$(SGX_LIBRARY_PATH) \
		-Wl,--whole-archive -l$(Trts_Library_Name) -Wl,--no-whole-archive \
		-Wl,--start-group -lsgx_tstdc -lsgx_tcxx -l$(Crypto_Library_Name) -l$(Service_Library_Name) -Wl,--end-group \
		-Wl,-Bstatic -Wl,-Bsymbolic -Wl,--no-undefined \
		-Wl,-pie,-eenclave_entry -Wl,--export-dynamic  \
		-Wl,--defsym,__ImageBase=0 -Wl,--gc-sections   \
		-Wl,--version-script=EnclaveM/Enclave.lds

EnclaveM_Cpp_Objects := $(sort $(EnclaveM_Cpp_Files:.cpp=.o))

EnclaveM_Name := enclavem.so
Signed_EnclaveM_Name := enclavem.signed.so
EnclaveM_Config_File := EnclaveM/Enclave.config.xml

ifeq ($(SGX_MODE), HW)
ifeq ($(SGX_DEBUG), 1)
	Build_Mode = HW_DEBUG
else ifeq ($(SGX_PRERELEASE), 1)
	Build_Mode = HW_PRERELEASE
else
	Build_Mode = HW_RELEASE
endif
else
ifeq ($(SGX_DEBUG), 1)
	Build_Mode = SIM_DEBUG
else ifeq ($(SGX_PRERELEASE), 1)
	Build_Mode = SIM_PRERELEASE
else
	Build_Mode = SIM_RELEASE
endif
endif

.PHONY: all target run
all: .config_$(Build_Mode)_$(SGX_ARCH)
	@$(MAKE) target

ifeq ($(Build_Mode), HW_RELEASE)
target:  $(Monitor_Name) $(EnclaveM_Name) $(Signed_EnclaveM_Name)
	@echo "The project has been built in release hardware mode."
	@echo "Please sign the $(EnclaveM_Name) first with your signing key before you run the $(Monitor_Name) to launch and access the enclave."
	@echo "To sign the enclave use the command:"
	@echo "   $(SGX_ENCLAVE_SIGNER) sign -key <your key> -enclave $(EnclaveM_Name) -out <$(Signed_EnclaveM_Name)> -config $(EnclaveM_Config_File)"
	@echo "You can also sign the enclave using an external signing tool."
	@echo "To build the project in simulation mode set SGX_MODE=SIM. To build the project in prerelease mode set SGX_PRERELEASE=1 and SGX_MODE=HW."


else
target: $(Monitor_Name) $(Signed_EnclaveM_Name)
ifeq ($(Build_Mode), HW_DEBUG)
	@echo "The project has been built in debug hardware mode."
else ifeq ($(Build_Mode), SIM_DEBUG)
	@echo "The project has been built in debug simulation mode."
else ifeq ($(Build_Mode), HW_PRERELEASE)
	@echo "The project has been built in pre-release hardware mode."
else ifeq ($(Build_Mode), SIM_PRERELEASE)
	@echo "The project has been built in pre-release simulation mode."
else
	@echo "The project has been built in release simulation mode."
endif__MONITORLOCAL_H_

endif

endif

run: all
ifneq ($(Build_Mode), HW_RELEASE)
	@$(CURDIR)/$(Monitor_Name)
	@echo "RUN  =>  $(Monitor_Name) [$(SGX_MODE)|$(SGX_ARCH), OK]"
endif

.config_$(Build_Mode)_$(SGX_ARCH):
	@rm -f .config_* $(Monitor_Name) $(EnclaveM_Name) $(Signed_EnclaveM_Name) $(App_Cpp_Objects) App/Enclave_u.* $(Enclave_Cpp_Objects) EnclaveT/Enclave_t.*
	@rm -f .config_* $(Monitor_Name) $(EnclaveM_Name) $(Signed_EnclaveM_Name) $(Monitor_Cpp_Objects) $(EnclaveM_Cpp_Objects) EnclaveM/Enclave_t.*
	@touch .config_$(Build_Mode)_$(SGX_ARCH)

######## Monitor Local Objects ########

EnclaveM_u.h: $(SGX_EDGER8R) EnclaveM/EnclaveM.edl
	@$(SGX_EDGER8R) --untrusted EnclaveM/EnclaveM.edl --search-path ../EnclaveM --search-path $(SGX_SDK)/include
	@echo "GEN  =>  $@"

EnclaveM_u.c: EnclaveM_u.h

EnclaveM_u.o: EnclaveM_u.c
	@$(CC) $(SGX_COMMON_CFLAGS) $(Monitor_Include_Paths) -c $< -o $@
	@echo "CC   <=  $<"


$(Monitor_Name): MonitorLocal.cpp EnclaveM_u.h EnclaveM_u.o
	@$(CC) $(SGX_COMMON_CXXFLAGS) $(Monitor_Include_Paths) -c $< -o $@
	@echo "CC   <=  $<"

######## Enclave Monitor Objects ########

EnclaveM/EnclaveM_t.h: $(SGX_EDGER8R) EnclaveM/EnclaveM.edl
	@cd EnclaveM && $(SGX_EDGER8R) --trusted ../EnclaveM/EnclaveM.edl --search-path ../EnclaveM --search-path $(SGX_SDK)/include
	@echo "GEN  =>  $@"

EnclaveM/EnclaveM_t.c: EnclaveM/EnclaveM_t.h

EnclaveM/EnclaveM_t.o: EnclaveM/EnclaveM_t.c
	@$(CC) $(SGX_COMMON_CFLAGS) $(EnclaveM_C_Flags) -c $< -o $@
	@echo "CC   <=  $<"

EnclaveM/%.o: EnclaveM/%.cpp EnclaveM/EnclaveM_t.h
	@$(CXX) $(SGX_COMMON_CXXFLAGS) $(EnclaveM_Cpp_Flags) -c $< -o $@
	@echo "CXX  <=  $<"

$(EnclaveM_Name): EnclaveM/EnclaveM_t.o EnclaveM/EnclaveM_t.o $(EnclaveM_Cpp_Objects)
	@$(CXX) $^ -o $@ $(EnclaveM_Link_Flags)
	@echo "LINK =>  $@"

$(Signed_EnclaveM_Name): $(EnclaveM_Name)
	@$(SGX_ENCLAVE_SIGNER) sign -key EnclaveM/Enclave_private.pem -enclave $(EnclaveM_Name) -out $@ -config $(EnclaveM_Config_File)
	@echo "SIGN =>  $@"

.PHONY: clean

clean:
	@rm -f $(EnclaveM_Name) $(Signed_EnclaveM_Name) *.o EnclaveM/*.o *_u.c *_u.h EnclaveM/*_t.c EnclaveM/*_t.h
