#!/bin/bash

set -e

echo "Compiling all the encalves and monitors"

(cd src/monitor_toplaywith && make clean && make)
(cd src/monitor_batch && make clean && make)
(cd src/monitor_length && make clean && make)

(cd src/contact_traced_toplaywith && make clean && make)
(cd src/contact_traced_batch && make clean && make)
(cd src/contact_traced_length && make clean && make)
(cd src/contact_vanilla && make clean && make)

(cd src/custom_traced_toplaywith && make clean && make)
(cd src/custom_traced_batch && make clean && make)
(cd src/custom_traced_length && make clean && make)
(cd src/custom_vanilla && make clean && make)

(cd src/sgx-biniax2_traced_toplaywith && make clean && make)
(cd src/sgx-biniax2_traced_batch && make clean && make)
(cd src/sgx-biniax2_traced_length && make clean && make)
(cd src/sgx-biniax2_vanilla && make clean && make)

## Clientpic first
(cd src/client && make Clientpic.o)
(cd src/stealthdb_toplaywith && make clean && make)
(cd src/stealthdb_vanilla && make clean && make)

(cd src/libdvdcss-sgx_traced_toplaywith/enclave && make clean && make)
# not executed
# libdvdcss-sgx_vanilla
    
