#!/bin/bash

echo "Compiling all the encalves and monitors"

(cd src/monitor_toplaywith && make)
(cd src/monitor_batch && make)
(cd src/monitor_length && make)

(cd src/contact_traced_toplaywith && make)
(cd src/contact_traced_batch && make)
(cd src/contact_traced_length && make)
(cd src/contact_vanilla && make)

(cd src/custom_traced_toplaywith && make)
(cd src/custom_traced_batch && make)
(cd src/custom_traced_length && make)
(cd src/custom_vanilla && make)

(cd src/sgx-biniax2_traced_toplaywith && make)
(cd src/sgx-biniax2_traced_batch && make)
(cd src/sgx-biniax2_traced_length && make)
(cd src/sgx-biniax2_vanilla && make)

## Clientpic first
(cd src/client && make Clientpic)
(cd src/stealthdb_toplaywith && make)
(cd src/stealthdb_vanilla && make)

(cd src/libdvdcss-sgx_traced_toplaywith/enclave && make)
# not executed
# libdvdcss-sgx_vanilla
    
