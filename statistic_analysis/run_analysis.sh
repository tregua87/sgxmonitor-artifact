#!/bin/bash

./get_cyclomatic_complexity.py -e ../src/contact_traced_toplaywith/enclave.signed.so
./get_cyclomatic_complexity.py -e ../src/stealthdb_toplaywith/build/enclave.debug.signed.so
./get_cyclomatic_complexity.py -e ../src/libdvdcss-sgx_traced_toplaywith/enclave/enclave.signed.so
./get_cyclomatic_complexity.py -e ../src/sgx-biniax2_traced_toplaywith/enclave.signed.so 
./get_cyclomatic_complexity.py -e ../src/custom_traced_batch/enclave.signed.so