#!/bin/bash

# for signal-contact
./extract_loops.py -e ../src/contact_traced_toplaywith/enclave.signed.so
./explore_decomposed_sym_enclave.py -e ../src/contact_traced_toplaywith/enclave.signed.so -l loops.txt -c Contact 

# for libdvdcss
./extract_loops.py -e ../src/libdvdcss-sgx_traced_toplaywith/enclave/enclave.signed.so
./explore_decomposed_sym_enclave.py -e  ../src/libdvdcss-sgx_traced_toplaywith/enclave/enclave.signed.so -l loops.txt -c Libdvdcss -v

# for sgx-biniax2
./explore_decomposed_sym_enclave.py -e  ../src/sgx-biniax2_traced_toplaywith/enclave.signed.so -l data_sgx-biniax2/loops_biniax2.txt -v

# for stealthdb
./explore_decomposed_sym_enclave.py -e  ../src/stealthdb_toplaywith/build/enclave.debug.signed.so -l data_stealthdb/loops_stealthdb.txt

# for custom
./explore_decomposed_sym_enclave.py -e ../src/custom_traced_batch/enclave.signed.so -l loops.txt 