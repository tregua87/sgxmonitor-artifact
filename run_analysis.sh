#!/bin/bash

set -e

pushd analyzer3

# for signal-contact
if [ ! -d "data_contact" ]; then
    rm loops.txt || true
    ./extract_loops.py -e ../src/contact_traced_toplaywith/enclave.signed.so
    ./explore_decomposed_sym_enclave.py -e ../src/contact_traced_toplaywith/enclave.signed.so -l loops.txt -c Contact 
    ./normalize_model.py -o model-n.txt -r model.txt model-insensitive.txt
    mkdir data_contact
    mv loops.txt data_contact/
    mv model.txt data_contact/
    mv model-insensitive.txt data_contact/ || true
    mv model-n.txt data_contact/
    mv loop_log.txt data_contact/
    mv statistics.txt data_contact/
fi

# for libdvdcss
if [ ! -d "data_libdvdcss" ]; then
    rm loops.txt || true
    ./extract_loops.py -e ../src/libdvdcss-sgx_traced_toplaywith/enclave/enclave.signed.so
    ./explore_decomposed_sym_enclave.py -e  ../src/libdvdcss-sgx_traced_toplaywith/enclave/enclave.signed.so -l loops.txt -c Libdvdcss -v
    ./normalize_model.py -o model-n.txt -r model.txt model-insensitive.txt
    mkdir data_libdvdcss
    mv loops.txt data_libdvdcss/
    mv model.txt data_libdvdcss/
    mv model-insensitive.txt data_libdvdcss/ || true
    mv model-n.txt data_libdvdcss/
    mv loop_log.txt data_libdvdcss/
    mv statistics.txt data_libdvdcss/
fi

# for sgx-biniax2
if [ ! -d "data_sgx-biniax2" ]; then
    rm loops.txt || true
    ./extract_loops.py -e ../src/sgx-biniax2_traced_toplaywith/enclave.signed.so
    ./explore_decomposed_sym_enclave.py -e  ../src/sgx-biniax2_traced_toplaywith/enclave.signed.so -l loops.txt -v
    ./normalize_model.py -o model-n.txt -r model.txt model-insensitive.txt
    mkdir data_sgx-biniax2
    mv loops.txt data_sgx-biniax2/
    mv model.txt data_sgx-biniax2/
    mv model-insensitive.txt data_sgx-biniax2/ || true
    mv model-n.txt data_sgx-biniax2/
    mv loop_log.txt data_sgx-biniax2/
    mv statistics.txt data_sgx-biniax2/
fi

# for stealthdb
if [ ! -d "data_stealthdb" ]; then
    rm loops.txt || true
    ./extract_loops.py -e ../src/stealthdb_toplaywith/build/enclave.debug.signed.so 
    ./explore_decomposed_sym_enclave.py -e  ../src/stealthdb_toplaywith/build/enclave.debug.signed.so -l loops.txt
    ./normalize_model.py -o model-n.txt -r model.txt model-insensitive.txt
    mkdir data_stealthdb
    mv loops.txt data_stealthdb/
    mv model.txt data_stealthdb/
    mv model-insensitive.txt data_stealthdb/ || true
    mv model-n.txt data_stealthdb/
    mv loop_log.txt data_stealthdb/
    mv statistics.txt data_stealthdb/
fi

# for custom
if [ ! -d "data_custom" ]; then
    rm loops.txt || true
    ./extract_loops.py -e ../src/custom_traced_batch/enclave.signed.so
    ./explore_decomposed_sym_enclave.py -e ../src/custom_traced_batch/enclave.signed.so -l loops.txt 
    ./normalize_model.py -o model-n.txt -r model.txt model-insensitive.txt
    mkdir data_custom
    mv loops.txt data_custom/
    mv model.txt data_custom/
    mv model-insensitive.txt data_custom/ || true
    mv model-n.txt data_custom/
    mv loop_log.txt data_custom/
    mv statistics.txt data_custom/
fi

popd