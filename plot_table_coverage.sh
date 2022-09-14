#!/bin/bash

pushd analyzer3

# for signal-contact
if [ ! -d "data_contact" ]; then
    echo "[ERROR] Contact not analyzed, analyze the enclave or import pre-computed models"
else
    ./normalize_model.py -o model-n-sym.txt -r data_contact/model.txt
    ./get_edge.py --use_case "Contact" --model_static ../analyzer2/data_contact/model-n.txt --model_symex model-n-sym.txt --model_insensitive data_contact/model-insensitive.txt > delta_info.txt
    ./compare-model.py -g ../analyzer2/data_contact/model-n.txt -m data_contact/model-n.txt
    mv model-n-sym.txt data_contact/
    mv delta_info.txt data_contact/
    mv coverage.txt data_contact/
fi


# for libdvdcss
if [ ! -d "data_libdvdcss" ]; then
    echo "[ERROR] LibDvdCss not analyzed, analyze the enclave or import pre-computed models"
else
    ./normalize_model.py -o model-n-sym.txt -r data_libdvdcss/model.txt
    ./get_edge.py --use_case "libdvdcss" --model_static ../analyzer2/data_libdvdcss/model-n.txt --model_symex model-n-sym.txt --model_insensitive data_libdvdcss/model-insensitive.txt > delta_info.txt
    ./compare-model.py -g ../analyzer2/data_libdvdcss/model-n.txt -m data_libdvdcss/model-n.txt
    mv model-n-sym.txt data_libdvdcss/
    mv delta_info.txt data_libdvdcss/
    mv coverage.txt data_libdvdcss/
fi

# for sgx-biniax2
if [ ! -d "data_sgx-biniax2" ]; then
    echo "[ERROR] SGX-Biniax2 not analyzed, analyze the enclave or import pre-computed models"
else
    ./normalize_model.py -o model-n-sym.txt -r data_sgx-biniax2/model.txt
    ./get_edge.py --use_case "SGX-Biniax2" --model_static ../analyzer2/data_sgx-biniax2/model-n.txt --model_symex model-n-sym.txt --model_insensitive data_sgx-biniax2/model-insensitive.txt > delta_info.txt
    ./compare-model.py -g ../analyzer2/data_sgx-biniax2/model-n.txt -m data_sgx-biniax2/model-n.txt
    mv model-n-sym.txt data_sgx-biniax2/
    mv delta_info.txt data_sgx-biniax2/
    mv coverage.txt data_sgx-biniax2/
fi

# for stealthdb
if [ ! -d "data_stealthdb" ]; then
    echo "[ERROR] StealthDB not analyzed, analyze the enclave or import pre-computed models"
else
    ./normalize_model.py -o model-n-sym.txt -r data_stealthdb/model.txt
    ./get_edge.py --use_case "StealthDB" --model_static ../analyzer2/data_stealthdb/model-n.txt --model_symex model-n-sym.txt --model_insensitive data_stealthdb/model-insensitive.txt > delta_info.txt
    ./compare-model.py -g ../analyzer2/data_stealthdb/model-n.txt -m data_stealthdb/model-n.txt
    mv model-n-sym.txt data_stealthdb/
    mv delta_info.txt data_stealthdb/
    mv coverage.txt data_stealthdb/
fi

# for custom
if [ ! -d "data_custom" ]; then
    echo "[ERROR] Unit-Test not analyzed, analyze the enclave or import pre-computed models"
else
    ./normalize_model.py -o model-n-sym.txt -r data_custom/model.txt
    ./get_edge.py --use_case "Unit-Test" --model_static ../analyzer2/data_custom/model-n.txt --model_symex model-n-sym.txt --model_insensitive data_custom/model-insensitive.txt > delta_info.txt
    ./compare-model.py -g ../analyzer2/data_custom/model-n.txt -m data_custom/model-n.txt
    mv model-n-sym.txt data_custom/
    mv delta_info.txt data_custom/
    mv coverage.txt data_custom/
fi

popd

pushd scripts

echo "[INFO] plot Table 2"

./plot_table_coverage.py

popd