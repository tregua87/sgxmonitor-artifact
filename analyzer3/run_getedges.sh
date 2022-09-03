#!/bin/bash

for ex in data_sgx-biniax2 data_contact data_custom data_libdvdcss data_stealthdb
do
    # echo $ex
    ./get_edge.py --use_case $ex --model_static ../analyzer2/$ex/model-n.txt --model_symex $ex/model-n.txt --model_insensitive $ex/model-insensitive.txt
done
