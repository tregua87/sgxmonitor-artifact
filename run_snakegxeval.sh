#!/bin/bash

set -e

if [[ ! $(pgrep -f aesm_service) ]]; then
    LD_LIBRARY_PATH=/opt/intel/sgxpsw/aesm/ /opt/intel/sgxpsw/aesm/aesm_service --no-daemon &
else
    echo "[INFO] aesm_service already running!!"
fi 

# check stealthdb model
if [ ! -d "analyzer3/data_stealthdb" ]; then
    echo "[ERROR] StealthDB not analyzed, analyze the enclave or import pre-computed models"
    exit 1
fi

SNAKEGX_ENCLAVE=/usr/local/lib/stealthDB/enclave.signed.so
DATA_SNAKEGX=data_snakegx

# clean stuffs
rm -f $SGXMONITOR_PATH/src/monitor_toplaywith/edges.txt || true

# rm -Rf $SGXMONITOR_PATH/analyzer3/$DATA_SNAKEGX || true
# just in case
# pkill -9 monitor

# run monitor
pushd src/monitor_toplaywith
echo "[INFO] Running monitor"
make
./monitor &> /dev/null &
popd

# compile and install enclave
pushd src/stealthdb_toplaywith
echo "[INFO] Install enclave"
make 
make install
popd

# extract gadgets
pushd src/stealthdb_toplaywith/src/app
echo "[INFO] Find gadgets"
./generateConstant.py
popd

# compole PoC again
pushd src/stealthdb_toplaywith
echo "[INFO] Compile PoC"
# to force re-compilation
rm src/app/app
make
popd

# run
pushd src/stealthdb_toplaywith/src/app
echo "[INFO] run PoC"
./app
popd

# don't know why, better killing it
pkill -9 monitor


pushd analyzer3

echo "[INFO] Validate the traces"
FIRST_ACTION=$(jq ."enter_enclave" $DATA_SNAKEGX/model-n.txt  | grep "T\[" | head -1 | tr -d "\" ")
./normalize_edges.py -e $SGXMONITOR_PATH/src/monitor_toplaywith/edges.txt -f $FIRST_ACTION -n edges-norm.txt
./validate.py -e edges-norm.txt -m $DATA_SNAKEGX/model-n.txt
popd