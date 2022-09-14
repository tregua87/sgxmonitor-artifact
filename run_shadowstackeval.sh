#!/bin/bash

set -e

if [[ ! $(pgrep -f aesm_service) ]]; then
    LD_LIBRARY_PATH=/opt/intel/sgxpsw/aesm/ /opt/intel/sgxpsw/aesm/aesm_service --no-daemon &
else
    echo "[INFO] aesm_service already running!!"
fi 

SECURITY_ENCLAVE=$SGXMONITOR_PATH/src/security_traced_toplaywith/enclave.signed.so
DATA_SECURITY=data_security

# clean stuffs
rm -f $SGXMONITOR_PATH/src/monitor_toplaywith/edges.txt || true
rm -Rf $SGXMONITOR_PATH/analyzer3/$DATA_SECURITY || true
# just in case
# pkill -9 monitor

# run monitor
pushd src/monitor_toplaywith
echo "[INFO] Running monitor"
make
nice -n -10 ./monitor &> /dev/null &
popd

sleep 10

# run target
pushd src/security_traced_toplaywith
echo "[INFO] Running target"
make
nice -n -10 ./app || true
popd

sleep 10

pushd analyzer3

# extract model
echo "[INFO] Extract the target enclave model"
rm loops.txt || true
./extract_loops.py -e $SECURITY_ENCLAVE
./explore_decomposed_sym_enclave.py -e  $SECURITY_ENCLAVE -l loops.txt
./normalize_model.py -o model-n.txt -r model.txt model-insensitive.txt
mkdir $DATA_SECURITY
mv loops.txt $DATA_SECURITY/
mv model.txt $DATA_SECURITY/
mv model-insensitive.txt $DATA_SECURITY/ || true
mv model-n.txt $DATA_SECURITY/
mv loop_log.txt $DATA_SECURITY/ || true
mv statistics.txt $DATA_SECURITY/

# validate the model
echo "[INFO] validate the model"
./validate.py -e $SGXMONITOR_PATH/src/monitor_toplaywith/edges.txt -m $DATA_SECURITY/model-n.txt 
popd

# kill the monitor
pkill -9 monitor
