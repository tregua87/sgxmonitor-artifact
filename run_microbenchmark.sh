#!/bin/bash

set -e

if [[ ! $(pgrep -f aesm_service) ]]; then
    LD_LIBRARY_PATH=/opt/intel/sgxpsw/aesm/ /opt/intel/sgxpsw/aesm/aesm_service --no-daemon &
else
    echo "[INFO] aesm_service already running!!"
fi

rm -f $SGXMONITOR_PATH/benchmark.txt || true
rm -f $SGXMONITOR_PATH/len_function.txt || true

pushd scripts

./runExperiments.py

popd