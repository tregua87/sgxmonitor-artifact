#!/bin/bash

set -e

pushd statistic_analysis

rm model.txt || true

./get_cyclomatic_complexity.py -e ../src/contact_traced_toplaywith/enclave.signed.so -u "Contact"
./get_cyclomatic_complexity.py -e ../src/stealthdb_toplaywith/build/enclave.debug.signed.so -u "StealthDB"
./get_cyclomatic_complexity.py -e ../src/libdvdcss-sgx_traced_toplaywith/enclave/enclave.signed.so -u "libdvdcss"
./get_cyclomatic_complexity.py -e ../src/sgx-biniax2_traced_toplaywith/enclave.signed.so -u "SGX-Biniax2"
./get_cyclomatic_complexity.py -e ../src/custom_traced_toplaywith/enclave.signed.so -u "Unit-Test"

rm loc.txt || true

LOC=$(cloc $SGXMONITOR_PATH/src/contact_traced_toplaywith/EnclaveT/ | tail -2 | head -1 | awk '{print $5}')
echo "Contact|$LOC" >> loc.txt
LOC=$(cloc $SGXMONITOR_PATH/src/stealthdb_toplaywith/src/enclave | tail -2 | head -1 | awk '{print $5}')
echo "StealthDB|$LOC" >> loc.txt
LOC=$(cloc $SGXMONITOR_PATH/src/libdvdcss-sgx_traced_toplaywith/enclave/ | tail -2 | head -1 | awk '{print $5}')
echo "libdvdcss|$LOC" >> loc.txt
LOC=$(cloc $SGXMONITOR_PATH/src/sgx-biniax2_traced_toplaywith/Enclave/ | tail -2 | head -1 | awk '{print $5}')
echo "SGX-Biniax2|$LOC" >> loc.txt
LOC=$(cloc $SGXMONITOR_PATH/src/custom_traced_toplaywith/EnclaveT/ | tail -2 | head -1 | awk '{print $5}')
echo "Unit-Test|$LOC" >> loc.txt

popd

pushd scripts
./plot_table_statistics.py
popd