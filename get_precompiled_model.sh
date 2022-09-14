#!/bin/bash

set -e

# analyzer3
cp -r $SGXMONITOR_PATH/backupenclaves/prebuild_models/analyzer3/data_* $SGXMONITOR_PATH/analyzer3/
# analyzer2
cp -r $SGXMONITOR_PATH/backupenclaves/prebuild_models/analyzer2/data_* $SGXMONITOR_PATH/analyzer2/

# move enclaves in their folders
cp -r $SGXMONITOR_PATH/backupenclaves/prebuild_models/analyzer3/data_contact/enclave.signed.so $SGXMONITOR_PATH/src/contact_traced_toplaywith/
cp -r $SGXMONITOR_PATH/backupenclaves/prebuild_models/analyzer3/data_libdvdcss/enclave.signed.so $SGXMONITOR_PATH/src/libdvdcss-sgx_traced_toplaywith/enclave/
cp -r $SGXMONITOR_PATH/backupenclaves/prebuild_models/analyzer3/data_sgx-biniax2/enclave.signed.so $SGXMONITOR_PATH/src/sgx-biniax2_traced_toplaywith/
cp -r $SGXMONITOR_PATH/backupenclaves/prebuild_models/analyzer3/data_stealthdb/enclave.debug.signed.so $SGXMONITOR_PATH/src/stealthdb_toplaywith/build/
cp -r $SGXMONITOR_PATH/backupenclaves/prebuild_models/analyzer3/data_custom/enclave.signed.so $SGXMONITOR_PATH/src/custom_traced_toplaywith/