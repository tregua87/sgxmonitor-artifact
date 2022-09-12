#!/bin/bash

set -e

if [[ ! $(pgrep -f aesm_service) ]]; then
    LD_LIBRARY_PATH=/opt/intel/sgxpsw/aesm/ /opt/intel/sgxpsw/aesm/aesm_service --no-daemon &
else
    echo "[INFO] aesm_service already running!!"
fi

rm -f $SGXMONITOR_PATH/benchmark.txt || true
rm -f $SGXMONITOR_PATH/len_function.txt || true

# for stealthdbo (vanilla|toplaywith)
rm -f $SGXMONITOR_PATH/src/stealthdb_vanilla/benchmark.txt || true
rm -f $SGXMONITOR_PATH/src/stealthdb_toplaywith/benchmark.txt || true
rm -f $SGXMONITOR_PATH/src/stealthdb_toplaywith/len_function.txt || true

pushd scripts

./runExperiments.py
cat ../src/stealthdb_vanilla/benchmark.txt >> ../benchmark.txt 
cat ../src/stealthdb_toplaywith/benchmark.txt >> ../benchmark.txt 
cat ../src/stealthdb_toplaywith/len_function.txt >> ../len_function.txt 

echo "[INFO] Plotting microbenchmakr overhead and actions per second..."

./plot_micro_overhead.py ../benchmark.txt 
./plot_action_second.py ../benchmark.txt ../len_function.txt

echo "[DONE] Microbenchmark overhead and action per second in:"
echo " /sgxmonitor-src/scripts/micro-overhead.jpg"
echo " /sgxmonitor-src/scripts/action-second.jpg"
echo "[INFO] To export micro_overhead.jpg and action-second.jpg, run from the host:"
echo "docker cp <containerid>:/sgxmonitor-src/scripts/micro-overhead.jpg . "
echo "docker cp <containerid>:/sgxmonitor-src/scripts/action-second.jpg . "

popd