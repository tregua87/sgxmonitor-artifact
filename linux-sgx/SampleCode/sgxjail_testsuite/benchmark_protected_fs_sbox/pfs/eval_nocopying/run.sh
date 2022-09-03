#!/bin/bash

NUMBER_OF_ITERATIONS=200
CHUNKS=1
PAYLOAD_SIZE=1048576


GOV=userspace
# Check performance
cpufreq-info -g | grep ${GOV}
if [[ "$?" -ne "0" ]]; then
  echo "Unable to change CPU frequency! Possible reasons:"
  echo "A) Wrong driver loaded. Required driver: 'acpi-cpufreq'. Current driver: $(cpufreq-info -d)"
  echo "B) CPU govenor '${GOV}' not available. Available govenors: $(cpufreq-info -g)"
  echo "   See https://www.kernel.org/doc/Documentation/cpu-freq/governors.txt"
  echo ""
  echo "To solve A:"
  echo "1. Open /etc/default/grub"
  echo "2. Add 'intel_pstate=disable' to GRUB_CMDLINE_LINUX_DEFAULT"
  echo "3. Run 'sudo update-grub'"
  echo "4. Reboot"
  exit -1
fi

# fail on error
set -e

# Set performance to max.
MIN=$(cpufreq-info -l | awk '{ print $1 }')
MAX=$(cpufreq-info -l | awk '{ print $2 }')

echo "Fixing CPU frequency..."
sudo cpufreq-set -r -g ${GOV}
for j in `seq 1 $(nproc)`; do
  i=$((j-1))
  sudo cpufreq-set -c $i -f ${MAX}
done

echo "Govenor: $(cpufreq-info -p)"
for j in `seq 1 $(nproc)`; do
  i=$((j-1))
  sudo cpufreq-set -c $i -f ${MAX}
  FREQ=$(cpufreq-info -c $i -f)
  echo "CPU$i freq: ${FREQ}"
done

########################################################################
make -C .. clean &> /dev/null
make -C .. SGX_PRERELEASE=1 SGX_DEBUG=0 PAYLOAD_SIZE=${PAYLOAD_SIZE} &> /dev/null
DIR=$PWD
pushd ..
./app OWRITE ${NUMBER_OF_ITERATIONS} ${CHUNKS} > $DIR/sbox_pfs_${PAYLOAD_SIZE}_${CHUNKS}_chunks.csv;
popd
cat sbox_pfs_${PAYLOAD_SIZE}_${CHUNKS}_chunks.csv | ./eval.py
