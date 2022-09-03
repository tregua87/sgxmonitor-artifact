#!/bin/bash

EOCALLS=500
OCALLS=100

# Select which benchmarks to enable
BENCH_EOCALLS=0
BENCH_OCALLS=1
BENCH_PFS=0

#for pfs
NUMBER_OF_ITERATIONS=200
MIN_PAYLOAD_SIZE=1
MAX_PAYLOAD_SIZE=1048576

RESULTS=$PWD/bench_results_both
SBOXPFS=sbox_pfs
VANILLAPFS=vanilla_pfs

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

echo "${FREQ}" > ${RESULTS}/cpufreq.txt

########################################################################

# Benchmark vanilla
pushd benchmark_program_vanilla/sgx
echo "Building vanilla"
make clean &> /dev/null
make SGX_PRERELEASE=1 SGX_DEBUG=0 &> /dev/null
if [[ "${BENCH_EOCALLS}" -eq "1" ]]; then
  echo "Benchmarking vanilla ECALLS"
  ./app ECALLS ${EOCALLS} > ${RESULTS}/vanilla_ecalls_${EOCALLS}.csv
  echo "Benchmarking vanilla OCALLSSingle"
  ./app OCALLSSingle ${EOCALLS} > ${RESULTS}/vanilla_ocallsSingle_${EOCALLS}.csv
fi
if [[ "${BENCH_OCALLS}" -eq "1" ]]; then
  echo "Benchmarking vanilla OCALLS"
  ./app OCALLS ${OCALLS} > ${RESULTS}/vanilla_ocalls_${OCALLS}.csv
  echo "Benchmarking vanilla OCALLS Baseline"
  ./app OCALLSBaseline ${OCALLS} > ${RESULTS}/vanilla_ocallsBaseline_${OCALLS}.csv
fi
popd

# Benchmark sbox
pushd benchmark_program_sbox/sgx
echo "Building sbox"
make clean &> /dev/null
make SGX_PRERELEASE=1 SGX_DEBUG=0 &> /dev/null
if [[ "${BENCH_EOCALLS}" -eq "1" ]]; then
  echo "Benchmarking sbox ECALLS"
  ./app ECALLS ${EOCALLS} > ${RESULTS}/sbox_ecalls_${EOCALLS}.csv
  echo "Benchmarking sbox OCALLSSingle"
  ./app OCALLSSingle ${EOCALLS} > ${RESULTS}/sbox_ocallsSingle_${EOCALLS}.csv
fi
if [[ "${BENCH_OCALLS}" -eq "1" ]]; then
  echo "Benchmarking sbox OCALLS"
  ./app OCALLS ${OCALLS} > ${RESULTS}/sbox_ocalls_${OCALLS}.csv
fi
popd

########################################################################

if [[ "${BENCH_PFS}" -eq "1" ]]; then
  if [[ -d "${RESULTS}/${SBOXPFS}" ]]; then
    echo "Folder ${RESULTS}/${SBOXPFS} already exists! Delete first"
    exit 1
  fi
  if [[ -d "${RESULTS}/${VANILLAPFS}" ]]; then
    echo "Folder ${RESULTS}/${VANILLAPFS} already exists! Delete first"
    exit 1
  fi
  # Benchmark sbox pfs
  # WRITE = WRITE + READ (change SIZE_PAYLOAD_KB for that)
  # OWRITE power of two chunks always 1MB Payload hardcoded
  pushd benchmark_protected_fs_sbox/pfs
  mkdir -p ${RESULTS}/${SBOXPFS}
  FILESZ=$MIN_PAYLOAD_SIZE
  while [[ "$FILESZ" -le "$MAX_PAYLOAD_SIZE" ]]; do
    CHUNKS=1
    while [  $CHUNKS -le $FILESZ ]; do
      echo "Benchmarking pfs sbox with filesize ${FILESZ} and ${CHUNKS} chunks"
      make clean &> /dev/null
      make SGX_PRERELEASE=1 SGX_DEBUG=0 PAYLOAD_SIZE=${FILESZ} &> /dev/null
      ./app OWRITE ${NUMBER_OF_ITERATIONS} ${CHUNKS} > ${RESULTS}/${SBOXPFS}/sbox_pfs_${FILESZ}_${CHUNKS}_chunks.csv;
      rm -f SGX_FILE.txt
      ((CHUNKS = CHUNKS * 2))
      CHUNKS=$((FILESZ+1)) # Force abort after 1 iteration
    done
    ((FILESZ = FILESZ * 2))
  done
  popd

  # Benchmark vanilla pfs
  # WRITE = WRITE + READ (change SIZE_PAYLOAD_KB for that)
  # OWRITE power of two chunks always 1MB Payload hardcoded
  pushd benchmark_protected_fs_vanilla/pfs
  mkdir -p ${RESULTS}/${VANILLAPFS}
  FILESZ=$MIN_PAYLOAD_SIZE
  while [[ "$FILESZ" -le "$MAX_PAYLOAD_SIZE" ]]; do
    CHUNKS=1
    while [  $CHUNKS -le $FILESZ ]; do
      echo "Benchmarking pfs vanilla with filesize ${FILESZ} and ${CHUNKS} chunks"
      make clean &> /dev/null
      make SGX_PRERELEASE=1 SGX_DEBUG=0 PAYLOAD_SIZE=${FILESZ} &> /dev/null
      ./app OWRITE ${NUMBER_OF_ITERATIONS} ${CHUNKS} > ${RESULTS}/${VANILLAPFS}/vanilla_pfs_${FILESZ}_${CHUNKS}_chunks.csv;
      rm -f SGX_FILE.txt
      ((CHUNKS = CHUNKS * 2))
      CHUNKS=$((FILESZ+1)) # Force abort after 1 iteration
    done
    ((FILESZ = FILESZ * 2))
  done
  popd
fi

# Evaluate results
pushd bench_results_both
source pyenv.sh
echo "Execute the following:"
echo "source pyenv.sh"
echo "./evaluate.py ${EOCALLS} --ocalls ${OCALLS} --pfsvanilla vanilla_pfs --pfssbox sbox_pfs --show=False --freq=True"
./evaluate.py ${EOCALLS} --ocalls ${OCALLS} --pfsvanilla vanilla_pfs --pfssbox sbox_pfs --show=False --freq=True
popd
