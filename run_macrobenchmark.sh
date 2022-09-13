#!/bin/bash

set -e

if [[ ! $(pgrep -f aesm_service) ]]; then
    LD_LIBRARY_PATH=/opt/intel/sgxpsw/aesm/ /opt/intel/sgxpsw/aesm/aesm_service --no-daemon &
else
    echo "[INFO] aesm_service already running!!"
fi

# clean previous logs
pushd src/stealthdb_toplaywith/benchmark
rm -Rf vanilla_*
rm -Rf sgxmonitor_*
popd

service postgresql start

pushd src/client
make Clientpic.o
popd

pushd src/stealthdb_vanilla
make
make install
popd

pushd src/stealthdb_vanilla/benchmark

# set postgres password
su postgres -c "psql -c \"ALTER USER postgres WITH PASSWORD 'postgres';\""
su postgres -c "echo 'postgres' | psql -h localhost -U postgres -c \"CREATE USER test WITH PASSWORD 'password';\""
su postgres -c "echo 'postgres' | psql -h localhost -U postgres -c \"CREATE DATABASE test;\""
su postgres -c "echo 'postgres' | psql -h localhost -U postgres -d test -c \"CREATE EXTENSION encdb;SELECT generate_key();SELECT load_key(0);\""
su postgres -c "echo 'password' | psql -h localhost -U test -d test -f db_schemas/tpcc-schema.sql"


# template command
# java -Dlog4j.configuration=log4j.properties -jar bin/oltp.jar -b tpcc -o output -s 10 --config config/tpcc_config.xml --load true --execute true
for scale_factor in 1 2 4 8 16
do
    java -Dlog4j.configuration=log4j.properties -jar bin/oltp.jar -b tpcc -o output -s $scale_factor --config config/tpcc_config.xml --load true --execute true
    mv results $SGXMONITOR_PATH/src/stealthdb_toplaywith/benchmark/vanilla_$scale_factor
done
popd

# clear stuffs for next macrobenchmark run
su postgres -c "echo 'postgres' | psql -h localhost -U postgres -d postgres -c \"DROP DATABASE test;\""
su postgres -c "echo 'postgres' | psql -h localhost -U postgres -d postgres -c \"DROP USER test;\""

# START AGAIN WITH EMPTY DATASET

pushd src/stealthdb_toplaywith
make
make install
popd

pushd src/stealthdb_vanilla/benchmark

# set postgres password
su postgres -c "psql -c \"ALTER USER postgres WITH PASSWORD 'postgres';\""
su postgres -c "echo 'postgres' | psql -h localhost -U postgres -c \"CREATE USER test WITH PASSWORD 'password';\""
su postgres -c "echo 'postgres' | psql -h localhost -U postgres -c \"CREATE DATABASE test;\""
su postgres -c "echo 'postgres' | psql -h localhost -U postgres -d test -c \"CREATE EXTENSION encdb;SELECT generate_key();SELECT load_key(0);\""
su postgres -c "echo 'password' | psql -h localhost -U test -d test -f db_schemas/tpcc-schema.sql"

# template command
# java -Dlog4j.configuration=log4j.properties -jar bin/oltp.jar -b tpcc -o output -s 10 --config config/tpcc_config.xml --load true --execute true
for scale_factor in 1 2 4 8 16
do
    java -Dlog4j.configuration=log4j.properties -jar bin/oltp.jar -b tpcc -o output -s $scale_factor --config config/tpcc_config.xml --load true --execute true
    mv results $SGXMONITOR_PATH/src/stealthdb_toplaywith/benchmark/sgxmonitor_$scale_factor
done
popd

# clear stuffs for next macrobenchmark run
su postgres -c "echo 'postgres' | psql -h localhost -U postgres -d postgres -c \"DROP DATABASE test;\""
su postgres -c "echo 'postgres' | psql -h localhost -U postgres -d postgres -c \"DROP USER test;\""


echo "[INFO] Plotting macrobenchmark latency and request per second..."

pushd scripts
./stealthdb_macrobenchmark_oltp.py $SGXMONITOR_PATH/src/stealthdb_toplaywith/benchmark/
popd

echo "[DONE] Macrobenchmark latency and request per second in:"
echo " /sgxmonitor-src/scripts/latency_2.jpg"
echo " /sgxmonitor-src/scripts/request_per_second.jpg"
echo "[INFO] To export latency_2.jpg and request_per_second.jpg, run from the host:"
echo "docker cp <containerid>:/sgxmonitor-src/scripts/latency_2.jpg . "
echo "docker cp <containerid>:/sgxmonitor-src/scripts/request_per_second.jpg . "
