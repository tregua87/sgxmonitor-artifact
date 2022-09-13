#!/bin/bash


# sudo pkill -9 monitor
pkill -9 monitor

# NOTE: you need to fix this variable in the script because postgres fucks 
# thing up
# TLDR: I did not manage to use the env variable in the postgres extension
# sorry, ddl too close!
SGXMONITOR_PATH=/sgxmonitor-src
mtr=$SGXMONITOR_PATH/src/monitor_batch/monitor
dir=$SGXMONITOR_PATH/src/monitor_batch/

(cd $dir && $mtr) &

sleep 1

exit 0
