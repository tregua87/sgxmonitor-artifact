#!/bin/bash


# sudo pkill -9 monitor
sudo pkill -9 monitor

mtr=$SGXMONITOR_PATH/src/monitor_batch/monitor
dir=$SGXMONITOR_PATH/src/monitor_batch/

(cd $dir && $mtr) &

sleep 1

exit 0
