#!/bin/bash

# Fail on error
set -e

# Turn off NIC's
sudo ifconfig enp0s31f6 down
sudo ifconfig wlp4s0 down

# Turn off monitor and lock screen
xset dpms force off
#gnome-screensaver-command -l &

set +e

sleep 1
#espeak "Start"

# Run actual benchmark

taskset 0x4 ./run.sh

#espeak "Stop"

# For overnight benchmarking
#systemctl suspend

sudo ifconfig enp0s31f6 up
sudo ifconfig wlp4s0 up
xset dpms force on
