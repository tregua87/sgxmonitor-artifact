#!/bin/bash

docker build -t sgx-monitor-docker -f docker/Dockerfile .

# NOTE: you need SGX legacy driver to work properly!
# docker run -it --device=/dev/isgx sgx-monitor-docker
# docker run -it --device=/dev/isgx -v .:./sgxmonitor-src sgx-monitor-docker
