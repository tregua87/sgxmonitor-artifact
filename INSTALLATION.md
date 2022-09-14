# Manual Installation

To execute SGX Monitor, we need an SGX machine that supports SGX Legacy driver.  
We tested our system on an Ubuntu 18.04 with Kernel version `5.4.0-124-generic`.

**Driver:**  
To install the SGX Legacy drivers, please refer to this repo:
```
https://github.com/intel/linux-sgx-driver
```

**SGX Monitor:**  
Then, we prepare a bash script to install the main SGX Monitor components.
```
./install.sh
```
The script recalls the Docker installation. 

Once done, the folder `$SGXMONITOR_PATH` contains all the `./run_*` script described in [usage](README.md#usage).