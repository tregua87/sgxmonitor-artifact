
## Build the Intel(R) SGX default Quote Provider Library
- To set the environment variables, enter the following command:
```
  $ source ${SGX_PACKAGES_PATH}/sgxsdk/environment
```
- To build the Intel(R) SGX default Quote Provider Library, enter the following command:
```
   $ cd qpl/linux
   $ make
```
The target library named ``libdcap_quoteprov.so`` will be generated.

You will also need to build  Intel(R) SGX default Collateral Network Library because the Quote Provider Library depends on it:
```
   $ cd qcnl/linux
   $ make
```

The target library named ``libsgx_default_qcnl_wrapper.so`` will be generated.
 - To clean the files generated by previous `make` command, enter the following command:
```
  $ make clean
```

 - To build debug libraries, enter the following command:
```
  $ make DEBUG=1
```
## Configuration

#### Linux
The configuration file for Intel(R) SGX default Quote Provider Library under Linux is /etc/sgx_default_qcnl.conf. If it is not present, the library will use hard-coded configurations.

#PCCS_URL is the URL of your PCCS caching service, the hard-coded value is https://localhost:8081/sgx/certification/v1/
PCCS_URL=https://your_pccs_server:8081/sgx/certification/v1/
#Should always set to TRUE for production environment. Set it to FALSE if PCCS server uses self-signed certificate and key 
USE_SECURE_CERT=TRUE
#### Windows
Intel(R) SGX default Quote Provider Library reads configuration data from Windows Registry, and hard-coded values will be used if the keys don't exist.

[HKEY_LOCAL_MACHINE\SOFTWARE\Intel\SGX\QCNL]
"PCCS_URL"="https://localhost:8081/sgx/certification/v1/"
"USE_SECURE_CERT"=drord:00000000
