# SgxMonitor

Source code of SgxMonitor, a runtime remote attestation schema for SGX encalves.

Here the main folders with relative more importan scripts.
Below, a list of other folders.

## HOW TO ANALYZE AN ENCLAVE

**Preparation:**

- Compile, have a look at `custom_trace_batch` to understand how to set the monitor communication, the LLVM pass and so on.
- Run `./analyzer/get_inline_functions.py` to extract the inlined functions.
- Compile again.

**Analysis:**

This is for insensitive static analysis, used as groundtruth.

- Run `./analyzer2/explore_decomposed_stc_enclave.py`, to extract the model with insensitive static analysis.
- Run `./analyzer2/normalize_model.py`, to get the respective normalized model.

This is for dynamic (symbolic) analysis.

- Run `./analyzer3/extract_loops.py`, this will extract loops from the enclave.
- Run `./analyzer3/./explore_decomposed_sym_enclave.py`, this will handle all the burned (besides some customizations, go with God for that!). Output expected: `model.txt` and `model-insensitive.txt`.
- Run `./analyzer3/normalize_model.py`, input both `model.txt` and `model-insensitive.txt`. Output expected `model-n.txt`.
- Run `./analyzer3/check_coverage.py`, to get coverage against the enclave itself.
- Run `./analyzer2/compare-model.py`, to compare the model witht the insensitive static one (i.e., `./analysis2/explore_decomposed_stc_enclave.py` *normalized* output).


## Analyzer

Folder `./analyzer`.  
It contains the first enclave analyzer based on angr - currently deprecated. 

- `./get_inline_functions.py`: a script that finds inlined functions, to be used in combination with the LLVM instrumentation pass (N.B. the pass is in another repository).

## Analyzer2

Folder `./analyzer2`.  

- `./explore_decomposed_stc_enclave.py`: a static decomposer analyzer that applies insensitive static analysis function by function.

## Analyzer3

Folder `./analyzer3`.  

- `./explore_decomposed_sym_enclave.py`: the main analyzer. It performs symbolic execution to each function, uses the loops information from `./extract_loops.py`, handles timeout, and automatically invokes `./explore_decomposed_stc_enclave.py` to those functions that reached timeout. It can also be customzed, see `./lib/customization.py`.
- `./normalize_model.py`: normalize the model from `./explore_decomposed_sym_enclave.py` and `./explore_decomposed_stc_enclave.py` into a graph of actions.
- `./check_coverage.py`: check the coverage of a model (from either `./explore_decomposed_sym_enclave.py` or `./explore_decomposed_stc_enclave.py`) against the enclave.
- `./compare-model.py`: compare the model extracted dynamically with the one extracted with insensitive static analysis.
- `./extract_loops.py`: extracts loops from an encalve, to use before `./explore_decomposed_sym_enclave.py`.
- `./normalize_edges.py`: some traces from `monitor_toplaywith` need to be normalized, i.e., extract the relative addresses. This is done by using the `T[., 0x0]` action from their respective model.
- `./validate.py`: validates the actions traced by `monitor_toplaywith` agains the normalized model from `./normalize_model.py`.
- `./get_all_id.py`: don't remember why I need it.

## Scripts

Folder `./scripts`. Mainly to make plots and synthetize results.

- `./runExperiments.py`: it runs the microbenchmark.
- `./stealthdb_macrobenchmark.py`: run macrobenchmrk for stealthdb.
- `./multiply.py`: generates `multiply.eps`
- `./make_ration.py`: generates `action-second.eps`

Deprecated:

- `./validate_plain.py`.
- `./validate.py`.
- `./bars_len.py`.
- `./bars.py`: generates `overhead.png`.
- `./nbench.py`: small test for nbench.

## Results

Folder `./results`.

- `./len_functions.txt`: number of actions for each secure function executed.
- `./benchmark.txt`: execution time of secure functions as vanilla, traced, traced batch, and other configurations that I don't remember now.
- `./macro-benchmark.txt`: macro benchmark from VLC.

## Other folders

- `./inc`: contains headers to include for the compilation.
- `./sgxsdki`: contains the compiled instrumented `tRts` Intel SGX SDK.
- `./linux-sgx-i`: the source code for the instrumented Intel SGX SDK.
- `./linux-sgx`: the sourcec code for the Intel SGX SDK.
- `./stealhdb_benchmark`: queries for macrobenchmark against StealthDB.
- `./vanilla_src`: bucket of *vanilla* code, mainly test and miscellaneous stuffs.
- `./src`: source code for SgxMonitor runtimes. It contains many configurations of `client`, `traced`-part of the enclave, `monitor`, and `enclaves` for microbenchmarking.