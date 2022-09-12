# TODOs for SgxMonitor Artifact

These are the evaluations:

## Fixes:
- collect "statistics.txt" into coverage-data.txt coherently
- stealthdbo macrobenchmark:
    - change abs path in stealthdb_toplaywith
    - for s from 1 2 4 8 16
    - mv vanilla$i/toplaywith$i

## Security evaluation:
Control-flow attacks (Sec. 7.1.1):
To check if I need to compile or use a pre-compiled version.
- SnakeGX [`stealthdb_toplaywith`]:
    - Compile (or give a precompiled one?)
    - Runtime + trace (so need asmed)
    - Extract module (or give one already extracted?)
    - Verify attacks (injection and backdoor activation)
- ShadowStack [`security_traced_toplaywith`]:
    - Compile (or give a precompiled one?)
    - Runtime + trace (so need asmed)
    - Extract module (or give one already extracted?)
    - Verify attacks (injection and backdoor activation)

## Usage evaluation:
Micro-benchmark (Sec. 7.2.1)
List of enclaves to compile (in `src`):
- **preliminary:** `monitor_toplaywith` (to check if it is the correct one)
- `contact_traced_toplaywith`
- `contact_vanilla`
- `custom_traced_toplaywith`
- `custom_vanilla`
- `libdvdcss-sgx_traced_toplaywith`
- `libdvdcss-sgx_vanilla`
- `sgx-biniax2_traced_toplaywith`
- `sgx-biniax2_vanilla`
- `stealthdb_toplaywith` (`src/microbenchmark`)
- `stealthdb_vanilla` (`src/microbenchmark`)

Macro-bencmark (Sec. 7.2.2)
Only stealthdb + guide for VLC and sgx-biniax2
- Compile stealthdb (??)
- Install postgres (update docker!!)
- Install stealthdb (move .so somewhere and pray it works!)
- run `stealhdb_benchmark/run_benchmkar.py` (it should work)

## Trace validation
1. extract model symex `explore_decomposed_sym_enclave.py`
3. normalize models (make scripts?)
4. verifies vs microbenchmark (`validate.py`)  

## Appendix B
1. extract model static `explore_decomposed_std_enclave.py` (make script)
2. run `statistic_analysis/run_analysis.sh`
3. try trace (from microbenchmark) vs different models? this is for Appendix B


# Plan for the reviewers:

A set of script for each *macro* step.  

1) compile monitor + enclaves 
    - snakegx/security? check stability
2) install stealthdb into postgres (to append to previous scripts)
3) get models (symex, static, symex+static)
4) run microbenchmark
5) run macrobenchamrk
6) run attacks (mabe move this pont above)
7) check model
