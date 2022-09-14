# TODOs for SgxMonitor Artifact

These are the evaluations:

## Fixes:
- export images CONTAINER_ID=$(docker ps -f "ancestor=sgx-monitor-docker" --format '{{.ID}}')
- guide to install VLC and SGX-Biniax
- import already built models/enclaves

## Trace validation
1. extract model symex `explore_decomposed_sym_enclave.py`
3. normalize models (make scripts?)
4. verifies vs microbenchmark (`validate.py`)  

## Appendix B
1. extract model static `explore_decomposed_std_enclave.py` (make script)
2. run `statistic_analysis/run_analysis.sh`
3. try trace (from microbenchmark) vs different models? this is for Appendix B
