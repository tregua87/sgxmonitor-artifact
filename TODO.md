# TODOs for SgxMonitor Artifact

These are the evaluations:

## Fixes:
- collect "statistics.txt" into coverage-data.txt coherently
- in `./run_snakegxeval.sh`, if `data_snakegx` does not exist, then exit
- nice to shadowstack experiment
- script for printing models
- prepared pre-computed models and find a way to download them `get_precompiled_model.sh`
- export images CONTAINER_ID=$(docker ps -f "ancestor=sgx-monitor-docker" --format '{{.ID}}')
- for secureenclave: get address with `RET_FUNC=$(objdump -M intel -d enclave.signed.so | grep "48 8b 7d 08" | head -1 | awk -F ":" '{print $1}' | tr -d " ")' and set ad -D var in Makefile
- guide to install VLC and SGX-Biniax
- analyzer2 -> fix for contact?

## Trace validation
1. extract model symex `explore_decomposed_sym_enclave.py`
3. normalize models (make scripts?)
4. verifies vs microbenchmark (`validate.py`)  

## Appendix B
1. extract model static `explore_decomposed_std_enclave.py` (make script)
2. run `statistic_analysis/run_analysis.sh`
3. try trace (from microbenchmark) vs different models? this is for Appendix B
