# SgxMonitor Artifact for ACSAC 2022

These document summarizes and redirects to important sub-documents for
installing and exercide the artifact.

- [Installation](#installation)
- [Usage](#usage)

## Installation

We provide three options to evaluate the artifcat. Reviewers can choose the
options that most fit their needs.

- SSH access to precunfigured environment ([here](#ssh-access))
- Downloading docker container ([here](#download-docker-container))
- Installing from source ([here](INSTALLATION.md))

### SSH Access

Use the code below to access the machine
```
ssh -h <magic magic magic>
```

### Download Docker Container

This link is to download an already build Docker container (TODO). In addition,
one can build and run the docker from skracth with:
```
 ./run_docker.sh
```
**NOTE:** the host machine needs to install the Intel SGX Legacy driver
(https://github.com/intel/linux-sgx-driver). We succesfully tested the artifcat
with last version.

## Usage

We organize the flow by following the evaluation section (Section 7).

### Preparation

- Compile
- Extract model

### Execution-flow attacks (Section 7.1.1)

- SnakeGX
- ShadowStack attack

### Micro-benchmark (Section 7.2.1 -- Figure 4)

- Run `vanilla` vs `toplaywith` versions

### Macro-benchmark (Section 7.2.2 -- Figure 5)

**Note:** running macro-benchmark requires to use human-interactive software
(VLC and SGX-Biniax2), that is hardly scriptable. We thus omit these from the
artifact. However, we leave the whole documented code and the instructions to
install and try our prototypes indipendently.

- Slealthdb

### Model Extractor (Section 7.2.3 -- Table 2)

- script the get static analysis
- script to make the table

### Use Case Analysis (Appendix B -- Table 3)

- script for the complexity
- script for the table