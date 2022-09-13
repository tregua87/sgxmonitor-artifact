# SgxMonitor Artifact for ACSAC 2022

These document summarizes and redirects to important sub-documents for
installing and exercising the artifact.

- [Installation](#installation)
- [Usage](#usage)

## Installation

We provide three options to install the artifcat. Reviewers can choose the
one that most fits their needs.

- SSH access to a precunfigured environment ([here](#ssh-access))
- Downloading docker container ([here](#download-docker-container))
- Installing from source ([here](INSTALLATION.md))

### SSH Access

Use the code below to access the machine
```
ssh -h <magic magic magic>
docker run -it sgx-monitor-artifact
```

From here, please follow the instruction in [usage](#usage).


### Download Docker Container

We provide a running Docker container at this link (**TODO**). In addition, one
can build and run the docker from scratch with:
```
 ./run_docker.sh
```
**NOTE:** the host machine needs the Intel SGX Legacy driver
(https://github.com/intel/linux-sgx-driver). We succesfully tested the artifcat
with last version.

## Usage

We organize the flow by following the evaluation section (Section 7).

### Preparation

- Compile
- Extract model

### Execution-flow attacks (Section 7.1.1)

- SnakeGX, expected outcome:
```
[ERROR] Edges [edges-norm.txt] NOT match the model [data_snakegx/model-n.txt]
```

- ShadowStack attack expected outcome:
```
[ERROR] Edges [/sgxmonitor-src/src/monitor_toplaywith/edges.txt] NOT match the model [data_security/model-n.txt]
The runtime return address is not coherent with the shadowstack value
```


### Micro-benchmark (Section 7.2.1 -- Figure 4)

- Run `vanilla` vs `toplaywith` versions

### Macro-benchmark (Section 7.2.2 -- Figure 5)

**Note:** Some macro-benchmark requires to use human-interactive software
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

---

Shield: [![CC BY-NC-SA 4.0][cc-by-nc-sa-shield]][cc-by-nc-sa]

This work is licensed under a
[Creative Commons Attribution-NonCommercial-ShareAlike 4.0 International License][cc-by-nc-sa].

[![CC BY-NC-SA 4.0][cc-by-nc-sa-image]][cc-by-nc-sa]

[cc-by-nc-sa]: http://creativecommons.org/licenses/by-nc-sa/4.0/
[cc-by-nc-sa-image]: https://licensebuttons.net/l/by-nc-sa/4.0/88x31.png
[cc-by-nc-sa-shield]: https://img.shields.io/badge/License-CC%20BY--NC--SA%204.0-lightgrey.svg