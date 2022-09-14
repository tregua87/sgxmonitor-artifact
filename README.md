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

Use the code below to access the machine: 

```
ssh -h <magic magic magic>
docker run -it sgx-monitor-artifact
```

We set a dedicated user, called `reviewer`. whose password is stated in the
artifact abstract (for security reason not published here).  `reviewer` does not
have `root` permits (i.e., no `sudo`), it can `tmux` tho. We suggest to run the
docker inside a `tmux` session for keeping the session alive.

From here, please follow the instruction in [usage](#usage).

### Download Docker Container

We provide a running Docker container at this link (**TODO**). In addition, one
can build and run the docker from scratch with:
```
 ./run_docker.sh
 docker run -it --device=/dev/isgx sgx-monitor-docker
```
**NOTE:** the host machine needs the Intel SGX Legacy driver
(https://github.com/intel/linux-sgx-driver). We succesfully tested the artifcat
with last version.

From here, please follow the instruction in [usage](#usage).

## Usage

We organize the artifact upon the evaluation section (Section 7). However, we
did not strictly follow the evaluation section for technical reasons (i.e., we
need models to verify the enclave execution). Each step in the artifact
evaluation specifies which experiment in Section 7 it refers to.

The main folder in the docker container is `/sgxmonitor-src`. We assume all the
relative paths and the main commands are fired from this directory.

### Preparation

Once enter in the docker, compile all the enclave by running this command:
```
./run_compileall.sh
```
This operation should take max 10 minutes.

### Model Extractor (Section 7.2.3 -- Table 2)

The script kicks the symbolic execution. This part might take few hours.
```
run_analysis.sh
```
**Important:** We implement timeout for the symbolic execution through
`timedecoretor` of Python. However, we observed that this approach sometime does
not stop the execution. This bug is over our control. Therefore, if the analysis
does not stop after 3 hours (or the machine memory reaches 100% -- `top`), we
*strongly* suggest stopping the execution (i.e., `Ctrl+C`) and use the
pre-compiled models, that can be installed with the following command:
```
./get_precompiled_model.sh
```

Once obtained the models, you can print the content of Table 2 with the following script:
```
./plot_table_coverage.sh
```


### Micro-benchmark (Section 7.2.1 -- Figure 4)

From the folder `/sgxmonitor-src`, run the following command for obtaining the results in Figure 4.

```
run_microbenchmark.sh
```
This command should take less than an hour to complete.

**Only for remote machine:**
If you are in the remote machine, the host contains this script:
```
./download_images_from_docker.sh
```
It will automatically download all the images from the running Docker.

### Macro-benchmark (Section 7.2.2 -- Figure 5)

From the folder `/sgxmonitor-src`, run the following command for obtaining the results in Figure 5.

```
run_macrobenchmark.sh
```
This command should take less than an hour to complete.

**Note:**  Since VLC and SGX-Biniax2 require human-interaction, we include only
StealthDB benchmark. We will include detailed documentation to install and try
the other prototypes independently.

**Only for remote machine:**
If you are in the remote machine, the host contains this script:
```
./download_images_from_docker.sh
```
It will automatically download all the images from the running Docker.

### Execution-flow attacks (Section 7.1.1)

We provide scripts to replicate the attacks in Section 7.1.1.

**SnakeGX:**

Run this command:

```
run_snakegxeval.sh
```

The standard output should containd this message:

```
[ERROR] Edges [edges-norm.txt] NOT match the model [data_snakegx/model-n.txt]
```

**ShadowStack attack:**

Run this script:

```
run_shadowstackeval.sh
```
The standard output should containd this message:
```
[ERROR] Edges [/sgxmonitor-src/src/monitor_toplaywith/edges.txt] NOT match the model [data_security/model-n.txt]
The runtime return address is not coherent with the shadowstack value
```

### Use Case Analysis (Appendix B -- Table 3)

**TODO:**
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