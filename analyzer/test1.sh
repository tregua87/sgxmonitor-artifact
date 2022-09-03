#!/bin/bash

./explore_traced_enclave.py -e ../../contact_enclave.signed.so -s 0 -d model-0-3.txt -l ./model_contact/loops-contact-new.txt -r error-0-3.txt -c Contact
