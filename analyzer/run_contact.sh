#!/bin/bash

DUMP_FILE=../results/analysis-time-contact.txt 
ENCLAVE=../../contact_enclave.signed.so
LOOPFILE=./model_contact/loops-contact.txt

echo "" > $DUMP_FILE

for I in {0..10}
do
    echo "secure function $I" &>> $DUMP_FILE
    echo "" > model-$I.txt
    { time ./explore_traced_enclave.py -e $ENCLAVE -s $I -d model-$I.txt -l $LOOPFILE -r error-$I.txt -c Contact 2> /dev/null ; } 2>> $DUMP_FILE
    echo "-----" &>> $DUMP_FILE
done

echo "exception" &>> $DUMP_FILE
echo "" > model-exception.txt
{ time ./explore_exception_enclave.py -e $ENCLAVE -d model-exception.txt -l $LOOPFILE -r error-exception.txt -c Contact 2> /dev/null ; } 2>> $DUMP_FILE
echo "-----" &>> $DUMP_FILE
