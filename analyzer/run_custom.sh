#!/bin/bash

DUMP_FILE=../results/analysis-time-custom.txt 
ENCLAVE=../../custom_enclave.signed.so
LOOPFILE=loops-custom.txt

echo "" > $DUMP_FILE

for I in {0..6}
do
    echo "secure function $I" &>> $DUMP_FILE
    echo "" > model-$I.txt
    { time ./explore_traced_enclave.py -e $ENCLAVE -s $I -d model-$I.txt -l $LOOPFILE -r error-$I.txt 2> /dev/null ; } 2>> $DUMP_FILE
    echo "-----" &>> $DUMP_FILE
done

echo "exception" &>> $DUMP_FILE
echo "" > model-exception.txt
{ time ./explore_exception_enclave.py -e $ENCLAVE -d model-exception.txt -l $LOOPFILE -r error-exception.txt 2> /dev/null ; } 2>> $DUMP_FILE
echo "-----" &>> $DUMP_FILE
