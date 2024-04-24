#!/bin/bash

# modify or create test_runs.csv and modify n_enc variable automatically by 500
# to prepare csv for generating graph of accuracy for different numbers of encryptions observed

# DELETE test_runs.csv if you want to run a new experiment without old data!

HEADER="extract.h"

for (( i= 3500; i <  30500; i += 500))
do
    sed -i "/#define n_enc/c\#define n_enc ($i)" $HEADER
    make || exit
    ./test
done