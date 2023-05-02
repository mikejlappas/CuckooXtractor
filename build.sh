#!/bin/bash

mkdir -p build
gcc -Iinclude/ -O3 -s -Wall source/*.c -o build/CuckooXtractor
