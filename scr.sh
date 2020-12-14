#!/bin/bash

if [ $1 = elf64.c ]; then
    make && ./elf64 test_bins/ch28.bin
elif [ $1 = elf32.c ]; then
    make && ./elf32 test_bins/ch13
elif [ $1 = remote.js ]; then
    frida -l remote.js -f ch28.bin --no-pause
else
    echo "nothing to be done"
fi

