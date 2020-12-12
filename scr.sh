#!/bin/bash

if [ $1 = emu.c ]; then
    make && ./emu ch28.bin
elif [ $1 = remote.js ]; then
    frida -l remote.js -f ch28.bin --no-pause
else
    echo "nothing to be done"
fi

