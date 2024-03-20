#!/bin/bash

make
addr=$(python kallsyms.py)
sudo insmod spybot.ko kallsyms_lookup_addr="$addr"
