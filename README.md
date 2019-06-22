# pathfinder

Finds paths through programs while detecting crashes. It can find these by itself or support afl in finding them.

## setup

This requires dynamorio (for tracing), afl (for classic fuzzing) and angr (for symbolic execution).
* you might want to disable swapping with swapoff -a

## run

`python fuzzer.py -i <inputs> "<target commandline>"`

## misc

Just ported the project to python3, there are some things that don't work yet.