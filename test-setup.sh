#!/bin/bash

# this script sets the programs and versions used as targets in the master thesis
# this creates a projects directory at the folder level where pathfinders folder is

cd ..
mkdir projects
cd projects

# libyaml
git clone https://github.com/yaml/libyaml.git libyaml
cd libyaml
git checkout 0.1.5
./bootstrap
./configure "LDFLAGS=-static"
make -j4
cd ..


# libjasper
mkdir jasper
mkdir jasper/build
git clone https://github.com/mdadams/jasper.git jasper/src
cd jasper/src
git checkout version-1.900.1
cd ../build
./configure "LDFLAGS=-static"
#cmake -DJAS_ENABLE_SHARED=OFF ../src # this is for current versions
make -j4
cd ../..


# giflib
git clone https://github.com/rcancro/giflib.git giflib
cd giflib
git checkout 5.1.1
./autogen.sh
./configure "LDFLAGS=-static"
make -j4
cd ..