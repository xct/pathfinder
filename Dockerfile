#Download base image ubuntu 16.04
FROM ubuntu:16.04

# Update Ubuntu Software repository
RUN dpkg --add-architecture i386
RUN apt-get update

# Install os dependencies
RUN apt-get install -y git virtualenvwrapper python-pip python2.7-dev build-essential libxml2-dev libxslt1-dev git libffi-dev cmake libreadline-dev libtool debootstrap debian-archive-keyring libglib2.0-dev libpixman-1-dev libqt4-dev binutils-multiarch nasm libssl-dev cmake g++ g++-multilib doxygen transfig imagemagick ghostscript git libc6:i386 libgcc1:i386 libstdc++6:i386 libtinfo5:i386 zlib1g:i386 nano speech-dispatcher

# setup afl
RUN git clone https://github.com/mcarpenter/afl.git
WORKDIR $PROJECT_HOME/afl
RUN make
WORKDIR $PROJECT_HOME/

# setup angr-dev
RUN git clone https://github.com/angr/angr-dev.git
RUN pip install --upgrade pip
RUN pip install diskcache
RUN echo "I know this is a bad idea." | angr-dev/setup.sh

# setup dynamorio
RUN git clone https://github.com/DynamoRIO/dynamorio.git
RUN mkdir dynamorio/build32 && mkdir dynamorio/build64
WORKDIR $PROJECT_HOME/dynamorio/build32  
RUN CFLAGS="-m32" CXXFLAGS="-m32" cmake .. && make -j 4
WORKDIR $PROJECT_HOME/dynamorio/build64 
RUN cmake .. && make -j 4
WORKDIR $PROJECT_HOME/

# setup pathfinder
RUN git clone git@github.com:xct/pathfinder.git
WORKDIR $PROJECT_HOME/pathfinder
RUN git clone git@github.com:xct/challenges.git
WORKDIR $PROJECT_HOME/pathfinder/tracer
RUN ./build.sh

#build challenges
WORKDIR $PROJECT_HOME/pathfinder/challenges/
RUN ./build.sh
WORKDIR $PROJECT_HOME/

# create temp directory within home for pathfinder
RUN mkdir tmp/in
RUN python -c 'print "A"*200' > tmp/in/seed
WORKDIR $PROJECT_HOME/pathfinder