#!/bin/bash

# Check if libpcap-dev exists
if [ -f "/usr/include/pcap/pcap.h" ]
then
  echo "Found libpcap"
else
  echo "libpcap not found, installing"
  apt-get install libpcap-dev
fi

# Check if binary directory exists
if [ ! -d bin ]; then
    # create the directory
    mkdir -p bin
    echo "Created binary directory"
fi

echo "Compiling source"
g++ -o bin/packet_listener source/packet_listener.c -lpcap
g++ -o bin/packet_logger source/packet_logger.c source/libs/mongoose.c -lm
chmod 777 bin/packet_listener
chmod 777 bin/packet_logger
(cd bin && ./packet_logger enp3s0f0)
