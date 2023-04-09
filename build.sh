#!/bin/bash

# Should probably put all these libraries in a array/loop

# Check if libpcap-dev exists
if [ -f "/usr/include/pcap/pcap.h" ] 
then
  echo "Found libpcap"
else
  echo "libpcap not found, installing"
  sudo apt-get install libpcap-dev
fi

# Check if libjson-c-dev exists
if [ -f "/usr/include/json-c/json.h" ]
then
  echo "Found libjson-c-dev"
else
  echo "libjson-c-dev not found, installing"
  sudo apt-get install libjson-c-dev
fi

binary_dir="bin"
source_dir="source"

# Check if binary directory exists
if [ ! -d $binary_dir ]; then
    # create the directory
    mkdir -p $binary_dir
    echo "Created binary directory $binary_dir"
fi

packet_listener="packet_listener"
packet_logger="packet_logger"

echo "Compiling source"
gcc "$source_dir/$packet_listener.c" -o "$binary_dir/$packet_listener" -lpcap
gcc "$source_dir/$packet_logger.c" "$source_dir/libs/mongoose.c" -o "$binary_dir/$packet_logger"
chmod 777 "$binary_dir/$packet_listener"
chmod 777 "$binary_dir/$packet_logger"

(cd bin && ./packet_logger enp3s0f0)
