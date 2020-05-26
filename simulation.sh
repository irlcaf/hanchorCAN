#!/bin/bash
TARGET_DIR="/home/irlcaf/Documents/Cybersecurity research/CAN_simulation"
cd "$TARGET_DIR"

if [[ $EUID -ne 0 ]]; then
    echo "This script must be run with sudo, use sudo instead "$0" instead" 1>&2
    exit 1
fi

echo "Creating virtual interface: vcan0"
sudo modprobe vcan
sudo ip link del vcan0
sudo ip link add dev vcan0 type vcan 
sudo ip link set up vcan0 

#directory=pwd
input="candump-2020-05-13_121432.log"

while IFS= read -r line; do
    #output=$(python3 hanchorCAN.py ${line:31:47})
    reading_line=${line:31:47}
    #echo $reading_line
    if [ -z "$reading_line" ]
    then
        continue
    else
        echo "Python hanchorCAN executing..."
        #echo $reading_line
        output=$(python3 hanchorCAN.py $reading_line)
    fi
    python3 sim.py
done < "$input"

#output=$(python3 hanchorCAN.py E3EDEB4068CFDF28)
#echo $output