#!/bin/bash
if ! [ $(id -u) = 0 ]; then
   echo "No root privileges.  Please run as root!"
   exit 1
fi
