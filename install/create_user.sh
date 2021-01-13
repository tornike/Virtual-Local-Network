#!/bin/bash

if [ $EUID -ne 0 ]
 then
 echo "Please run as root"
 exit 1
fi

useradd -M -d /nonexistent -c "vln user" -s /usr/sbin/nologin vlnd
