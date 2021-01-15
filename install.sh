#!/bin/bash

VLN_INST_DIR=/usr/sbin/
VLN_USER=vln
VLN_DAEMON_DIR=/usr/lib/systemd/system/

if [ ! `getent passwd $VLN_USER` ]
then
    useradd -r -M -d /nonexistent -c "vln_user" -s /usr/sbin/nologin $VLN_USER
fi

mkdir /etc/vln
cp etc/vln_server.conf /etc/vln/vln.conf
chmod 644 /etc/vln/vln.conf

cp build/vlnd $VLN_INST_DIR
cp vlnd.service $VLN_DAEMON_DIR

systemctl start vlnd

