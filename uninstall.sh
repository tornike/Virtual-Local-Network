#!/bin/bash

VLN_CONFIG_DIR=/etc/vln
VLN_INST_DIR=/usr/sbin
VLN_DAEMON_DIR=/etc/systemd/system
VLN_USER=vln

echo -n "Stopping daemon..."
systemctl stop vlnd
if [ $? -eq 0 ]
then
    echo "Done."
fi

echo "Removing files..."

echo -n "$VLN_INST_DIR/vlnd..."
rm $VLN_INST_DIR/vlnd
if [ $? -eq 0 ]
then
    echo "Done."
fi

echo -n "$VLN_DAEMON_DIR/vlnd.service..."
rm $VLN_DAEMON_DIR/vlnd.service
if [ $? -eq 0 ]
then
    echo "Done."
fi

echo -n "Removing user $VLN_USER... "
userdel $VLN_USER
if [ $? -eq 0 ]
then
    echo "Done."
fi

systemctl daemon-reload
echo "All Done."
