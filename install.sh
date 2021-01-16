#!/bin/bash

VLN_CONFIG_DIR=/etc/vln
VLN_INST_DIR=/usr/sbin
VLN_DAEMON_DIR=/etc/systemd/system
VLN_USER=vln

echo -n "Creating user $VLN_USER... "
getent passwd $VLN_USER &> /dev/null
GETENT_RES=$?
if [ $GETENT_RES -eq 0 ]
then
    echo "User $VLN_USER already exists."
elif [ $GETENT_RES -eq 2 ]
then
    useradd -r -M -d /nonexistent -c "vln user" -s /usr/sbin/nologin $VLN_USER
    if [ $? -eq 0 ]; then
        echo "Done."
    else
        exit 1
    fi
else
    echo "Failed to create user."
    exit 1
fi

echo -n "Creating directory $VLN_CONFIG_DIR... "
if [ -d $VLN_CONFIG_DIR ]
then
    echo "Directory $VLN_CONFIG_DIR already exists."
else
    if mkdir $VLN_CONFIG_DIR
    then
        echo "Done."
    else
        exit 1
    fi
fi

echo "Copying files..."
echo -n "$VLN_CONFIG_DIR/vln.conf..."
cp etc/vln.conf $VLN_CONFIG_DIR/vln.conf
chmod 644 /etc/vln/vln.conf
echo "Done."

echo -n "$VLN_INST_DIR/vlnd..."
cp build/vlnd $VLN_INST_DIR/
echo "Done."

echo -n "$VLN_DAEMON_DIR/vlnd.service..."
cp vlnd.service $VLN_DAEMON_DIR/
echo "Done."

systemctl daemon-reload
echo "All Done."
echo "Type 'systemctl start vlnd' to start daemon."
