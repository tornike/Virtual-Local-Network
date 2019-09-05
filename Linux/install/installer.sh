#!/bin/bash
if [ $EUID -ne 0 ]
 then
 echo "Please run installer as root"
 exit 1
fi

instdir=/opt/vln

mkdir $instdir
cp vlnstarter vlnclient vln.config $instdir
chmod +x $instdir/vlnstarter
chmod +x $instdir/vlnclient
chown $SUDO_USER: $instdir/vlnstarter
chown $SUDO_USER: $instdir/vlnclient
chown $SUDO_USER: $instdir/vln.config
chown $SUDO_USER: $instdir
setcap cap_net_admin=eip $instdir/vlnstarter
setcap cap_net_admin=eip $instdir/vlnclient
