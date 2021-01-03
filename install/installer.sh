#!/bin/bash
if [ $EUID -ne 0 ]
 then
 echo "Please run installer as root"
 exit 1
fi

instdir=/opt/vln

mkdir $instdir
mkdir ~/.vln/
cp vlnstarter vlnclient vlnserver $instdir
cp vln.config ~/.vln/
chmod +x $instdir/vlnstarter
chmod +x $instdir/vlnclient
chown $SUDO_USER: $instdir/vlnstarter
chown $SUDO_USER: $instdir/vlnclient
chown $SUDO_USER: ~/.vln/vln.config
chown $SUDO_USER: $instdir
chown $SUDO_USER: ~/.vln/
setcap cap_net_admin=eip $instdir/vlnstarter
setcap cap_net_admin=eip $instdir/vlnclient
