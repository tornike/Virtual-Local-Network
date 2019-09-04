#!/bin/bash
if [ $EUID -ne 0 ]
 then
 echo "Please run installer as root"
 exit 1
fi

instdir=/opt/vln

mkdir $instdir
cp starter client vln.config $instdir
chmod +x $instdir/starter
chmod +x $instdir/client
chown $SUDO_USER: $instdir/starter
chown $SUDO_USER: $instdir/client
chown $SUDO_USER: $instdir/vln.config
chown $SUDO_USER: $instdir
setcap cap_net_admin=eip $instdir/starter
setcap cap_net_admin=eip $instdir/client
