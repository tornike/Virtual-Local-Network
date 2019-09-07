# Virtual-Local-Network

VLN is a network virtualization software, with it you can create and connect to private networks. Devices in same network can communicate
with each other as they were directly connected, like LAN, despite NAT or blocked LANs.

Behind the scenes, VLN is trying to connect devices directly, peer to peer, using udp punching. if p2p connection fails, traffic is 
redirected with server.

In order to operate, VLN needs server which will be accessible in public network. At this moment one server is up and ready for 
connection, it's address is written in vln.config. Of course it can be changed, server can be anyone if it's satisfies upper mentioned 
condition.

Information about networks is stored on server, so different servers will have different networks.

At this moment vln just works on Linux operating system.

Using VLN is very simple, you just need to download install folder and run installer.sh as root. By default vln is installed in
/opt/vln directory.

After installation you must communicate vlnclient with vlnstarter.
you can either create new network, connect and disconnect from already connected one:
  vlnstarter disconnect
  vlnstarter connect {network name} {network password}
  vlnstarter create {network name} {network password} {subnet}
  parameters in {} must be changed to desired names.
  Example of Subnet: 172.6.2.0/28.

You also can build it by yourself but you will need this packages:
  libjson-c-dev
  sqlite3
  libsqlite3-dev

