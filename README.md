# Virtual Local Network #

VLN is a network virtualization software for linux, which allows you to create virtual
local networks over existing one. Using vln, hosts can communicate with each other as 
they were directly connected in LAN.

VLN does this by tunneling traffic through publicly accessible rendezvous server, but
always tries to connect network hosts directly, using hole punching technique.

## Installation ##

VLN requires `libconfig-dev`, `libcap-dev` packages to be installed.
For installation just run `make install` from source directory.

## Usage ##

#### Starting vlnd:
```
systemctl start vlnd
```
#### Stopping vlnd:
```
systemctl stop vlnd
```
#### Restarting vlnd:
```
systemctl restart vlnd
```

### Config file:

VLN can be configured with configuration file: `vln.conf` located in `/etc/vln/`.
File contains 2 main directives: `servers` and `clients`.

Base on the blocks in `servers` directive, `vlnd` creates networks and serves as, upper
mentioned, rendezvous server, example:
```
servers = 
(
	{
		network_name = "network1"
		network_subnet = "172.16.2.0/28"
		bind_address = "0.0.0.0"
		bind_port = "33508"
	},
  {
		network_name = "network2"
		network_subnet = "192.168.10.0/24"
		bind_address = "0.0.0.0"
		bind_port = "33509"
	}
)
```

On the other hand, `clients` directive combines configurations about networks `vlnd` should
connect to, for example:
```
clients = 
(
	{
		network_name = "network1"
		address = "192.168.33.17" # here should be publicly accesible address of the server
		port = "33508"
	},
  {
		network_name = "network2"
		address = "192.168.33.17"
		port = "33509"
	}
)
```

Configuration file is read only ones by vlnd, at startup, so in order for configuration changes
to take effect you must restart `vlnd` service.

For traffic vln uses udp ephemeral ports, so firewall shouldn't be blocking them.

