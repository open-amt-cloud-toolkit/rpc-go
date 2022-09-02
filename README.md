# RPC Beta

> Disclaimer: Production viable releases are tagged and listed under 'Releases'. All other check-ins should be considered 'in-development' and should not be used in production

## Prerequisites 

1) Install GO https://golang.org/

## Build

### Windows

#### As executable: 
```
go build -o rpc.exe ./cmd/main.go
```
#### As Library: 
```
go build -buildmode=c-shared -o rpc.dll ./cmd
```

### Linux

#### As executable: 
```
go build -o rpc ./cmd/main.go
```

#### As Library: 
```
go build -buildmode=c-shared -o librpc.so ./cmd   
```
### Docker image

```bash
docker build -t openamt:rpc-go .
```

and then you can run it using

```bash
$ docker run --rm -it --device /dev/mei0 openamt:rpc-go amtinfo
Version			    : 15.0.30
Build Number		: 1776
SKU			        : 16392
UUID			    : a94a55cc-267e-11b2-a85c-e2a9c1f3470e
Control Mode		: pre-provisioning state
DNS Suffix		    : 
DNS Suffix (OS)		: 
Hostname (OS)		: bd2e72e5d572
RAS Network      	: unknown
RAS Remote Status	: not connected
RAS Trigger      	: user initiated
RAS MPS Hostname 	: 
---Wired Adapter---
DHCP Enabled 		: true
DHCP Mode    		: active
Link Status  		: down
IP Address   		: 0.0.0.0
MAC Address  		: 00:00:00:00:00:00
---Wireless Adapter---
DHCP Enabled 		: true
DHCP Mode    		: passive
Link Status  		: down
IP Address   		: 0.0.0.0
MAC Address  		: 00:00:00:00:00:00
```
