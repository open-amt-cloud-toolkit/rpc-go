[![OpenSSF Scorecard](https://api.securityscorecards.dev/projects/github.com/open-amt-cloud-toolkit/rpc-go/badge)](https://api.securityscorecards.dev/projects/github.com/open-amt-cloud-toolkit/rpc-go)

# Remote Provisioning Client (RPC) Beta
<em>Used for activation, deactivation, maintenance, and status of an AMT device</em>

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
docker build -t rpc-go:latest .
```

## Run

Install the executable on a target device and then run from a terminal/shell
command line with <b>adminstrator privileges</b>.  

For usage, call the executable with no additional parameters.  

### Windows
```shell
.\rpc
```

### Linux
```bash
sudo ./rpc
```

### Docker
```bash
$ docker run --rm -it --device /dev/mei0 rpc-go:latest
```
