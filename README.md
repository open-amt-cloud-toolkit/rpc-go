# Remote Provisioning Client (RPC)

![CodeQL](https://github.com/open-amt-cloud-toolkit/rpc-go/actions/workflows/codeql-analysis.yml/badge.svg?branch=main&event=push) 
![codecov.io](https://codecov.io/github/open-amt-cloud-toolkit/rpc-go/coverage.svg?branch=main) 
[![OpenSSF Scorecard](https://api.securityscorecards.dev/projects/github.com/open-amt-cloud-toolkit/rpc-go/badge)](https://api.securityscorecards.dev/projects/github.com/open-amt-cloud-toolkit/rpc-go) 
[![Discord Shield](https://discordapp.com/api/guilds/1063200098680582154/widget.png?style=shield)](https://discord.gg/yrcMp2kDWh)
[![Docker Pulls](https://img.shields.io/docker/pulls/intel/oact-rpc-go)](https://hub.docker.com/r/intel/oact-rpc-go)

> Disclaimer: Production viable releases are tagged and listed under 'Releases'. All other check-ins should be considered 'in-development' and should not be used in production

RPC is used for activation, deactivation, maintenance, and status of an AMT device
The Remote Provisioning Client (RPC) is an application that assists with activation, configuration, and maintenance of for Intel® AMT devices. RPC provides source code that must be compiled into a binary to run or library for integration with other client applications.

---

**For detailed documentation** about Getting Started or other features of the Open AMT Cloud Toolkit, see the [docs](https://open-amt-cloud-toolkit.github.io/docs/).

---


## Prerequisites 

- [Golang](https://go.dev/dl/)

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

<br>

## Additional Resources

- For detailed documentation and Getting Started, [visit the docs site](https://open-amt-cloud-toolkit.github.io/docs).

- Looking to contribute? [Find more information here about contribution guidelines and practices](.\CONTRIBUTING.md).

- Find a bug? Or have ideas for new features? [Open a new Issue](https://github.com/open-amt-cloud-toolkit/rpc-go/issues).

- Need additional support or want to get the latest news and events about Open AMT? Connect with the team directly through Discord.

    [![Discord Banner 1](https://discordapp.com/api/guilds/1063200098680582154/widget.png?style=banner2)](https://discord.gg/yrcMp2kDWh)