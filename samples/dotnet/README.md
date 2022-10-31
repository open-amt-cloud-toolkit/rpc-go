# CSharp sample leveraging rpc-go as a library

## Howto for Ubuntu Linux
Install dotnet sdk if needed via snap
```shell
sudo snap install dotnet-sdk
```

From the rpc-go root directory, build the csharp executable
```shell
dotnet build samples/dotnet/client.csproj
```
This will create the directory samples/dotnet/bin/Debug/net6.0/  

Build a shared object library from the rpc-go sources
and just put it directly into the bin folder created above  
NOTE: REQUIRES GCC INSTALLATION  
NOTE: standard library naming presented here  
NOTE: assumes the dotnet SDK version is 6.0, check the bin path and adjust as needed
```
# at the root of the rpc-go project with the command
go build -buildmode=c-shared -o samples/dotnet/bin/Debug/net6.0/librpc.so ./cmd
```

On Ubuntu, there seems to be issues with Console.WriteLine showing up in
the command line termninal. Execute the csharp .dll directly rather than
using ```dotnet run```  
NOTE: the path of the .dll is created from ```dotnet build``` step.
Check the path and .dll name on the build system
```shell
dotnet samples/dotnet/bin/Debug/net6.0/client.dll
```
