# Get version from the first argument
version=$1

docker build -t vprodemo.azurecr.io/rpc-go:v$version . 

# Build for Linux
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags "-s -w -X 'rpc/pkg/utils.ProjectVersion=$version'" -trimpath -o rpc_linux_x64 ./cmd/main.go
CGO_ENABLED=0 GOOS=linux GOARCH=386 go build -ldflags "-s -w -X 'rpc/pkg/utils.ProjectVersion=$version'" -trimpath -o rpc_linux_x86 ./cmd/main.go

# Build for Windows
CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -ldflags "-s -w -X 'rpc/pkg/utils.ProjectVersion=$version'" -trimpath -o rpc_windows_x64.exe ./cmd/main.go 
CGO_ENABLED=0 GOOS=windows GOARCH=386 go build -ldflags "-s -w -X 'rpc/pkg/utils.ProjectVersion=$version'" -trimpath -o rpc_windows_x86.exe ./cmd/main.go

# Build library for Linux
CGO_ENABLED=1 GOOS=linux GOARCH=amd64 go build -ldflags "-s -w" -trimpath -buildmode=c-shared -o rpc.so.$version ./cmd

# Mark the Unix system outputs as executable
chmod +x rpc_linux_x64
chmod +x rpc_linux_x86

# Add them to tar files respectively
tar cvfpz rpc_linux_x64.tar.gz rpc_linux_x64
tar cvfpz rpc_linux_x86.tar.gz rpc_linux_x86
tar cvfpz rpc_linux_x86.tar.gz rpc_linux_x86
tar cvfpz rpc_so_x64.tar.gz rpc.so.$version

# Add Windows build to a zip file
zip rpc_windows_x64.zip rpc_windows_x64.exe
zip rpc_windows_x86.zip rpc_windows_x86.exe

# Generate license files
go-licenses save ./... --include_tests --save_path=licensefiles

# Create a zip file for license files
zip -r licenses.zip licensefiles/