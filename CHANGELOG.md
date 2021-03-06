<a name="v2.2.0"></a>
## [v2.2.0] - 2022-05-09

### Build
- **version:** bump to v2.2.0

### Ci
- add build for sample
- **docker:** ensure docker build occurs in PR checks
- **lint:** adds semantic checks to PRs

### Docs
- **changelog:** update version
- **readme:** add command for shared library build
- **readme:** remove unnecessary prerequisites

### Feat
- **build:** adds support for c-shared buildmode
- **logging:** adds support for fine grained control of log ouput

### Fix
- **heci:** adds retry for device busy

### Refactor
- **lms:** rewrite lme communication in go
- **main:** eliminate need for CGO if not buildling library

## [v2.1.0] - 2022-03-18
### Build
- **docker:** C style comments are not valid in Dockerfiles
- **version:** update version to v2.1.0

### Ci
- **jenkinsfile:** removes protex scan
- **workflow:** only uploads codecov for 20.04

### Docs
- **docker:** how to build and run using Docker

### Feat
- **activate:** prompts for password when device is activated
- **cli:** Remove ControlModeRaw from json
- **cli:** Add json flag to version command
- **log:** adds -json option to all rpc commands
- **output:** adds json output for amtinfo command

### Fix
- update password with user input

### Refactor
- **pthi:** converts amt and pthi commands to go from C

<a name="v2.0.0"></a>
## v2.0.0 - 2021-11-08
### Build
- **dockerfile:** adds license header

### Ci
- update default branch name to main for jobs
- add docker and changelog builds
- update codeql build command
- add codeql
- **jenkins:** create jenkinsfile

### Docs
- add contributing guidlines
- add license and security guidelines

### Feat
- add environment variable support
- add heartbeat support
- **hostname:** can now override hostname of device by passing -h as command line arg
- **maintenance:** add time sync for AMT
- **rpc:** initial commit

### Fix
- dns suffix and trim string outputs for commands
- **version:** add version output to cli command

### Refactor
- rename mps to rps for accurate naming
- **rpc:** organize code to be unit testable


