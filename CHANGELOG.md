<a name="v2.4.0"></a>
## [v2.4.0] - 2022-11-07

### Build
- bump to v2.4.0

### Feat
- **maintenance:** add subcommands for syncip, syncclock, and changepassword

### Fix
- remove extra log.error statement

<a name="v2.3.0"></a>
## v2.3.0 - 2022-10-05

### Ci
- add junit test output

### Docs
- update changelog for v2.3.0

### Feat
- add warnings for link status and dns suffix
- added admin privilege check and AMT not found error check
- **amtinfo:** display wired only when wired adapter is available
- **win:** add admin privilege check

### Fix
- **amtinfo:** shouldnt display warnings on amtinfo
- **tls:** tls configuration now completes after TLS configuration

### Refactor
- **return codes:** replace log.Fatal with log.Error replace os.Exit calls
- **return-codes:** change tag error handling to continue instead of exit
- **status:** attempt to unmarshal error message

<a name="v2.2.0"></a>
## [v2.2.0] - 2022-05-09

### Build
- **version:** bump to v2.2.00

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