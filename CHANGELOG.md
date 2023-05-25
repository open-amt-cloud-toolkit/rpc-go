<a name="2.9.0"></a>
## [2.9.0] - 2023-05-25
### Build
- update version and changelog for v2.9.0
- **deps:** bump github.com/stretchr/testify from 1.8.2 to 1.8.3

### Ci
- add trivy container scan

### Feat
- **cli:** addwifisettings directly without cloud interaction

### Refactor
- **internal:** move each command to its own file

### Test
- move flag tests to respective files for better organization

<a name="2.8.0"></a>
## [2.8.0] - 2023-05-18
### Build
- update version to 2.8.0 and changelog
- add tasks.json for vscode
- add launch.json to gitignore
- add various command templates for easy debugging in VSCode
- **deps:** bump github.com/sirupsen/logrus from 1.9.1 to 1.9.2 ([#129](https://github.com/open-amt-cloud-toolkit/rpc-go/issues/129))
- **deps:** bump github.com/sirupsen/logrus from 1.9.0 to 1.9.1 ([#127](https://github.com/open-amt-cloud-toolkit/rpc-go/issues/127))

### Feat
- deactivate a device in CCM from RPC

<a name="2.7.0"></a>
## [2.7.0] - 2023-05-04
### Build
- update version to 2.7.0, update changelogbuild: update version to 2.6.0, update changelog
- update go to 1.20
- **deps:** bump golang.org/x/sys from 0.5.0 to 0.6.0
- **deps:** bump github.com/stretchr/testify from 1.8.1 to 1.8.2
- **deps:** bump github.com/gorilla/websocket from 1.4.2 to 1.5.0
- **deps:** bump github.com/sirupsen/logrus from 1.7.0 to 1.9.0
- **deps:** bump github.com/stretchr/testify from 1.7.0 to 1.8.1
- **deps:** bump golang.org/x/sys from 0.3.0 to 0.5.0

### Ci
- add go fmt and format code
- update github runners
- adds dependabot config
- **deps:** bump codecov to 3.1.3 ([#119](https://github.com/open-amt-cloud-toolkit/rpc-go/issues/119))

### Docs
- add discord info ([#111](https://github.com/open-amt-cloud-toolkit/rpc-go/issues/111))

### Feat
- **utils:** add -f (force) flag

### Fix
- **rps:** rpc will exit instead of hang when connection fails to rps

<a name="v2.6.0"></a>
## [v2.6.0] - 2023-02-16
### Build
- update version to 2.6.0, update changelog
- **docker:** update golang base to 1.19

### Ci
- set os to 18.04
- fix changelog job
- add ossf action

### Docs
- align format to match other repositories
- add ossf badge to readme

### Feat
- added flag tenantId
- **rps:** added proxy support

### Fix
- proper processing of command line flags

### Refactor
- adds new return codes

<a name="v2.5.0"></a>
## [v2.5.0] - 2022-12-08
### Build
- update version to 2.5.0, update changelog

### Ci
- pin .net core build
- update actions/checkout to v3, update semantic
- add azure board sync
- add project sync to rpc-go

### Feat
- **AMTtimeout:** Handle wait if AMT is not ready
- **cli:** sync hostname

### Refactor
- update log messages to be a bit more clear

<a name="v2.4.0"></a>
## [v2.4.0] - 2022-11-07

### Build
- bump to v2.4.0

### Feat
- **maintenance:** add subcommands for syncip, syncclock, and changepassword

### Fix
- channel recipient channel should not be 0
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