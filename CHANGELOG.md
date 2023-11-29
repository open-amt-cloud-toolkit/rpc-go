<a name="v2.24.1"></a>
## [v2.24.1] - 2023-11-29
### Fix
- project version is updated

<a name="v2.24.0"></a>
## [v2.24.0] - 2023-11-29
### Build
- **deps:** bump golang.org/x/sys from 0.14.0 to 0.15.0

### Feat
- add UUID Override flag to maintenance commands

<a name="v2.23.0"></a>
## [v2.23.0] - 2023-11-27
### Build
- **deps:** bump github/codeql-action from 2.22.7 to 2.22.8
- **deps:** bump github/codeql-action from 2.22.6 to 2.22.7
- **deps:** bump step-security/harden-runner from 2.6.0 to 2.6.1
- **deps:** bump github/codeql-action from 2.22.5 to 2.22.6
- **deps:** bump golang from `96a8a70` to `110b07a`
- **deps:** bump github.com/open-amt-cloud-toolkit/go-wsman-messages

### Feat
- support AMTEnabled flag

<a name="v2.22.0"></a>
## [v2.22.0] - 2023-11-07
### Build
- **deps:** bump aquasecurity/trivy-action from 0.13.1 to 0.14.0

### Feat
- adds report out to code analysis action

<a name="v2.21.0"></a>
## [v2.21.0] - 2023-11-06
### Build
- **deps:** bump golang.org/x/sys from 0.13.0 to 0.14.0
- **deps:** bump github.com/gorilla/websocket from 1.5.0 to 1.5.1
- **deps:** bump software.sslmate.com/src/go-pkcs12 from 0.3.0 to 0.4.0
- **deps:** bump aquasecurity/trivy-action from 0.13.0 to 0.13.1
- **deps:** bump wagoid/commitlint-github-action from 5.4.3 to 5.4.4
- **deps:** bump golang from `926f7f7` to `96a8a70`

### Feat
- support smb: urls for remote .yaml or .pfx config files

<a name="v2.20.0"></a>
## [v2.20.0] - 2023-11-01
### Feat
- add local wifi enable and profile sync

<a name="v2.19.0"></a>
## [v2.19.0] - 2023-10-30
### Build
- **deps:** bump github/codeql-action from 2.22.4 to 2.22.5
- **deps:** bump software.sslmate.com/src/go-pkcs12 from 0.2.1 to 0.3.0

### Feat
- local operations read secrets from environment

<a name="v2.18.0"></a>
## [v2.18.0] - 2023-10-26
### Build
- **deps:** bump aquasecurity/trivy-action from 0.12.0 to 0.13.0
- **deps:** bump ossf/scorecard-action from 2.3.0 to 2.3.1
- **deps:** bump github/codeql-action from 2.22.3 to 2.22.4
- **deps:** bump actions/checkout from 4.1.0 to 4.1.1
- **deps:** bump github/codeql-action from 2.22.2 to 2.22.3

### Feat
- add device info maintenance

<a name="v2.17.0"></a>
## [v2.17.0] - 2023-10-13
### Build
- **deps:** bump github/codeql-action from 2.22.1 to 2.22.2

### Feat
- add features field to message payload

<a name="v2.16.1"></a>
## [v2.16.1] - 2023-10-12
### Build
- removes jenkinsfile
- **deps:** bump golang from `a76f153` to `926f7f7`
- **deps:** bump ossf/scorecard-action from 2.2.0 to 2.3.0
- **deps:** bump github/codeql-action from 2.21.9 to 2.22.0
- **deps:** bump golang from `1c9cc94` to `a76f153`
- **deps:** bump golang.org/x/sys from 0.12.0 to 0.13.0
- **deps:** bump golang from `4bc6541` to `1c9cc94`
- **deps:** bump step-security/harden-runner from 2.5.1 to 2.6.0
- **deps:** bump github/codeql-action from 2.22.0 to 2.22.1
- **deps:** bump golang from `ec31b7f` to `4bc6541`
- **deps:** bump github/codeql-action from 2.21.8 to 2.21.9
- **deps:** bump github.com/open-amt-cloud-toolkit/go-wsman-messages ([#240](https://github.com/open-amt-cloud-toolkit/rpc-go/issues/240))
- **deps:** bump golang from `96634e5` to `ec31b7f`

### Ci
- only release when semantic-release generates a new version
- automate publishing of docker images to dockerhub

### Fix
- update ProjectVersion to v2.16.1

<a name="v2.16.0"></a>
## [v2.16.0] - 2023-09-26
### Build
- **deps:** bump actions/checkout from 4.0.0 to 4.1.0

### Feat
- adds uuid flag to activate command

<a name="v2.15.2"></a>
## [v2.15.2] - 2023-09-20
### Build
- **deps:** bump github/codeql-action from 2.21.7 to 2.21.8
- **deps:** bump github.com/open-amt-cloud-toolkit/go-wsman-messages

### Ci
- update docker release

### Fix
- trigger ci build for release with docker

### Refactor
- amtinfo userCert password prompt ([#228](https://github.com/open-amt-cloud-toolkit/rpc-go/issues/228))

<a name="v2.15.1"></a>
## [v2.15.1] - 2023-09-15
### Build
- **deps:** bump github/codeql-action from 2.21.6 to 2.21.7
- **deps:** bump github/codeql-action from 2.21.5 to 2.21.6

### Ci
- add semantic-release-docker plugin
- adds exec plugin for [@semantic](https://github.com/semantic)-release

### Docs
- config file names and comments

### Fix
- add prompt for password acm local deactivation
- addwifisettings validate unique priorities

### Refactor
- config file names and comments

<a name="v2.15.0"></a>
## [v2.15.0] - 2023-09-13
### Build
- **deps:** bump docker/login-action from 2.2.0 to 3.0.0
- **deps:** bump golang from `445f340` to `96634e5`
- **deps:** bump actions/upload-artifact from 3.1.2 to 3.1.3
- **deps:** bump golang.org/x/sys from 0.11.0 to 0.12.0

### Ci
- add release tag to docker image

### Docs
- update badges

### Feat
- amtinfo display user certificates

### Refactor
- **utils:** creates type for return codes and makes variable names consistent ([#212](https://github.com/open-amt-cloud-toolkit/rpc-go/issues/212))

<a name="v2.14.2"></a>
## [v2.14.2] - 2023-09-08
### Fix
- ensure warning for CCM deactivation password flag

<a name="v2.14.1"></a>
## [v2.14.1] - 2023-09-06
### Fix
- addwifisettings - track added certs to prevent duplicates error

<a name="v2.14.0"></a>
## [v2.14.0] - 2023-09-06
### Build
- bump go-wsman-messages to v1.8.2 ([#205](https://github.com/open-amt-cloud-toolkit/rpc-go/issues/205))
- **deps:** bump actions/checkout from 3.6.0 to 4.0.0
- **deps:** bump aquasecurity/trivy-action
- **deps:** bump go-wsman-messages to v1.8.1
- **deps:** bump cycjimmy/semantic-release-action from 3.4.2 to 4.0.0
- **deps:** bump github/codeql-action from 2.21.4 to 2.21.5
- **deps:** bump actions/checkout from 3.5.3 to 3.6.0

### Feat
- local wifi configuration

<a name="v2.13.1"></a>
## [v2.13.1] - 2023-08-16
### Build
- **deps:** bump github/codeql-action from 2.21.3 to 2.21.4
- **deps:** bump docker/login-action from 1.6.0 to 2.2.0

### Ci
- push another image with a github tag

### Fix
- update ProjectVersion to 2.13.0

<a name="v2.13.0"></a>
## [v2.13.0] - 2023-08-14
### Build
- **deps:** bump github/codeql-action from 1.1.39 to 2.21.3
- **deps:** bump step-security/harden-runner from 2.5.0 to 2.5.1
- **deps:** bump aquasecurity/trivy-action
- **deps:** bump codecov/codecov-action from 3.1.3 to 3.1.4
- **deps:** bump golang.org/x/sys from 0.10.0 to 0.11.0
- **deps:** bump github.com/open-amt-cloud-toolkit/go-wsman-messages
- **deps:** bump actions/upload-artifact from 2.3.1 to 3.1.2
- **deps:** bump golang from 1.20-alpine to 1.21-alpine
- **deps:** bump actions/checkout from 3.1.0 to 3.5.3
- **deps:** bump actions/setup-dotnet from 2.1.1 to 3.2.0
- **deps:** bump danhellem/github-actions-issue-to-work-item
- **deps:** bump wagoid/commitlint-github-action from 4.1.15 to 5.4.3
- **deps:** bump actions/add-to-project from 0.3.0 to 0.5.0
- **deps:** bump ossf/scorecard-action from 2.0.6 to 2.2.0

### Ci
- [StepSecurity] Apply security best practices
- adds release notes generator and github to semantic release

### Feat
- activate in acm using local command

### Refactor
- result codes ([#185](https://github.com/open-amt-cloud-toolkit/rpc-go/issues/185))
- add configure command

<a name="v2.12.0"></a>
## [v2.12.0] - 2023-07-27
### Build
- **deps:** bump github.com/open-amt-cloud-toolkit/go-wsman-messages
- **deps:** bump github.com/ilyakaznacheev/cleanenv from 1.4.2 to 1.5.0

### Feat
- add local deactivation in ACM

### Refactor
- move command execution out of flags package

<a name="v2.11.1"></a>
## [v2.11.0] - 2023-07-14
### Fix
- password not set correctly for ccm activate

### Refactor
- **internal:** remove .parsed check

<a name="v2.11.0"></a>
## [v2.11.0] - 2023-07-10
### Build
- update version to v2.11.0
- **deps:** bump golang.org/x/sys from 0.9.0 to 0.10.0
- **deps:** bump github.com/open-amt-cloud-toolkit/go-wsman-messages
- **deps:** bump golang.org/x/sys from 0.8.0 to 0.9.0

### Ci
- added semantic release

### Feat
- add local CCM activate

### Fix
- allow for spaces in input parameters

### Refactor
- simplify friendly name

<a name="v2.10.0"></a>
## [v2.10.0] - 2023-06-16
### Build
- update version and changelog to v2.10.0

### Feat
- adds AMT Features to amtinfo
- support device friendly name

<a name="v2.9.1"></a>
## [v2.9.1] - 2023-06-08
### Build
- update version and changelog to v2.9.1
- **deps:** bump github.com/sirupsen/logrus from 1.9.2 to 1.9.3
- **deps:** bump github.com/stretchr/testify from 1.8.3 to 1.8.4

### Fix
- **internal:** GetOSDnsSuffixOS bug with docker desktop

<a name="v2.9.0"></a>
## [v2.9.0] - 2023-05-25
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

<a name="v2.8.0"></a>
## [v2.8.0] - 2023-05-18
### Build
- update version to 2.8.0 and changelog
- add tasks.json for vscode
- add launch.json to gitignore
- add various command templates for easy debugging in VSCode
- **deps:** bump github.com/sirupsen/logrus from 1.9.1 to 1.9.2 ([#129](https://github.com/open-amt-cloud-toolkit/rpc-go/issues/129))
- **deps:** bump github.com/sirupsen/logrus from 1.9.0 to 1.9.1 ([#127](https://github.com/open-amt-cloud-toolkit/rpc-go/issues/127))

### Feat
- deactivate a device in CCM from RPC

<a name="v2.7.0"></a>
## [v2.7.0] - 2023-05-04
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