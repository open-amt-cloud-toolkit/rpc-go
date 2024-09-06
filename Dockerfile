#*********************************************************************
# * Copyright (c) Intel Corporation 2021
# * SPDX-License-Identifier: Apache-2.0
# **********************************************************************

FROM golang:1.23-alpine@sha256:436e2d978524b15498b98faa367553ba6c3655671226f500c72ceb7afb2ef0b1 as builder

RUN apk update && apk upgrade && apk add --no-cache git

WORKDIR /rpc
COPY . .

# Install go-licenses
RUN go install github.com/google/go-licenses@latest

# Generate license files
RUN go-licenses save ./... --include_tests --save_path=licensefiles

# Build rpc
RUN CGO_ENABLED=0 LDFLAGS="-s -w" GOOS=linux GOARCH=amd64 go build -o /build/rpc ./cmd/main.go

FROM scratch
LABEL license='SPDX-License-Identifier: Apache-2.0' \
      copyright='Copyright (c) Intel Corporation 2021'

COPY --from=builder /build/rpc /rpc
COPY --from=builder /rpc/licensefiles /licensefiles

ENTRYPOINT ["/rpc"]
