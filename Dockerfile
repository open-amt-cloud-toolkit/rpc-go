#*********************************************************************
# * Copyright (c) Intel Corporation 2021
# * SPDX-License-Identifier: Apache-2.0
# **********************************************************************

FROM golang:1.23-alpine@sha256:6c5c9590f169f77c8046e45c611d3b28fe477789acd8d3762d23d4744de69812 as builder

RUN apk update && apk upgrade && apk add --no-cache git

WORKDIR /rpc
COPY . .

# Install go-licenses
RUN go install github.com/google/go-licenses@latest
# Generate license files
RUN go-licenses save ./... --save_path=licenses

# Build rpc
RUN CGO_ENABLED=0 LDFLAGS="-s -w" GOOS=linux GOARCH=amd64 go build -o /build/rpc ./cmd/main.go

FROM scratch
LABEL license='SPDX-License-Identifier: Apache-2.0' \
      copyright='Copyright (c) Intel Corporation 2021'

COPY --from=builder /build/rpc /rpc
#go-licenses will install when ./build.sh is executed
COPY --from=builder /rpc/licenses /licenses

ENTRYPOINT ["/rpc"]
