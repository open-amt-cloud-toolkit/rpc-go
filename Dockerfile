#*********************************************************************
# * Copyright (c) Intel Corporation 2021
# * SPDX-License-Identifier: Apache-2.0
# **********************************************************************

FROM golang:1.21-alpine@sha256:30a46e750f1b22656de03fa7d5e3225d6069cb4e80a4f62a770c97854d1a46d6 as builder
RUN apk update
RUN apk upgrade
RUN apk add --no-cache git
WORKDIR /rpc
COPY . .
RUN CGO_ENABLED=0 LDFLAGS="-s -w" GOOS=linux GOARCH=amd64 go build -o /build/rpc ./cmd/main.go


FROM scratch
LABEL license='SPDX-License-Identifier: Apache-2.0' \
      copyright='Copyright (c) Intel Corporation 2021'
COPY --from=builder /build/rpc /rpc
ENTRYPOINT ["/rpc"]
