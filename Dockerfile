#*********************************************************************
# * Copyright (c) Intel Corporation 2021
# * SPDX-License-Identifier: Apache-2.0
# **********************************************************************

FROM golang:1.21-alpine@sha256:96a8a701943e7eabd81ebd0963540ad660e29c3b2dc7fb9d7e06af34409e9ba6 as builder
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
