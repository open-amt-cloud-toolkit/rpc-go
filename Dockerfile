#*********************************************************************
# * Copyright (c) Intel Corporation 2021
# * SPDX-License-Identifier: Apache-2.0
# **********************************************************************

FROM golang:1.20-alpine@sha256:7efb78dac256c450d194e556e96f80936528335033a26d703ec8146cec8c2090 as builder
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
