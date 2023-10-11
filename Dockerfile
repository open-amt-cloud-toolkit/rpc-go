#*********************************************************************
# * Copyright (c) Intel Corporation 2021
# * SPDX-License-Identifier: Apache-2.0
# **********************************************************************

FROM golang:1.21-alpine@sha256:926f7f7e1ab8509b4e91d5ec6d5916ebb45155b0c8920291ba9f361d65385806 as builder
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
