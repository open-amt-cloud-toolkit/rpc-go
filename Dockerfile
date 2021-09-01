FROM golang:1.17-alpine as builder
RUN apk update
RUN apk upgrade
RUN apk add gcc libc-dev  linux-headers libexecinfo-dev 
WORKDIR /rpc
COPY . .
RUN CGO_LDFLAGS="-lexecinfo" GOOS=linux GOARCH=amd64 go build -o /build/rpc ./cmd


FROM alpine:latest
RUN apk add libexecinfo 
COPY --from=builder /build/rpc /rpc
ENTRYPOINT ["/rpc"]
