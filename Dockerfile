## Basic test tool
FROM goboring/golang:1.14.6b4 as p11tool
ENV GOARCH amd64
ENV GOOS linux
ENV CGO_ENABLED 1
RUN GO111MODULE=off go get -u github.com/thales-e-security/p11tool

## build stack

FROM goboring/golang:1.14.6b4 as build
WORKDIR /app
ADD go.mod /app/go.mod
ADD go.sum /app/go.sum
ADD tools.go /app/pkg/tools.go
ADD vendor /app/vendor
ADD pkg /app/pkg
ADD apis /app/apis
ADD cmd/ /app/cmd/

ENV GOOS linux
ENV GOARCH amd64
ENV CGO_ENABLED 1
ENV GOFLAGS -mod=vendor
RUN go build -o k8s-kms-plugin ./cmd/k8s-kms-plugin


### Plugin Server
FROM ubuntu:20.04 as base-server
RUN apt-get update && apt-get install -y softhsm curl openssl libssl-dev && rm -rf /var/lib/apt/lists/
#RUN softhsm2-util --init-token --slot 0 --label default --so-pin changeme --pin changeme

#FROM centos:7 as base-server
#RUN yum install -y git softhsm glibc.i686 wget net-tools curl openssl-libs rsyslog && \
#    yum clean all

FROM base-server as kms-server
WORKDIR /
COPY --from=build /app/k8s-kms-plugin /k8s-kms-plugin
COPY --from=p11tool /go/bin/p11tool /usr/bin/p11tool
COPY scripts/start.sh /start.sh
RUN chmod +x /start.sh
ENTRYPOINT ["/start.sh"]