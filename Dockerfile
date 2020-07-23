FROM golang:1.14-stretch as build
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
RUN go build -o est-server ./cmd/est-server


### Client

FROM ubuntu:18.04 as client
WORKDIR /
COPY --from=build /app/k8s-kms-plugin /k8s-kms-plugin
ENTRYPOINT ["/k8s-kms-plugin"]

FROM gcr.io/distroless/base-debian10 as est-server
WORKDIR /
COPY --from=build /app/est-server /est-server
ENTRYPOINT ["/est-server"]

FROM centos:7 as server
RUN yum install -y git softhsm glibc.i686 wget net-tools && \
    softhsm2-util --init-token --slot 0 --label default --so-pin changeme --pin changeme && \
    yum clean all
WORKDIR /
COPY --from=build /app/k8s-kms-plugin /k8s-kms-plugin
ENTRYPOINT ["/k8s-kms-plugin"]