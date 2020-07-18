.PHONY: all clean lint vet coverage
GOCMD:=go
GOCLEAN:=$(GOCMD) clean
GOTEST:=$(GOCMD) test
GOGET:=$(GOCMD) get
GOVET:=$(GOCMD) vet
GOLINT:=golint
SRCS:=$(wildcard *.go) $(wildcard jose/*.go)

all: clean lint vet coverage

clean:
		$(GOCLEAN)
		rm -f coverage.out

lint:
		$(GOLINT) -set_exit_status ./...

vet:
		$(GOVET) ./...

test:
		$(GOTEST) -gcflags=-l -short -race ./...

coverage: coverage.out

coverage.out: $(SRCS)
		$(GOTEST) -gcflags=-l -coverprofile coverage.out ./...
