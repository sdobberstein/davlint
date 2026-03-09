.PHONY: build test lint vuln run clean setup

BINARY  := bin/davlint
VERSION := 0.1.0-dev
LDFLAGS := -ldflags="-w -s -X main.version=$(VERSION)"

build:
	go build $(LDFLAGS) -o $(BINARY) ./cmd/davlint

test:
	go test -race -coverprofile=coverage.out ./...
	go tool cover -html=coverage.out -o coverage.html

lint:
	go vet ./...
	golangci-lint run

vuln:
	govulncheck ./...
	gosec ./...

run:
	go run ./cmd/davlint

setup:
	git config core.hooksPath hooks

clean:
	rm -rf bin/ coverage.out coverage.html results/
