.PHONY: build test lint vuln run install-tools clean setup

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

# Install all development tools. Re-run to upgrade.
install-tools:
	go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@latest
	go install github.com/securego/gosec/v2/cmd/gosec@latest
	go install golang.org/x/vuln/cmd/govulncheck@latest

setup:
	git config core.hooksPath hooks

clean:
	rm -rf bin/ coverage.out coverage.html results/
