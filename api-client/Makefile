VERSION ?= dev
LDFLAGS := -s -w -X github.com/vasyakrg/vaultls-agent/internal/version.Version=$(VERSION)

.PHONY: test build deb clean

test:
	go test ./...

build:
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags "$(LDFLAGS)" -o dist/vaultls-agent ./cmd/vaultls-agent

deb: build
	VERSION=$(VERSION) nfpm pkg --packager deb --config packaging/nfpm.yaml --target dist/

clean:
	rm -rf dist
