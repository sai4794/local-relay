BINARY    := relay
VERSION   := $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
COMMIT    := $(shell git rev-parse --short HEAD 2>/dev/null || echo "none")
BUILD     := $(shell date -u +%Y-%m-%dT%H:%M:%SZ)
LDFLAGS   := -s -w \
  -X main.Version=$(VERSION) \
  -X main.Commit=$(COMMIT) \
  -X main.BuildTime=$(BUILD)

.PHONY: build clean test lint cross-compile

build:
	go build -ldflags '$(LDFLAGS)' -o $(BINARY) ./cmd/relay

clean:
	rm -f $(BINARY) $(BINARY)-*

test:
	go test -v ./...

lint:
	golangci-lint run ./...

cross-compile:
	GOOS=linux   GOARCH=amd64 go build -ldflags '$(LDFLAGS)' -o $(BINARY)-linux-amd64 ./cmd/relay
	GOOS=linux   GOARCH=arm64 go build -ldflags '$(LDFLAGS)' -o $(BINARY)-linux-arm64 ./cmd/relay
	GOOS=darwin  GOARCH=arm64 go build -ldflags '$(LDFLAGS)' -o $(BINARY)-darwin-arm64 ./cmd/relay
	GOOS=darwin  GOARCH=amd64 go build -ldflags '$(LDFLAGS)' -o $(BINARY)-darwin-amd64 ./cmd/relay
	GOOS=windows GOARCH=amd64 go build -ldflags '$(LDFLAGS)' -o $(BINARY)-windows-amd64.exe ./cmd/relay

install: build
	install -m 755 $(BINARY) /usr/local/bin/

run: build
	./$(BINARY) --config config.yaml
