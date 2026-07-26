BIN      := bin/husk
PKG      := ./cmd/husk
VERSION  ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS  := -s -w -X github.com/apoorvan10/husk/internal/cli.Version=$(VERSION)

# CGO_ENABLED=0 is not an optimisation. husk execs itself inside the container's
# mount namespace, where the host's dynamic loader and shared libraries do not
# exist; a dynamically linked binary would fail to start with no useful error.
# It is also why the seccomp filter is assembled by hand rather than through
# libseccomp, which would require cgo.
export CGO_ENABLED := 0

.PHONY: all
all: build

.PHONY: build
build:
	@mkdir -p bin
	go build -trimpath -ldflags '$(LDFLAGS)' -o $(BIN) $(PKG)

.PHONY: install
install: build
	install -m 0755 $(BIN) /usr/local/bin/husk

.PHONY: vet
vet:
	go vet ./...

.PHONY: fmt
fmt:
	gofmt -l -w .

.PHONY: check-fmt
check-fmt:
	@out=$$(gofmt -l .); if [ -n "$$out" ]; then echo "gofmt needed:"; echo "$$out"; exit 1; fi

.PHONY: test
test:
	go test ./internal/...

# The escape suite creates real namespaces, cgroups, mounts and network
# interfaces, so it needs root and a Linux host. It is a separate target from
# `test` so that a normal `make test` stays runnable by anyone.
.PHONY: test-escape
test-escape: build
	@if [ "$$(id -u)" != "0" ]; then echo "the escape suite must run as root"; exit 1; fi
	go test -count=1 -v -timeout 15m ./test/escape/...

.PHONY: bench
bench: build
	./scripts/benchmark.sh

.PHONY: clean
clean:
	rm -rf bin
	go clean -testcache

# Remove every host resource husk may have created. Useful after an interrupted
# test run, which can leave a cgroup, a veth or a netfilter rule behind.
.PHONY: purge
purge:
	@if [ "$$(id -u)" != "0" ]; then echo "purge must run as root"; exit 1; fi
	./scripts/purge.sh
