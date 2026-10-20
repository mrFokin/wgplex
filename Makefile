BUILD   := build
BIN     := $(BUILD)/wgplex
VERSION := $(shell cat VERSION)
LDFLAGS := -X main.version=$(VERSION)

.PHONY: check fmt-check vet test build clean FORCE

check: fmt-check vet test

fmt-check:
	@out=$$(gofmt -l .); if [ -n "$$out" ]; then echo "gofmt needed:"; echo "$$out"; exit 1; fi

vet:
	go vet ./...

test:
	go test ./...

# Universal (arm64 + x86_64) build/wgplex with cgo (design 16.2). The linker
# signs only the arm64 slice, so the lipo output is signed ad-hoc again.
build: $(BIN)

$(BIN): FORCE
	@mkdir -p $(BUILD)
	CGO_ENABLED=1 GOOS=darwin GOARCH=arm64 go build -ldflags "$(LDFLAGS)" -o $@-arm64 ./cmd/wgplex
	CGO_ENABLED=1 GOOS=darwin GOARCH=amd64 CC="clang -arch x86_64" go build -ldflags "$(LDFLAGS)" -o $@-amd64 ./cmd/wgplex
	lipo -create -output $@ $@-arm64 $@-amd64
	rm -f $@-arm64 $@-amd64
	codesign --force --sign - $@

clean:
	rm -rf $(BUILD)
