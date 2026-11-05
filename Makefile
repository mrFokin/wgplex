BUILD   := build
BIN     := $(BUILD)/wgplex
VERSION := $(shell cat VERSION)
LDFLAGS := -X main.version=$(VERSION)
ARCHIVE := wgplex-$(VERSION)-darwin-universal.tar.gz

.PHONY: check fmt-check vet test build release clean FORCE

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

# Release archive (design 16.2, M6 decisions 1-2): no top-level directory,
# bin/wgplex, share/wgplex/wgplex.yaml and LICENSE, plus a sha256 file in the
# `shasum -a 256` format with the bare archive name. Tagging and gh release
# are manual (design 16.3).
release: check build
	@echo '$(VERSION)' | grep -Eq '^[0-9]+\.[0-9]+\.[0-9]+$$' || { echo 'VERSION $(VERSION) is not X.Y.Z: drop -dev (or pass VERSION=X.Y.Z)'; exit 1; }
	rm -rf $(BUILD)/release $(BUILD)/$(ARCHIVE) $(BUILD)/$(ARCHIVE).sha256
	mkdir -p $(BUILD)/release/bin $(BUILD)/release/share/wgplex
	cp $(BIN) $(BUILD)/release/bin/wgplex
	cp share/wgplex/wgplex.yaml $(BUILD)/release/share/wgplex/wgplex.yaml
	cp LICENSE $(BUILD)/release/LICENSE
	COPYFILE_DISABLE=1 tar --no-xattrs --no-mac-metadata --uid 0 --gid 0 --uname root --gname wheel -czf $(BUILD)/$(ARCHIVE) -C $(BUILD)/release bin share LICENSE
	rm -rf $(BUILD)/release
	cd $(BUILD) && shasum -a 256 $(ARCHIVE) > $(ARCHIVE).sha256

clean:
	rm -rf $(BUILD)
