PROJECT_URL=github.com/grafana/okta-logs-collector
METADATA_PACKAGE=${PROJECT_URL}/metadata
LAST_TAGGED_COMMIT=$(shell git rev-list --tags --max-count=1)
VERSION=$(shell git describe --tags ${LAST_TAGGED_COMMIT})
EXTRA_LDFLAGS=-X ${METADATA_PACKAGE}.Version=${VERSION}
FILES=okta-logs-collector README.md LICENSE checksum.txt

.PHONY: run build-dev build-docker-release tidy create-build-dir build-release build-platform

run:
	@go run *.go $(args)

build-dev:
	@go build -o okta-logs-collector *.go

build-docker-release:
	@CGO_ENABLED=0 GOOS=$(GOOS) GOARCH=$(GOARCH) go build -trimpath -ldflags "-s -w ${EXTRA_LDFLAGS}" -o /app/okta-logs-collector *.go

tidy:
	@go mod tidy

create-build-dir:
	@mkdir -p dist

build-release: tidy create-build-dir
	@echo "Building okta-logs-collector ${VERSION} for release"
	@$(MAKE) build-platform GOOS=linux GOARCH=amd64 OUTPUT_DIR=dist/linux-amd64
	@$(MAKE) build-platform GOOS=linux GOARCH=arm64 OUTPUT_DIR=dist/linux-arm64
	@$(MAKE) build-platform GOOS=darwin GOARCH=amd64 OUTPUT_DIR=dist/darwin-amd64
	@$(MAKE) build-platform GOOS=darwin GOARCH=arm64 OUTPUT_DIR=dist/darwin-arm64
	@$(MAKE) build-platform GOOS=windows GOARCH=amd64 OUTPUT_DIR=dist/windows-amd64
	@$(MAKE) build-platform GOOS=windows GOARCH=arm64 OUTPUT_DIR=dist/windows-arm64

build-platform: tidy
	@echo "Building okta-logs-collector ${VERSION} for $(GOOS)-$(GOARCH)"
	@mkdir -p $(OUTPUT_DIR)
	@cp README.md LICENSE $(OUTPUT_DIR)/
	@if [ "$(GOOS)" = "windows" ]; then \
		GOOS=$(GOOS) GOARCH=$(GOARCH) CGO_ENABLED=0 go build -trimpath -ldflags "-s -w ${EXTRA_LDFLAGS}" -o $(OUTPUT_DIR)/okta-logs-collector.exe *.go; \
		sha256sum $(OUTPUT_DIR)/okta-logs-collector.exe | sed 's#$(OUTPUT_DIR)/##g' >> $(OUTPUT_DIR)/checksum.txt; \
		zip -q -r dist/okta-logs-collector-$(GOOS)-$(GOARCH)-${VERSION}.zip -j $(OUTPUT_DIR)/; \
	else \
		GOOS=$(GOOS) GOARCH=$(GOARCH) CGO_ENABLED=0 go build -trimpath -ldflags "-s -w ${EXTRA_LDFLAGS}" -o $(OUTPUT_DIR)/okta-logs-collector *.go; \
		sha256sum $(OUTPUT_DIR)/okta-logs-collector | sed 's#$(OUTPUT_DIR)/##g' >> $(OUTPUT_DIR)/checksum.txt; \
		tar czf dist/okta-logs-collector-$(GOOS)-$(GOARCH)-${VERSION}.tar.gz -C $(OUTPUT_DIR)/ ${FILES}; \
	fi
	@sha256sum dist/okta-logs-collector-$(GOOS)-$(GOARCH)-${VERSION}.* | sed 's#dist/##g' >> dist/checksums.txt
