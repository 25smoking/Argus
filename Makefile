.PHONY: build build-linux build-windows clean docker-build

APP=argus
VERSION?=3.0.0-dev
COMMIT?=$(shell git rev-parse --short HEAD 2>/dev/null || echo unknown)
BUILD_TIME?=$(shell date -u +%Y-%m-%dT%H:%M:%SZ)
LDFLAGS=-s -w -buildid= -X main.version=$(VERSION) -X main.commit=$(COMMIT) -X main.buildTime=$(BUILD_TIME)
BUILDFLAGS=-trimpath -ldflags "$(LDFLAGS)"

build:
	CGO_ENABLED=1 go build -tags static_link $(BUILDFLAGS) -o $(APP) ./cmd/argus

build-linux:
	@echo "完整 YARA-X 引擎需要 Linux 目标平台的 yara_x_capi、pkg-config 和 C 交叉编译链"
	CGO_ENABLED=1 GOOS=linux GOARCH=amd64 go build -tags static_link $(BUILDFLAGS) -o $(APP)-linux ./cmd/argus

build-windows:
	@echo "完整 YARA-X 引擎需要 Windows 目标平台的 yara_x_capi、pkg-config 和 MinGW 交叉编译链"
	CGO_ENABLED=1 GOOS=windows GOARCH=amd64 go build -tags static_link $(BUILDFLAGS) -o $(APP).exe ./cmd/argus

checksums:
	shasum -a 256 $(APP) $(APP)-linux $(APP).exe 2>/dev/null > SHA256SUMS || true

clean:
	rm -f $(APP) $(APP)-linux $(APP).exe

# 使用 Docker 编译 Linux 版完整 YARA-X 引擎
docker-build:
	docker build -t argus-builder .
	docker run --rm -v $(shell pwd):/app argus-builder go build -tags static_link $(BUILDFLAGS) -o $(APP)-linux ./cmd/argus
