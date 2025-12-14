.PHONY: build clean docker-build

APP=argus

build:
	go build -o $(APP) ./cmd/argus

clean:
	rm -f $(APP) $(APP)-linux $(APP).exe

# 使用 Docker 进行跨平台编译 (生成 Linux 和 Windows 二进制)
docker-build:
	docker build -t gscan-builder .
	# 编译 Linux 版
	docker run --rm -v $(shell pwd):/app gscan-builder go build -tags yara_static -o $(APP)-linux ./cmd/gscan
	# 编译 Windows 版 (使用 MinGW)
	docker run --rm -v $(shell pwd):/app -e CGO_ENABLED=1 -e CC=x86_64-w64-mingw32-gcc -e GOOS=windows gscan-builder go build -tags yara_static -o $(APP).exe ./cmd/gscan
