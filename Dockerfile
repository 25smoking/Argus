# 使用与 go.mod 匹配的 Go 版本作为基础镜像
FROM golang:1.24-bookworm

# 设置工作目录
WORKDIR /app

# 安装基础构建依赖
RUN apt-get update && apt-get install -y \
    build-essential \
    ca-certificates \
    curl \
    git \
    pkg-config \
    && rm -rf /var/lib/apt/lists/*

# 构建并安装 YARA-X CAPI，避免依赖系统 libyara 动态库。
ARG YARA_X_VERSION=v1.16.0
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --profile minimal
ENV PATH="/root/.cargo/bin:${PATH}"
RUN git clone --depth 1 --branch "${YARA_X_VERSION}" https://github.com/VirusTotal/yara-x.git /tmp/yara-x \
    && cargo build --release --package yara-x-capi --manifest-path /tmp/yara-x/Cargo.toml \
    && cp /tmp/yara-x/target/release/libyara_x_capi.a /usr/local/lib/ \
    && cp /tmp/yara-x/capi/include/yara_x.h /usr/local/include/ \
    && mkdir -p /usr/local/lib/pkgconfig \
    && printf '%s\n' \
        'prefix=/usr/local' \
        'exec_prefix=${prefix}' \
        'libdir=${exec_prefix}/lib' \
        'includedir=${prefix}/include' \
        'Name: yara_x_capi' \
        'Description: YARA-X C API static package' \
        'Version: 1.16.0' \
        'Libs: -L${libdir} -lyara_x_capi -ldl -lpthread -lm' \
        'Cflags: -I${includedir}' \
        > /usr/local/lib/pkgconfig/yara_x_capi.pc \
    && rm -rf /tmp/yara-x

# 复制依赖文件
COPY go.mod go.sum ./
RUN go mod download

# 复制源码
COPY . .

# 默认命令: 编译 Linux 版
CMD ["go", "build", "-tags", "static_link", "-trimpath", "-ldflags", "-s -w -buildid=", "-o", "argus-linux", "./cmd/argus"]
