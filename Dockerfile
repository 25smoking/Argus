# 使用 Go 1.21 作为基础镜像
FROM golang:1.21-bullseye

# 设置工作目录
WORKDIR /app

# 安装依赖: libyara (用于 YARA 支持) 和 mingw (用于编译 Windows 版)
RUN apt-get update && apt-get install -y \
    libyara-dev \
    gcc-mingw-w64 \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

# 复制依赖文件
COPY go.mod go.sum ./
RUN go mod download

# 复制源码
COPY . .

# 默认命令: 编译 Linux 版
CMD ["go", "build", "-tags", "yara_static", "-o", "gscan-linux", "./cmd/gscan"]
