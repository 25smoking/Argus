# 使用与 go.mod 匹配的 Go 版本作为基础镜像
FROM golang:1.24-bookworm

# 设置工作目录
WORKDIR /app

# 安装基础构建依赖
RUN apt-get update && apt-get install -y \
    build-essential \
    libyara-dev \
    pkg-config \
    && rm -rf /var/lib/apt/lists/*

# 复制依赖文件
COPY go.mod go.sum ./
RUN go mod download

# 复制源码
COPY . .

# 默认命令: 编译 Linux 版
CMD ["go", "build", "-trimpath", "-ldflags", "-s -w -buildid=", "-o", "argus-linux", "./cmd/argus"]
