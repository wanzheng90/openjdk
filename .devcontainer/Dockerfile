# 使用一个基础的Linux镜像，例如Ubuntu
FROM ubuntu:20.04

# 设定维护者信息
LABEL maintainer="wanzheng90@hotmail.com"

# 避免时区选择交互
ENV DEBIAN_FRONTEND=noninteractive

# 更新软件包列表并安装所需依赖
RUN apt-get update && apt-get install -y \
    apt-utils \
    ca-certificates \
    wget \
    curl \
    git \
    unzip \
    mercurial \
    build-essential \
    autoconf \
    libx11-dev \
    libxext-dev \
    libxrender-dev \
    libxrandr-dev \
    libxtst-dev \
    libxt-dev \
    libcups2-dev \
    libfontconfig1-dev \
    libasound2-dev \
    libfreetype6-dev \
    zip \
    openjdk-17-jdk

# 使用shell命令自动设置JDK路径
RUN ARCH=$(uname -m) && \
    if [ "$ARCH" = "x86_64" ]; then \
        JDK_ARCH=amd64; \
    elif [ "$ARCH" = "aarch64" ]; then \
        JDK_ARCH=arm64; \
    fi && \
    echo "export PATH=/usr/lib/jvm/java-17-openjdk-${JDK_ARCH}/bin:$PATH" >> /etc/bash.bashrc
