FROM ubuntu:22.04

# 환경 변수 설정
ENV DEBIAN_FRONTEND=noninteractive
ENV RUST_VERSION=1.80.0

# 시스템 패키지 업데이트 및 필요한 패키지 설치
RUN apt-get update && apt-get install -y \
    build-essential \
    curl \
    git \
    pkg-config \
    libssl-dev \
    libelf-dev \
    zlib1g-dev \
    clang \
    llvm \
    libclang-dev \
    linux-headers-generic \
    linux-tools-common \
    linux-tools-generic \
    && rm -rf /var/lib/apt/lists/*

# bpftool 설치 (가상 패키지 문제 해결)
RUN apt-get update && apt-get install -y \
    linux-hwe-6.5-tools-common \
    && rm -rf /var/lib/apt/lists/*

# Rust 설치
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --default-toolchain $RUST_VERSION
ENV PATH="/root/.cargo/bin:${PATH}"

# 작업 디렉토리 설정
WORKDIR /app

# Cargo.toml 복사
COPY Cargo.toml .

# 소스 코드 복사
COPY src ./src
COPY ebpf ./ebpf

# eBPF 프로그램 빌드 (ARM64에서는 조건부 빌드)
RUN if [ "$(uname -m)" = "x86_64" ]; then \
        cd ebpf && make; \
    else \
        echo "eBPF compilation skipped on ARM64"; \
    fi

# Rust 프로그램 빌드
RUN cargo build --release

# 테스트 스크립트 복사
COPY tests/scripts/test_reverse_shell_plugin.sh .
RUN chmod +x test_reverse_shell_plugin.sh

# 컨테이너 실행 시 필요한 권한 설정
RUN echo 'kernel.core_pattern = |/bin/false' >> /etc/sysctl.conf

# 실행 명령
CMD ["./target/release/linux_agent"]
