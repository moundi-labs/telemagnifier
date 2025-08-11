# Linux Agent - Kernel-based Reverse Shell Detection Plugin

OpenStack Nova 가상 환경에서 **커널 레벨 eBPF 후킹**을 사용하여 리버스 쉘을 탐지하는 Linux 에이전트입니다.

## 기능

### 1. 커널 레벨 네트워크 모니터링
- **eBPF XDP 프로그램**을 통한 패킷 레벨 모니터링
- **커널 후킹**을 통한 실시간 네트워크 연결 탐지
- 의심스러운 포트로의 연결 탐지 (4444, 8080, 9001, 1337 등)
- 외부 IP로의 연결 탐지
- Nova 인스턴스에서 나가는 연결 모니터링

### 2. 커널 레벨 프로세스 모니터링
- **eBPF Tracepoint**를 통한 시스템 콜 후킹
- **execve, socket, connect** 시스템 콜 실시간 모니터링
- 의심스러운 프로세스 패턴 탐지
- 리버스 쉘 관련 명령어 탐지 (nc, netcat, bash -i 등)
- 프로세스 주입 시도 탐지

### 3. OpenStack Nova 특화 탐지
- Nova 인스턴스 보안 상태 모니터링
- 인스턴스 내부 프로세스 모니터링
- 인스턴스 IP 주소에서 나가는 의심스러운 연결 탐지
- 인스턴스 침해 탐지

### 4. 커널 레벨 이벤트 추적
- **eBPF Perf Event**를 통한 커널에서 유저스페이스로의 실시간 이벤트 전송
- 탐지된 이벤트의 실시간 로깅
- 심각도 레벨별 분류 (Low, Medium, High, Critical)
- 상세한 연결 정보 및 프로세스 정보 기록

## 설치 및 실행

### 요구사항
- Linux 환경 (Ubuntu 20.04+ 권장)
- Rust 1.70+
- OpenStack Nova 환경
- **eBPF 지원 커널** (Linux 4.18+)
- **clang/LLVM** (eBPF 컴파일용)
- **root 권한** (eBPF 프로그램 로드용)

### 빌드
```bash
cd agent/linux_agent

# eBPF 프로그램 컴파일
cd ebpf
make

# Rust 프로그램 빌드
cd ..
cargo build --release
```

### 실행
```bash
# 환경 변수 설정
export RUST_LOG=info

# 에이전트 실행
./target/release/linux_agent
```

## 탐지 패턴

### 네트워크 연결 패턴
- **의심스러운 포트**: 4444, 8080, 9001, 9002, 1337, 31337, 54321, 12345, 6667, 6668, 6669
- **외부 IP 연결**: 프라이빗 네트워크 외부로의 연결
- **높은 포트 연결**: 1024-49152 범위의 동적 포트

### 프로세스 패턴
- **리버스 쉘 도구**: nc, netcat, ncat, nc.traditional
- **인터랙티브 쉘**: bash -i, sh -i
- **스크립트 실행**: python -c, perl -e, ruby -rsocket, php -r
- **네트워크 도구**: wget, curl, ftp, telnet, ssh, scp, rsync

### Nova 특화 패턴
- **인스턴스 내부 프로세스**: bash, sh, python, nginx, mysql, ssh 등
- **인스턴스 IP 주소**: 각 Nova 인스턴스의 할당된 IP 주소 모니터링
- **인스턴스 네임스페이스**: 가상 머신 내부의 프로세스 및 네트워크 활동

## 설정

### 로그 레벨 설정
```bash
# 디버그 레벨
export RUST_LOG=debug

# 정보 레벨
export RUST_LOG=info

# 경고 레벨
export RUST_LOG=warn
```

### 모니터링 간격 조정
코드에서 다음 값들을 조정할 수 있습니다:
- 네트워크 연결 스캔: 5초
- 프로세스 생성 스캔: 10초
- 인스턴스 프로세스 스캔: 15초
- Nova 인스턴스 스캔: 30초
- 리포트 생성: 60초

## 출력 예시

### 탐지된 이벤트
```
[2024-01-15T10:30:45Z INFO] Suspicious connection detected: 192.168.1.100:54321->8.8.8.8:4444
[2024-01-15T10:30:50Z WARN] Suspicious process detected: nc -l 4444
[2024-01-15T10:31:00Z ERROR] Nova instance web-server-1 (instance-00000001) may be compromised! Suspicious connection to 8.8.8.8:4444
[2024-01-15T10:31:15Z WARN] Suspicious process detected in Nova instance db-server-1 (instance-00000002): bash -i - connection to 192.168.1.50:1337
```

### 주기적 리포트
```
Kernel-based Reverse Shell Detection Report
===========================================
Total Events Detected: 5
Suspicious Connections: 3

Recent Events:
[45] Medium - Suspicious connection detected: 192.168.1.100:54321->8.8.8.8:4444
[40] High - Suspicious process detected: nc -l 4444
[30] Critical - Kernel hook detected suspicious connection from Nova instance web-server-1 (instance-00000001): 192.168.1.100 -> 8.8.8.8:4444
[15] High - Suspicious process detected in Nova instance db-server-1 (instance-00000002): bash -i - connection to 192.168.1.50:1337
```

## eBPF 아키텍처

### 커널 레벨 후킹
```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   User Space    │    │   Kernel Space  │    │   eBPF Maps     │
│                 │    │                 │    │                 │
│  Rust Agent     │◄──►│  XDP Program    │◄──►│  Event Map      │
│                 │    │                 │    │                 │
│  Event Handler  │◄──►│  Tracepoints    │◄──►│  Port Map       │
│                 │    │                 │    │                 │
│  Nova Monitor   │    │  System Calls   │◄──►│  Instance Map   │
└─────────────────┘    └─────────────────┘    └─────────────────┘
```

### eBPF 프로그램 구성
1. **XDP 프로그램**: 네트워크 패킷 레벨 모니터링
2. **Tracepoint 프로그램**: 시스템 콜 후킹 (execve, socket, connect)
3. **eBPF 맵**: 이벤트 전송, 포트 목록, 인스턴스 IP 저장

## Nova 인스턴스 모니터링

### 인스턴스 정보 구조
```rust
pub struct NovaInstance {
    pub id: String,           // 인스턴스 ID
    pub name: String,         // 인스턴스 이름
    pub status: String,       // 인스턴스 상태
    pub ip_addresses: Vec<u32>, // 할당된 IP 주소들 (u32로 저장)
    pub flavor: String,       // 인스턴스 사양
    pub image: String,        // 사용된 이미지
}
```

### 탐지 로직
1. **커널 레벨 IP 주소 기반 탐지**: eBPF에서 Nova 인스턴스 IP 주소에서 나가는 연결을 실시간 모니터링
2. **커널 레벨 프로세스 기반 탐지**: eBPF Tracepoint를 통한 의심스러운 프로세스 생성 탐지
3. **커널 레벨 연결 패턴 분석**: eBPF XDP를 통한 패킷 레벨 연결 패턴 분석

## 보안 고려사항

1. **권한**: 에이전트는 root 권한으로 실행해야 합니다.
2. **네트워크 접근**: `/proc/net/` 파일에 대한 읽기 권한이 필요합니다.
3. **프로세스 정보**: `/proc/` 디렉토리에 대한 읽기 권한이 필요합니다.
4. **로그 보안**: 민감한 정보가 로그에 기록될 수 있으므로 로그 파일 보안에 주의하세요.
5. **Nova API 접근**: 실제 환경에서는 Nova API에 대한 인증 정보가 필요합니다.

## 개발

### 테스트 실행
```bash
cargo test
```

### 코드 포맷팅
```bash
cargo fmt
```

### 린트 검사
```bash
cargo clippy
```

## 라이선스

이 프로젝트는 MIT 라이선스 하에 배포됩니다.

## 기여

버그 리포트, 기능 요청, 풀 리퀘스트를 환영합니다.
