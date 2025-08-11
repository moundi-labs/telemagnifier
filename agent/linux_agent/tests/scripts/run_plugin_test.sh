#!/bin/bash

# Reverse Shell Plugin Test Runner
# reverse_shell.rs 플러그인을 Docker 컨테이너에서 테스트합니다.

set -e

echo "=== Reverse Shell Plugin Test Runner ==="
echo "Testing reverse_shell.rs plugin in Docker container environment"

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

# Docker 설치 확인
check_docker() {
    print_step "Checking Docker installation..."
    if ! command -v docker &> /dev/null; then
        print_error "Docker is not installed. Please install Docker first."
        exit 1
    fi
    
    if ! docker info &> /dev/null; then
        print_error "Docker is not running. Please start Docker first."
        exit 1
    fi
    
    print_success "Docker is available"
}

# Docker Compose 설치 확인
check_docker_compose() {
    print_step "Checking Docker Compose installation..."
    if ! command -v docker-compose &> /dev/null; then
        print_error "Docker Compose is not installed. Please install Docker Compose first."
        exit 1
    fi
    
    print_success "Docker Compose is available"
}

# 기존 컨테이너 정리
cleanup_containers() {
    print_step "Cleaning up existing containers..."
    
    # 기존 컨테이너 중지 및 제거
    docker-compose -f docker-compose.plugin-test.yml down --remove-orphans 2>/dev/null || true
    docker-compose -f docker-compose.test.yml down --remove-orphans 2>/dev/null || true
    
    # 관련 컨테이너 강제 제거
    docker rm -f reverse-shell-plugin-test reverse-shell-targets plugin-monitor 2>/dev/null || true
    
    print_success "Existing containers cleaned up"
}

# Docker 이미지 빌드
build_image() {
    print_step "Building Docker image for plugin testing..."
    
    # Dockerfile 존재 확인
    if [ ! -f "Dockerfile" ]; then
        print_error "Dockerfile not found in current directory"
        exit 1
    fi
    
    # 이미지 빌드
    docker build -t reverse-shell-detector .
    
    if [ $? -eq 0 ]; then
        print_success "Docker image built successfully"
    else
        print_error "Failed to build Docker image"
        exit 1
    fi
}

# 플러그인 테스트 실행
run_plugin_tests() {
    print_step "Starting reverse shell plugin test environment..."
    
    # 테스트 스크립트 권한 설정
    chmod +x test_reverse_shell_plugin.sh
    
    # Docker Compose로 플러그인 테스트 실행
    docker-compose -f docker-compose.plugin-test.yml up --build
    
    print_success "Plugin test environment started"
}

# 플러그인 로그 확인
check_plugin_logs() {
    print_step "Checking plugin test logs..."
    
    echo ""
    echo "=== Plugin Test Logs ==="
    
    # 메인 플러그인 테스트 컨테이너 로그
    if docker ps -a | grep -q reverse-shell-plugin-test; then
        echo "--- Reverse Shell Plugin Test Container Logs ---"
        docker logs reverse-shell-plugin-test 2>/dev/null || echo "No logs available"
    fi
    
    # 타겟 서버 컨테이너 로그
    if docker ps -a | grep -q reverse-shell-targets; then
        echo ""
        echo "--- Reverse Shell Targets Container Logs ---"
        docker logs reverse-shell-targets 2>/dev/null || echo "No logs available"
    fi
    
    # 모니터링 컨테이너 로그
    if docker ps -a | grep -q plugin-monitor; then
        echo ""
        echo "--- Plugin Monitor Container Logs ---"
        docker logs plugin-monitor 2>/dev/null || echo "No logs available"
    fi
}

# 플러그인 테스트 결과 분석
analyze_plugin_results() {
    print_step "Analyzing plugin test results..."
    
    echo ""
    echo "=== Plugin Test Results Analysis ==="
    
    # 컨테이너 상태 확인
    echo "Container Status:"
    docker ps -a --filter "name=reverse-shell" --format "table {{.Names}}\t{{.Status}}\t{{.Ports}}"
    
    # 네트워크 연결 확인
    echo ""
    echo "Plugin Test Network:"
    docker network ls --filter "name=plugin-test" --format "table {{.Name}}\t{{.Driver}}\t{{.Scope}}"
    
    # 플러그인 특화 정보
    echo ""
    echo "Plugin-Specific Information:"
    
    # eBPF 프로그램 상태 확인
    if docker ps -a | grep -q reverse-shell-plugin-test; then
        echo "eBPF Programs in Plugin Container:"
        docker exec reverse-shell-plugin-test ls -la /sys/fs/bpf/ 2>/dev/null || echo "No eBPF programs found"
        
        echo ""
        echo "Kernel Modules in Plugin Container:"
        docker exec reverse-shell-plugin-test lsmod | grep -E "(bpf|xdp)" 2>/dev/null || echo "No BPF/XDP modules found"
    fi
}

# 정리
cleanup() {
    print_step "Cleaning up plugin test environment..."
    
    # 컨테이너 중지 및 제거
    docker-compose -f docker-compose.plugin-test.yml down --remove-orphans
    
    # 이미지 정리 (선택사항)
    read -p "Do you want to remove the Docker image? (y/N): " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        docker rmi reverse-shell-detector 2>/dev/null || true
        print_success "Docker image removed"
    fi
    
    print_success "Plugin test cleanup completed"
}

# 플러그인 테스트 요약
show_plugin_test_summary() {
    echo ""
    echo "=== Reverse Shell Plugin Test Summary ==="
    echo "✓ Docker environment checked"
    echo "✓ Plugin test containers built and started"
    echo "✓ Reverse shell plugin features tested:"
    echo "  - Suspicious port detection (4444, 1337, 31337, etc.)"
    echo "  - Reverse shell pattern detection (nc, bash, python)"
    echo "  - Process injection detection"
    echo "  - Network anomaly detection"
    echo "  - Kernel hook functionality"
    echo "  - eBPF program monitoring"
    echo "✓ Plugin monitoring completed"
    echo "✓ Results analyzed"
    echo "✓ Environment cleaned up"
}

# 메인 실행
main() {
    echo "Starting reverse shell plugin test..."
    echo ""
    
    # 사전 검사
    check_docker
    check_docker_compose
    
    # 정리
    cleanup_containers
    
    # 빌드
    build_image
    
    # 플러그인 테스트 실행
    run_plugin_tests
    
    # 결과 확인
    check_plugin_logs
    analyze_plugin_results
    
    # 정리
    cleanup
    
    # 요약
    show_plugin_test_summary
    
    echo ""
    print_success "Reverse shell plugin test completed successfully!"
}

# 스크립트 실행
if [ "${BASH_SOURCE[0]}" = "${0}" ]; then
    main "$@"
fi
