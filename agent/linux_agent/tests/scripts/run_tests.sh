#!/bin/bash

# Main Test Runner Script
# 모든 테스트를 실행하는 통합 스크립트

set -e

echo "=== Telemagnifier Test Suite ==="
echo "Running comprehensive tests for reverse shell detection system"

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

# 환경 확인
check_environment() {
    print_step "Checking test environment..."
    
    # Docker 확인
    if ! command -v docker &> /dev/null; then
        print_error "Docker is not installed"
        exit 1
    fi
    
    if ! docker info &> /dev/null; then
        print_error "Docker is not running"
        exit 1
    fi
    
    # Docker Compose 확인
    if ! command -v docker-compose &> /dev/null; then
        print_error "Docker Compose is not installed"
        exit 1
    fi
    
    print_success "Environment check passed"
}

# 기존 컨테이너 정리
cleanup() {
    print_step "Cleaning up existing containers..."
    
    docker-compose -f tests/docker/docker-compose.yml down --remove-orphans 2>/dev/null || true
    docker rm -f reverse-shell-plugin-test reverse-shell-targets plugin-monitor 2>/dev/null || true
    
    print_success "Cleanup completed"
}

# Docker 이미지 빌드
build_image() {
    print_step "Building Docker image..."
    
    # Docker Compose를 사용해서 빌드 (Dockerfile 경로 문제 해결)
    docker-compose -f tests/docker/docker-compose.yml build
    
    if [ $? -eq 0 ]; then
        print_success "Docker image built successfully"
    else
        print_error "Failed to build Docker image"
        exit 1
    fi
}

# 플러그인 테스트 실행
run_plugin_tests() {
    print_step "Running reverse shell plugin tests..."
    
    # 테스트 스크립트 권한 설정
    chmod +x tests/scripts/test_reverse_shell_plugin.sh
    
    # Docker Compose로 테스트 실행
    docker-compose -f tests/docker/docker-compose.yml up --build
    
    print_success "Plugin tests completed"
}

# 결과 분석
analyze_results() {
    print_step "Analyzing test results..."
    
    echo ""
    echo "=== Test Results Analysis ==="
    
    # 컨테이너 상태 확인
    echo "Container Status:"
    docker ps -a --filter "name=reverse-shell" --format "table {{.Names}}\t{{.Status}}\t{{.Ports}}"
    
    # 로그 확인
    echo ""
    echo "Test Logs:"
    if docker ps -a | grep -q reverse-shell-plugin-test; then
        echo "--- Plugin Test Logs ---"
        docker logs reverse-shell-plugin-test 2>/dev/null || echo "No logs available"
    fi
    
    if docker ps -a | grep -q plugin-monitor; then
        echo ""
        echo "--- Monitor Logs ---"
        docker logs plugin-monitor 2>/dev/null || echo "No logs available"
    fi
}

# 정리
final_cleanup() {
    print_step "Final cleanup..."
    
    docker-compose -f tests/docker/docker-compose.yml down --remove-orphans
    
    read -p "Do you want to remove the Docker image? (y/N): " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        docker rmi reverse-shell-detector 2>/dev/null || true
        print_success "Docker image removed"
    fi
    
    print_success "Final cleanup completed"
}

# 메인 실행
main() {
    echo "Starting comprehensive test suite..."
    echo ""
    
    # 환경 확인
    check_environment
    
    # 정리
    cleanup
    
    # 빌드
    build_image
    
    # 테스트 실행
    run_plugin_tests
    
    # 결과 분석
    analyze_results
    
    # 정리
    final_cleanup
    
    echo ""
    print_success "All tests completed successfully!"
    echo ""
    echo "=== Test Summary ==="
    echo "✓ Environment checked"
    echo "✓ Docker image built"
    echo "✓ Plugin tests executed"
    echo "✓ Results analyzed"
    echo "✓ Cleanup completed"
}

# 스크립트 실행
if [ "${BASH_SOURCE[0]}" = "${0}" ]; then
    main "$@"
fi
