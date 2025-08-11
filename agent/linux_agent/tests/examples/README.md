# Test Examples

이 디렉토리는 `reverse_shell.rs` 플러그인 테스트를 위한 예제들을 포함합니다.

## 파일 구조

```
tests/
├── docker/                    # Docker 관련 파일들
│   └── docker-compose.yml     # 메인 Docker Compose 설정
├── scripts/                   # 테스트 스크립트들
│   ├── run_tests.sh          # 메인 테스트 실행 스크립트
│   └── test_reverse_shell_plugin.sh  # 플러그인 테스트 스크립트
└── examples/                  # 테스트 예제들
    ├── README.md             # 이 파일
    └── test_scenarios.md     # 테스트 시나리오 문서
```

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

## 테스트 실행 방법

### 전체 테스트 실행
```bash
# 권한 설정
chmod +x tests/scripts/run_tests.sh
chmod +x tests/scripts/test_reverse_shell_plugin.sh

# 전체 테스트 실행
./tests/scripts/run_tests.sh
```

### 개별 컨테이너 테스트
```bash
# Docker Compose로 테스트 실행
docker-compose -f tests/docker/docker-compose.yml up --build
```

### Rust 예제 실행
```bash
# 플러그인 테스트 예제 실행
cd agent/linux_agent
cargo run --example plugin_test
```

## 테스트 시나리오

자세한 테스트 시나리오는 [test_scenarios.md](test_scenarios.md) 파일을 참조하세요.

### 주요 테스트 시나리오
1. **의심스러운 포트 연결 탐지**
2. **리버스 쉘 패턴 탐지**
3. **외부 연결 탐지**
4. **의심스러운 프로세스 탐지**
5. **커널 후킹 기능 테스트**

## 모니터링 및 분석

### 실시간 모니터링
- 네트워크 연결 상태
- 프로세스 실행 상태
- eBPF 프로그램 상태
- 시스템 리소스 사용량

### 결과 분석
- 이벤트 타입별 분석
- 포트별 연결 통계
- 프로세스별 연결 통계
- 탐지 정확도 측정

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

## 문제 해결

### 일반적인 문제들
1. **Docker 권한 문제**: `sudo` 사용 또는 Docker 그룹에 사용자 추가
2. **eBPF 로드 실패**: 커널 버전 확인 (4.18 이상 필요)
3. **포트 충돌**: 다른 서비스가 사용 중인 포트 확인
4. **메모리 부족**: Docker 메모리 제한 증가

### 로그 확인
```bash
# 컨테이너 로그 확인
docker logs reverse-shell-plugin-test
docker logs plugin-monitor

# 실시간 로그 모니터링
docker-compose -f tests/docker/docker-compose.yml logs -f
```

## 기여하기

새로운 테스트 시나리오나 개선사항을 제안하려면:
1. 이슈를 생성하거나
2. 풀 리퀘스트를 제출하세요

테스트 코드 작성 시 다음 사항을 고려해주세요:
- 명확한 테스트 목적
- 재현 가능한 시나리오
- 적절한 정리 및 리소스 해제
- 문서화된 예상 결과
