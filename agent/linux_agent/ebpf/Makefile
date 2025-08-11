# eBPF 프로그램 빌드 Makefile

# 컴파일러 설정
CLANG ?= clang
LLC ?= llc
CC ?= gcc

# 커널 헤더 경로
KERNEL_HEADERS ?= /usr/include

# 소스 파일
SRC = reverse_shell_detector.c
OBJ = reverse_shell_detector.o

# 컴파일 플래그
CFLAGS = -O2 -target bpf -c
INCLUDES = -I$(KERNEL_HEADERS)

# 기본 타겟
all: $(OBJ)

# eBPF 오브젝트 파일 생성
$(OBJ): $(SRC)
	$(CLANG) $(CFLAGS) $(INCLUDES) -o $@ $<

# 정리
clean:
	rm -f $(OBJ)

.PHONY: all clean
