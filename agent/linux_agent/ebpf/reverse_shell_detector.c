#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/in.h>
#include <linux/ptrace.h>
#include <linux/sched.h>
#include <linux/nsproxy.h>
#include <linux/ns_common.h>
#include <linux/pid_namespace.h>
#include <linux/net_namespace.h>
#include <linux/utsname.h>
#include <linux/version.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

// 탐지된 이벤트를 저장할 맵
struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(int));
    __uint(value_size, sizeof(u32));
    __uint(max_entries, 1024);
} events SEC(".maps");

// 의심스러운 포트 목록
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(key_size, sizeof(u16));
    __uint(value_size, sizeof(u8));
    __uint(max_entries, 64);
} suspicious_ports SEC(".maps");

// 연결 추적 맵
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(key_size, sizeof(u64));
    __uint(value_size, sizeof(u64));
    __uint(max_entries, 10000);
} connection_tracker SEC(".maps");

// 이벤트 구조체
struct reverse_shell_event {
    u32 local_addr;
    u32 remote_addr;
    u16 local_port;
    u16 remote_port;
    u32 pid;
    u64 timestamp;
    u8 event_type;
    u8 severity;
};

// 의심스러운 포트 초기화
SEC("xdp")
int reverse_shell_detector(struct xdp_md *ctx)
{
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    
    struct ethhdr *eth = data;
    if (data + sizeof(*eth) > data_end)
        return XDP_PASS;
    
    // IP 패킷인지 확인
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;
    
    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return XDP_PASS;
    
    // TCP 패킷인지 확인
    if (ip->protocol != IPPROTO_TCP)
        return XDP_PASS;
    
    struct tcphdr *tcp = (void *)(ip + 1);
    if ((void *)(tcp + 1) > data_end)
        return XDP_PASS;
    
    // SYN 패킷인지 확인 (새로운 연결)
    if (!(tcp->syn && !tcp->ack))
        return XDP_PASS;
    
    u32 local_addr = ip->saddr;
    u32 remote_addr = ip->daddr;
    u16 local_port = bpf_ntohs(tcp->source);
    u16 remote_port = bpf_ntohs(tcp->dest);
    
    // 의심스러운 포트인지 확인
    u8 *is_suspicious = bpf_map_lookup_elem(&suspicious_ports, &remote_port);
    if (is_suspicious) {
        // 이벤트 생성
        struct reverse_shell_event event = {
            .local_addr = local_addr,
            .remote_addr = remote_addr,
            .local_port = local_port,
            .remote_port = remote_port,
            .pid = 0, // 나중에 프로세스 정보 추가
            .timestamp = bpf_ktime_get_ns(),
            .event_type = 1, // SuspiciousConnection
            .severity = 3,   // Critical
        };
        
        // 이벤트 전송
        bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &event, sizeof(event));
    }
    
    // 외부 IP로의 연결인지 확인
    if (!is_private_ip(remote_addr)) {
        struct reverse_shell_event event = {
            .local_addr = local_addr,
            .remote_addr = remote_addr,
            .local_port = local_port,
            .remote_port = remote_port,
            .pid = 0,
            .timestamp = bpf_ktime_get_ns(),
            .event_type = 2, // ExternalConnection
            .severity = 2,   // High
        };
        
        bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &event, sizeof(event));
    }
    
    return XDP_PASS;
}

// 프로세스 생성 후킹
SEC("tracepoint/syscalls/sys_enter_execve")
int trace_execve(struct trace_event_raw_sys_enter *ctx)
{
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u32 tgid = bpf_get_current_pid_tgid() & 0xFFFFFFFF;
    
    // 프로세스 이름 가져오기 (간단한 버전)
    char comm[16];
    bpf_get_current_comm(&comm, sizeof(comm));
    
    // 의심스러운 프로세스 패턴 확인
    if (is_suspicious_process(comm)) {
        struct reverse_shell_event event = {
            .local_addr = 0,
            .remote_addr = 0,
            .local_port = 0,
            .remote_port = 0,
            .pid = pid,
            .timestamp = bpf_ktime_get_ns(),
            .event_type = 3, // ProcessInjection
            .severity = 2,   // High
        };
        
        bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &event, sizeof(event));
    }
    
    return 0;
}

// 소켓 생성 후킹
SEC("tracepoint/syscalls/sys_enter_socket")
int trace_socket(struct trace_event_raw_sys_enter *ctx)
{
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    
    // 소켓 생성 시도 모니터링
    struct reverse_shell_event event = {
        .local_addr = 0,
        .remote_addr = 0,
        .local_port = 0,
        .remote_port = 0,
        .pid = pid,
        .timestamp = bpf_ktime_get_ns(),
        .event_type = 4, // SocketCreation
        .severity = 1,   // Medium
    };
    
    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &event, sizeof(event));
    
    return 0;
}

// 연결 후킹
SEC("tracepoint/syscalls/sys_enter_connect")
int trace_connect(struct trace_event_raw_sys_enter *ctx)
{
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    
    // connect 시스템 콜 모니터링
    struct reverse_shell_event event = {
        .local_addr = 0,
        .remote_addr = 0,
        .local_port = 0,
        .remote_port = 0,
        .pid = pid,
        .timestamp = bpf_ktime_get_ns(),
        .event_type = 5, // ConnectCall
        .severity = 1,   // Medium
    };
    
    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &event, sizeof(event));
    
    return 0;
}

// 프라이빗 IP 주소 확인 함수
static inline int is_private_ip(u32 ip)
{
    // 127.0.0.0/8
    if ((ip & 0xFF000000) == 0x7F000000)
        return 1;
    
    // 10.0.0.0/8
    if ((ip & 0xFF000000) == 0x0A000000)
        return 1;
    
    // 172.16.0.0/12
    if ((ip & 0xFFF00000) == 0xAC100000)
        return 1;
    
    // 192.168.0.0/16
    if ((ip & 0xFFFF0000) == 0xC0A80000)
        return 1;
    
    return 0;
}

// 의심스러운 프로세스 확인 함수
static inline int is_suspicious_process(char *comm)
{
    // 간단한 패턴 매칭
    char suspicious_patterns[][16] = {
        "nc", "netcat", "bash", "sh", "python", "perl", "ruby", "php",
        "wget", "curl", "ftp", "telnet", "ssh", "scp", "rsync"
    };
    
    for (int i = 0; i < 15; i++) {
        if (bpf_strncmp(comm, suspicious_patterns[i], 16) == 0)
            return 1;
    }
    
    return 0;
}

// 문자열 비교 함수
static inline int bpf_strncmp(const char *s1, const char *s2, int n)
{
    for (int i = 0; i < n; i++) {
        if (s1[i] != s2[i])
            return s1[i] - s2[i];
        if (s1[i] == '\0')
            return 0;
    }
    return 0;
}

char _license[] SEC("license") = "GPL";
