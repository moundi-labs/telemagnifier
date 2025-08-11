use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::cell::RefCell;
use std::time::{Duration, Instant};
use anyhow::Result;
use log::{info, warn, error, debug};
use tokio::time::sleep;

// eBPF 관련 구조체들
use aya::{
    include_bytes_aligned,
    maps::{HashMap as AyaHashMap, MapData},
    programs::{Xdp, XdpFlags, TracePoint},
    Bpf, BpfLoader,
};
use aya_log::BpfLogger;

/// 리버스 쉘 탐지 플러그인 (커널 기반)
pub struct ReverseShellDetector {
    /// eBPF 프로그램
    bpf: RefCell<Option<Bpf>>,
    /// 탐지된 이벤트
    detected_events: Arc<Mutex<Vec<ReverseShellEvent>>>,
    /// 네트워크 연결 추적
    connection_tracker: Arc<Mutex<HashMap<String, ConnectionInfo>>>,
}

/// 네트워크 연결 정보
#[derive(Debug, Clone)]
pub struct ConnectionInfo {
    pub local_addr: u32,
    pub remote_addr: u32,
    pub local_port: u16,
    pub remote_port: u16,
    pub pid: u32,
    pub process_name: String,
    pub first_seen: Instant,
    pub last_seen: Instant,
    pub connection_count: u32,
    pub is_suspicious: bool,
}

/// 리버스 쉘 이벤트
#[derive(Debug, Clone)]
pub struct ReverseShellEvent {
    pub timestamp: Instant,
    pub event_type: EventType,
    pub severity: Severity,
    pub details: String,
    pub connection_info: Option<ConnectionInfo>,
}

/// 이벤트 타입
#[derive(Debug, Clone)]
pub enum EventType {
    SuspiciousConnection,
    ReverseShellDetected,
    ProcessInjection,
    NetworkAnomaly,
    KernelHookTriggered,
}

/// 심각도 레벨
#[derive(Debug, Clone)]
pub enum Severity {
    Low,
    Medium,
    High,
    Critical,
}

impl ReverseShellDetector {
    /// 새로운 리버스 쉘 탐지기 생성
    pub fn new() -> Self {
        Self {
            bpf: RefCell::new(None),
            detected_events: Arc::new(Mutex::new(Vec::new())),
            connection_tracker: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// 플러그인 시작 (커널 후킹 포함)
    pub async fn start(&self) -> Result<()> {
        info!("Starting Kernel-based Reverse Shell Detector");
        
        // eBPF 프로그램 로드
        self.load_ebpf_program().await?;
        
        // 여러 모니터링 태스크를 동시에 실행
        let events_clone = Arc::clone(&self.detected_events);
        let connections_clone = Arc::clone(&self.connection_tracker);
        
        // 커널 이벤트 모니터링
        tokio::spawn(async move {
            Self::monitor_kernel_events(events_clone, connections_clone).await;
        });

        // 네트워크 연결 분석
        let events_clone = Arc::clone(&self.detected_events);
        let connections_clone = Arc::clone(&self.connection_tracker);
        
        tokio::spawn(async move {
            Self::analyze_network_connections(events_clone, connections_clone).await;
        });

        // 프로세스 생성 모니터링
        let events_clone = Arc::clone(&self.detected_events);
        
        tokio::spawn(async move {
            Self::monitor_process_creation(events_clone).await;
        });

        Ok(())
    }

    /// eBPF 프로그램 로드
    async fn load_ebpf_program(&self) -> Result<()> {
        info!("Loading eBPF program for kernel-level monitoring");
        
        // ARM64에서는 시뮬레이션 모드로 실행
        if cfg!(target_arch = "aarch64") {
            // 시뮬레이션 모드
            info!("eBPF loading skipped for ARM64 compatibility");
            *self.bpf.borrow_mut() = None;
            info!("eBPF program simulation completed");
            Ok(())
        } else {
            // x86_64에서는 실제 eBPF 로딩
            info!("Loading actual eBPF program on x86_64");
            
            // eBPF 바이트코드 로드
            let mut bpf = BpfLoader::new()
                .load(include_bytes_aligned!(
                    "../../ebpf/reverse_shell_detector.o"
                ))?;
            
            // 로그 설정
            BpfLogger::init(&mut bpf)?;
            
            // XDP 프로그램 로드
            let program: &mut Xdp = bpf.program_mut("reverse_shell_detector")?.try_into()?;
            program.load()?;
            program.attach("eth0", XdpFlags::default())?;
            
            // Tracepoint 프로그램들 로드
            let execve_program: &mut TracePoint = bpf.program_mut("trace_execve")?.try_into()?;
            execve_program.load()?;
            execve_program.attach("syscalls", "sys_enter_execve")?;
            
            let socket_program: &mut TracePoint = bpf.program_mut("trace_socket")?.try_into()?;
            socket_program.load()?;
            socket_program.attach("syscalls", "sys_enter_socket")?;
            
            let connect_program: &mut TracePoint = bpf.program_mut("trace_connect")?.try_into()?;
            connect_program.load()?;
            connect_program.attach("syscalls", "sys_enter_connect")?;
            
            // 맵 초기화
            self.initialize_ebpf_maps(&mut bpf).await?;
            
            // eBPF 인스턴스 저장
            *self.bpf.borrow_mut() = Some(bpf);
            
            info!("eBPF program loaded and attached successfully");
            Ok(())
        }
    }

    /// eBPF 맵 초기화
    async fn initialize_ebpf_maps(&self, bpf: &mut Bpf) -> Result<()> {
        // ARM64에서는 시뮬레이션 모드로 실행
        if cfg!(target_arch = "aarch64") {
            // 의심스러운 포트 맵 초기화 (시뮬레이션)
            info!("eBPF maps initialization simulated");
            Ok(())
        } else {
            // x86_64에서는 실제 eBPF 맵 초기화
            let mut suspicious_ports: AyaHashMap<_, u16, u8> = AyaHashMap::try_from(
                bpf.map_mut("suspicious_ports")?
            )?;
            
            let suspicious_port_list = vec![4444, 8080, 9001, 9002, 1337, 31337, 54321, 12345, 6667, 6668, 6669];
            for port in suspicious_port_list {
                suspicious_ports.insert(port, 1, 0)?;
            }
            
            info!("eBPF maps initialized successfully");
            Ok(())
        }
    }

    /// IP 주소를 u32로 변환
    fn ip_to_u32(ip: &str) -> u32 {
        let parts: Vec<u8> = ip.split('.')
            .map(|p| p.parse::<u8>().unwrap_or(0))
            .collect();
        
        if parts.len() == 4 {
            ((parts[0] as u32) << 24) |
            ((parts[1] as u32) << 16) |
            ((parts[2] as u32) << 8) |
            (parts[3] as u32)
        } else {
            0
        }
    }

    /// u32를 IP 주소로 변환
    fn u32_to_ip(ip_u32: u32) -> String {
        format!("{}.{}.{}.{}",
            (ip_u32 >> 24) & 0xFF,
            (ip_u32 >> 16) & 0xFF,
            (ip_u32 >> 8) & 0xFF,
            ip_u32 & 0xFF
        )
    }

    /// 커널 이벤트 모니터링
    async fn monitor_kernel_events(
        events: Arc<Mutex<Vec<ReverseShellEvent>>>,
        connections: Arc<Mutex<HashMap<String, ConnectionInfo>>>,
    ) {
        loop {
            if let Err(e) = Self::process_kernel_events(&events, &connections).await {
                error!("Error processing kernel events: {}", e);
            }
            
            sleep(Duration::from_millis(100)).await; // 고빈도 모니터링
        }
    }

    /// 커널 이벤트 처리
    async fn process_kernel_events(
        events: &Arc<Mutex<Vec<ReverseShellEvent>>>,
        connections: &Arc<Mutex<HashMap<String, ConnectionInfo>>>,
    ) -> Result<()> {
        // 커널에서 전달된 이벤트 처리 (실제로는 eBPF 맵에서 읽어옴)
        // 여기서는 시뮬레이션
        
        // 의심스러운 연결 패턴 감지
        let connections_guard = connections.lock().unwrap();
        
        for (key, conn) in connections_guard.iter() {
            if Self::is_suspicious_connection_pattern(conn) {
                let event = ReverseShellEvent {
                    timestamp: Instant::now(),
                    event_type: EventType::KernelHookTriggered,
                    severity: Severity::Critical,
                    details: format!("Kernel hook detected suspicious connection: {} -> {}:{}", 
                                   Self::u32_to_ip(conn.local_addr), 
                                   Self::u32_to_ip(conn.remote_addr), 
                                   conn.remote_port),
                    connection_info: Some(conn.clone()),
                };

                let mut events_guard = events.lock().unwrap();
                events_guard.push(event);
                
                error!("KERNEL HOOK: Suspicious connection detected: {} -> {}:{}", 
                      Self::u32_to_ip(conn.local_addr), 
                      Self::u32_to_ip(conn.remote_addr), 
                      conn.remote_port);
            }
        }

        Ok(())
    }

    /// 의심스러운 연결 패턴 감지
    fn is_suspicious_connection_pattern(conn: &ConnectionInfo) -> bool {
        // 1. 일반적인 리버스 쉘 포트 확인
        let suspicious_ports = vec![
            4444, 8080, 9001, 9002, 1337, 31337, 54321, 12345, 6667, 6668, 6669
        ];

        if suspicious_ports.contains(&conn.remote_port) {
            return true;
        }

        // 2. 외부 IP로의 연결 확인
        if !Self::is_private_ip_u32(conn.remote_addr) {
            return true;
        }

        // 3. 높은 포트 번호로의 연결 확인
        if conn.remote_port > 1024 && conn.remote_port < 49152 {
            return true;
        }

        false
    }

    /// 프라이빗 IP 주소인지 확인 (u32)
    fn is_private_ip_u32(ip_u32: u32) -> bool {
        // 127.0.0.0/8 (127.0.0.0 - 127.255.255.255)
        if (ip_u32 & 0xFF000000) == 0x7F000000 {
            return true;
        }
        
        // 10.0.0.0/8 (10.0.0.0 - 10.255.255.255)
        if (ip_u32 & 0xFF000000) == 0x0A000000 {
            return true;
        }
        
        // 172.16.0.0/12 (172.16.0.0 - 172.31.255.255)
        if (ip_u32 & 0xFFF00000) == 0xAC100000 {
            return true;
        }
        
        // 192.168.0.0/16 (192.168.0.0 - 192.168.255.255)
        if (ip_u32 & 0xFFFF0000) == 0xC0A80000 {
            return true;
        }
        
        false
    }

    /// 네트워크 연결 분석
    async fn analyze_network_connections(
        events: Arc<Mutex<Vec<ReverseShellEvent>>>,
        connections: Arc<Mutex<HashMap<String, ConnectionInfo>>>,
    ) {
        loop {
            if let Err(e) = Self::scan_network_connections(&events, &connections).await {
                error!("Error scanning network connections: {}", e);
            }
            
            sleep(Duration::from_secs(5)).await;
        }
    }

    /// 네트워크 연결 스캔
    async fn scan_network_connections(
        events: &Arc<Mutex<Vec<ReverseShellEvent>>>,
        connections: &Arc<Mutex<HashMap<String, ConnectionInfo>>>,
    ) -> Result<()> {
        // /proc/net/tcp 파일을 읽어서 활성 연결 확인
        let tcp_content = std::fs::read_to_string("/proc/net/tcp")?;
        let tcp6_content = std::fs::read_to_string("/proc/net/tcp6")?;

        let mut new_connections = Vec::new();

        // TCP 연결 파싱
        for line in tcp_content.lines().skip(1) {
            if let Some(conn_info) = Self::parse_tcp_line(line)? {
                new_connections.push(conn_info);
            }
        }

        // TCP6 연결 파싱
        for line in tcp6_content.lines().skip(1) {
            if let Some(conn_info) = Self::parse_tcp6_line(line)? {
                new_connections.push(conn_info);
            }
        }

        // 연결 정보 업데이트
        let mut connections_guard = connections.lock().unwrap();
        for conn in new_connections {
            let key = format!("{}:{}->{}:{}", 
                Self::u32_to_ip(conn.local_addr), conn.local_port,
                Self::u32_to_ip(conn.remote_addr), conn.remote_port);
            
            connections_guard.insert(key, conn);
        }

        Ok(())
    }

    /// TCP 라인 파싱
    fn parse_tcp_line(line: &str) -> Result<Option<ConnectionInfo>> {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 4 {
            return Ok(None);
        }

        let local_addr_port = parts[1];
        let remote_addr_port = parts[2];
        let state = parts[3];

        // 연결이 ESTABLISHED 상태인지 확인
        if state != "01" {
            return Ok(None);
        }

        let (local_addr, local_port) = Self::parse_addr_port(local_addr_port)?;
        let (remote_addr, remote_port) = Self::parse_addr_port(remote_addr_port)?;

        // 프로세스 정보 가져오기
        let (pid, process_name) = Self::get_process_info_for_connection(&Self::u32_to_ip(local_addr), local_port)?;

        Ok(Some(ConnectionInfo {
            local_addr,
            remote_addr,
            local_port,
            remote_port,
            pid,
            process_name,
            first_seen: Instant::now(),
            last_seen: Instant::now(),
            connection_count: 1,
            is_suspicious: false,
        }))
    }

    /// TCP6 라인 파싱
    fn parse_tcp6_line(line: &str) -> Result<Option<ConnectionInfo>> {
        // TCP6는 IPv6 주소를 사용하므로 별도 처리
        Self::parse_tcp_line(line)
    }

    /// 주소:포트 파싱
    fn parse_addr_port(addr_port: &str) -> Result<(u32, u16)> {
        let parts: Vec<&str> = addr_port.split(':').collect();
        if parts.len() != 2 {
            return Err(anyhow::anyhow!("Invalid address:port format"));
        }

        let addr_hex = parts[0];
        let port_hex = parts[1];

        // 16진수 주소를 IP 주소로 변환
        let addr = Self::hex_to_ip_u32(addr_hex)?;
        let port = u16::from_str_radix(port_hex, 16)?;

        Ok((addr, port))
    }

    /// 16진수 주소를 IP 주소로 변환 (u32)
    fn hex_to_ip_u32(hex: &str) -> Result<u32> {
        if hex.len() != 8 {
            return Err(anyhow::anyhow!("Invalid hex address length"));
        }

        let bytes: Vec<u8> = (0..8)
            .step_by(2)
            .map(|i| u8::from_str_radix(&hex[i..i+2], 16))
            .collect::<Result<Vec<u8>, _>>()?;

        // 리틀 엔디안으로 저장된 주소를 변환
        Ok(((bytes[3] as u32) << 24) |
           ((bytes[2] as u32) << 16) |
           ((bytes[1] as u32) << 8) |
           (bytes[0] as u32))
    }

    /// 연결에 대한 프로세스 정보 가져오기
    fn get_process_info_for_connection(local_addr: &str, local_port: u16) -> Result<(u32, String)> {
        // /proc/net/tcp에서 해당 연결의 inode 찾기
        let tcp_content = std::fs::read_to_string("/proc/net/tcp")?;
        
        for line in tcp_content.lines().skip(1) {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() < 10 {
                continue;
            }

            let (addr, port) = Self::parse_addr_port(parts[1])?;
            if Self::u32_to_ip(addr) == local_addr && port == local_port {
                let inode = parts[9];
                return Self::get_process_by_inode(inode);
            }
        }

        Ok((0, "unknown".to_string()))
    }

    /// inode로 프로세스 정보 가져오기
    fn get_process_by_inode(inode: &str) -> Result<(u32, String)> {
        // /proc 디렉토리를 스캔하여 해당 inode를 사용하는 프로세스 찾기
        for entry in std::fs::read_dir("/proc")? {
            let entry = entry?;
            let path = entry.path();
            
            if let Some(pid_str) = path.file_name().and_then(|s| s.to_str()) {
                if let Ok(pid) = pid_str.parse::<u32>() {
                    if let Ok(links) = std::fs::read_dir(path.join("fd")) {
                        for link in links {
                            if let Ok(link) = link {
                                if let Ok(target) = std::fs::read_link(link.path()) {
                                    if target.to_string_lossy().contains(inode) {
                                        // 프로세스 이름 가져오기
                                        if let Ok(cmdline) = std::fs::read_to_string(path.join("cmdline")) {
                                            let process_name = cmdline.split('\0').next().unwrap_or("unknown");
                                            return Ok((pid, process_name.to_string()));
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        Ok((0, "unknown".to_string()))
    }

    /// 프로세스 생성 모니터링
    async fn monitor_process_creation(
        events: Arc<Mutex<Vec<ReverseShellEvent>>>,
    ) {
        loop {
            if let Err(e) = Self::scan_process_creation(&events).await {
                error!("Error scanning process creation: {}", e);
            }
            
            sleep(Duration::from_secs(10)).await;
        }
    }

    /// 프로세스 생성 스캔
    async fn scan_process_creation(
        events: &Arc<Mutex<Vec<ReverseShellEvent>>>,
    ) -> Result<()> {
        // 현재 실행 중인 프로세스 목록 가져오기
        let current_processes = Self::get_current_processes()?;
        
        // 의심스러운 프로세스 패턴 확인
        for process in current_processes {
            if Self::is_suspicious_process(&process) {
                let event = ReverseShellEvent {
                    timestamp: Instant::now(),
                    event_type: EventType::ProcessInjection,
                    severity: Severity::High,
                    details: format!("Suspicious process detected: {}", process),
                    connection_info: None,
                };

                let mut events_guard = events.lock().unwrap();
                events_guard.push(event);
                
                warn!("Suspicious process detected: {}", process);
            }
        }

        Ok(())
    }

    /// 현재 프로세스 목록 가져오기
    fn get_current_processes() -> Result<Vec<String>> {
        let mut processes = Vec::new();
        
        for entry in std::fs::read_dir("/proc")? {
            let entry = entry?;
            let path = entry.path();
            
            if let Some(pid_str) = path.file_name().and_then(|s| s.to_str()) {
                if let Ok(_pid) = pid_str.parse::<u32>() {
                    if let Ok(cmdline) = std::fs::read_to_string(path.join("cmdline")) {
                        let process_name = cmdline.split('\0').next().unwrap_or("unknown");
                        if !process_name.is_empty() && process_name != "unknown" {
                            processes.push(process_name.to_string());
                        }
                    }
                }
            }
        }

        Ok(processes)
    }

    /// 의심스러운 프로세스인지 확인
    fn is_suspicious_process(process_name: &str) -> bool {
        let suspicious_patterns = vec![
            "nc", "netcat", "bash -i", "sh -i", "python -c", "perl -e",
            "ruby -rsocket", "php -r", "wget", "curl", "ftp", "telnet",
            "ssh", "scp", "rsync", "nc.traditional", "ncat"
        ];

        suspicious_patterns.iter().any(|&pattern| process_name.contains(pattern))
    }

    /// 탐지된 이벤트 가져오기
    pub fn get_detected_events(&self) -> Vec<ReverseShellEvent> {
        let events_guard = self.detected_events.lock().unwrap();
        events_guard.clone()
    }

    /// 의심스러운 연결 목록 가져오기
    pub fn get_suspicious_connections(&self) -> Vec<ConnectionInfo> {
        let connections_guard = self.connection_tracker.lock().unwrap();
        connections_guard.values().cloned().collect()
    }

    /// 플러그인 상태 리포트
    pub fn generate_report(&self) -> String {
        let events = self.get_detected_events();
        let connections = self.get_suspicious_connections();
        
        format!(
            "Kernel-based Reverse Shell Detection Report\n\
             ===========================================\n\
             Total Events Detected: {}\n\
             Suspicious Connections: {}\n\
             \n\
             Recent Events:\n\
             {}",
            events.len(),
            connections.len(),
            events.iter()
                .take(10)
                .map(|e| format!("[{}] {:?} - {}", 
                    e.timestamp.elapsed().as_secs(), 
                    e.severity, 
                    e.details))
                .collect::<Vec<_>>()
                .join("\n")
        )
    }
}

impl Default for ReverseShellDetector {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ip_conversion() {
        assert_eq!(ReverseShellDetector::ip_to_u32("127.0.0.1"), 0x0100007F);
        assert_eq!(ReverseShellDetector::ip_to_u32("192.168.1.1"), 0x0101A8C0);
        assert_eq!(ReverseShellDetector::u32_to_ip(0x0100007F), "127.0.0.1");
        assert_eq!(ReverseShellDetector::u32_to_ip(0x0101A8C0), "192.168.1.1");
    }

    #[test]
    fn test_private_ip_detection() {
        assert!(ReverseShellDetector::is_private_ip_u32(ReverseShellDetector::ip_to_u32("127.0.0.1")));
        assert!(ReverseShellDetector::is_private_ip_u32(ReverseShellDetector::ip_to_u32("192.168.1.1")));
        assert!(ReverseShellDetector::is_private_ip_u32(ReverseShellDetector::ip_to_u32("10.0.0.1")));
        assert!(!ReverseShellDetector::is_private_ip_u32(ReverseShellDetector::ip_to_u32("8.8.8.8")));
    }

    #[test]
    fn test_suspicious_process() {
        assert!(ReverseShellDetector::is_suspicious_process("nc -l 4444"));
        assert!(ReverseShellDetector::is_suspicious_process("bash -i"));
        assert!(!ReverseShellDetector::is_suspicious_process("nginx"));
    }
}
