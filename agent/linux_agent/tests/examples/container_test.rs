use std::time::Duration;
use tokio::time::sleep;
use linux_agent::plugins::reverse_shell::ReverseShellDetector;
use std::process::Command;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // 로깅 초기화
    env_logger::init();
    
    println!("=== Container Test for Reverse Shell Detector ===");
    println!("This example demonstrates testing in a container environment");
    
    // 탐지기 생성
    let detector = ReverseShellDetector::new();
    
    // 탐지기 시작
    println!("Starting detector...");
    detector.start().await?;
    
    println!("Detector started successfully!");
    println!("Waiting for initialization...");
    sleep(Duration::from_secs(5)).await;
    
    // 테스트 시나리오 실행
    println!("\n=== Running Test Scenarios ===");
    
    // 테스트 1: Netcat 리버스 쉘
    println!("Test 1: Netcat reverse shell");
    test_netcat_reverse_shell().await?;
    
    // 테스트 2: Python 리버스 쉘
    println!("Test 2: Python reverse shell");
    test_python_reverse_shell().await?;
    
    // 테스트 3: 의심스러운 포트 연결
    println!("Test 3: Suspicious port connection");
    test_suspicious_port_connection().await?;
    
    // 테스트 4: 외부 연결
    println!("Test 4: External connection");
    test_external_connection().await?;
    
    // 결과 확인
    println!("\n=== Checking Detection Results ===");
    sleep(Duration::from_secs(10)).await;
    
    let events = detector.get_detected_events();
    let connections = detector.get_suspicious_connections();
    
    println!("Total events detected: {}", events.len());
    println!("Suspicious connections: {}", connections.len());
    
    if !events.is_empty() {
        println!("\nRecent events:");
        for (i, event) in events.iter().take(5).enumerate() {
            println!("  {}. [{}] {:?}: {}", 
                i + 1,
                event.timestamp.elapsed().as_secs(),
                event.severity,
                event.details);
        }
    }
    
    if !connections.is_empty() {
        println!("\nSuspicious connections:");
        for (i, conn) in connections.iter().take(5).enumerate() {
            println!("  {}. {}:{} -> {}:{} (PID: {}, Process: {})", 
                i + 1,
                conn.local_addr, conn.local_port,
                conn.remote_addr, conn.remote_port,
                conn.pid, conn.process_name);
        }
    }
    
    // 최종 리포트 생성
    println!("\n=== Final Report ===");
    let report = detector.generate_report();
    println!("{}", report);
    
    println!("\nContainer test completed!");
    Ok(())
}

/// Netcat 리버스 쉘 테스트
async fn test_netcat_reverse_shell() -> Result<(), Box<dyn std::error::Error>> {
    // netcat 리스너 시작
    let mut listener = Command::new("nc")
        .args(&["-l", "-p", "4444"])
        .spawn()?;
    
    sleep(Duration::from_secs(2)).await;
    
    // 리버스 쉘 연결 시도
    let _result = Command::new("bash")
        .args(&["-c", "bash -i >& /dev/tcp/127.0.0.1/4444 0>&1"])
        .output();
    
    sleep(Duration::from_secs(3)).await;
    
    // 리스너 종료
    let _ = listener.kill();
    
    println!("  ✓ Netcat reverse shell test completed");
    Ok(())
}

/// Python 리버스 쉘 테스트
async fn test_python_reverse_shell() -> Result<(), Box<dyn std::error::Error>> {
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
    
    println!("  ✓ Python reverse shell test completed");
    Ok(())
}

/// 의심스러운 포트 연결 테스트
async fn test_suspicious_port_connection() -> Result<(), Box<dyn std::error::Error>> {
    let _result = Command::new("nc")
        .args(&["-v", "127.0.0.1", "1337"])
        .output();
    
    sleep(Duration::from_secs(1)).await;
    
    println!("  ✓ Suspicious port connection test completed");
    Ok(())
}

/// 외부 연결 테스트
async fn test_external_connection() -> Result<(), Box<dyn std::error::Error>> {
    let _result = Command::new("curl")
        .args(&["-s", "--connect-timeout", "3", "http://8.8.8.8"])
        .output();
    
    sleep(Duration::from_secs(1)).await;
    
    println!("  ✓ External connection test completed");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[tokio::test]
    async fn test_detector_creation() {
        let detector = ReverseShellDetector::new();
        assert!(detector.get_detected_events().is_empty());
        assert!(detector.get_suspicious_connections().is_empty());
    }
    
    #[tokio::test]
    async fn test_detector_start() {
        let detector = ReverseShellDetector::new();
        let result = detector.start().await;
        assert!(result.is_ok());
    }
}
