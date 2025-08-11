use std::time::Duration;
use tokio::time::sleep;
use linux_agent::plugins::reverse_shell::ReverseShellDetector;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // 로깅 초기화
    env_logger::init();
    
    println!("=== Reverse Shell Detector Basic Usage Example ===");
    
    // 탐지기 생성
    let detector = ReverseShellDetector::new();
    
    // 탐지기 시작
    detector.start().await?;
    
    println!("Detector started. Monitoring for reverse shell activities...");
    println!("Press Ctrl+C to stop");
    
    // 메인 루프
    loop {
        sleep(Duration::from_secs(30)).await;
        
        // 리포트 생성
        let report = detector.generate_report();
        println!("\n{}", report);
        
        // 탐지된 이벤트 확인
        let events = detector.get_detected_events();
        if !events.is_empty() {
            println!("\n=== Detected Events ===");
            for event in events.iter().take(5) {
                println!("[{}] {:?}: {}", 
                    event.timestamp.elapsed().as_secs(),
                    event.severity,
                    event.details);
            }
        }
    }
}
