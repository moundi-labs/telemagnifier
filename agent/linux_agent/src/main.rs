mod plugins;

use anyhow::Result;
use log::{info, error};
use tokio;

#[tokio::main]
async fn main() -> Result<()> {
    // 로깅 초기화
    env_logger::init();
    
    info!("Starting Linux Agent with Kernel Hooking for Reverse Shell Detection");
    
    // 리버스 쉘 탐지 플러그인 생성 및 시작
    let detector = plugins::reverse_shell::ReverseShellDetector::new();
    
    if let Err(e) = detector.start().await {
        error!("Failed to start reverse shell detector: {}", e);
        return Err(e);
    }
    
    info!("Reverse shell detector started successfully");
    
    // 메인 루프 - 플러그인이 백그라운드에서 실행됨
    loop {
        tokio::time::sleep(tokio::time::Duration::from_secs(60)).await;
        
        // 주기적으로 리포트 생성
        let report = detector.generate_report();
        info!("Periodic Report:\n{}", report);
    }
}
