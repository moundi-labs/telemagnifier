# telemagnifier

### Background
Traditional Capture The Flag (CTF) competitions differ significantly from real-world security environments due to the absence of internal monitoring systems. This allows participants to freely use attack techniques that would be easily detected in production environments.   
Telemagnifier bridges this gap by introducing a realistic security monitoring platform designed specifically for competitive hacking scenarios. By incorporating detection techniques used in actual enterprise environments, it encourages participants to develop stealthy and sophisticated attack methodologies.

### Features
- **Real-time eBPF Monitoring**: Advanced system-level monitoring using eBPF technology to detect attack techniques and suspicious activities in real-time, mimicking enterprise security environments
- **Cross-Platform Support**: Linux eBPF agent and Windows agent for comprehensive monitoring across different operating systems
- **Centralized Data Collection**: Collector server for aggregating and analyzing security events from multiple agents
- **Extensible Architecture**: Modular design allowing easy addition of new monitoring capabilities and analysis features
