# 🛡️ Cyberpunk Dashboard Guide

## Overview

The Enhanced Botnet Implementation now includes a cyberpunk-themed web dashboard with matrix digital rain effects for real-time monitoring of the Command & Control server.

## Features

### 🎨 Visual Design
- **Cyberpunk Theme**: Dark background with neon green/cyan accents
- **Matrix Rain Effect**: Animated falling characters in the background  
- **Futuristic Fonts**: Orbitron and Share Tech Mono for authentic cyberpunk feel
- **Animated Elements**: Glowing borders, hover effects, and pulsing indicators
- **Responsive Design**: Works on desktop and mobile devices

### 📊 Real-time Monitoring
- **Server Status**: Uptime, version, encryption, and TLS status
- **Bot Network**: Active bot count, total connections, command statistics
- **Performance Metrics**: Data transfer rates and processing statistics
- **Active Bots**: Real-time list of connected bots with details
- **Security Status**: Authentication state and threat monitoring
- **Command History**: Recent command execution history

## Usage

### Starting the Server with Dashboard

1. **Start the Enhanced Server**:
   ```bash
   python botnet_server_enhanced.py
   ```

2. **Access the Dashboard**:
   - Open your web browser
   - Navigate to: `http://localhost:8080`
   - The dashboard will load with live data updates every 2 seconds

### Configuration

The dashboard can be configured via environment variables:

```bash
# Web dashboard port (default: 8080)
export BOTNET_WEB_PORT=8080

# Main server port (default: 9999)  
export BOTNET_PORT=9999

# Server host (default: 127.0.0.1)
export BOTNET_HOST=127.0.0.1

# Maximum message size (default: 1MB)
export BOTNET_MAX_MESSAGE_SIZE=1048576
```

### Dashboard Components

#### 🖥️ Server Status Card
- Shows if server is online/offline
- Displays uptime in real-time
- Server version and configuration
- Encryption and TLS status

#### 🤖 Bot Network Card  
- Number of active bots
- Total connection count
- Commands processed counter
- Connection utilization progress bar

#### 📊 Performance Card
- Bytes sent/received counters
- Data transfer rates
- Memory usage (when available)

#### 🌐 Active Bots Card
- List of currently connected bots
- Bot IDs and IP addresses
- Last seen timestamps
- Command statistics per bot

#### 🔒 Security Card
- Authentication status
- Failed login attempts
- Blocked IP addresses
- Current threat level

#### 📝 Command History Card
- Recent command executions
- Timestamps and target bots
- Command summaries (sanitized)

## API Endpoints

The dashboard uses REST API endpoints for data:

- `GET /` - Serves the dashboard HTML
- `GET /api/status` - Server status and statistics
- `GET /api/bots` - Active bot information
- `GET /api/stats` - Detailed performance metrics

## Technical Details

### Matrix Rain Effect
- Canvas-based animation using falling characters
- Customizable character set and speed
- Transparent overlay that doesn't interfere with UI
- Automatically resizes with browser window

### Real-time Updates
- JavaScript fetches data every 2 seconds
- Graceful fallback to demo data if server unavailable
- Smooth animations for changing values
- Progress bars update in real-time

### Security
- All existing security features maintained
- API endpoints use same validation as main server
- No sensitive data exposed in web interface
- Sanitized logging and display

## Development

The dashboard consists of:

- `dashboard.html` - Complete HTML template with embedded CSS and JavaScript
- `botnet_server_enhanced.py` - Enhanced server with web endpoints
- `utils.py` - Updated configuration for web server settings

## Browser Compatibility

- Chrome/Chromium (recommended)
- Firefox
- Safari
- Edge

Note: The matrix effect uses HTML5 Canvas and may perform better in modern browsers.

## Troubleshooting

### Dashboard Not Loading
1. Verify server is running: `netstat -an | grep 8080`
2. Check firewall settings for port 8080
3. Review server logs for errors

### No Data Updates
1. Ensure main server is running on port 9999
2. Check network connectivity between dashboard and API
3. Review browser console for JavaScript errors

### Matrix Effect Not Working
1. Ensure JavaScript is enabled in browser
2. Check browser console for Canvas errors
3. Try refreshing the page

## Educational Purpose

This dashboard is designed for cybersecurity education and research:
- Demonstrates modern C&C monitoring interfaces
- Shows real-time network activity visualization
- Provides insight into botnet operational metrics
- Maintains educational focus with clear labeling

Remember: This is for educational and research purposes only. Use responsibly and in accordance with all applicable laws and regulations.
