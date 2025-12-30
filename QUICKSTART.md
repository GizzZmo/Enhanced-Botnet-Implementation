# 🚀 Quick Start Guide

Get started with the Enhanced Botnet Implementation in minutes!

## Prerequisites

- Python 3.8 or higher
- pip package manager
- Internet connection (for installing dependencies)

## Installation

### Option 1: Automated Setup (Recommended)

**Linux/macOS:**
```bash
./setup.sh
source venv/bin/activate
```

**Windows:**
```cmd
setup.bat
venv\Scripts\activate.bat
```

### Option 2: Manual Setup

```bash
# Create virtual environment
python3 -m venv venv

# Activate virtual environment
source venv/bin/activate  # Linux/macOS
# OR
venv\Scripts\activate.bat  # Windows

# Install dependencies
pip install -r requirements.txt
```

## Running the Server

### Interactive Mode (Easiest)

Simply run the launcher and follow the prompts:

```bash
python launch.py
```

This will:
1. Check if dependencies are installed
2. Let you choose between basic or enhanced mode
3. Launch the server with sensible defaults

### Basic Controller Mode

For a simple C&C server without the web dashboard:

```bash
python launch.py --basic
```

Or directly:

```bash
python botnet_controller.py
```

### Enhanced Server Mode

For the full-featured server with web dashboard:

```bash
python launch.py --enhanced
```

Or directly:

```bash
python botnet_server_enhanced.py
```

Then open your browser to: `http://localhost:8080`

## Command-Line Options

Both servers support extensive command-line options:

```bash
# Show all available options
python botnet_controller.py --help
python botnet_server_enhanced.py --help

# Common options
--host 127.0.0.1           # Bind to specific address
--port 9999                # Use custom port
--no-auth                  # Skip authentication
--verbose                  # Enable debug logging
--quiet                    # Minimize output
```

## Configuration

### Quick Configuration

Use default settings with localhost binding (most secure for testing):

```bash
python launch.py --basic --host 127.0.0.1 --port 9999
```

### Environment Variables

Create a `.env` file from the example:

```bash
cp .env.example .env
# Edit .env with your settings
```

Or set variables directly:

```bash
export BOTNET_HOST="127.0.0.1"
export BOTNET_PORT="9999"
export BOTNET_LOG_LEVEL="INFO"
```

### Configuration File

Create a `config.json` file:

```json
{
  "SERVER_HOST": "127.0.0.1",
  "SERVER_PORT": 9999,
  "LOG_LEVEL": "INFO",
  "MAX_CONNECTIONS": 100
}
```

Then use it:

```bash
python botnet_controller.py --config config.json
```

## Common Use Cases

### 1. Local Testing (Most Secure)

```bash
python launch.py --basic --host 127.0.0.1 --no-auth
```

### 2. Network Lab Testing

```bash
python launch.py --enhanced --host 0.0.0.0 --port 9999
```

Then access dashboard at: `http://your-server-ip:8080`

### 3. Debug Mode

```bash
python launch.py --basic --verbose
```

### 4. Minimal Output

```bash
python launch.py --enhanced --quiet
```

## Verifying Installation

Check dependencies:

```bash
python launch.py --check-deps
```

Install missing dependencies:

```bash
python launch.py --install-deps
```

Test basic functionality:

```bash
# In one terminal
python botnet_controller.py --no-auth --host 127.0.0.1

# The server should start and display:
# ============================================================
# Enhanced Botnet Controller v2.0
# Educational/Research Use Only
# ============================================================
# Server: 127.0.0.1:9999
# ...
```

## Troubleshooting

### Import Errors

If you see `ModuleNotFoundError`:

```bash
# Make sure virtual environment is activated
source venv/bin/activate  # Linux/macOS
venv\Scripts\activate.bat  # Windows

# Reinstall dependencies
pip install -r requirements.txt
```

### Port Already in Use

```bash
# Use a different port
python botnet_controller.py --port 8888
```

### Permission Denied (Linux/macOS)

```bash
# Use a port above 1024 (default is 9999, which is fine)
# Or run with sudo for ports below 1024 (not recommended)
```

### Web Dashboard Not Working

The enhanced server requires optional dependencies:

```bash
pip install aiohttp aiohttp-cors
```

Or run in basic mode:

```bash
python launch.py --basic
```

## Next Steps

1. **Read the Documentation**: See [README.md](README.md) for comprehensive documentation
2. **Review Security**: Check [CONTRIBUTING.md](CONTRIBUTING.md) for security guidelines
3. **Explore Features**: Try the web dashboard at `http://localhost:8080`
4. **Configure TLS**: Set up SSL/TLS for secure communications (see README.md)
5. **Customize**: Modify configuration files for your research environment

## Getting Help

- Check the [README.md](README.md) for detailed documentation
- Review [DASHBOARD.md](DASHBOARD.md) for dashboard features
- See [CONTRIBUTING.md](CONTRIBUTING.md) for development guidelines
- Use `--help` flag on any script for command-line options

## Important Reminders

⚠️ **Educational Use Only**
- This software is for educational and research purposes only
- Always use in isolated, controlled environments
- Obtain proper authorization before any testing
- Follow all applicable laws and regulations

🔒 **Security Best Practices**
- Use strong passwords for admin authentication
- Generate unique encryption keys for each deployment
- Enable TLS for production-like testing
- Monitor all network traffic
- Keep dependencies updated

## Example Workflow

Here's a complete example workflow for getting started:

```bash
# 1. Clone repository (if not already done)
git clone [repository-url]
cd Enhanced-Botnet-Implementation

# 2. Run setup
./setup.sh  # Linux/macOS
# OR
setup.bat   # Windows

# 3. Activate environment
source venv/bin/activate

# 4. Launch in interactive mode
python launch.py

# 5. Choose option 1 (Basic) or 2 (Enhanced)
# Enter: 2

# 6. Server starts and shows:
# ============================================================
# Enhanced Botnet Server v2.0
# Educational/Research Use Only
# ============================================================
# Main Server: 127.0.0.1:9999
# Web Dashboard: 127.0.0.1:8080 (Enabled)
# ...
# Dashboard URL: http://127.0.0.1:8080
# ============================================================

# 7. Open browser to http://localhost:8080
# See live dashboard with monitoring

# 8. Stop with Ctrl+C when done
```

That's it! You're now ready to explore the Enhanced Botnet Implementation for your educational and research needs.
