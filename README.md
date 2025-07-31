[![CI](https://github.com/GizzZmo/Enhanced-Botnet-Implementation/actions/workflows/ci.yml/badge.svg)](https://github.com/GizzZmo/Enhanced-Botnet-Implementation/actions/workflows/ci.yml)
# Enhanced Botnet Implementation

> **Disclaimer & Legal Notice**  
> This repository is intended **strictly for educational and research purposes.** Any use of this code must comply with all applicable laws. The authors and contributors do **not** condone or support malicious or unauthorized use. Always test in isolated, controlled environments with explicit permission. See the [Ethical Usage Recommendations](#ethical-usage-recommendations) and [Legal Notice](#legal-notice).

---

## Table of Contents
- [Purpose](#purpose)
- [Features](#features)
- [Project Structure](#project-structure)
- [Setup Instructions](#setup-instructions)
- [Sample Output](#sample-output)
- [Troubleshooting](#troubleshooting)
- [Ethical Deployment Guidelines](#ethical-deployment-guidelines)
- [Legal Notice](#legal-notice)
- [Contribution](#contribution)
- [References](#references)

---

## Purpose
This project demonstrates the implementation of a Command & Control (C&C) server for a botnet, focusing on techniques such as encrypted communication, active bot tracking, stealth, persistence, and execution history logging. It is meant as a model for studying botnet behaviors and defensive cybersecurity measures.

---

## Features
- **Stealth Mechanisms**: XOR/AES encryption of commands, pseudo-random command prioritization, and structured JSON payloads to evade basic detection.
- **Persistence & Logging**: Maintains a list of active bots across restarts; logs events and commands with timestamps.
- **Monitoring & Execution History**: Tracks connected bots, execution history, communication times, and command outcomes.
- **Threaded Architecture**: Handles multiple bot connections concurrently.
- **Structured Protocol**: JSON-based messaging for clear, extensible communication.
- **Code Samples & Documentation**: Fully documented controller code and sample configuration included.

---

## Project Structure
```
Enhanced-Botnet-Implementation/
├── botnet_controller.py      # Main C&C server application
├── botnet_server_enhanced.py # Enhanced server with extra monitoring/logging
├── requirements.txt          # Python dependencies
└── README.md                 # Documentation (this file)
```

---

## Setup Instructions

### Requirements
- Python 3.8+
- Install dependencies in a **virtual environment**:
  ```bash
  python3 -m venv venv
  source venv/bin/activate
  pip install -r requirements.txt
  ```
  Or manually:
  ```bash
  pip install cryptography requests pycryptodome
  ```

### Running Locally
- For research/testing **only**. Do not deploy in production or on unauthorized networks.
- Start the server:
  ```bash
  python3 botnet_controller.py
  # or
  python3 botnet_server_enhanced.py
  ```

---

## Sample Output

Example console output when a bot connects:
```
[*] Listening on 0.0.0.0:9999
[+] Welcome to botnet controller!
Registered bot: 4a1b2c3d
4a1b2c3d> <your command>
```

Example of command payload sent (JSON):
```
{
  "timestamp": 1722345600.0,
  "cmd": "e9a1...",   # Encrypted command
  "priority": 51
}
```

---

## Troubleshooting
- **Port already in use**: Change the port number in the script.
- **Permission denied**: Use an elevated shell or a higher port number (>1024).
- **Dependency errors**: Ensure you are in your virtual environment and all dependencies are installed.
- **Network issues**: Test locally, and ensure firewalls are not blocking your server.

---

## Ethical Deployment Guidelines
1. **Network Segmentation**: Only deploy in isolated lab/test networks.
2. **Access Controls**: Implement authentication for admin access.
3. **Monitoring**: Add outbound/inbound traffic monitoring.
4. **Minimal Data Collection**: Log only what is necessary for research.

---

## Legal Notice
Distribution and usage must comply with all local, national, and international laws. Unauthorized access or network disruption is illegal. This repository is for defensive research and academic study **only**.

---

## Contribution
Contributions are welcome! Please:
- Submit issues or feature requests via GitHub Issues.
- Fork and submit Pull Requests for improvements.
- Follow the [GitHub Community Guidelines](https://docs.github.com/en/site-policy/github-terms/github-community-guidelines).

> All contributors must adhere to ethical and legal standards. Malicious code or irresponsible usage will not be accepted.

---

## References
- [MITRE ATT&CK - Botnet](https://attack.mitre.org/techniques/T1583/001/)
- [OWASP - Secure Coding Practices](https://owasp.org/www-project-secure-coding-practices-quick-reference-guide/)
- [Python cryptography docs](https://cryptography.io/)

---

Let me know if you need more details about the implementation or want to learn how specific features work!
