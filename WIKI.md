# 📘 Enhanced Botnet Wiki

> Educational and research use only. Operate in isolated, permissioned environments and follow all applicable laws and policies.

## 🗺️ What this page covers
- Quick pointers to setup, operation, and dashboards
- Links to detailed guides and deep dives already in this repository
- Ready-to-use commands for common workflows

## 🚀 Getting started
- **Setup fast**: Use [QUICKSTART.md](QUICKSTART.md) or run `./setup.sh` (Linux/macOS) / `setup.bat` (Windows), then `source venv/bin/activate`.
- **Launch options**:
  - Interactive menu: `python launch.py`
  - Basic controller: `python launch.py --basic`
  - Enhanced server + dashboard: `python launch.py --enhanced` and open `http://localhost:8080`
- **Configuration**: Copy `.env.example` to `.env` or use `config.example.json` as a template. Command-line flags override env and file settings.

## ⚙️ Operating modes at a glance
- **Basic Controller (`botnet_controller.py`)**
  - Minimal C&C without web UI
  - Supports auth, TLS, and secure logging
- **Enhanced Server (`botnet_server_enhanced.py`)**
  - Adds dashboard endpoints and monitoring
  - Configure ports with `--port` and `--web-port`

## 🖥️ Dashboard quick reference
- Start: `python botnet_server_enhanced.py` (or `python launch.py --enhanced`)
- Access: `http://localhost:8080`
- Key env vars: `BOTNET_WEB_PORT` (default 8080), `BOTNET_PORT` (default 9999), `BOTNET_HOST`, `BOTNET_MAX_MESSAGE_SIZE`
- Full details: [DASHBOARD.md](DASHBOARD.md)

## 🔐 Security & ethics essentials
- Educational-only license; never deploy to production networks.
- Use strong admin credentials and unique encryption keys.
- Prefer localhost or lab networks; enable TLS when testing beyond localhost.
- Review [README → Security Considerations](README.md#-security-considerations) and [Ethical Usage Recommendations](README.md#-ethical-usage-recommendations).

## 🧪 Testing & quality checks
- Run tests: `pytest` (see README testing section for coverage and categories).
- Linting/formatting used in CI: `flake8` (max line length 100, E203/W503 ignored) and `black --check`.

## 🛠️ Troubleshooting fast picks
- **Deps**: `python launch.py --check-deps` (install with `--install-deps`).
- **Ports**: ensure chosen ports are free (`netstat -tlnp | grep 9999`).
- **Debug**: `python botnet_controller.py --verbose` and set `BOTNET_LOG_LEVEL=DEBUG`.
- More fixes: see [README → Troubleshooting](README.md#-troubleshooting).

## 📚 More references
- Architecture, features, and API snippets: [README.md](README.md)
- Quick start walkthrough: [QUICKSTART.md](QUICKSTART.md)
- Dashboard visuals and endpoints: [DASHBOARD.md](DASHBOARD.md)
- Deep dives: [TechnicalAnalysis.md](TechnicalAnalysis.md), [THREADING_FIX_SUMMARY.md](THREADING_FIX_SUMMARY.md)
- UX changes: [USABILITY_IMPROVEMENTS.md](USABILITY_IMPROVEMENTS.md)
- Contribution process: [CONTRIBUTING.md](CONTRIBUTING.md)

---

*Last updated: 2026 | Maintainers: GizzZmo & contributors*
