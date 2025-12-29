#!/bin/bash
# Setup script for Enhanced Botnet Implementation

set -e

echo "=========================================="
echo "Enhanced Botnet Implementation - Setup"
echo "Educational/Research Use Only"
echo "=========================================="
echo ""

# Check Python version
echo "Checking Python version..."
python_version=$(python3 --version 2>&1 | awk '{print $2}')
echo "✓ Python $python_version found"
echo ""

# Create virtual environment
if [ ! -d "venv" ]; then
    echo "Creating virtual environment..."
    python3 -m venv venv
    echo "✓ Virtual environment created"
else
    echo "✓ Virtual environment already exists"
fi
echo ""

# Activate virtual environment
echo "Activating virtual environment..."
source venv/bin/activate || . venv/bin/activate
echo "✓ Virtual environment activated"
echo ""

# Upgrade pip
echo "Upgrading pip..."
python -m pip install --upgrade pip --quiet
echo "✓ pip upgraded"
echo ""

# Install dependencies
echo "Installing dependencies..."
pip install -r requirements.txt --quiet
echo "✓ Dependencies installed"
echo ""

# Generate encryption key if needed
echo "Checking encryption key..."
if [ -z "$BOTNET_ENCRYPTION_KEY" ]; then
    encryption_key=$(python3 -c "import os, base64; print(base64.b64encode(os.urandom(32)).decode())")
    echo "Generated encryption key: $encryption_key"
    echo ""
    echo "Add this to your environment:"
    echo "  export BOTNET_ENCRYPTION_KEY=\"$encryption_key\""
    echo ""
    echo "Or create a .env file with this key"
else
    echo "✓ Encryption key already configured"
fi
echo ""

# Create example config if it doesn't exist
if [ ! -f ".env" ] && [ -f ".env.example" ]; then
    echo "Creating .env from example..."
    cp .env.example .env
    echo "✓ .env file created (please customize it)"
    echo ""
fi

echo "=========================================="
echo "Setup Complete!"
echo "=========================================="
echo ""
echo "Quick Start:"
echo "  1. Activate virtual environment:"
echo "     source venv/bin/activate"
echo ""
echo "  2. Run the launcher:"
echo "     python launch.py"
echo ""
echo "  3. Or run directly:"
echo "     python botnet_controller.py --help"
echo "     python botnet_server_enhanced.py --help"
echo ""
echo "For more information, see README.md"
echo "=========================================="
