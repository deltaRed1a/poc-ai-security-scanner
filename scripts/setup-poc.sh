#!/bin/bash

echo "🚀 Setting up AI Security Scanner POC"

# Check Python
if ! command -v python3 &> /dev/null; then
    echo "❌ Python 3 not found. Please install Python 3.11+"
    exit 1
fi

# Create virtual environment
echo "📦 Creating virtual environment..."
python3 -m venv .venv
source .venv/bin/activate

# Install dependencies
echo "📥 Installing dependencies..."
pip install --upgrade pip
pip install -r requirements.txt

# Check for .env
if [ ! -f .env ]; then
    echo "⚙️  Creating .env file..."
    cp .env.example .env
    echo "⚠️  Please edit .env with your Azure AI Foundry credentials"
    exit 1
fi

echo "✅ Setup complete!"
echo ""
echo "To run the POC:"
echo "  source .venv/bin/activate"
echo "  python -m src.main"