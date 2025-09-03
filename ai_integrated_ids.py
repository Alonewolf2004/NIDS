#!/bin/bash

# AI-Integrated IDS Setup and Run Script
# This script helps set up and run the AI-Integrated IDS with your trained models

echo "╔══════════════════════════════════════════════════════════════════════════════╗"
echo "║                    AI-Integrated IDS Setup Script                           ║"
echo "║                        Model Integration Assistant                          ║"
echo "╚══════════════════════════════════════════════════════════════════════════════╝"
echo

# Check if running as root
if [[ $EUID -eq 0 ]]; then
    echo "⚠️  Running as root - IP blocking will be available"
    BLOCKING_AVAILABLE=true
else
    echo "ℹ️  Not running as root - IP blocking will be disabled"
    BLOCKING_AVAILABLE=false
fi

# Check if models directory exists
if [ -d "models" ]; then
    echo "✅ Models directory found"
    
    # Check for required model files
    MODEL_COUNT=$(find models -name "*_model.pkl" | wc -l)
    SCALER_COUNT=$(find models -name "*_scaler.pkl" | wc -l)
    
    echo "   Found $MODEL_COUNT model file(s)"
    echo "   Found $SCALER_COUNT scaler file(s)"
    
    if [ -f "models/label_encoder.pkl" ]; then
        echo "   ✅ Label encoder found"
        LABEL_ENCODER_OK=true
    else
        echo "   ❌ Label encoder missing (models/label_encoder.pkl)"
        LABEL_ENCODER_OK=false
    fi
    
    if [ -f "models/metadata.json" ]; then
        echo "   ✅ Model metadata found"
        echo "   Model info:"
        python3 -c "
import json
try:
    with open('models/metadata.json', 'r') as f:
        meta = json.load(f)
    perf = meta.get('model_performance', {})
    print(f'      Accuracy: {perf.get("accuracy\", \"unknown\")}')
    if 'training_history' in meta and meta['training_history']:
        latest = meta['training_history'][-1]
        print(f'      Model type: {latest.get(\"model_type\", \"unknown\")}')
        print(f'      Classes: {latest.get(\"classes\", \"unknown\")}')
except:
    print('      Could not read metadata')
"
    else
        echo "   ⚠️  Model metadata not found (optional)"
    fi
    
    if [ $MODEL_COUNT -gt 0 ] && [ $SCALER_COUNT -gt 0 ] && [ "$LABEL_ENCODER_OK" = true ]; then
        MODELS_READY=true
        echo "   ✅ Models appear ready for integration"
    else
        MODELS_READY=false
        echo "   ❌ Models not ready - missing required files"
    fi
else
    echo "❌ Models directory not found"
    echo "   Please ensure your trained models are in a 'models/' directory"
    MODELS_READY=false
fi

echo

# Check Python dependencies
echo "🔍 Checking Python dependencies..."
DEPS_OK=true

for dep in scapy joblib sklearn numpy; do
    if python3 -c "import $dep" 2>/dev/null; then
        echo "   ✅ $dep installed"
    else
        echo "   ❌ $dep missing"
        DEPS_OK=false
    fi
done

if [ "$DEPS_OK" = false ]; then
    echo
    echo "❌ Missing Python dependencies. Install with:"
    echo "   pip3 install scapy joblib scikit-learn numpy"
    echo
    read -p "Install dependencies now? (y/N): " install_deps
    if [[ $install_deps =~ ^[Yy]$ ]]; then
        pip3 install scapy joblib scikit-learn numpy
        echo "✅ Dependencies installed"
    else
        echo "⚠️  Please install dependencies before running"
        exit 1
    fi
fi

echo

# Check network interfaces
echo "🌐 Available network interfaces:"
python3 -c "
from scapy.all import get_if_list, get_if_addr
interfaces = get_if_list()
for i, iface in enumerate(interfaces, 1):
    try:
        addr = get_if_addr(iface)
        if addr and addr != '0.0.0.0':
            print(f'   {i}. {iface} ({addr})')
    except:
        pass
"

echo

# Check if signature file exists (optional)
if [ -f "signatures.json" ]; then
    echo "✅ Signature file found (signatures.json)"
else
    echo "ℹ️  No signature file found (optional)"
    echo "   Creating basic signature file..."
    cat > signatures.json << 'EOF'
{
  "signatures": [
    {
      "id": "BASIC_SQL_INJECTION",
      "payload_pattern": "union select",
      "description": "Basic SQL injection attempt",
      "severity": "high"
    },
    {
      "id": "XSS_ATTEMPT",
      "payload_pattern": "<script",
      "description": "Cross-site scripting attempt",
      "severity": "medium"
    },
    {
      "id": "SHELL_INJECTION",
      "payload_pattern": "/bin/sh",
      "description": "Shell injection attempt",
      "severity": "high"
    }
  ]
}
EOF
    echo "   ✅ Basic signature file created"
fi

echo

# Summary and run options
if [ "$MODELS_READY" = true ] && [ "$DEPS_OK" = true ]; then
    echo "✅ System ready for AI-Integrated IDS"
    echo
    echo "🚀 Run options:"
    echo
    
    if [ "$BLOCKING_AVAILABLE" = true ]; then
        echo "1. Full monitoring with AI detection and IP blocking:"
        echo "   sudo python3 ai_integrated_ids.py --enable-blocking --verbose"
        echo
        echo "2. AI monitoring without blocking:"
        echo "   python3 ai_integrated_ids.py --verbose"
        echo
        echo "3. Monitor specific interface with blocking:"
        echo "   sudo python3 ai_integrated_ids.py --interface eth0 --enable-blocking"
        echo
        echo "4. High-confidence detection with extended blocking:"
        echo "   sudo python3 ai_integrated_ids.py --enable-blocking --confidence 0.9 --block-duration 600"
    else
        echo "1. AI monitoring (no blocking - not running as root):"
        echo "   python3 ai_integrated_ids.py --verbose"
        echo
        echo "2. Monitor specific interface:"
        echo "   python3 ai_integrated_ids.py --interface eth0 --verbose"
        echo
        echo "3. High-confidence detection:"
        echo "   python3 ai_integrated_ids.py --confidence 0.9 --verbose"
        echo
        echo "4. Run with root for blocking capability:"
        echo "   sudo python3 ai_integrated_ids.py --enable-blocking --verbose"
    fi
    
    echo
    echo "📊 Additional options:"
    echo "   --port 80          Monitor specific port"
    echo "   --model-dir ./path Custom model directory"
    echo "   --confidence 0.85  Set confidence threshold"
    echo "   --interface eth0   Specific network interface"
    echo
    
    # Ask user what they want to do
    echo "What would you like to do?"
    echo "1. Run basic AI monitoring (recommended for first test)"
    echo "2. Run with IP blocking (requires root)"
    echo "3. Custom run (enter your own parameters)"
    echo "4. Exit"
    echo
    
    read -p "Choose option (1-4): " choice
    
    case $choice in
        1)
            echo "Starting basic AI monitoring..."
            python3 ai_integrated_ids.py --verbose
            ;;
        2)
            if [ "$BLOCKING_AVAILABLE" = true ]; then
                echo "Starting AI monitoring with IP blocking..."
                python3 ai_integrated_ids.py --enable-blocking --verbose
            else
                echo "Starting AI monitoring with IP blocking (need to re-run as root)..."
                sudo python3 ai_integrated_ids.py --enable-blocking --verbose
            fi
            ;;
        3)
            echo "Enter your custom parameters:"
            read -p "Parameters: " custom_params
            echo "Running: python3 ai_integrated_ids.py $custom_params"
            python3 ai_integrated_ids.py $custom_params
            ;;
        4)
            echo "Exiting..."
            exit 0
            ;;
        *)
            echo "Invalid choice. Running basic monitoring..."
            python3 ai_integrated_ids.py --verbose
            ;;
    esac
    
else
    echo "❌ System not ready"
    echo
    if [ "$MODELS_READY" = false ]; then
        echo "Issues with models:"
        echo "- Ensure models/ directory exists"
        echo "- Required files: *_model.pkl, *_scaler.pkl, label_encoder.pkl"
        echo "- Run your training script first to generate models"
    fi
    if [ "$DEPS_OK" = false ]; then
        echo "Issues with dependencies:"
        echo "- Install missing Python packages"
    fi
    echo
    echo "Please fix the issues above and run this script again."
fi