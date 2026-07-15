#!/bin/bash
set -euo pipefail

echo "=== Publishing Trusty VS Code Extension ==="
echo ""
echo "Prerequisites:"
echo "  1. Install vsce: npm install -g @vscode/vsce"
echo "  2. Create publisher: vsce create-publisher trusty"
echo "  3. Login: vsce login trusty"
echo ""
echo "Steps:"
echo "  cd vscode-trusty"
echo "  vsce package    # creates trusty-vscode-0.1.0.vsix"
echo "  vsce publish    # publishes to marketplace"
echo ""
echo "For local testing:"
echo "  code --install-extension trusty-vscode-0.1.0.vsix"
