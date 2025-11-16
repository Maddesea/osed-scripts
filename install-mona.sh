#!/bin/bash
#
# install-mona.sh - Download mona.py and dependencies for Windows lab VM
#
# This script downloads all components needed to install mona.py on the
# OSED Windows lab VM, creates an RDP share, and provides instructions.
#
# Usage: ./install-mona.sh <lab-vm-ip>
#
set -e

TOOLS=("https://github.com/corelan/windbglib/raw/master/pykd/pykd.zip" "https://github.com/corelan/windbglib/raw/master/windbglib.py" "https://github.com/corelan/mona/raw/master/mona.py" "https://www.python.org/ftp/python/2.7.17/python-2.7.17.msi" "https://download.microsoft.com/download/2/E/6/2E61CFA4-993B-4DD4-91DA-3737CD5CD6E3/vcredist_x86.exe" "https://raw.githubusercontent.com/epi052/osed-scripts/main/install-mona.ps1")

TMPDIR=$(mktemp -d)
SHARENAME="mona-share"
SHARE="\\\\tsclient\\$SHARENAME"

trap "rm -rf $TMPDIR" SIGINT EXIT 

if [ -z "$1" ]; then
    echo "[!] Usage: $0 <lab-vm-ip>"
    echo "    Example: $0 192.168.45.123"
    exit 1
fi

pushd "$TMPDIR" >/dev/null || exit 1

echo "[+] Downloading mona.py and dependencies..."
echo "[=] Files will be saved to: $TMPDIR"
echo

for tool in "${TOOLS[@]}"; do
    echo "[=] Downloading $(basename "$tool")..."
    if ! wget -q "$tool"; then
        echo "[!] Failed to download $tool"
        exit 1
    fi
done

echo "[+] Extracting pykd.zip..."
if ! unzip -qqo pykd.zip; then
    echo "[!] Failed to extract pykd.zip"
    exit 1
fi

echo
echo "[+] Files downloaded successfully!"
echo "[+] Once the RDP window opens, execute the following in an Administrator PowerShell:"
echo
echo "    powershell -c \"cat $SHARE\\install-mona.ps1 | powershell -\""
echo
echo "[*] Starting RDP connection to $1..."
echo

rdesktop "$1" -u offsec -p lab -r disk:"$SHARENAME"=.

