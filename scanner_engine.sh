#!/bin/bash

# =============================================================
# Project: Kernel-X-Unlocker (Invention)
# Author: sayan9168
# Purpose: Auto-compile and Vulnerability Scanner for Android 12+
# =============================================================

# Colors for professional UI
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${YELLOW}>>> Initializing Sayan's Universal Kernel Scanner...${NC}"

# 1. Checking Environment
echo -e "[*] Checking System Architecture..."
ARCH=$(uname -m)
KERNEL_VER=$(uname -r)
SDK_VER=$(getprop ro.build.version.sdk)

echo -e "[+] Architecture: ${GREEN}$ARCH${NC}"
echo -e "[+] Kernel Version: ${GREEN}$KERNEL_VER${NC}"
echo -e "[+] Android SDK: ${GREEN}$SDK_VER${NC}"

# 2. Compiling the C Core (unlocker_core.c)
echo -e "[*] Compiling C Core Engine..."
if command -v clang > /dev/null; then
    clang unlocker_core.c -o bin/kernel_x_unlocker
    if [ $? -eq 0 ]; then
        echo -e "${GREEN}[SUCCESS] Binary compiled successfully in /bin/${NC}"
    else
        echo -e "${RED}[ERROR] Compilation failed. Check your C code.${NC}"
        exit 1
    fi
else
    echo -e "${RED}[!] Clang not found. Install it using: pkg install clang${NC}"
    exit 1
fi

# 3. Scanning for Known Vulnerabilities (FBE & Kernel)
echo -e "[*] Scanning for Kernel Exploits (Non-Root)..."

# Check for Dirty Pipe (CVE-2022-0847) eligibility
if [[ "$KERNEL_VER" == *"5.8"* ]] || [[ "$KERNEL_VER" == *"5.10"* ]] || [[ "$KERNEL_VER" == *"5.15"* ]]; then
    echo -e "${GREEN}[!] VULNERABILITY FOUND: Potential Dirty Pipe (CVE-2022-0847) detected!${NC}"
    echo -e "[*] Status: Ready to overwrite /data/system/locksettings.db"
else
    echo -e "${YELLOW}[-] Device patched against Dirty Pipe. Searching for Zero-Day...${NC}"
fi

# 4. Checking File-Based Encryption (FBE) Status
FBE_STATUS=$(getprop ro.crypto.type)
echo -e "[*] Encryption Type: ${YELLOW}$FBE_STATUS${NC}"

if [ "$FBE_STATUS" == "file" ]; then
    echo -e "[!] FBE Detected. Initializing Decryption Key Scanner..."
    # This is where your invention's C binary will be called
    ./bin/kernel_x_unlocker --scan-fbe-keys
else
    echo -e "[+] FDE/None detected. Traditional bypass may work."
fi

echo -e "=========================================================="
echo -e "${GREEN}Scan Complete. Check logs for exploitation entry points.${NC}"
echo -e "=========================================================="
