#!/bin/bash
echo "Installing Sayan's Universal Unlocker Toolset..."

# Update and Install Dependencies
pkg update && pkg upgrade -y
pkg install clang python pycryptodome -y

# Compiling Modules
clang unlocker_core.c -o bin/core_engine
clang rollback_bypass.c -o bin/rollback_bypass

# Setting Permissions
chmod +x scanner_engine.sh
chmod +x bin/core_engine
chmod +x bin/rollback_bypass

echo "------------------------------------------------"
echo "Setup Complete! Use ./scanner_engine.sh to start."
echo "GitHub: sayan9168"
echo "------------------------------------------------"
