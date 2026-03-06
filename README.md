🏆 Kernel-X-Unlocker (The Universal Android Decryptor)
Developer: sayan9168
Status: 🚀 Active Research & Development
Target: Android 12, 13, 14+ (Non-Rooted)
📖 Overview
Kernel-X-Unlocker is an advanced security research tool designed to bypass Android's File-Based Encryption (FBE) and Rollback Protection. By injecting payloads directly into the kernel memory (RAM) via Termux, this tool aims to bypass lockscreens without requiring permanent root access or triggering system-wide corruption.
🛠️ Core Features (The Invention)
Zero-Root Kernel Access: Establishes direct communication with the Android kernel via Termux environment.
Live Memory Patching: Temporarily modifies Gatekeeper and Keymaster services in-memory to bypass password validation.
AVB 2.0 Bypass: Implements mechanisms to neutralize Verified Boot alerts, preventing bootloops or "Device Corrupted" errors after modification.
FBE Key Extraction: Utilizes memory-scanning algorithms to locate the master encryption keys required to decrypt the /data partition.
📂 Repository Structure
├── bin/                    # Compiled binaries (Core Engine)
├── unlocker_core.c         # Main C code for Kernel Exploitation
├── rollback_bypass.c       # AVB & Rollback Protection bypass logic
├── decryptor_module.py     # Python script for hash & key decryption
├── scanner_engine.sh       # Automation script for scanning vulnerabilities
├── setup_master.sh         # One-click installer for all dependencies
└── README.md               # Documentation
🚀 How to Use (Research Mode)
Follow these steps within your Termux environment to initialize the toolset:
1. Clone & Setup
2. git clone https://github.com/sayan9168/Kernel-X-Unlocker
cd Kernel-X-Unlocker
chmod +x setup_master.sh
./setup_master.sh
Start Scanning
./scanner_engine.sh
Execution
The tool will automatically detect the kernel version and push the appropriate Kernel Payload to attempt a live memory bypass.
⚠️ Security Warning & Disclaimer
Disclaimer: This project is strictly for Educational and Ethical Research Purposes Only. Gaining unauthorized access to a mobile device is illegal and violates privacy laws. The developer (sayan9168) assumes no liability for any misuse or damage caused by this software. Use at your own risk.
📈 Future Roadmap
[ ] Support for Qualcomm Snapdragon 8 Gen 3 security bypass.
[ ] Integration of Samsung Knox Real-time Kernel Protection (RKP) bypass.
[ ] AI-driven automated Zero-Day vulnerability discovery engine.
