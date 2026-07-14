#!/bin/bash
# lab_setup.sh - GraySentinel Lab Automation

echo "[+] Updating System....."
sudo apt update && sudo apt upgrade -y

echo "[+] Installing security tools...."
sudo apt install -y nmap wireshark tcpdump metasploit-framework burpsuite gobuster ffuf hydra john dirb

echo "[+] Configuring network...."

#Add your network configuration here

echo "[+] Lab setup complete."
