#!/bin/bash
# network_mapper.sh - GraySentinel Network Discovery

NETWORK=${1:-"192.168.60.0/24"}
OUTPUT_DIR="GraySentinel_Commissioning/1_Portfolio/Reports/"
TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
OUTPUT_FILE="${OUTPUT_DIR}network_map_${TIMESTAMP}.txt"

# Ensure the output directory exists
mkdir -p "$OUTPUT_DIR"

echo "[+] Scanning network: $NETWORK"
echo "Network Discovery Report - $(date)" > "$OUTPUT_FILE"
echo "==========================================" >> "$OUTPUT_FILE"

# Ping sweep
echo -e "\n[+] Live Hosts:" >> "$OUTPUT_FILE"
nmap -sn $NETWORK | grep "Nmap scan" | awk '{print $5}' >> "$OUTPUT_FILE"

# Service scan on found hosts
echo -e "\n[+] Service Detection:" >> "$OUTPUT_FILE"
nmap -sV --open $NETWORK >> "$OUTPUT_FILE"

echo "[+] Report saved to $OUTPUT_FILE"
