#!/bin/bash
# nmap_automator.sh - GraySentinel Automated Nmap Scanner

TARGET=$1
OUTPUT_DIR="GraySentinel_Commissioning/1_Portfolio/Reports/"
TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
OUTPUT_PREFIX="${OUTPUT_DIR}nmap_${TARGET}_${TIMESTAMP}"

# Check if target IP is provided
if [ -z "$TARGET" ]; then
    echo "Usage: $0 <target_ip>"
    exit 1
fi

# Create output directory if it doesn't exist
mkdir -p $OUTPUT_DIR

echo -e "\033[0;32m[+] Starting Nmap scan on $TARGET\033[0m"

# Run Nmap scan
sudo nmap -sS -sV -sC -T4 $TARGET -oA $OUTPUT_PREFIX

# Extract open ports
echo -e "\n\033[0;32m[+] Open ports:\033[0m"
grep "open" ${OUTPUT_PREFIX}.gnmap | grep -v "filtered" | awk '{print $4}'

# Show saved report locations
echo -e "\033[0;32m[+] Reports saved to:\033[0m"
echo "    Normal: ${OUTPUT_PREFIX}.nmap"
echo "    XML:    ${OUTPUT_PREFIX}.xml"
echo "    Grep:   ${OUTPUT_PREFIX}.gnmap"
