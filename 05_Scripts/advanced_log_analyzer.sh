#!/bin/bash

# advanced_log_analyzer.sh - GraySentinel Multi-Log Analyzer

LOG_FILE=$1
OUTPUT_DIR="GraySentinel_Commissioning/1_Portfolio/Reports"

mkdir -p "$OUTPUT_DIR"

TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
OUTPUT_FILE="${OUTPUT_DIR}/log_analysis_${TIMESTAMP}.txt"

if [ -z "$LOG_FILE" ]; then
    echo "Usage: $0 <logfile>"
    exit 1
fi

echo "[+] Analyzing $LOG_FILE..."

echo "Log Analysis Report - $(date)" > "$OUTPUT_FILE"
echo "==================================" >> "$OUTPUT_FILE"
echo "File: $LOG_FILE" >> "$OUTPUT_FILE"

# Detect log type
if grep -q "Failed password" "$LOG_FILE" 2>/dev/null; then

    echo -e "\n[!] Detected AUTH log" >> "$OUTPUT_FILE"
    echo -e "\nTop 10 Failed Login IPs:" >> "$OUTPUT_FILE"

    grep "Failed password" "$LOG_FILE" | awk '{print $(NF-3)}' | sort | uniq -c | sort -nr | head -10 >> "$OUTPUT_FILE"

elif grep -qE "GET|POST" "$LOG_FILE" 2>/dev/null; then

    echo -e "\n[!] Detected WEB log" >> "$OUTPUT_FILE"

    echo -e "\nTop 10 Requesting IPs:" >> "$OUTPUT_FILE"
    awk '{print $1}' "$LOG_FILE" | sort | uniq -c | sort -nr | head -10 >> "$OUTPUT_FILE"

    echo -e "\nTop 10 Requested URLs:" >> "$OUTPUT_FILE"
    awk '{print $7}' "$LOG_FILE" | sort | uniq -c | sort -nr | head -10 >> "$OUTPUT_FILE"

    echo -e "\nHTTP Errors:" >> "$OUTPUT_FILE"
    grep -E ' 404 | 500 | 403 ' "$LOG_FILE" >> "$OUTPUT_FILE"

else
    echo -e "\n[!] Unknown log type" >> "$OUTPUT_FILE"
fi

echo -e "\n[+] Report saved to $OUTPUT_FILE"
cat "$OUTPUT_FILE"
