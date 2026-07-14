#!/bin/bash
# log_analyzer.sh - GraySentinel Log Analysis Tool

LOG_FILE=$1
OUTPUT_DIR="GraySentinel_Commissioning/1_Portfolio/Reports/"

TIMESTAMP=$(date +"%y%m%d_%H%M%S")
OUTPUT_FILE="${OUTPUT_DIR}failed_logins_${TIMESTAMP}.txt"

echo "[+] Analyzing $LOG_FILE...."
echo "Failed Login Attempts Report - $(date)" > $OUTPUT_FILE
echo "=================================" >> $OUTPUT_FILE
grep "Failed password" $LOG_FILE | \
    awk '{print $11}' | \
    sort | \
    uniq -c | \
    sort -nr | \

    head -10 >> $OUTPUT_FILE

echo "[+] Report saved to $OUTPUT_FILE"
echo "-------------------------------------"
cat $OUTPUT_FILE
