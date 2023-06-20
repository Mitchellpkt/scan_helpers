#!/bin/bash

# Define the target network
NETWORK="10.0.0.0/24"

# Define the email address to send the report
# (if you're not me, please don't email me your reports)
EMAIL="x-auto-scans@mitchellpkt.com"

# Define timestamp function
timestamp() {
  date +"%Y-%m-%d_%H-%M-%S"
}

# Define the output directory and create it if necessary
OUTPUT_DIR="./output"
mkdir -p $OUTPUT_DIR

# Define the output file
OUTPUT_FILE="$OUTPUT_DIR/nmap_scan_$(timestamp).txt"

# Check if the --include-udp flag is set
if [[ $* == *--include-udp* ]]; then
  echo "Scanning both TCP and UDP ports."
  SCAN_COMMAND="sudo nmap -sS -sU -p- $NETWORK"
else
  echo "Scanning TCP ports only."
  echo "(Hint: Run with --include-udp if you want to scan both TCP and UDP)"
  SCAN_COMMAND="sudo nmap -sS -p- $NETWORK"
fi

echo "Starting scan, which will be saved to $OUTPUT_FILE"

# Run the scan and save the output
$SCAN_COMMAND > $OUTPUT_FILE

echo "Scan complete, see $OUTPUT_FILE"

# Send the output by email
cat $OUTPUT_FILE | mail -s "Nmap scan report $(timestamp)" $EMAIL

# Print the location of the output file
echo "The scan result is saved in $OUTPUT_FILE and sent to $EMAIL"

