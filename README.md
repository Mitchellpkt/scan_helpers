# Network Scan and Differential Analysis

This project runs a network scan and performs a differential analysis of the results. It includes a bash script to run the scan, a Python script to compare the results, and another Python script for continuous scanning and reporting.

## Usage

### Single Scan

To perform a single network scan, run the `scan_network.sh` script. This will create a text file with the scan results in the `./output` directory.

```bash
./scan_network.sh
```

### Comparing Two Scans

To compare the results of two scans, use the `differential_analysis_nmap.py` script.

```bash
python3 differential_analysis_nmap.py ./output/scan1.txt ./output/scan2.txt
```

This will print the differences between the two scan results, including new or departed hosts and changes in port status.

### Continuous Scanning and Reporting

To continuously scan the network and report changes, use the `continuous_scan.py` script.

```bash
sudo python3 continuous_scan.py
```

This script will continuously run the network scan and perform differential analysis on the most recent two scans, logging the results to `./output/continuous_differential_analysis_{timestamp}.txt`. 

Please note that you might need to use `sudo` for the scanning process to be able to run the Nmap scan command.

## Requirements

The scripts use Nmap for network scanning and Python 3 for differential analysis. Make sure to install these dependencies before running the scripts:

- Install Nmap: `sudo apt-get install nmap`
- Install Python: [https://www.python.org/downloads/](https://www.python.org/downloads/)
