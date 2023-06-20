import collections
import re
from datetime import datetime
from pathlib import Path
from typing import Dict, Set


def parse_nmap_output(filename: Path) -> Dict[str, Set[int]]:
    """
    Parse an Nmap output file to extract the open TCP and UDP ports for each host.

    Args:
        filename (Path): The path to the Nmap output file.

    Returns:
        A dictionary where the keys are hostnames/IP addresses and the values are sets of open ports.
    """
    filename = Path(filename)  # Convert filename to Path object

    if not filename.exists():
        raise FileNotFoundError(f"Nmap output file not found: {filename}")

    with open(filename) as file:
        contents = file.read()

    matches = re.findall(
        r"Nmap scan report for (\S+).*?(\d+)/(tcp|udp) open", contents, re.DOTALL
    )
    host_to_ports = collections.defaultdict(set)

    for host, port, protocol in matches:
        host_to_ports[host].add((protocol, int(port)))

    return host_to_ports


def compare_outputs_and_log(file1: str, file2: str, log_file: str):
    """
    Compare two nmap outputs and logs the differences.

    Args:
        file1 (str): The path to the first nmap output file.
        file2 (str): The path to the second nmap output file.
        log_file (str): The path to the log file.

    Returns:
        None
    """
    old_hosts = parse_nmap_output(file1)
    new_hosts = parse_nmap_output(file2)

    with open(log_file, "a") as f:
        for host, new_ports in new_hosts.items():
            old_ports = old_hosts.get(host, set())

            if old_ports:
                for port in new_ports - old_ports:
                    print(f"New port {port} open on host {host}")
                    f.write(f"{datetime.now()} - New port {port} open on host {host}\n")
                for port in old_ports - new_ports:
                    print(f"Port {port} closed on host {host}")
                    f.write(f"{datetime.now()} - Port {port} closed on host {host}\n")
            else:
                print(f"New host {host} with open ports: {list(new_ports)}")
                f.write(
                    f"{datetime.now()} - New host {host} with open ports: {list(new_ports)}\n"
                )

        for host in old_hosts.keys() - new_hosts.keys():
            print(f"Host {host} is no longer present")
            f.write(f"{datetime.now()} - Host {host} is no longer present\n")
