import collections
import re
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
        r"Nmap scan report for (\S+).*?(\d+)/(tcp|udp)\s+open", contents, re.DOTALL
    )
    hosts = collections.defaultdict(set)

    for host, port, protocol in matches:
        # We include the protocol with the port number to distinguish TCP and UDP ports
        hosts[host].add(f"{port}/{protocol}")

    return hosts


def compare_outputs(file1: Path, file2: Path) -> str:
    """
    Compare the open ports in two Nmap output files and return the differences as a string.

    Args:
        file1 (Path): The path to the first Nmap output file.
        file2 (Path): The path to the second Nmap output file.

    Returns:
        A string of differences.
    """
    hosts1 = parse_nmap_output(file1)
    hosts2 = parse_nmap_output(file2)

    diffs = []
    for host in set(hosts1.keys()) | set(hosts2.keys()):
        if host not in hosts1:
            diffs.append(f"New host {host} with open ports: {sorted(hosts2[host])}")
        elif host not in hosts2:
            diffs.append(f"Host {host} left, it had open ports: {sorted(hosts1[host])}")
        else:
            newly_open = hosts2[host] - hosts1[host]
            newly_closed = hosts1[host] - hosts2[host]
            if newly_open:
                diffs.append(f"Host {host} has newly open ports: {sorted(newly_open)}")
            if newly_closed:
                diffs.append(
                    f"Host {host} has newly closed ports: {sorted(newly_closed)}"
                )

    return "\n".join(diffs)


if __name__ == "__main__":
    import sys

    if len(sys.argv) != 3:
        print("Usage: python3 differential_analysis_nmap.py <file1> <file2>")
        sys.exit(1)

    file1 = Path(sys.argv[1])
    file2 = Path(sys.argv[2])

    print(compare_outputs(file1, file2))
