import os
import subprocess
import time
from datetime import datetime
from pathlib import Path

from differential_analysis_nmap import compare_outputs_and_log


def continuous_scan(shell_script: str, analysis_func: callable, delay_sec: int = 5):
    """
    This function runs the nmap scanning script continuously and logs changes in the network ports.

    Parameters:
    shell_script (str): The shell script file name to run the nmap scan.
    analysis_func (callable): The function to analyze the nmap scan.
    delay (int): The delay in seconds between each scan. Default is 3600 seconds (1 hour).

    Returns:
    None
    """
    last_two_files = []
    timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    log_file = f"./output/continuous_differential_analysis_{timestamp}.txt"

    while True:
        # Run the shell script
        print(f"{datetime.now()} - Running the nmap scan...")
        subprocess.call(["bash", shell_script])

        # Get the list of output files sorted by modification time
        output_files = sorted(Path("output").glob("*.txt"), key=os.path.getmtime)

        # We only start the analysis if there are at least two output files
        if len(output_files) > 1:
            new_last_two_files = output_files[-2:]

            # Run the analysis if there is a new scan file
            if new_last_two_files != last_two_files:
                print(f"{datetime.now()} - Running the analysis...")
                analysis_func(
                    str(new_last_two_files[0]), str(new_last_two_files[1]), log_file
                )
                last_two_files = new_last_two_files

        # Sleep for the delay duration
        print(f"{datetime.now()} - Sleeping for {delay_sec} seconds...")
        time.sleep(delay_sec)


if __name__ == "__main__":
    continuous_scan("scan_network.sh", compare_outputs_and_log)
