import os
import sys
import socket
import psutil
import winreg
import requests
import hashlib
import time
import json
import threading
import platform
from datetime import datetime
import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import queue
import traceback
import ctypes

# Configuration
THREAT_DATABASE_URL = "https://raw.githubusercontent.com/mitchellkrogza/Phishing.Database/master/ALL-phishing-domains.txt"
MALWARE_HASH_DB = "https://raw.githubusercontent.com/mitchellkrogza/malware-hashes/main/hashes.txt"
VIRUSTOTAL_API_URL = "https://www.virustotal.com/api/v3/files/"
BLACKLIST_CACHE = "threat_blacklist.txt"
HASH_DB_CACHE = "malware_hashes.txt"
LOG_FILE = "security_scan.log"
CONFIG_FILE = "security_config.json"

SUSPICIOUS_KEYWORDS = [
    "spy", "track", "monitor", "keylog", "stalk", "remote", "admin", "hidden",
    "hack", "stealer", "rat", "exploit", "inject", "backdoor", "rootkit"
]

# Initialize global state
scan_results = []
last_scan_time = None
monitoring_active = False
config = {
    "remote_logging": False,
    "log_location": LOG_FILE,
    "scan_interval": 300,
    "virustotal_api_key": "",
    "email_settings": {},
    "discord_webhook": "",
    "fast_scan": False,
    "scan_depth": 3,
    "excluded_dirs": [
        "C:\\Windows\\WinSxS",
        "C:\\Windows\\Temp",
        "C:\\System Volume Information",
        "C:\\$Recycle.Bin",
        "C:\\ProgramData",
        "C:\\hiberfil.sys",
        "C:\\pagefile.sys"
    ]
}

# For cross-thread communication
scan_queue = queue.Queue()
log_queue = queue.Queue()

def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False

class SecurityScanner:
    def __init__(self):
        self.known_hashes = set()
        self.known_processes = set()
        self.startup_items = set()
        self.file_hash_cache = {}
        self.scanned_files = 0
        self.malicious_files = 0
        self.load_config()
        self.update_threat_database()
        self.update_malware_hashes()
        self.baseline_system()
        self.log("Security Scanner initialized")

    def load_config(self):
        global config
        try:
            if os.path.exists(CONFIG_FILE):
                with open(CONFIG_FILE) as f:
                    config.update(json.load(f))
        except Exception as e:
            self.log(f"Config load error: {str(e)}", level="ERROR")
            self.log(traceback.format_exc(), level="DEBUG")

    def save_config(self):
        try:
            with open(CONFIG_FILE, 'w') as f:
                json.dump(config, f, indent=2)
        except Exception as e:
            self.log(f"Config save error: {str(e)}", level="ERROR")

    def log(self, message, level="INFO"):
        global log_queue
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        log_entry = f"[{timestamp}] [{level}] {message}"
        
        # Add to log queue for GUI updates
        log_queue.put(log_entry)
        
        # Save to log file
        try:
            with open(config["log_location"], 'a') as f:
                f.write(log_entry + "\n")
        except Exception as e:
            print(f"Log write error: {str(e)}")
            
        return log_entry

    def update_threat_database(self):
        try:
            # Only update once per day
            if os.path.exists(BLACKLIST_CACHE):
                file_age = time.time() - os.path.getmtime(BLACKLIST_CACHE)
                if file_age < 86400:
                    with open(BLACKLIST_CACHE) as f:
                        return set(f.read().splitlines())
            
            response = requests.get(THREAT_DATABASE_URL, timeout=10)
            with open(BLACKLIST_CACHE, 'w') as f:
                f.write(response.text)
            self.log(f"Updated threat database ({len(response.text.splitlines())} entries)")
            return set(response.text.splitlines())
        except Exception as e:
            self.log(f"Database update failed: {str(e)}", level="ERROR")
            if os.path.exists(BLACKLIST_CACHE):
                with open(BLACKLIST_CACHE) as f:
                    return set(f.read().splitlines())
            return set()

    def update_malware_hashes(self):
        try:
            # Only update once per day
            if os.path.exists(HASH_DB_CACHE):
                file_age = time.time() - os.path.getmtime(HASH_DB_CACHE)
                if file_age < 86400:
                    with open(HASH_DB_CACHE) as f:
                        self.known_hashes = set(f.read().splitlines())
                        return
            
            response = requests.get(MALWARE_HASH_DB, timeout=15)
            with open(HASH_DB_CACHE, 'w') as f:
                f.write(response.text)
            self.known_hashes = set(response.text.splitlines())
            self.log(f"Updated malware hashes ({len(self.known_hashes)} entries)")
        except Exception as e:
            self.log(f"Hash update failed: {str(e)}", level="ERROR")
            if os.path.exists(HASH_DB_CACHE):
                with open(HASH_DB_CACHE) as f:
                    self.known_hashes = set(f.read().splitlines())

    def baseline_system(self):
        # Capture initial running processes
        for proc in psutil.process_iter(['pid', 'name']):
            try:
                self.known_processes.add(proc.info['name'].lower())
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
        
        # Capture startup items
        self.startup_items = self.get_startup_items()
        self.log(f"System baseline created: {len(self.known_processes)} processes, {len(self.startup_items)} startup items")

    def get_startup_items(self):
        startup_items = set()
        if platform.system() == 'Windows':
            registries = [
                (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Run"),
                (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\Run"),
                (winreg.HKEY_LOCAL_MACHINE, r"Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run")
            ]
            
            for hive, path in registries:
                try:
                    with winreg.OpenKey(hive, path) as key:
                        idx = 0
                        while True:
                            try:
                                name, value, _ = winreg.EnumValue(key, idx)
                                startup_items.add(name.lower())
                                idx += 1
                            except OSError:
                                break
                except FileNotFoundError:
                    continue
        return startup_items

    def calculate_file_hash(self, file_path):
        # Skip files that are likely to cause permission issues
        if any(file_path.startswith(excluded) for excluded in [
            'C:\\DumpStack.log',
            'C:\\hiberfil.sys',
            'C:\\pagefile.sys',
            'C:\\swapfile.sys'
        ]):
            return None
        
        # Skip temporary files
        if file_path.endswith('.tmp') or '.log.tmp' in file_path:
            return None
            
        # Check cache first
        if file_path in self.file_hash_cache:
            return self.file_hash_cache[file_path]
        
        try:
            # Skip files that are too large
            file_size = os.path.getsize(file_path)
            if file_size > 100 * 1024 * 1024:  # 100MB
                return None
                
            with open(file_path, 'rb') as f:
                file_hash = hashlib.sha256()
                while chunk := f.read(8192):
                    file_hash.update(chunk)
            self.file_hash_cache[file_path] = file_hash.hexdigest()
            return file_hash.hexdigest()
        except (PermissionError, OSError) as e:
            # Skip logging common permission errors
            if e.errno not in (13, 32):  # 13=Permission denied, 32=Sharing violation
                self.log(f"Hash calculation skipped for {file_path}: {str(e)}", level="DEBUG")
            return None
        except Exception as e:
            self.log(f"Hash calculation failed for {file_path}: {str(e)}", level="DEBUG")
            return None

    def scan_file_hash(self, file_path):
        file_hash = self.calculate_file_hash(file_path)
        if not file_hash:
            return False
        
        # Check local hash database
        if file_hash in self.known_hashes:
            self.malicious_files += 1
            return True
        
        # Only check VirusTotal if we're not in fast scan mode
        if not config.get("fast_scan", False) and config.get("virustotal_api_key"):
            try:
                headers = {"x-apikey": config["virustotal_api_key"]}
                response = requests.get(VIRUSTOTAL_API_URL + file_hash, headers=headers, timeout=15)
                if response.status_code == 200:
                    result = response.json()
                    if result.get('data', {}).get('attributes', {}).get('last_analysis_stats', {}).get('malicious', 0) > 0:
                        self.malicious_files += 1
                        return True
            except Exception as e:
                self.log(f"VirusTotal check failed: {str(e)}", level="ERROR")
        
        return False

    def scan_file_system(self):
        suspicious = []
        self.log("Starting full file system scan...")
        
        # Get all drives
        drives = [f"{d}:\\" for d in "ABCDEFGHIJKLMNOPQRSTUVWXYZ" if os.path.exists(f"{d}:")]
        
        for drive in drives:
            self.log(f"Scanning drive: {drive}")
            for root, dirs, files in os.walk(drive):
                # Skip excluded directories
                if any(excluded in root for excluded in config["excluded_dirs"]):
                    continue
                
                # Skip hidden directories
                if os.path.basename(root).startswith('.'):
                    continue
                
                # Skip protected system directories
                if any(root.startswith(path) for path in [
                    'C:\\System Volume Information',
                    'C:\\Windows\\WinSxS',
                    'C:\\Windows\\Temp',
                    'C:\\$Recycle.Bin'
                ]):
                    continue
                
                for file in files:
                    file_path = os.path.join(root, file)
                    
                    # Skip files that are likely to cause issues
                    if any(file_path.endswith(ext) for ext in [
                        '.log.tmp', 
                        '.tmp', 
                        '.dmp', 
                        '.hiberfil', 
                        '.pagefile'
                    ]):
                        continue
                    
                    # Skip non-executable files in fast mode
                    if config.get("fast_scan", False):
                        if not file_path.lower().endswith(('.exe', '.dll', '.sys', '.bat', '.cmd', '.ps1')):
                            continue
                    
                    # Check for suspicious keywords in filename
                    if any(kw in file.lower() for kw in SUSPICIOUS_KEYWORDS):
                        suspicious.append(("Suspicious File", file_path))
                    
                    # Scan file hash
                    if self.scan_file_hash(file_path):
                        suspicious.append(("Malicious File", file_path))
                    
                    self.scanned_files += 1
                    
                    # Update progress every 100 files
                    if self.scanned_files % 100 == 0:
                        scan_queue.put(("file_progress", (self.scanned_files, self.malicious_files)))
        
        return suspicious

    def scan_installed_software(self):
        suspicious = []
        if platform.system() == 'Windows':
            registries = [
                winreg.HKEY_LOCAL_MACHINE,
                winreg.HKEY_CURRENT_USER
            ]
            paths = [
                r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
                r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"
            ]
            
            for hive in registries:
                for path in paths:
                    try:
                        with winreg.OpenKey(hive, path) as key:
                            idx = 0
                            while True:
                                try:
                                    subkey_name = winreg.EnumKey(key, idx)
                                    with winreg.OpenKey(key, subkey_name) as subkey:
                                        try:
                                            name = winreg.QueryValueEx(subkey, "DisplayName")[0]
                                            
                                            # Check for suspicious keywords
                                            if any(kw in name.lower() for kw in SUSPICIOUS_KEYWORDS):
                                                suspicious.append(("Suspicious Software", name))
                                        except OSError:
                                            pass
                                    idx += 1
                                except OSError:
                                    break
                    except FileNotFoundError:
                        continue
        return suspicious

    def scan_processes(self):
        suspicious = []
        current_processes = set()
        
        processes = list(psutil.process_iter(['pid', 'name', 'exe', 'cmdline']))
        total_processes = len(processes)
        processed = 0
        
        for proc in processes:
            try:
                name = proc.info['name'].lower()
                current_processes.add(name)
                
                # Check for unknown processes
                if name not in self.known_processes:
                    suspicious.append(("New Process", f"{name} (PID: {proc.pid})"))
                    self.known_processes.add(name)
                
                # Check process name for suspicious keywords
                if any(kw in name for kw in SUSPICIOUS_KEYWORDS):
                    suspicious.append(("Suspicious Process", f"{name} (PID: {proc.pid})"))
                
                # Check command line
                cmdline = " ".join(proc.info['cmdline'] or []).lower()
                if cmdline and any(kw in cmdline for kw in SUSPICIOUS_KEYWORDS):
                    suspicious.append(("Suspicious Command", f"{name}: {cmdline}"))
                
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
            
            processed += 1
            if processed % 10 == 0:
                scan_queue.put(("progress_update", f"Scanned {processed}/{total_processes} processes"))
        
        return suspicious

    def scan_network_connections(self):
        suspicious = []
        blacklist = self.update_threat_database()
        
        connections = psutil.net_connections()
        total_connections = len(connections)
        processed = 0
        
        for conn in connections:
            if conn.status == 'ESTABLISHED' and conn.raddr:
                ip = conn.raddr.ip
                try:
                    # Check if IP is in blacklist
                    if ip in blacklist:
                        suspicious.append(("Malicious Connection", f"{ip} (PID: {conn.pid})"))
                    
                    # Reverse DNS lookup
                    host = socket.gethostbyaddr(ip)[0]
                    if host in blacklist:
                        suspicious.append(("Malicious Host", f"{host} ({ip})"))
                except (socket.herror, OSError):
                    pass
            
            processed += 1
            if processed % 50 == 0:
                scan_queue.put(("progress_update", f"Scanned {processed}/{total_connections} connections"))
        
        return suspicious

    def scan_startup_items(self):
        suspicious = []
        current_startup = self.get_startup_items()
        
        # Check for new startup items
        new_items = current_startup - self.startup_items
        for item in new_items:
            suspicious.append(("New Startup Item", item))
            self.startup_items.add(item)
        
        # Check existing items
        total_items = len(current_startup)
        processed = 0
        
        for item in current_startup:
            if any(kw in item for kw in SUSPICIOUS_KEYWORDS):
                suspicious.append(("Suspicious Startup", item))
            
            processed += 1
            if processed % 10 == 0:
                scan_queue.put(("progress_update", f"Scanned {processed}/{total_items} startup items"))
        
        return suspicious

    def full_scan(self):
        global last_scan_time
        self.log("Starting full system scan")
        results = []
        self.scanned_files = 0
        self.malicious_files = 0
        
        # Reduce scan priority on Windows
        if sys.platform == 'win32':
            try:
                import win32api, win32process, win32con
                handle = win32api.GetCurrentProcess()
                win32process.SetPriorityClass(handle, win32process.BELOW_NORMAL_PRIORITY_CLASS)
                self.log("Reduced process priority for scanning")
            except ImportError:
                self.log("pywin32 not installed, running at normal priority", level="WARNING")
            except Exception as e:
                self.log(f"Priority reduction failed: {str(e)}", level="ERROR")
        
        # Perform scans with progress tracking
        scan_steps = [
            ("Scanning file system", self.scan_file_system),
            ("Scanning installed software", self.scan_installed_software),
            ("Scanning running processes", self.scan_processes),
            ("Scanning network connections", self.scan_network_connections),
            ("Scanning startup items", self.scan_startup_items),
        ]
        
        for i, (step_name, scan_func) in enumerate(scan_steps):
            self.log(step_name)
            scan_queue.put(("progress", (i + 1, len(scan_steps), step_name)))
            try:
                step_results = scan_func()
                results.extend(step_results)
                self.log(f"{step_name} completed: found {len(step_results)} items")
            except Exception as e:
                self.log(f"Error during {step_name}: {str(e)}", level="ERROR")
                self.log(traceback.format_exc(), level="DEBUG")
        
        last_scan_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        self.log(f"Scan completed. Scanned {self.scanned_files} files, found {self.malicious_files} malicious files and {len(results)} potential threats")
        return results


class SecurityDashboard(tk.Tk):
    def __init__(self):
        super().__init__()
        self.scanner = SecurityScanner()
        self.title("Security Scanner Dashboard")
        self.geometry("1000x700")
        self.protocol("WM_DELETE_WINDOW", self.on_close)
        
        self.create_widgets()
        self.monitoring_thread = None
        self.scan_thread = None
        self.scan_in_progress = False
        self.update_dashboard()
        
    def create_widgets(self):
        # Create tabs
        tab_control = ttk.Notebook(self)
        
        dashboard_tab = ttk.Frame(tab_control)
        scan_tab = ttk.Frame(tab_control)
        config_tab = ttk.Frame(tab_control)
        logs_tab = ttk.Frame(tab_control)
        
        tab_control.add(dashboard_tab, text='Dashboard')
        tab_control.add(scan_tab, text='Scan')
        tab_control.add(config_tab, text='Configuration')
        tab_control.add(logs_tab, text='Logs')
        tab_control.pack(expand=1, fill="both")
        
        # Dashboard Tab
        dashboard_frame = ttk.LabelFrame(dashboard_tab, text="System Status")
        dashboard_frame.pack(fill="both", expand=True, padx=10, pady=10)
        
        self.status_text = tk.Text(dashboard_frame, height=20)
        self.status_text.pack(fill="both", expand=True, padx=10, pady=10)
        self.status_text.config(state=tk.DISABLED)
        
        # Scan Tab
        scan_frame = ttk.LabelFrame(scan_tab, text="Scan Controls")
        scan_frame.pack(fill="x", padx=10, pady=10)
        
        self.scan_button = ttk.Button(scan_frame, text="Run Full Scan", command=self.run_full_scan)
        self.scan_button.pack(side=tk.LEFT, padx=5, pady=5)
        self.monitor_start_button = ttk.Button(scan_frame, text="Start Monitoring", command=self.start_monitoring)
        self.monitor_start_button.pack(side=tk.LEFT, padx=5, pady=5)
        self.monitor_stop_button = ttk.Button(scan_frame, text="Stop Monitoring", command=self.stop_monitoring)
        self.monitor_stop_button.pack(side=tk.LEFT, padx=5, pady=5)
        
        # Progress bar
        self.progress_frame = ttk.Frame(scan_tab)
        self.progress_frame.pack(fill="x", padx=10, pady=5)
        
        self.progress_label = ttk.Label(self.progress_frame, text="Ready to scan")
        self.progress_label.pack(side=tk.TOP, fill="x", pady=5)
        
        self.progress_var = tk.DoubleVar()
        self.progress_bar = ttk.Progressbar(
            self.progress_frame, 
            variable=self.progress_var, 
            maximum=100
        )
        self.progress_bar.pack(fill="x", pady=5)
        
        # Current task label
        self.task_label = ttk.Label(self.progress_frame, text="")
        self.task_label.pack(fill="x", pady=5)
        
        # File scan status
        self.file_status = ttk.Label(self.progress_frame, text="")
        self.file_status.pack(fill="x", pady=5)
        
        # Results display
        results_frame = ttk.Frame(scan_tab)
        results_frame.pack(fill="both", expand=True, padx=10, pady=10)
        
        self.scan_results = ttk.Treeview(results_frame, columns=("Type", "Details"), show="headings")
        self.scan_results.heading("Type", text="Threat Type")
        self.scan_results.heading("Details", text="Details")
        self.scan_results.column("Type", width=150)
        self.scan_results.column("Details", width=800)
        
        scrollbar = ttk.Scrollbar(results_frame, orient="vertical", command=self.scan_results.yview)
        self.scan_results.configure(yscrollcommand=scrollbar.set)
        
        scrollbar.pack(side="right", fill="y")
        self.scan_results.pack(fill="both", expand=True)
        
        # Configuration Tab
        config_frame = ttk.Frame(config_tab)
        config_frame.pack(fill="both", expand=True, padx=10, pady=10)
        
        # Logging options
        logging_frame = ttk.LabelFrame(config_frame, text="Logging Configuration")
        logging_frame.pack(fill="x", padx=5, pady=5)
        
        ttk.Label(logging_frame, text="Log Storage:").grid(row=0, column=0, padx=5, pady=5, sticky="w")
        self.log_local = ttk.Radiobutton(logging_frame, text="Local", value="local", command=self.set_log_local)
        self.log_local.grid(row=0, column=1, padx=5, pady=5)
        self.log_remote = ttk.Radiobutton(logging_frame, text="Remote", value="remote", command=self.set_log_remote)
        self.log_remote.grid(row=0, column=2, padx=5, pady=5)
        
        self.log_location_var = tk.StringVar()
        self.log_location_entry = ttk.Entry(logging_frame, textvariable=self.log_location_var, state="readonly", width=50)
        self.log_location_entry.grid(row=1, column=0, columnspan=2, padx=5, pady=5, sticky="ew")
        
        ttk.Button(logging_frame, text="Browse...", command=self.select_log_location).grid(row=1, column=2, padx=5, pady=5)
        
        # Scan configuration
        scan_config_frame = ttk.LabelFrame(config_frame, text="Scan Configuration")
        scan_config_frame.pack(fill="x", padx=5, pady=5)
        
        # Fast scan option
        self.fast_scan_var = tk.BooleanVar(value=config.get("fast_scan", False))
        self.fast_scan_check = ttk.Checkbutton(
            scan_config_frame, 
            text="Enable Fast Scan (scan only executable files)",
            variable=self.fast_scan_var
        )
        self.fast_scan_check.pack(padx=5, pady=5, anchor="w")
        
        # Excluded directories
        ttk.Label(scan_config_frame, text="Excluded Directories:").pack(padx=5, pady=5, anchor="w")
        self.excluded_dirs_text = tk.Text(scan_config_frame, height=4, width=50)
        self.excluded_dirs_text.pack(padx=5, pady=5, fill="x")
        self.excluded_dirs_text.insert("1.0", "\n".join(config["excluded_dirs"]))
        
        # VirusTotal configuration
        vt_frame = ttk.LabelFrame(config_frame, text="VirusTotal API")
        vt_frame.pack(fill="x", padx=5, pady=5)
        
        ttk.Label(vt_frame, text="API Key:").grid(row=0, column=0, padx=5, pady=5, sticky="w")
        self.vt_api_key = ttk.Entry(vt_frame, width=50)
        self.vt_api_key.grid(row=0, column=1, columnspan=3, padx=5, pady=5, sticky="ew")
        self.vt_api_key.insert(0, config.get("virustotal_api_key", ""))
        
        # Save button
        ttk.Button(config_frame, text="Save Configuration", command=self.save_config).pack(pady=10)
        
        # Load current config
        self.load_config()
        
        # Logs Tab
        logs_frame = ttk.Frame(logs_tab)
        logs_frame.pack(fill="both", expand=True, padx=10, pady=10)
        
        self.logs_text = tk.Text(logs_frame, wrap="word")
        scrollbar = ttk.Scrollbar(logs_frame, command=self.logs_text.yview)
        self.logs_text.config(yscrollcommand=scrollbar.set)
        
        scrollbar.pack(side="right", fill="y")
        self.logs_text.pack(fill="both", expand=True)
        
        self.load_logs()
    
    def load_config(self):
        if config["remote_logging"]:
            self.log_remote.invoke()
        else:
            self.log_local.invoke()
        
        self.log_location_var.set(config["log_location"])
        self.vt_api_key.delete(0, tk.END)
        self.vt_api_key.insert(0, config.get("virustotal_api_key", ""))
        self.fast_scan_var.set(config.get("fast_scan", False))
        self.excluded_dirs_text.delete("1.0", tk.END)
        self.excluded_dirs_text.insert("1.0", "\n".join(config["excluded_dirs"]))
    
    def save_config(self):
        # Save logging preference
        config["remote_logging"] = (self.log_remote.instate(['selected']))
        config["log_location"] = self.log_location_var.get()
        
        # Save scan settings
        config["fast_scan"] = self.fast_scan_var.get()
        config["virustotal_api_key"] = self.vt_api_key.get()
        
        # Save excluded directories
        excluded_dirs = self.excluded_dirs_text.get("1.0", tk.END).splitlines()
        config["excluded_dirs"] = [d.strip() for d in excluded_dirs if d.strip()]
        
        self.scanner.save_config()
        messagebox.showinfo("Configuration", "Settings saved successfully!")
    
    def set_log_local(self):
        config["remote_logging"] = False
    
    def set_log_remote(self):
        config["remote_logging"] = True
    
    def select_log_location(self):
        file_path = filedialog.asksaveasfilename(
            defaultextension=".log",
            filetypes=[("Log files", "*.log"), ("All files", "*.*")]
        )
        if file_path:
            config["log_location"] = file_path
            self.log_location_var.set(file_path)
    
    def load_logs(self):
        try:
            with open(config["log_location"], 'r') as f:
                self.logs_text.delete(1.0, tk.END)
                self.logs_text.insert(tk.END, f.read())
                self.logs_text.see(tk.END)
        except Exception as e:
            self.logs_text.insert(tk.END, f"Error loading logs: {str(e)}")
    
    def run_full_scan(self):
        global scan_results, scan_queue
        if self.scan_in_progress:
            messagebox.showinfo("Scan", "A scan is already in progress")
            return
            
        # Check for admin rights
        if not is_admin():
            messagebox.showwarning(
                "Admin Privileges Required", 
                "Full system scan requires administrator privileges. Please restart the application as administrator."
            )
            return
            
        self.scan_in_progress = True
        self.scan_button.config(state=tk.DISABLED)
        self.monitor_start_button.config(state=tk.DISABLED)
        self.monitor_stop_button.config(state=tk.DISABLED)
        self.progress_label.config(text="Preparing scan...")
        self.progress_var.set(0)
        self.task_label.config(text="")
        self.file_status.config(text="")
        
        # Clear previous results
        for item in self.scan_results.get_children():
            self.scan_results.delete(item)
        
        # Run scan in a separate thread
        self.scan_thread = threading.Thread(target=self._perform_scan, daemon=True)
        self.scan_thread.start()
        
        # Check scan progress periodically
        self.check_scan_progress()
    
    def _perform_scan(self):
        global scan_results, scan_queue
        try:
            scan_results = self.scanner.full_scan()
            scan_queue.put(("complete", scan_results))
        except Exception as e:
            self.scanner.log(f"Scan failed: {str(e)}", level="ERROR")
            self.scanner.log(traceback.format_exc(), level="DEBUG")
            scan_queue.put(("error", str(e)))
    
    def check_scan_progress(self):
        global scan_queue
        try:
            while not scan_queue.empty():
                msg_type, data = scan_queue.get_nowait()
                if msg_type == "progress":
                    current_step, total_steps, task_name = data
                    progress = (current_step / total_steps) * 100
                    self.progress_var.set(progress)
                    self.progress_label.config(text=f"Progress: {int(progress)}%")
                    self.task_label.config(text=f"Current Task: {task_name}")
                elif msg_type == "file_progress":
                    scanned, malicious = data
                    self.file_status.config(text=f"Files scanned: {scanned} | Malicious found: {malicious}")
                elif msg_type == "progress_update":
                    self.file_status.config(text=data)
                elif msg_type == "complete":
                    self.scan_in_progress = False
                    self.scan_button.config(state=tk.NORMAL)
                    self.monitor_start_button.config(state=tk.NORMAL)
                    self.monitor_stop_button.config(state=tk.NORMAL)
                    self.progress_label.config(text="Scan completed")
                    self.progress_var.set(100)
                    self.task_label.config(text="")
                    self.update_scan_results(data)
                    self.update_dashboard()
                    return
                elif msg_type == "error":
                    self.scan_in_progress = False
                    self.scan_button.config(state=tk.NORMAL)
                    self.monitor_start_button.config(state=tk.NORMAL)
                    self.monitor_stop_button.config(state=tk.NORMAL)
                    self.progress_label.config(text=f"Scan failed: {data}")
                    self.progress_var.set(0)
                    self.task_label.config(text="")
                    messagebox.showerror("Scan Error", f"Scan failed:\n{data}")
                    return
        except queue.Empty:
            pass
        
        # If we haven't received completion, check again
        if self.scan_in_progress:
            self.after(100, self.check_scan_progress)
    
    def start_monitoring(self):
        global monitoring_active
        if monitoring_active:
            return
        
        monitoring_active = True
        self.monitor_start_button.config(state=tk.DISABLED)
        self.monitor_stop_button.config(state=tk.NORMAL)
        self.monitoring_thread = threading.Thread(target=self.monitoring_loop, daemon=True)
        self.monitoring_thread.start()
        self.scanner.log("Background monitoring started")
    
    def stop_monitoring(self):
        global monitoring_active
        monitoring_active = False
        self.monitor_start_button.config(state=tk.NORMAL)
        self.monitor_stop_button.config(state=tk.DISABLED)
        self.scanner.log("Background monitoring stopped")
    
    def monitoring_loop(self):
        global monitoring_active
        while monitoring_active:
            self.run_full_scan()
            time.sleep(config["scan_interval"])
    
    def update_scan_results(self, results=None):
        global scan_results
        if results is None:
            results = scan_results
        
        # Clear previous results
        for item in self.scan_results.get_children():
            self.scan_results.delete(item)
        
        # Add new results
        for result in results:
            self.scan_results.insert("", "end", values=result)
    
    def update_dashboard(self):
        global last_scan_time, scan_results
        
        # Process log entries
        try:
            while not log_queue.empty():
                log_entry = log_queue.get_nowait()
                self.logs_text.insert(tk.END, log_entry + "\n")
                self.logs_text.see(tk.END)
        except queue.Empty:
            pass
        
        # Update status text
        self.status_text.config(state=tk.NORMAL)
        self.status_text.delete(1.0, tk.END)
        
        status_lines = [
            f"Last Scan: {last_scan_time or 'Never'}",
            f"Threats Detected: {len(scan_results)}",
            f"Monitoring: {'Active' if monitoring_active else 'Inactive'}",
            f"Log Location: {config['log_location']}",
            f"Fast Scan Mode: {'Enabled' if config.get('fast_scan', False) else 'Disabled'}",
            f"Files Scanned: {self.scanner.scanned_files}",
            f"Malicious Files Found: {self.scanner.malicious_files}",
            "\nSystem Information:",
            f"OS: {platform.platform()}",
            f"CPU Usage: {psutil.cpu_percent()}%",
            f"Memory Usage: {psutil.virtual_memory().percent}%",
            f"Disk Usage: {psutil.disk_usage('/').percent}%"
        ]
        
        self.status_text.insert(tk.END, "\n".join(status_lines))
        self.status_text.config(state=tk.DISABLED)
        
        # Schedule next update
        self.after(1000, self.update_dashboard)
    
    def on_close(self):
        self.stop_monitoring()
        self.destroy()


if __name__ == "__main__":
    # Check for admin rights and relaunch if needed
    if not is_admin():
        # Re-run the program with admin rights
        ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, " ".join(sys.argv), None, 1)
        sys.exit(0)
    
    # Create and run dashboard
    app = SecurityDashboard()
    app.mainloop()
    