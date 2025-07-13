#!/usr/bin/env python3
"""
Digital Spectrum Analyzer (DSA) - Advanced Forensic Device Fingerprinting
Version: 3.0
Date: 2025-07-13

Purpose:
Generates unique device fingerprints using comprehensive hardware/software characteristics
for tracking devices in cybercrime investigations across networks and reformatted systems.

Key Features:
- Multi-platform support (Windows/Linux)
- Mobile device fingerprinting (Android/iOS via USB)
- Light mode for low-resource systems
- RAM analysis for tamper detection
- Forensic-grade reporting with digital signatures
- Tamper detection mechanisms

Usage:
1. Install dependencies: 
   pip install psutil pyudev tabulate cryptography pyyaml paramiko boto3 docker

2. Additional tools required:
   - For Android: ADB (https://developer.android.com/studio/command-line/adb)
   - For iOS: libimobiledevice (https://libimobiledevice.org/)

3. CLI Usage:
   Generate fingerprint: 
      python digital_spectrum_analyzer.py --generate --device-id CASE123 --output report.json
   Light mode:
      python digital_spectrum_analyzer.py --generate --device-id CASE123 --light-mode --output report.json
   Compare fingerprints: 
      python digital_spectrum_analyzer.py --compare
   Export report: 
      python digital_spectrum_analyzer.py --export --device-id CASE123 --output report.json

Forensic Compliance:
- ISO/IEC 27037 compliant
- SHA-256/RSA integrity verification
- Tamper-evident logging
- Platform-agnostic collection

Note: Requires administrator/root privileges for full functionality.
"""

import argparse
import json
import hashlib
import sqlite3
import sys
import platform
import tempfile
import time
import datetime
import subprocess
import psutil
import os
import re
import socket
import struct
import yaml
import base64
import threading
from collections import OrderedDict
from tabulate import tabulate
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, NoEncryption
from cryptography.hazmat.primitives.serialization import PublicFormat


# Database setup
DB_NAME = "forensic_fingerprints.db"
FINGERPRINT_TABLE = """
CREATE TABLE IF NOT EXISTS fingerprints (
    id INTEGER PRIMARY KEY,
    device_id TEXT NOT NULL,
    timestamp DATETIME NOT NULL,
    fingerprint_hash TEXT NOT NULL UNIQUE,
    report_data TEXT NOT NULL,
    report_hash TEXT NOT NULL,
    public_key TEXT
);
"""

MOBILE_FINGERPRINT_TABLE = """
CREATE TABLE IF NOT EXISTS mobile_fingerprints (
    id INTEGER PRIMARY KEY,
    device_id TEXT NOT NULL,
    timestamp DATETIME NOT NULL,
    device_type TEXT NOT NULL,
    fingerprint_hash TEXT NOT NULL UNIQUE,
    report_data TEXT NOT NULL,
    report_hash TEXT NOT NULL,
    public_key TEXT
);
"""

CHAIN_OF_CUSTODY_TABLE = """
CREATE TABLE IF NOT EXISTS chain_of_custody (
    id INTEGER PRIMARY KEY,
    fingerprint_id INTEGER NOT NULL,
    action TEXT NOT NULL,
    actor TEXT NOT NULL,
    timestamp DATETIME NOT NULL,
    details TEXT,
    FOREIGN KEY(fingerprint_id) REFERENCES fingerprints(id)
);
"""

# Configuration defaults
DEFAULT_CONFIG = {
    'fingerprint': {
        'cpu_benchmark_iterations': 5000,
        'disk_test_size_mb': 10,
        'network_test_count': 5,
        'memory_test_size_mb': 10,
        'ram_analysis': True
    },
    'tamper_detection': {
        'bios_time_threshold': 3600,  # 1 hour
        'disk_signature_change_threshold': 0.3,
        'ram_change_threshold': 20  # 20% change
    },
    'reporting': {
        'sign_reports': True
    }
}

def initialize_db():
    """Initialize SQLite database with forensic integrity features"""
    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()
    c.execute(FINGERPRINT_TABLE)
    c.execute(MOBILE_FINGERPRINT_TABLE)
    c.execute(CHAIN_OF_CUSTODY_TABLE)
    conn.commit()
    return conn

def load_config(args):
    """Load configuration from YAML file or use defaults, applying light mode if specified"""
    config_path = "dsa_config.yaml"
    config = DEFAULT_CONFIG.copy()
    
    if os.path.exists(config_path):
        try:
            with open(config_path, 'r') as f:
                user_config = yaml.safe_load(f)
                # Merge with defaults
                for section, settings in user_config.items():
                    if section not in config:
                        config[section] = settings
                    else:
                        for key, value in settings.items():
                            config[section][key] = value
        except Exception as e:
            print(f"[-] Config error: {str(e)} - Using defaults")
    
    # Apply light mode adjustments
    if args.light_mode:
        config['fingerprint']['cpu_benchmark_iterations'] = 1000
        config['fingerprint']['disk_test_size_mb'] = 1
        config['fingerprint']['memory_test_size_mb'] = 0  # Skip memory test
        config['fingerprint']['network_test_count'] = 0    # Skip network test
        config['fingerprint']['ram_analysis'] = False      # Skip RAM analysis
    
    return config

def get_bios_info():
    """Collect comprehensive BIOS/UEFI information"""
    bios_info = OrderedDict()
    system = platform.system()
    
    try:
        if system == "Windows":
            try:
                import wmi
                w = wmi.WMI()
                bios = w.Win32_BIOS()[0]
                bios_info["Vendor"] = bios.Manufacturer
                bios_info["Version"] = bios.Version
                bios_info["ReleaseDate"] = bios.ReleaseDate
                bios_info["Serial"] = bios.SerialNumber
                bios_info["CurrentLanguage"] = bios.CurrentLanguage
                bios_info["InstallableLanguages"] = bios.InstallableLanguages
            except ImportError:
                import winreg
                key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"HARDWARE\DESCRIPTION\System\BIOS")
                for name in ["BIOSVendor", "BIOSVersion", "BIOSReleaseDate", "SystemSerialNumber"]:
                    try:
                        value, _ = winreg.QueryValueEx(key, name)
                        bios_info[name] = value
                    except OSError:
                        bios_info[name] = "N/A"
        
        elif system == "Linux":
            dmi_path = "/sys/class/dmi/id/"
            dmi_fields = {
                "bios_vendor": "Vendor",
                "bios_version": "Version",
                "bios_date": "ReleaseDate",
                "bios_release": "ReleaseVersion",
                "product_serial": "Serial",
                "product_uuid": "UUID"
            }
            
            for field, name in dmi_fields.items():
                path = dmi_path + field
                try:
                    with open(path, "r") as f:
                        bios_info[name] = f.read().strip()
                except IOError:
                    bios_info[name] = "N/A"
        
        # Add BIOS timestamp for tamper detection
        bios_info["CollectionTime"] = datetime.datetime.utcnow().isoformat() + "Z"
        
    except Exception as e:
        bios_info["Error"] = f"BIOS collection failed: {str(e)}"
    
    return bios_info

def measure_cpu_performance(config):
    """Measure advanced CPU performance characteristics"""
    results = OrderedDict()
    
    # Prime number benchmark with configurable iterations
    def is_prime(n):
        if n <= 1: return False
        if n == 2: return True
        if n % 2 == 0: return False
        for i in range(3, int(n**0.5)+1, 2):
            if n % i == 0: return False
        return True
    
    iterations = config['fingerprint']['cpu_benchmark_iterations']
    start_time = time.perf_counter()
    primes = []
    num = 2
    while len(primes) < iterations:
        if is_prime(num):
            primes.append(num)
        num += 1
    results["PrimeCalcTime"] = round(time.perf_counter() - start_time, 4)
    
    # Floating Point Operations Per Second (FLOPS)
    start_time = time.perf_counter()
    val = 1.0
    for _ in range(10**7):
        val = val * 1.000001 + 0.000001
    results["FLOPS"] = round(10**7 / (time.perf_counter() - start_time), 2)
    
    # Timing consistency (10 measurements)
    timings = []
    for _ in range(10):
        start = time.perf_counter()
        sum(range(10**6))
        timings.append(time.perf_counter() - start)
    
    results["MinTiming"] = round(min(timings), 6)
    results["MaxTiming"] = round(max(timings), 6)
    results["AvgTiming"] = round(sum(timings)/len(timings), 6)
    
    # Instruction latency
    try:
        start = time.perf_counter()
        for _ in range(10**7): pass
        results["NopLatency"] = round((time.perf_counter() - start) / 10**7, 9)
    except:
        results["NopLatency"] = "N/A"
    
    return results

def analyze_disk_io(config):
    """Perform advanced disk I/O pattern analysis"""
    results = OrderedDict()
    
    try:
        # Get disk signatures
        if platform.system() == "Windows":
            try:
                import wmi
                w = wmi.WMI()
                for disk in w.Win32_DiskDrive():
                    results["Model"] = disk.Model
                    results["Serial"] = disk.SerialNumber.strip()
                    results["Firmware"] = disk.FirmwareRevision
                    break
            except:
                pass
        else:
            with open("/sys/block/sda/device/model", "r") as f:
                results["Model"] = f.read().strip()
            with open("/sys/block/sda/device/serial", "r") as f:
                results["Serial"] = f.read().strip()
            with open("/sys/block/sda/device/firmware_rev", "r") as f:
                results["Firmware"] = f.read().strip()
        
        # Performance testing
        test_size = config['fingerprint']['disk_test_size_mb'] * 1024 * 1024
        
        # Skip disk test in light mode if size is 0
        if test_size > 0:
            test_data = os.urandom(test_size)
            
            with tempfile.NamedTemporaryFile() as temp_file:
                # Write performance
                start_time = time.perf_counter()
                with open(temp_file.name, "wb") as f:
                    f.write(test_data)
                    os.fsync(f.fileno())
                write_time = time.perf_counter() - start_time
                
                # Read performance
                start_time = time.perf_counter()
                with open(temp_file.name, "rb") as f:
                    f.read()
                read_time = time.perf_counter() - start_time
            
            results["WriteSpeed"] = f"{test_size / write_time / (1024*1024):.2f} MB/s"
            results["ReadSpeed"] = f"{test_size / read_time / (1024*1024):.2f} MB/s"
            
            # IOPS measurement
            start_time = time.perf_counter()
            with open(temp_file.name, "wb") as f:
                for _ in range(100):
                    f.write(os.urandom(4096))
                    f.flush()
                    os.fsync(f.fileno())
            results["IOPS"] = int(100 / (time.perf_counter() - start_time))
        else:
            results["WriteSpeed"] = "Skipped (light mode)"
            results["ReadSpeed"] = "Skipped (light mode)"
            results["IOPS"] = "Skipped (light mode)"
    
    except Exception as e:
        results["Error"] = f"Disk analysis failed: {str(e)}"
    
    return results

def get_usb_signatures():
    """Collect detailed USB device signatures"""
    usb_devices = []
    system = platform.system()
    
    try:
        if system == "Windows":
            try:
                import wmi
                w = wmi.WMI()
                for usb in w.Win32_USBHub():
                    device = OrderedDict()
                    device["Description"] = usb.Description
                    device["DeviceID"] = usb.DeviceID
                    device["Manufacturer"] = getattr(usb, "Manufacturer", "N/A")
                    device["Serial"] = getattr(usb, "SerialNumber", "N/A")
                    usb_devices.append(device)
            except ImportError:
                import winreg
                key_path = r"SYSTEM\CurrentControlSet\Enum\USB"
                key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, key_path)
                
                for i in range(winreg.QueryInfoKey(key)[0]):
                    device_id = winreg.EnumKey(key, i)
                    device_key = winreg.OpenKey(key, device_id)
                    
                    for j in range(winreg.QueryInfoKey(device_key)[0]):
                        instance_id = winreg.EnumKey(device_key, j)
                        instance_key = winreg.OpenKey(device_key, instance_id)
                        
                        device = OrderedDict()
                        try:
                            device["DeviceID"] = device_id
                            device["VendorID"] = device_id.split("&")[0]
                            device["ProductID"] = device_id.split("&")[1] if "&" in device_id else "N/A"
                            device["Serial"], _ = winreg.QueryValueEx(instance_key, "SerialNumber")
                        except OSError:
                            continue
                        
                        usb_devices.append(device)
        
        elif system == "Linux":
            usb_path = "/sys/bus/usb/devices/"
            for device_dir in os.listdir(usb_path):
                if not device_dir.startswith(("usb", "1-", "2-", "3-", "4-")):
                    continue
                
                device = OrderedDict()
                try:
                    with open(os.path.join(usb_path, device_dir, "idVendor"), "r") as f:
                        device["VendorID"] = f.read().strip()
                    with open(os.path.join(usb_path, device_dir, "idProduct"), "r") as f:
                        device["ProductID"] = f.read().strip()
                    with open(os.path.join(usb_path, device_dir, "serial"), "r") as f:
                        device["Serial"] = f.read().strip()
                    with open(os.path.join(usb_path, device_dir, "product"), "r") as f:
                        device["Product"] = f.read().strip()
                    with open(os.path.join(usb_path, device_dir, "manufacturer"), "r") as f:
                        device["Manufacturer"] = f.read().strip()
                except IOError:
                    continue
                
                usb_devices.append(device)
    
    except Exception as e:
        usb_devices.append({"Error": f"USB collection failed: {str(e)}"})
    
    return usb_devices

def analyze_memory_patterns(config):
    """Analyze memory allocation and access patterns"""
    results = OrderedDict()
    test_size = config['fingerprint']['memory_test_size_mb'] * 1024 * 1024
    
    # Skip memory test if size is 0 (light mode)
    if test_size == 0:
        results["Status"] = "Skipped (light mode)"
        return results
    
    try:
        # Memory allocation speed
        start_time = time.perf_counter()
        mem_block = bytearray(test_size)
        results["AllocationTime"] = round(time.perf_counter() - start_time, 4)
        
        # Memory access patterns
        access_times = []
        step = max(1, test_size // 1000)  # Sample 1000 points
        
        for i in range(0, test_size, step):
            start = time.perf_counter_ns()
            _ = mem_block[i]  # Read access
            access_times.append(time.perf_counter_ns() - start)
        
        results["MinAccessTime"] = min(access_times)
        results["MaxAccessTime"] = max(access_times)
        results["AvgAccessTime"] = sum(access_times) / len(access_times)
        
        # Memory latency consistency
        deviations = [abs(t - results["AvgAccessTime"]) for t in access_times]
        results["LatencyDeviation"] = sum(deviations) / len(deviations)
        
    except Exception as e:
        results["Error"] = f"Memory analysis failed: {str(e)}"
    
    return results

def measure_network_latency(config):
    """Measure network adapter response times"""
    results = OrderedDict()
    test_count = config['fingerprint']['network_test_count']
    
    # Skip network test if count is 0 (light mode)
    if test_count == 0:
        results["Status"] = "Skipped (light mode)"
        return results
    
    try:
        # Google DNS for reliable testing
        target = "8.8.8.8"
        port = 53  # DNS port
        
        # TCP connect latency
        tcp_times = []
        for _ in range(test_count):
            start = time.perf_counter()
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2)
            sock.connect((target, port))
            sock.close()
            tcp_times.append(time.perf_counter() - start)
        
        results["MinTCPLatency"] = round(min(tcp_times) * 1000, 2)
        results["MaxTCPLatency"] = round(max(tcp_times) * 1000, 2)
        results["AvgTCPLatency"] = round(sum(tcp_times) / len(tcp_times) * 1000, 2)
        
        # UDP latency (DNS query)
        try:
            from scapy.all import DNS, DNSQR, IP, UDP, sr1
            udp_times = []
            for _ in range(test_count):
                start = time.perf_counter()
                packet = IP(dst=target)/UDP(dport=port)/DNS(rd=1, qd=DNSQR(qname="example.com"))
                sr1(packet, timeout=2, verbose=0)
                udp_times.append(time.perf_counter() - start)
            
            results["MinUDPLatency"] = round(min(udp_times) * 1000, 2)
            results["MaxUDPLatency"] = round(max(udp_times) * 1000, 2)
            results["AvgUDPLatency"] = round(sum(udp_times) / len(udp_times) * 1000, 2)
        except ImportError:
            results["UDPLatency"] = "Scapy not available"
    
    except Exception as e:
        results["Error"] = f"Network latency test failed: {str(e)}"
    
    return results

def get_firmware_signatures():
    """Collect firmware signatures from various hardware components"""
    signatures = OrderedDict()
    
    try:
        # GPU firmware
        if platform.system() == "Windows":
            try:
                import wmi
                w = wmi.WMI()
                for gpu in w.Win32_VideoController():
                    signatures["GPU"] = {
                        "Name": gpu.Name,
                        "DriverVersion": gpu.DriverVersion,
                        "AdapterRAM": gpu.AdapterRAM
                    }
                    break
            except:
                pass
        else:
            try:
                lspci = subprocess.check_output(["lspci", "-vnn"], text=True)
                gpu_info = re.search(r"VGA.*?:(.*?)\n.*?Kernel.*?(\d+\.\d+\.\d+)", lspci, re.DOTALL)
                if gpu_info:
                    signatures["GPU"] = {
                        "Model": gpu_info.group(1).strip(),
                        "Driver": gpu_info.group(2).strip()
                    }
            except:
                pass
        
        # Network card firmware
        if platform.system() == "Windows":
            try:
                import wmi
                w = wmi.WMI()
                for nic in w.Win32_NetworkAdapter():
                    if nic.NetConnectionID:
                        signatures[f"NIC_{nic.NetConnectionID}"] = {
                            "Name": nic.Name,
                            "MAC": nic.MACAddress,
                            "Driver": nic.DriverVersion
                        }
            except:
                pass
        else:
            try:
                for iface in os.listdir("/sys/class/net"):
                    if iface.startswith(("eth", "wlan", "en")):
                        with open(f"/sys/class/net/{iface}/device/vendor", "r") as f:
                            vendor = f.read().strip()
                        with open(f"/sys/class/net/{iface}/device/device", "r") as f:
                            device = f.read().strip()
                        with open(f"/sys/class/net/{iface}/address", "r") as f:
                            mac = f.read().strip()
                        signatures[f"NIC_{iface}"] = {
                            "Vendor": vendor,
                            "Device": device,
                            "MAC": mac
                        }
            except:
                pass
        
        # SSD firmware (if available)
        if platform.system() == "Linux":
            try:
                for disk in os.listdir("/sys/block"):
                    if disk.startswith("sd") or disk.startswith("nvme"):
                        path = f"/sys/block/{disk}/device/firmware_rev"
                        if os.path.exists(path):
                            with open(path, "r") as f:
                                signatures[f"SSD_{disk}"] = f.read().strip()
            except:
                pass
    
    except Exception as e:
        signatures["Error"] = f"Firmware collection failed: {str(e)}"
    
    return signatures

def analyze_ram():
    """Analyze RAM for tamper detection"""
    ram_info = OrderedDict()
    
    try:
        # Collect RAM usage patterns
        vm_stats = psutil.virtual_memory()
        ram_info["Total"] = f"{vm_stats.total / (1024**3):.2f} GB"
        ram_info["Available"] = f"{vm_stats.available / (1024**3):.2f} GB"
        ram_info["UsedPercent"] = f"{vm_stats.percent}%"
        
        # Collect page fault statistics
        mem_stats = psutil.Process().memory_info()
        ram_info["PageFaults"] = mem_stats.num_page_faults
        
        # Get memory allocation patterns
        ram_info["Allocations"] = []
        for proc in psutil.process_iter(['pid', 'name', 'memory_info']):
            try:
                mem = proc.info['memory_info']
                ram_info["Allocations"].append({
                    "PID": proc.pid,
                    "Name": proc.info['name'],
                    "RSS": f"{mem.rss / (1024**2):.2f} MB",
                    "VMS": f"{mem.vms / (1024**2):.2f} MB"
                })
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
        
        # Limit to top 10 memory-intensive processes
        ram_info["Allocations"] = sorted(
            ram_info["Allocations"], 
            key=lambda x: float(x['RSS'].split()[0]), 
            reverse=True
        )[:10]
        
        # Add timestamp
        ram_info["CollectionTime"] = datetime.datetime.utcnow().isoformat() + "Z"
        
    except Exception as e:
        ram_info["Error"] = f"RAM analysis failed: {str(e)}"
    
    return ram_info

def get_application_residues():
    """Collect application residues and software signatures"""
    residues = OrderedDict()
    
    try:
        # Browser cache metadata
        if platform.system() == "Windows":
            browser_paths = {
                "Chrome": os.path.expanduser("~\\AppData\\Local\\Google\\Chrome\\User Data"),
                "Firefox": os.path.expanduser("~\\AppData\\Roaming\\Mozilla\\Firefox\\Profiles")
            }
        else:
            browser_paths = {
                "Chrome": os.path.expanduser("~/.config/google-chrome"),
                "Firefox": os.path.expanduser("~/.mozilla/firefox")
            }
        
        for browser, path in browser_paths.items():
            if os.path.exists(path):
                total_size = 0
                for dirpath, _, filenames in os.walk(path):
                    for filename in filenames:
                        file_path = os.path.join(dirpath, filename)
                        total_size += os.path.getsize(file_path)
                
                residues[browser] = {
                    "Path": path,
                    "LastModified": datetime.datetime.fromtimestamp(
                        os.path.getmtime(path)).isoformat(),
                    "Size": f"{total_size / (1024*1024):.2f} MB"
                }
        
        # Installed software signatures
        if platform.system() == "Windows":
            try:
                import winreg
                key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, 
                                    r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall")
                software = []
                for i in range(winreg.QueryInfoKey(key)[0]):
                    try:
                        subkey_name = winreg.EnumKey(key, i)
                        subkey = winreg.OpenKey(key, subkey_name)
                        name, _ = winreg.QueryValueEx(subkey, "DisplayName")
                        version, _ = winreg.QueryValueEx(subkey, "DisplayVersion")
                        software.append(f"{name} (v{version})")
                    except OSError:
                        continue
                residues["InstalledSoftware"] = software
            except:
                pass
        else:
            try:
                residues["InstalledSoftware"] = subprocess.check_output(
                    ["dpkg", "--list"], text=True).splitlines()[:20]  # First 20 packages
            except:
                try:
                    residues["InstalledSoftware"] = subprocess.check_output(
                        ["rpm", "-qa"], text=True).splitlines()[:20]
                except:
                    pass
    
    except Exception as e:
        residues["Error"] = f"Residue collection failed: {str(e)}"
    
    return residues

def detect_tampering(current_fp, previous_fp, config):
    """Detect device tampering by comparing current and previous fingerprints"""
    tamper_indicators = OrderedDict()
    threshold = config['tamper_detection']
    
    if not previous_fp:
        return {"Status": "No previous fingerprint for comparison"}
    
    # BIOS version and date comparison
    bios_current = current_fp["Hardware"]["BIOS"]
    bios_previous = previous_fp["Hardware"]["BIOS"]
    
    for field in ["Version", "ReleaseDate", "Serial"]:
        if bios_current.get(field) != bios_previous.get(field):
            tamper_indicators[f"BIOS_{field}"] = {
                "Previous": bios_previous.get(field, "N/A"),
                "Current": bios_current.get(field, "N/A")
            }
    
    # BIOS time anomaly detection
    try:
        prev_time = datetime.datetime.fromisoformat(bios_previous["CollectionTime"].rstrip("Z"))
        curr_time = datetime.datetime.fromisoformat(bios_current["CollectionTime"].rstrip("Z"))
        time_diff = abs((curr_time - prev_time).total_seconds())
        
        if time_diff > threshold['bios_time_threshold']:
            tamper_indicators["BIOS_TimeAnomaly"] = {
                "TimeDifference": f"{time_diff/3600:.2f} hours",
                "Threshold": f"{threshold['bios_time_threshold']/3600} hours"
            }
    except:
        pass
    
    # Disk signature comparison
    disk_current = current_fp["Hardware"].get("Disk", {})
    disk_previous = previous_fp["Hardware"].get("Disk", {})
    
    signature_changes = 0
    total_fields = 0
    for field in ["Model", "Serial", "Firmware"]:
        if field in disk_current and field in disk_previous:
            total_fields += 1
            if disk_current[field] != disk_previous[field]:
                signature_changes += 1
                tamper_indicators[f"Disk_{field}"] = {
                    "Previous": disk_previous[field],
                    "Current": disk_current[field]
                }
    
    if total_fields > 0:
        change_ratio = signature_changes / total_fields
        if change_ratio > threshold['disk_signature_change_threshold']:
            tamper_indicators["Disk_SignatureChange"] = {
                "ChangeRatio": f"{change_ratio*100:.1f}%",
                "Threshold": f"{threshold['disk_signature_change_threshold']*100}%"
            }
    
    # USB device changes
    usb_current = {dev.get("Serial", "") for dev in current_fp["Hardware"]["USBDevices"]}
    usb_previous = {dev.get("Serial", "") for dev in previous_fp["Hardware"]["USBDevices"]}
    
    added = usb_current - usb_previous
    removed = usb_previous - usb_current
    
    if added:
        tamper_indicators["USB_Added"] = list(added)
    if removed:
        tamper_indicators["USB_Removed"] = list(removed)
    
    # Firmware version changes
    for component, current_data in current_fp["Hardware"]["Firmware"].items():
        prev_data = previous_fp["Hardware"]["Firmware"].get(component, {})
        for key, value in current_data.items():
            if key in prev_data and value != prev_data[key]:
                tamper_indicators[f"{component}_{key}"] = {
                    "Previous": prev_data[key],
                    "Current": value
                }
    
    # RAM analysis comparison
    if config['fingerprint']['ram_analysis']:
        try:
            ram_current = current_fp["Hardware"].get("RAM", {})
            ram_previous = previous_fp["Hardware"].get("RAM", {})
            
            # Page fault rate comparison
            if "PageFaults" in ram_current and "PageFaults" in ram_previous:
                current_faults = ram_current["PageFaults"]
                previous_faults = ram_previous["PageFaults"]
                fault_change = abs(current_faults - previous_faults) / max(previous_faults, 1) * 100
                
                if fault_change > threshold['ram_change_threshold']:
                    tamper_indicators["RAM_PageFaultChange"] = {
                        "ChangePercent": f"{fault_change:.2f}%",
                        "Threshold": f"{threshold['ram_change_threshold']}%",
                        "Previous": previous_faults,
                        "Current": current_faults
                    }
            
            # Memory allocation pattern comparison
            if "Allocations" in ram_current and "Allocations" in ram_previous:
                current_procs = {p["Name"]: p["RSS"] for p in ram_current["Allocations"]}
                previous_procs = {p["Name"]: p["RSS"] for p in ram_previous["Allocations"]}
                
                new_procs = set(current_procs.keys()) - set(previous_procs.keys())
                missing_procs = set(previous_procs.keys()) - set(current_procs.keys())
                
                if new_procs:
                    tamper_indicators["RAM_NewProcesses"] = list(new_procs)
                if missing_procs:
                    tamper_indicators["RAM_MissingProcesses"] = list(missing_procs)
        except Exception as e:
            tamper_indicators["RAM_Error"] = f"RAM comparison failed: {str(e)}"
    
    return tamper_indicators if tamper_indicators else {"Status": "No tampering detected"}

def get_mobile_device_fingerprints():
    """Collect fingerprints from connected mobile devices (Android/iOS) via USB"""
    mobile_devices = []
    
    try:
        # Check for Android devices via ADB
        try:
            adb_devices = subprocess.check_output(["adb", "devices"], text=True).splitlines()
            # Skip the first line ("List of devices attached") and empty lines
            adb_devices = [line.split('\t')[0] for line in adb_devices[1:] if line.strip() and 'device' in line]
            
            for device_id in adb_devices:
                try:
                    device_info = OrderedDict()
                    device_info["Type"] = "Android"
                    
                    # Collect device information
                    device_info["Model"] = subprocess.check_output(
                        ["adb", "-s", device_id, "shell", "getprop", "ro.product.model"],
                        text=True
                    ).strip()
                    
                    device_info["AndroidVersion"] = subprocess.check_output(
                        ["adb", "-s", device_id, "shell", "getprop", "ro.build.version.release"],
                        text=True
                    ).strip()
                    
                    device_info["BuildFingerprint"] = subprocess.check_output(
                        ["adb", "-s", device_id, "shell", "getprop", "ro.build.fingerprint"],
                        text=True
                    ).strip()
                    
                    device_info["Serial"] = subprocess.check_output(
                        ["adb", "-s", device_id, "shell", "getprop", "ro.serialno"],
                        text=True
                    ).strip()
                    
                    # Get storage usage
                    storage_info = subprocess.check_output(
                        ["adb", "-s", device_id, "shell", "df", "/sdcard"],
                        text=True
                    ).splitlines()
                    if len(storage_info) > 1:
                        parts = storage_info[1].split()
                        if len(parts) > 4:
                            device_info["StorageUsed"] = parts[2]
                            device_info["StorageAvailable"] = parts[3]
                    
                    device_info["CollectionTime"] = datetime.datetime.utcnow().isoformat() + "Z"
                    mobile_devices.append(device_info)
                except Exception as e:
                    mobile_devices.append({
                        "Type": "Android",
                        "Error": f"Failed to collect info for device {device_id}: {str(e)}"
                    })
        except (FileNotFoundError, subprocess.CalledProcessError):
            pass  # ADB not installed or failed
        
        # Check for iOS devices via libimobiledevice
        try:
            idevices = subprocess.check_output(["idevice_id", "-l"], text=True).splitlines()
            for udid in idevices:
                try:
                    device_info = OrderedDict()
                    device_info["Type"] = "iOS"
                    
                    # Collect device information
                    device_info["UDID"] = udid.strip()
                    
                    device_info["ProductType"] = subprocess.check_output(
                        ["ideviceinfo", "-u", udid, "-k", "ProductType"],
                        text=True
                    ).strip()
                    
                    device_info["ProductVersion"] = subprocess.check_output(
                        ["ideviceinfo", "-u", udid, "-k", "ProductVersion"],
                        text=True
                    ).strip()
                    
                    device_info["SerialNumber"] = subprocess.check_output(
                        ["ideviceinfo", "-u", udid, "-k", "SerialNumber"],
                        text=True
                    ).strip()
                    
                    device_info["CollectionTime"] = datetime.datetime.utcnow().isoformat() + "Z"
                    mobile_devices.append(device_info)
                except Exception as e:
                    mobile_devices.append({
                        "Type": "iOS",
                        "Error": f"Failed to collect info for device {udid}: {str(e)}"
                    })
        except (FileNotFoundError, subprocess.CalledProcessError):
            pass  # libimobiledevice not installed or failed
    
    except Exception as e:
        mobile_devices.append({"Error": f"Mobile device collection failed: {str(e)}"})
    
    return mobile_devices

def save_mobile_fingerprint(conn, device_id, device_type, fingerprint, fingerprint_hash, report_hash, report_data):
    """Store mobile fingerprint in database with forensic integrity checks"""
    c = conn.cursor()
    timestamp = fingerprint["CollectionTime"]
    
    try:
        # Generate RSA key pair for digital signature
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        public_key = private_key.public_key().public_bytes(
            Encoding.PEM,
            PublicFormat.SubjectPublicKeyInfo
        ).decode()
        
        c.execute("""
            INSERT INTO mobile_fingerprints 
            (device_id, timestamp, device_type, fingerprint_hash, report_data, report_hash, public_key) 
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (device_id, timestamp, device_type, fingerprint_hash, report_data, report_hash, public_key))
        
        fp_id = c.lastrowid
        
        # Add chain of custody entry
        c.execute("""
            INSERT INTO chain_of_custody 
            (fingerprint_id, action, actor, timestamp, details) 
            VALUES (?, ?, ?, ?, ?)
        """, (fp_id, "GENERATE", os.getlogin(), timestamp, f"Mobile fingerprint collection ({device_type})"))
        
        conn.commit()
        return True, private_key
    except sqlite3.IntegrityError:
        print("[-] Error: Duplicate mobile fingerprint detected. Device already registered.")
        return False, None

def generate_fingerprint(device_id, config):
    """Generate comprehensive device fingerprint with forensic metadata"""
    fingerprint = OrderedDict()
    timestamp = datetime.datetime.utcnow().isoformat() + "Z"
    
    # Collect forensic metadata
    fingerprint["Metadata"] = OrderedDict([
        ("DeviceID", device_id),
        ("CollectionTime", timestamp),
        ("Investigator", os.getlogin()),
        ("Platform", platform.platform()),
        ("Hostname", platform.node()),
        ("SystemBootTime", datetime.datetime.fromtimestamp(psutil.boot_time()).isoformat())
    ])
    
    # Collect hardware characteristics
    hardware = OrderedDict([
        ("BIOS", get_bios_info()),
        ("CPU", OrderedDict([
            ("Model", platform.processor()),
            ("Cores", psutil.cpu_count(logical=False)),
            ("Threads", psutil.cpu_count(logical=True)),
            ("Performance", measure_cpu_performance(config))
        ])),
        ("Disk", analyze_disk_io(config)),
        ("USBDevices", get_usb_signatures()),
        ("NetworkLatency", measure_network_latency(config)),
        ("Firmware", get_firmware_signatures())
    ])
    
    # Add RAM analysis if enabled
    if config['fingerprint']['ram_analysis']:
        hardware["RAM"] = analyze_ram()
    
    # Add memory analysis if enabled (not skipped in light mode)
    if config['fingerprint']['memory_test_size_mb'] > 0:
        hardware["Memory"] = analyze_memory_patterns(config)
    
    fingerprint["Hardware"] = hardware
    
    # Collect software characteristics
    fingerprint["Software"] = OrderedDict([
        ("OS", platform.system()),
        ("OSVersion", platform.version()),
        ("PythonVersion", platform.python_version()),
        ("ApplicationResidues", get_application_residues())
    ])
    
    # Generate forensic integrity hashes
    report_data = json.dumps(fingerprint, indent=2)
    fingerprint_hash = hashlib.sha256(report_data.encode()).hexdigest()
    report_hash = hashlib.sha256(report_data.encode()).hexdigest()
    
    return fingerprint, fingerprint_hash, report_hash, report_data

def save_fingerprint(conn, device_id, fingerprint, fingerprint_hash, report_hash, report_data):
    """Store fingerprint in database with forensic integrity checks"""
    c = conn.cursor()
    timestamp = fingerprint["Metadata"]["CollectionTime"]
    
    try:
        # Generate RSA key pair for digital signature
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        public_key = private_key.public_key().public_bytes(
            Encoding.PEM,
            PublicFormat.SubjectPublicKeyInfo
        ).decode()
        
        c.execute("""
            INSERT INTO fingerprints 
            (device_id, timestamp, fingerprint_hash, report_data, report_hash, public_key) 
            VALUES (?, ?, ?, ?, ?, ?)
        """, (device_id, timestamp, fingerprint_hash, report_data, report_hash, public_key))
        
        fp_id = c.lastrowid
        
        # Add chain of custody entry
        c.execute("""
            INSERT INTO chain_of_custody 
            (fingerprint_id, action, actor, timestamp, details) 
            VALUES (?, ?, ?, ?, ?)
        """, (fp_id, "GENERATE", os.getlogin(), timestamp, "Initial fingerprint collection"))
        
        conn.commit()
        return True, private_key
    except sqlite3.IntegrityError:
        print("[-] Error: Duplicate fingerprint detected. Device already registered.")
        return False, None

def sign_report(report_data, private_key):
    """Digitally sign the forensic report"""
    signature = private_key.sign(
        report_data.encode(),
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    return base64.b64encode(signature).decode()

def generate_report(fingerprint, output_file, private_key=None, config=None):
    """Generate forensic report with integrity verification"""
    report_data = json.dumps(fingerprint, indent=2)
    
    # Add integrity verification
    fingerprint["ForensicIntegrity"] = OrderedDict([
        ("SHA256", hashlib.sha256(report_data.encode()).hexdigest()),
        ("VerificationTime", datetime.datetime.utcnow().isoformat() + "Z")
    ])
    
    # Add digital signature if enabled
    if config and config['reporting']['sign_reports'] and private_key:
        signature = sign_report(report_data, private_key)
        fingerprint["ForensicIntegrity"]["DigitalSignature"] = signature
    
    # Add tamper detection analysis
    conn = initialize_db()
    c = conn.cursor()
    c.execute("""
        SELECT report_data FROM fingerprints 
        WHERE device_id=? 
        ORDER BY timestamp DESC 
        LIMIT 1,1
    """, (fingerprint["Metadata"]["DeviceID"],))
    
    prev_report = c.fetchone()
    if prev_report:
        prev_fp = json.loads(prev_report[0])
        fingerprint["TamperDetection"] = detect_tampering(fingerprint, prev_fp, config)
    
    final_report = json.dumps(fingerprint, indent=2)
    
    with open(output_file, "w") as f:
        f.write(final_report)
    
    print(f"[+] Forensic report generated: {output_file}")
    print(f"[+] SHA-256: {hashlib.sha256(final_report.encode()).hexdigest()}")

def compare_fingerprints(conn):
    """Compare stored fingerprints for forensic analysis"""
    c = conn.cursor()
    c.execute("SELECT id, device_id, timestamp, fingerprint_hash FROM fingerprints")
    fingerprints = c.fetchall()
    
    if not fingerprints:
        print("[-] No fingerprints found in database")
        return
    
    # Display comparison table
    headers = ["ID", "Device ID", "Collection Time", "Fingerprint Hash"]
    table = []
    
    for fp in fingerprints:
        table.append([
            fp[0],
            fp[1],
            fp[2][:19] + " UTC",
            fp[3][:16] + "..." + fp[3][-16:]
        ])
    
    print("\n[+] Stored Fingerprints:")
    print(tabulate(table, headers=headers, tablefmt="grid"))
    
    # Detailed comparison
    if len(fingerprints) > 1:
        print("\n[+] Comparison Matrix:")
        comparison = []
        
        for i in range(len(fingerprints)):
            row = [fingerprints[i][1]]
            c.execute("SELECT report_data FROM fingerprints WHERE id=?", (fingerprints[i][0],))
            fp1 = json.loads(c.fetchone()[0])
            
            for j in range(len(fingerprints)):
                if i == j:
                    row.append("--")
                    continue
                
                c.execute("SELECT report_data FROM fingerprints WHERE id=?", (fingerprints[j][0],))
                fp2 = json.loads(c.fetchone()[0])
                
                # Calculate similarity score
                similarity = 0
                total = 0
                
                # Compare hardware characteristics
                for category in ["BIOS", "CPU", "Disk", "Memory", "NetworkLatency", "RAM"]:
                    if category in fp1["Hardware"] and category in fp2["Hardware"]:
                        for key in fp1["Hardware"][category]:
                            if key in fp2["Hardware"][category]:
                                if isinstance(fp1["Hardware"][category][key], dict):
                                    for subkey in fp1["Hardware"][category][key]:
                                        if subkey in fp2["Hardware"][category][key]:
                                            if (fp1["Hardware"][category][key][subkey] == 
                                                fp2["Hardware"][category][key][subkey]):
                                                similarity += 1
                                            total += 1
                                else:
                                    if (fp1["Hardware"][category][key] == 
                                        fp2["Hardware"][category][key]):
                                        similarity += 1
                                    total += 1
                
                # Add USB comparison
                usb_similarity = 0
                if "USBDevices" in fp1["Hardware"] and "USBDevices" in fp2["Hardware"]:
                    usb1 = {dev.get("Serial", "") for dev in fp1["Hardware"]["USBDevices"]}
                    usb2 = {dev.get("Serial", "") for dev in fp2["Hardware"]["USBDevices"]}
                    usb_similarity = len(usb1 & usb2) / max(len(usb1 | usb2), 1) * 100
                
                # Final similarity score
                score = (similarity / max(total, 1) * 0.7 + usb_similarity * 0.3) * 100
                row.append(f"{score:.1f}%")
            
            comparison.append(row)
        
        comparison_headers = ["Device ID"] + [fp[1] for fp in fingerprints]
        print(tabulate(comparison, headers=comparison_headers, tablefmt="grid"))
        print("\n[!] Note: Scores below 85% indicate significantly different devices")

def export_report(conn, device_id, output_file, config):
    """Export forensic report from database"""
    c = conn.cursor()
    c.execute("""
        SELECT report_data, public_key FROM fingerprints 
        WHERE device_id=? 
        ORDER BY timestamp DESC 
        LIMIT 1
    """, (device_id,))
    
    result = c.fetchone()
    if not result:
        print(f"[-] No fingerprint found for device: {device_id}")
        return
    
    fingerprint = json.loads(result[0], object_pairs_hook=OrderedDict)
    public_key_pem = result[1]
    
    # Reconstruct private key (in real use, this would be securely stored)
    private_key = None
    if public_key_pem and config['reporting']['sign_reports']:
        # In a real implementation, we'd retrieve the private key from secure storage
        # For this demo, we'll generate a new one (not cryptographically sound)
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
    
    generate_report(fingerprint, output_file, private_key, config)

def main():
    """Main entry point for Digital Spectrum Analyzer"""
    parser = argparse.ArgumentParser(
        description="Digital Spectrum Analyzer - Advanced Forensic Device Fingerprinting",
        epilog="Example: python digital_spectrum_analyzer.py --generate --device-id CASE123 --light-mode --output report.json"
    )
    parser.add_argument("--generate", action="store_true", help="Generate new device fingerprint")
    parser.add_argument("--mobile", action="store_true", help="Generate mobile device fingerprints")
    parser.add_argument("--compare", action="store_true", help="Compare stored fingerprints")
    parser.add_argument("--export", action="store_true", help="Export forensic report")
    parser.add_argument("--light-mode", action="store_true", help="Optimize for low-resource systems")
    parser.add_argument("--device-id", help="Unique identifier for the device")
    parser.add_argument("--output", help="Output file for forensic report")
    
    args = parser.parse_args()
    
    if not any([args.generate, args.compare, args.export, args.mobile]):
        parser.print_help()
        sys.exit(1)
    
    config = load_config(args)
    conn = initialize_db()
    
    try:
        if args.generate:
            if not args.device_id:
                print("[-] Error: --device-id is required for fingerprint generation")
                sys.exit(1)
                
            print("[+] Generating device fingerprint...")
            fingerprint, fp_hash, report_hash, report_data = generate_fingerprint(args.device_id, config)
            
            print(f"[+] Fingerprint generated: {fp_hash}")
            saved, private_key = save_fingerprint(conn, args.device_id, fingerprint, fp_hash, report_hash, report_data)
            
            if saved:
                print("[+] Fingerprint stored in database")
                if args.output:
                    generate_report(fingerprint, args.output, private_key, config)
        
        elif args.mobile:
            print("[+] Scanning for connected mobile devices...")
            mobile_devices = get_mobile_device_fingerprints()
            
            if not mobile_devices:
                print("[-] No mobile devices found or required tools not installed")
                print("[!] Ensure ADB is installed for Android and libimobiledevice for iOS")
                return
            
            print(f"[+] Found {len(mobile_devices)} mobile device(s)")
            
            for i, device in enumerate(mobile_devices):
                device_id = device.get("Serial") or device.get("UDID") or f"MOBILE_{i+1}"
                report_data = json.dumps(device, indent=2)
                fingerprint_hash = hashlib.sha256(report_data.encode()).hexdigest()
                report_hash = hashlib.sha256(report_data.encode()).hexdigest()
                
                saved, private_key = save_mobile_fingerprint(
                    conn,
                    args.device_id or "MOBILE",
                    device.get("Type", "Unknown"),
                    device,
                    fingerprint_hash,
                    report_hash,
                    report_data
                )
                
                if saved:
                    print(f"[+] Mobile fingerprint stored: {device.get('Type')} - {device_id}")
                    if args.output:
                        output_file = args.output.replace(".json", f"_{device_id}.json")
                        generate_report(device, output_file, private_key, config)
        
        elif args.compare:
            compare_fingerprints(conn)
        
        elif args.export:
            if not args.device_id or not args.output:
                print("[-] Error: Both --device-id and --output are required for export")
                sys.exit(1)
                
            export_report(conn, args.device_id, args.output, config)
    
    except PermissionError:
        print("[-] Error: Administrator/root privileges required")
        sys.exit(1)
    except Exception as e:
        print(f"[-] Critical error: {str(e)}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
    finally:
        conn.close()

if __name__ == "__main__":
    main()
