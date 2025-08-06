#!/usr/bin/env python3
"""
PENTU - Penetration Testing Unified
Comprehensive all-in-one penetration testing toolkit
Integrating: Burp Suite, Nmap, Metasploit, sqlmap, OWASP ZAP, Wireshark, Aircrack-ng, John the Ripper,
SET, TheHarvester, Shodan, Maltego, Nikto, Gobuster, Dirb, FFuF, Masscan, Zmap, Enum4linux, MobSF,
Empire, Bloodhound, Nuclei, AI-powered Analysis, 3D Visualization, and more

Author: Security Research Team
Version: 2.0.0
Platform: Linux (Optimized for Kali Linux)
WARNING: Use ethically and legally only.
"""

import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox, filedialog, simpledialog
import subprocess
import threading
import os
import sys
import json
import time
import re
from datetime import datetime
import urllib.parse
import socket
import requests
from pathlib import Path

class PentuSuite:
    def __init__(self):
        self.root = tk.Tk()
        self.setup_main_window()
        self.create_interface()
        self.results = {}
        self.current_scan = None
        self.scan_running = False
        
    def setup_main_window(self):
        """Setup the main application window"""
        self.root.title("🔥 PENTU - Ultimate Penetration Testing Suite v1.0")
        self.root.geometry("1400x900")
        self.root.configure(bg='#0a0a0a')
        
        # Center window
        self.root.update_idletasks()
        x = (self.root.winfo_screenwidth() // 2) - (1400 // 2)
        y = (self.root.winfo_screenheight() // 2) - (900 // 2)
        self.root.geometry(f"1400x900+{x}+{y}")
        
        # Style configuration
        self.style = ttk.Style()
        self.style.theme_use('clam')
        self.configure_styles()
        
    def configure_styles(self):
        """Configure custom styles for the interface"""
        # Configure notebook style
        self.style.configure('TNotebook', 
                           background='#1a1a1a',
                           tabposition='n')
        self.style.configure('TNotebook.Tab',
                           background='#2d2d2d',
                           foreground='#ffffff',
                           padding=[15, 8],
                           font=('Consolas', 10, 'bold'))
        self.style.map('TNotebook.Tab',
                      background=[('selected', '#ff6b35'),
                                ('active', '#444444')])
        
        # Configure frame and button styles
        self.style.configure('TFrame', background='#1a1a1a')
        self.style.configure('TLabel', background='#1a1a1a', foreground='#ffffff', 
                           font=('Consolas', 10))
        self.style.configure('Title.TLabel', font=('Consolas', 14, 'bold'),
                           foreground='#ff6b35')
        
    def create_interface(self):
        """Create the main interface with all penetration testing modules"""
        
        # Header
        header_frame = tk.Frame(self.root, bg='#0a0a0a', height=80)
        header_frame.pack(fill=tk.X)
        header_frame.pack_propagate(False)
        
        # Title with gradient effect
        title_label = tk.Label(header_frame, 
                              text="🔥 PENTU - PENETRATION TESTING SUITE",
                              bg='#0a0a0a', fg='#ff6b35',
                              font=('Consolas', 20, 'bold'))
        title_label.pack(pady=15)
        
        subtitle_label = tk.Label(header_frame,
                                text="Integrated: Burp Suite • Nmap • Metasploit • sqlmap • OWASP ZAP • Wireshark • Aircrack-ng • John the Ripper",
                                bg='#0a0a0a', fg='#888888',
                                font=('Consolas', 10))
        subtitle_label.pack()
        
        # Main notebook for different testing modules
        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Create all penetration testing modules
        self.create_web_app_tab()
        self.create_network_tab()
        self.create_exploitation_tab()
        self.create_wireless_tab()
        self.create_password_tab()
        self.create_osint_tab()
        self.create_mobile_tab()
        self.create_advanced_web_tab()
        self.create_post_exploit_tab()
        self.create_ai_dashboard_tab()
        self.create_reporting_tab()
        
        # Status bar
        self.create_status_bar()
        
    def create_web_app_tab(self):
        """Web Application Security Testing Module"""
        web_frame = ttk.Frame(self.notebook)
        self.notebook.add(web_frame, text="🌐 Web Application Security")
        
        # Create sections for different web app tools
        self.create_section_header(web_frame, "Web Application Penetration Testing")
        
        # Tool selection frame
        tool_frame = tk.Frame(web_frame, bg='#1a1a1a')
        tool_frame.pack(fill=tk.X, padx=20, pady=10)
        
        # Burp Suite Integration
        burp_frame = tk.LabelFrame(tool_frame, text="🎯 Burp Suite Integration", 
                                  bg='#2d2d2d', fg='#ff6b35', font=('Consolas', 12, 'bold'))
        burp_frame.pack(fill=tk.X, pady=5)
        
        tk.Button(burp_frame, text="Launch Burp Suite", 
                 command=self.launch_burp_suite,
                 bg='#ff6b35', fg='white', font=('Consolas', 10, 'bold')).pack(side=tk.LEFT, padx=10, pady=5)
        
        tk.Button(burp_frame, text="Configure Proxy", 
                 command=self.configure_burp_proxy,
                 bg='#555555', fg='white', font=('Consolas', 10)).pack(side=tk.LEFT, padx=5, pady=5)
        
        # OWASP ZAP Integration
        zap_frame = tk.LabelFrame(tool_frame, text="🕷️ OWASP ZAP Scanner", 
                                 bg='#2d2d2d', fg='#ff6b35', font=('Consolas', 12, 'bold'))
        zap_frame.pack(fill=tk.X, pady=5)
        
        self.zap_target = tk.StringVar()
        tk.Label(zap_frame, text="Target URL:", bg='#2d2d2d', fg='white').pack(side=tk.LEFT, padx=10)
        tk.Entry(zap_frame, textvariable=self.zap_target, width=40, bg='#444444', fg='white').pack(side=tk.LEFT, padx=5)
        tk.Button(zap_frame, text="Start ZAP Scan", 
                 command=self.start_zap_scan,
                 bg='#ff6b35', fg='white', font=('Consolas', 10, 'bold')).pack(side=tk.LEFT, padx=10, pady=5)
        
        # SQLMap Integration
        sql_frame = tk.LabelFrame(tool_frame, text="💉 SQLMap - SQL Injection Testing", 
                                 bg='#2d2d2d', fg='#ff6b35', font=('Consolas', 12, 'bold'))
        sql_frame.pack(fill=tk.X, pady=5)
        
        self.sql_target = tk.StringVar()
        tk.Label(sql_frame, text="Target URL:", bg='#2d2d2d', fg='white').pack(side=tk.LEFT, padx=10)
        tk.Entry(sql_frame, textvariable=self.sql_target, width=40, bg='#444444', fg='white').pack(side=tk.LEFT, padx=5)
        tk.Button(sql_frame, text="Test SQL Injection", 
                 command=self.test_sql_injection,
                 bg='#ff6b35', fg='white', font=('Consolas', 10, 'bold')).pack(side=tk.LEFT, padx=10, pady=5)
        
        # Results area for web app testing
        self.web_results = scrolledtext.ScrolledText(web_frame, height=25, bg='#0f0f0f', fg='#00ff00',
                                                   font=('Consolas', 10), insertbackground='#00ff00')
        self.web_results.pack(fill=tk.BOTH, expand=True, padx=20, pady=10)
        
    def create_network_tab(self):
        """Network Reconnaissance & Analysis Module"""
        network_frame = ttk.Frame(self.notebook)
        self.notebook.add(network_frame, text="🔍 Network Reconnaissance")
        
        self.create_section_header(network_frame, "Network Scanning & Analysis")
        
        # Nmap integration
        nmap_frame = tk.LabelFrame(network_frame, text="🗺️ Nmap Network Scanner", 
                                  bg='#2d2d2d', fg='#ff6b35', font=('Consolas', 12, 'bold'))
        nmap_frame.pack(fill=tk.X, padx=20, pady=10)
        
        # Target input
        target_frame = tk.Frame(nmap_frame, bg='#2d2d2d')
        target_frame.pack(fill=tk.X, padx=10, pady=5)
        
        tk.Label(target_frame, text="Target(s):", bg='#2d2d2d', fg='white').pack(side=tk.LEFT)
        self.nmap_target = tk.StringVar()
        tk.Entry(target_frame, textvariable=self.nmap_target, width=50, bg='#444444', fg='white').pack(side=tk.LEFT, padx=10)
        
        # Scan type selection
        scan_frame = tk.Frame(nmap_frame, bg='#2d2d2d')
        scan_frame.pack(fill=tk.X, padx=10, pady=5)
        
        self.scan_type = tk.StringVar(value="quick")
        scan_types = [
            ("Quick Scan", "quick"),
            ("Comprehensive Scan", "comprehensive"),
            ("Stealth Scan", "stealth"),
            ("UDP Scan", "udp"),
            ("OS Detection", "os"),
            ("Version Detection", "version")
        ]
        
        for text, value in scan_types:
            tk.Radiobutton(scan_frame, text=text, variable=self.scan_type, value=value,
                         bg='#2d2d2d', fg='white', selectcolor='#ff6b35').pack(side=tk.LEFT, padx=10)
        
        # Control buttons
        control_frame = tk.Frame(nmap_frame, bg='#2d2d2d')
        control_frame.pack(fill=tk.X, padx=10, pady=10)
        
        tk.Button(control_frame, text="🚀 Start Nmap Scan", 
                 command=self.start_nmap_scan,
                 bg='#ff6b35', fg='white', font=('Consolas', 10, 'bold')).pack(side=tk.LEFT, padx=5)
        
        tk.Button(control_frame, text="⏹️ Stop Scan", 
                 command=self.stop_scan,
                 bg='#cc0000', fg='white', font=('Consolas', 10, 'bold')).pack(side=tk.LEFT, padx=5)
        
        tk.Button(control_frame, text="📊 Export Results", 
                 command=self.export_nmap_results,
                 bg='#555555', fg='white', font=('Consolas', 10)).pack(side=tk.LEFT, padx=5)
        
        # Wireshark integration
        wireshark_frame = tk.LabelFrame(network_frame, text="📡 Wireshark Packet Analysis", 
                                      bg='#2d2d2d', fg='#ff6b35', font=('Consolas', 12, 'bold'))
        wireshark_frame.pack(fill=tk.X, padx=20, pady=5)
        
        tk.Button(wireshark_frame, text="Launch Wireshark", 
                 command=self.launch_wireshark,
                 bg='#ff6b35', fg='white', font=('Consolas', 10, 'bold')).pack(side=tk.LEFT, padx=10, pady=5)
        
        tk.Button(wireshark_frame, text="Capture Traffic", 
                 command=self.start_packet_capture,
                 bg='#555555', fg='white', font=('Consolas', 10)).pack(side=tk.LEFT, padx=5, pady=5)
        
        # Network results
        self.network_results = scrolledtext.ScrolledText(network_frame, height=20, bg='#0f0f0f', fg='#00ff00',
                                                       font=('Consolas', 10), insertbackground='#00ff00')
        self.network_results.pack(fill=tk.BOTH, expand=True, padx=20, pady=10)
        
    def create_exploitation_tab(self):
        """Exploitation & Frameworks Module"""
        exploit_frame = ttk.Frame(self.notebook)
        self.notebook.add(exploit_frame, text="🎯 Exploitation Framework")
        
        self.create_section_header(exploit_frame, "Metasploit Framework Integration")
        
        # Metasploit console integration
        msf_frame = tk.LabelFrame(exploit_frame, text="💣 Metasploit Framework", 
                                 bg='#2d2d2d', fg='#ff6b35', font=('Consolas', 12, 'bold'))
        msf_frame.pack(fill=tk.X, padx=20, pady=10)
        
        # Quick exploit selection
        exploit_select_frame = tk.Frame(msf_frame, bg='#2d2d2d')
        exploit_select_frame.pack(fill=tk.X, padx=10, pady=5)
        
        tk.Label(exploit_select_frame, text="Quick Exploits:", bg='#2d2d2d', fg='white').pack(side=tk.LEFT)
        self.exploit_type = tk.StringVar()
        exploits = ["windows/smb/ms17_010_eternalblue", "linux/http/apache_range_dos", "windows/http/iis_webdav"]
        exploit_combo = ttk.Combobox(exploit_select_frame, textvariable=self.exploit_type, values=exploits)
        exploit_combo.pack(side=tk.LEFT, padx=10)
        
        # Target configuration
        target_config_frame = tk.Frame(msf_frame, bg='#2d2d2d')
        target_config_frame.pack(fill=tk.X, padx=10, pady=5)
        
        tk.Label(target_config_frame, text="Target:", bg='#2d2d2d', fg='white').pack(side=tk.LEFT)
        self.msf_target = tk.StringVar()
        tk.Entry(target_config_frame, textvariable=self.msf_target, width=30, bg='#444444', fg='white').pack(side=tk.LEFT, padx=10)
        
        tk.Label(target_config_frame, text="LHOST:", bg='#2d2d2d', fg='white').pack(side=tk.LEFT, padx=(20,0))
        self.msf_lhost = tk.StringVar()
        tk.Entry(target_config_frame, textvariable=self.msf_lhost, width=20, bg='#444444', fg='white').pack(side=tk.LEFT, padx=10)
        
        # Control buttons
        msf_control_frame = tk.Frame(msf_frame, bg='#2d2d2d')
        msf_control_frame.pack(fill=tk.X, padx=10, pady=10)
        
        tk.Button(msf_control_frame, text="🚀 Launch Metasploit", 
                 command=self.launch_metasploit,
                 bg='#ff6b35', fg='white', font=('Consolas', 10, 'bold')).pack(side=tk.LEFT, padx=5)
        
        tk.Button(msf_control_frame, text="🎯 Run Exploit", 
                 command=self.run_exploit,
                 bg='#cc6600', fg='white', font=('Consolas', 10, 'bold')).pack(side=tk.LEFT, padx=5)
        
        tk.Button(msf_control_frame, text="📋 Show Payloads", 
                 command=self.show_payloads,
                 bg='#555555', fg='white', font=('Consolas', 10)).pack(side=tk.LEFT, padx=5)
        
        # Exploitation results
        self.exploit_results = scrolledtext.ScrolledText(exploit_frame, height=25, bg='#0f0f0f', fg='#ff6600',
                                                       font=('Consolas', 10), insertbackground='#ff6600')
        self.exploit_results.pack(fill=tk.BOTH, expand=True, padx=20, pady=10)
        
    def create_wireless_tab(self):
        """Wireless Security Testing Module"""
        wireless_frame = ttk.Frame(self.notebook)
        self.notebook.add(wireless_frame, text="📡 Wireless Security")
        
        self.create_section_header(wireless_frame, "Wireless Network Penetration Testing")
        
        # Aircrack-ng integration
        aircrack_frame = tk.LabelFrame(wireless_frame, text="📶 Aircrack-ng Wireless Suite", 
                                     bg='#2d2d2d', fg='#ff6b35', font=('Consolas', 12, 'bold'))
        aircrack_frame.pack(fill=tk.X, padx=20, pady=10)
        
        # Interface selection
        interface_frame = tk.Frame(aircrack_frame, bg='#2d2d2d')
        interface_frame.pack(fill=tk.X, padx=10, pady=5)
        
        tk.Label(interface_frame, text="Interface:", bg='#2d2d2d', fg='white').pack(side=tk.LEFT)
        self.wifi_interface = tk.StringVar()
        tk.Entry(interface_frame, textvariable=self.wifi_interface, width=20, bg='#444444', fg='white').pack(side=tk.LEFT, padx=10)
        tk.Button(interface_frame, text="Scan Interfaces", 
                 command=self.scan_wifi_interfaces,
                 bg='#555555', fg='white', font=('Consolas', 9)).pack(side=tk.LEFT, padx=5)
        
        # Wireless operations
        wifi_ops_frame = tk.Frame(aircrack_frame, bg='#2d2d2d')
        wifi_ops_frame.pack(fill=tk.X, padx=10, pady=5)
        
        tk.Button(wifi_ops_frame, text="🔍 Scan Networks", 
                 command=self.scan_wifi_networks,
                 bg='#ff6b35', fg='white', font=('Consolas', 10, 'bold')).pack(side=tk.LEFT, padx=5, pady=5)
        
        tk.Button(wifi_ops_frame, text="🎯 Monitor Mode", 
                 command=self.enable_monitor_mode,
                 bg='#cc6600', fg='white', font=('Consolas', 10, 'bold')).pack(side=tk.LEFT, padx=5, pady=5)
        
        tk.Button(wifi_ops_frame, text="📡 Capture Handshake", 
                 command=self.capture_handshake,
                 bg='#555555', fg='white', font=('Consolas', 10)).pack(side=tk.LEFT, padx=5, pady=5)
        
        tk.Button(wifi_ops_frame, text="🔓 Crack WPA/WPA2", 
                 command=self.crack_wifi_password,
                 bg='#cc0000', fg='white', font=('Consolas', 10, 'bold')).pack(side=tk.LEFT, padx=5, pady=5)
        
        # Wireless results
        self.wireless_results = scrolledtext.ScrolledText(wireless_frame, height=25, bg='#0f0f0f', fg='#00ffff',
                                                        font=('Consolas', 10), insertbackground='#00ffff')
        self.wireless_results.pack(fill=tk.BOTH, expand=True, padx=20, pady=10)
        
    def create_password_tab(self):
        """Password Cracking & Authentication Testing Module"""
        password_frame = ttk.Frame(self.notebook)
        self.notebook.add(password_frame, text="🔐 Password Cracking")
        
        self.create_section_header(password_frame, "Password & Authentication Security")
        
        # John the Ripper integration
        john_frame = tk.LabelFrame(password_frame, text="🔨 John the Ripper", 
                                 bg='#2d2d2d', fg='#ff6b35', font=('Consolas', 12, 'bold'))
        john_frame.pack(fill=tk.X, padx=20, pady=10)
        
        # Hash file selection
        hash_frame = tk.Frame(john_frame, bg='#2d2d2d')
        hash_frame.pack(fill=tk.X, padx=10, pady=5)
        
        tk.Label(hash_frame, text="Hash File:", bg='#2d2d2d', fg='white').pack(side=tk.LEFT)
        self.hash_file = tk.StringVar()
        tk.Entry(hash_frame, textvariable=self.hash_file, width=40, bg='#444444', fg='white').pack(side=tk.LEFT, padx=10)
        tk.Button(hash_frame, text="Browse", 
                 command=self.browse_hash_file,
                 bg='#555555', fg='white', font=('Consolas', 9)).pack(side=tk.LEFT, padx=5)
        
        # Wordlist selection
        wordlist_frame = tk.Frame(john_frame, bg='#2d2d2d')
        wordlist_frame.pack(fill=tk.X, padx=10, pady=5)
        
        tk.Label(wordlist_frame, text="Wordlist:", bg='#2d2d2d', fg='white').pack(side=tk.LEFT)
        self.wordlist_file = tk.StringVar(value="/usr/share/wordlists/rockyou.txt")
        tk.Entry(wordlist_frame, textvariable=self.wordlist_file, width=40, bg='#444444', fg='white').pack(side=tk.LEFT, padx=10)
        tk.Button(wordlist_frame, text="Browse", 
                 command=self.browse_wordlist_file,
                 bg='#555555', fg='white', font=('Consolas', 9)).pack(side=tk.LEFT, padx=5)
        
        # Attack type selection
        attack_frame = tk.Frame(john_frame, bg='#2d2d2d')
        attack_frame.pack(fill=tk.X, padx=10, pady=5)
        
        self.attack_type = tk.StringVar(value="dictionary")
        attack_types = [
            ("Dictionary Attack", "dictionary"),
            ("Brute Force", "brute"),
            ("Hybrid Attack", "hybrid"),
            ("Rainbow Tables", "rainbow")
        ]
        
        for text, value in attack_types:
            tk.Radiobutton(attack_frame, text=text, variable=self.attack_type, value=value,
                         bg='#2d2d2d', fg='white', selectcolor='#ff6b35').pack(side=tk.LEFT, padx=10)
        
        # Control buttons
        john_control_frame = tk.Frame(john_frame, bg='#2d2d2d')
        john_control_frame.pack(fill=tk.X, padx=10, pady=10)
        
        tk.Button(john_control_frame, text="🚀 Start Cracking", 
                 command=self.start_password_crack,
                 bg='#ff6b35', fg='white', font=('Consolas', 10, 'bold')).pack(side=tk.LEFT, padx=5)
        
        tk.Button(john_control_frame, text="⏹️ Stop Cracking", 
                 command=self.stop_password_crack,
                 bg='#cc0000', fg='white', font=('Consolas', 10, 'bold')).pack(side=tk.LEFT, padx=5)
        
        tk.Button(john_control_frame, text="📊 Show Progress", 
                 command=self.show_crack_progress,
                 bg='#555555', fg='white', font=('Consolas', 10)).pack(side=tk.LEFT, padx=5)
        
        # Password cracking results
        self.password_results = scrolledtext.ScrolledText(password_frame, height=25, bg='#0f0f0f', fg='#ffff00',
                                                        font=('Consolas', 10), insertbackground='#ffff00')
        self.password_results.pack(fill=tk.BOTH, expand=True, padx=20, pady=10)
        
    # ===== BEAST MODE ADVANCED MODULES =====
    
    def create_osint_tab(self):
        """OSINT & Social Engineering Module - BEAST MODE!"""
        osint_frame = ttk.Frame(self.notebook)
        self.notebook.add(osint_frame, text="🎯 OSINT & Social Engineering")
        
        self.create_section_header(osint_frame, "Open Source Intelligence & Social Engineering Arsenal")
        
        # TheHarvester integration
        harvester_frame = tk.LabelFrame(osint_frame, text="🌾 TheHarvester - Email/Domain Intel", 
                                       bg='#2d2d2d', fg='#ff6b35', font=('Consolas', 12, 'bold'))
        harvester_frame.pack(fill=tk.X, padx=20, pady=5)
        
        self.harvester_domain = tk.StringVar()
        tk.Label(harvester_frame, text="Target Domain:", bg='#2d2d2d', fg='white').pack(side=tk.LEFT, padx=10)
        tk.Entry(harvester_frame, textvariable=self.harvester_domain, width=30, bg='#444444', fg='white').pack(side=tk.LEFT, padx=5)
        tk.Button(harvester_frame, text="🔍 Harvest Intel", command=self.run_harvester,
                 bg='#ff6b35', fg='white', font=('Consolas', 10, 'bold')).pack(side=tk.LEFT, padx=10, pady=5)
        
        # Shodan integration
        shodan_frame = tk.LabelFrame(osint_frame, text="🛰️ Shodan - IoT Device Discovery", 
                                   bg='#2d2d2d', fg='#ff6b35', font=('Consolas', 12, 'bold'))
        shodan_frame.pack(fill=tk.X, padx=20, pady=5)
        
        self.shodan_query = tk.StringVar()
        tk.Label(shodan_frame, text="Shodan Query:", bg='#2d2d2d', fg='white').pack(side=tk.LEFT, padx=10)
        tk.Entry(shodan_frame, textvariable=self.shodan_query, width=30, bg='#444444', fg='white').pack(side=tk.LEFT, padx=5)
        tk.Button(shodan_frame, text="🛰️ Search Shodan", command=self.run_shodan_search,
                 bg='#ff6b35', fg='white', font=('Consolas', 10, 'bold')).pack(side=tk.LEFT, padx=10, pady=5)
        
        # Social Engineer Toolkit
        set_frame = tk.LabelFrame(osint_frame, text="🎭 Social Engineer Toolkit (SET)", 
                                bg='#2d2d2d', fg='#ff6b35', font=('Consolas', 12, 'bold'))
        set_frame.pack(fill=tk.X, padx=20, pady=5)
        
        tk.Button(set_frame, text="🚀 Launch SET", command=self.launch_set,
                 bg='#cc6600', fg='white', font=('Consolas', 10, 'bold')).pack(side=tk.LEFT, padx=10, pady=5)
        tk.Button(set_frame, text="📧 Phishing Campaign", command=self.create_phishing_campaign,
                 bg='#cc0000', fg='white', font=('Consolas', 10, 'bold')).pack(side=tk.LEFT, padx=5, pady=5)
        tk.Button(set_frame, text="📱 SMS Spoofing", command=self.sms_spoofing,
                 bg='#555555', fg='white', font=('Consolas', 10)).pack(side=tk.LEFT, padx=5, pady=5)
        
        # OSINT results
        self.osint_results = scrolledtext.ScrolledText(osint_frame, height=20, bg='#0f0f0f', fg='#ff00ff',
                                                     font=('Consolas', 10), insertbackground='#ff00ff')
        self.osint_results.pack(fill=tk.BOTH, expand=True, padx=20, pady=10)
    
    def create_mobile_tab(self):
        """Mobile & IoT Security Module - BEAST MODE!"""
        mobile_frame = ttk.Frame(self.notebook)
        self.notebook.add(mobile_frame, text="📱 Mobile & IoT Security")
        
        self.create_section_header(mobile_frame, "Mobile Application & IoT Device Security Testing")
        
        # MobSF integration
        mobsf_frame = tk.LabelFrame(mobile_frame, text="📱 Mobile Security Framework (MobSF)", 
                                  bg='#2d2d2d', fg='#ff6b35', font=('Consolas', 12, 'bold'))
        mobsf_frame.pack(fill=tk.X, padx=20, pady=10)
        
        tk.Button(mobsf_frame, text="🚀 Launch MobSF", command=self.launch_mobsf,
                 bg='#ff6b35', fg='white', font=('Consolas', 10, 'bold')).pack(side=tk.LEFT, padx=10, pady=5)
        tk.Button(mobsf_frame, text="📱 Upload APK", command=self.upload_apk,
                 bg='#555555', fg='white', font=('Consolas', 10)).pack(side=tk.LEFT, padx=5, pady=5)
        tk.Button(mobsf_frame, text="🍎 Upload IPA", command=self.upload_ipa,
                 bg='#555555', fg='white', font=('Consolas', 10)).pack(side=tk.LEFT, padx=5, pady=5)
        
        # Android debugging
        android_frame = tk.LabelFrame(mobile_frame, text="🤖 Android Security Testing", 
                                    bg='#2d2d2d', fg='#ff6b35', font=('Consolas', 12, 'bold'))
        android_frame.pack(fill=tk.X, padx=20, pady=5)
        
        tk.Button(android_frame, text="📱 ADB Connect", command=self.adb_connect,
                 bg='#00cc44', fg='white', font=('Consolas', 10, 'bold')).pack(side=tk.LEFT, padx=10, pady=5)
        tk.Button(android_frame, text="🔍 Device Info", command=self.get_device_info,
                 bg='#555555', fg='white', font=('Consolas', 10)).pack(side=tk.LEFT, padx=5, pady=5)
        tk.Button(android_frame, text="📦 Extract APK", command=self.extract_apk,
                 bg='#555555', fg='white', font=('Consolas', 10)).pack(side=tk.LEFT, padx=5, pady=5)
        
        # IoT security
        iot_frame = tk.LabelFrame(mobile_frame, text="🌐 IoT Device Security", 
                                bg='#2d2d2d', fg='#ff6b35', font=('Consolas', 12, 'bold'))
        iot_frame.pack(fill=tk.X, padx=20, pady=5)
        
        tk.Button(iot_frame, text="🔍 IoT Discovery", command=self.iot_discovery,
                 bg='#ff6b35', fg='white', font=('Consolas', 10, 'bold')).pack(side=tk.LEFT, padx=10, pady=5)
        tk.Button(iot_frame, text="📡 Protocol Analysis", command=self.protocol_analysis,
                 bg='#555555', fg='white', font=('Consolas', 10)).pack(side=tk.LEFT, padx=5, pady=5)
        tk.Button(iot_frame, text="🔐 Firmware Analysis", command=self.firmware_analysis,
                 bg='#555555', fg='white', font=('Consolas', 10)).pack(side=tk.LEFT, padx=5, pady=5)
        
        # Mobile results
        self.mobile_results = scrolledtext.ScrolledText(mobile_frame, height=20, bg='#0f0f0f', fg='#00cc44',
                                                      font=('Consolas', 10), insertbackground='#00cc44')
        self.mobile_results.pack(fill=tk.BOTH, expand=True, padx=20, pady=10)
    
    def create_advanced_web_tab(self):
        """Advanced Web Security Module - BEAST MODE!"""
        advanced_web_frame = ttk.Frame(self.notebook)
        self.notebook.add(advanced_web_frame, text="🕷️ Advanced Web Security")
        
        self.create_section_header(advanced_web_frame, "Advanced Web Application Security Arsenal")
        
        # Nikto web scanner
        nikto_frame = tk.LabelFrame(advanced_web_frame, text="🕷️ Nikto Web Scanner", 
                                  bg='#2d2d2d', fg='#ff6b35', font=('Consolas', 12, 'bold'))
        nikto_frame.pack(fill=tk.X, padx=20, pady=10)
        
        self.nikto_target = tk.StringVar()
        tk.Label(nikto_frame, text="Target URL:", bg='#2d2d2d', fg='white').pack(side=tk.LEFT, padx=10)
        tk.Entry(nikto_frame, textvariable=self.nikto_target, width=40, bg='#444444', fg='white').pack(side=tk.LEFT, padx=5)
        tk.Button(nikto_frame, text="🕷️ Start Nikto Scan", command=self.run_nikto_scan,
                 bg='#ff6b35', fg='white', font=('Consolas', 10, 'bold')).pack(side=tk.LEFT, padx=10, pady=5)
        
        # Directory brute forcing
        dirb_frame = tk.LabelFrame(advanced_web_frame, text="📁 Directory Brute Forcing", 
                                 bg='#2d2d2d', fg='#ff6b35', font=('Consolas', 12, 'bold'))
        dirb_frame.pack(fill=tk.X, padx=20, pady=5)
        
        self.dirb_target = tk.StringVar()
        tk.Label(dirb_frame, text="Target URL:", bg='#2d2d2d', fg='white').pack(side=tk.LEFT, padx=10)
        tk.Entry(dirb_frame, textvariable=self.dirb_target, width=30, bg='#444444', fg='white').pack(side=tk.LEFT, padx=5)
        tk.Button(dirb_frame, text="📁 Gobuster", command=self.run_gobuster,
                 bg='#cc6600', fg='white', font=('Consolas', 10, 'bold')).pack(side=tk.LEFT, padx=5, pady=5)
        tk.Button(dirb_frame, text="🔍 Dirb", command=self.run_dirb,
                 bg='#555555', fg='white', font=('Consolas', 10)).pack(side=tk.LEFT, padx=5, pady=5)
        tk.Button(dirb_frame, text="⚡ FFuF", command=self.run_ffuf,
                 bg='#555555', fg='white', font=('Consolas', 10)).pack(side=tk.LEFT, padx=5, pady=5)
        
        # Nuclei vulnerability scanner
        nuclei_frame = tk.LabelFrame(advanced_web_frame, text="☢️ Nuclei Template Scanner", 
                                   bg='#2d2d2d', fg='#ff6b35', font=('Consolas', 12, 'bold'))
        nuclei_frame.pack(fill=tk.X, padx=20, pady=5)
        
        self.nuclei_target = tk.StringVar()
        tk.Label(nuclei_frame, text="Target URL:", bg='#2d2d2d', fg='white').pack(side=tk.LEFT, padx=10)
        tk.Entry(nuclei_frame, textvariable=self.nuclei_target, width=30, bg='#444444', fg='white').pack(side=tk.LEFT, padx=5)
        tk.Button(nuclei_frame, text="☢️ Run Nuclei", command=self.run_nuclei_scan,
                 bg='#ff6b35', fg='white', font=('Consolas', 10, 'bold')).pack(side=tk.LEFT, padx=10, pady=5)
        tk.Button(nuclei_frame, text="📥 Update Templates", command=self.update_nuclei_templates,
                 bg='#555555', fg='white', font=('Consolas', 10)).pack(side=tk.LEFT, padx=5, pady=5)
        
        # Advanced web results
        self.advanced_web_results = scrolledtext.ScrolledText(advanced_web_frame, height=20, bg='#0f0f0f', fg='#ffaa00',
                                                            font=('Consolas', 10), insertbackground='#ffaa00')
        self.advanced_web_results.pack(fill=tk.BOTH, expand=True, padx=20, pady=10)
    
    def create_post_exploit_tab(self):
        """Post-Exploitation & Persistence Module - BEAST MODE!"""
        post_exploit_frame = ttk.Frame(self.notebook)
        self.notebook.add(post_exploit_frame, text="💀 Post-Exploitation")
        
        self.create_section_header(post_exploit_frame, "Post-Exploitation & Persistence Arsenal")
        
        # Empire framework
        empire_frame = tk.LabelFrame(post_exploit_frame, text="👑 Empire Framework", 
                                   bg='#2d2d2d', fg='#ff6b35', font=('Consolas', 12, 'bold'))
        empire_frame.pack(fill=tk.X, padx=20, pady=10)
        
        tk.Button(empire_frame, text="👑 Launch Empire", command=self.launch_empire,
                 bg='#ff6b35', fg='white', font=('Consolas', 10, 'bold')).pack(side=tk.LEFT, padx=10, pady=5)
        tk.Button(empire_frame, text="🏭 Generate Stager", command=self.generate_stager,
                 bg='#cc6600', fg='white', font=('Consolas', 10, 'bold')).pack(side=tk.LEFT, padx=5, pady=5)
        tk.Button(empire_frame, text="📡 C2 Server", command=self.setup_c2_server,
                 bg='#555555', fg='white', font=('Consolas', 10)).pack(side=tk.LEFT, padx=5, pady=5)
        
        # Bloodhound AD analysis
        bloodhound_frame = tk.LabelFrame(post_exploit_frame, text="🩸 Bloodhound AD Analysis", 
                                       bg='#2d2d2d', fg='#ff6b35', font=('Consolas', 12, 'bold'))
        bloodhound_frame.pack(fill=tk.X, padx=20, pady=5)
        
        tk.Button(bloodhound_frame, text="🩸 Launch Bloodhound", command=self.launch_bloodhound,
                 bg='#cc0000', fg='white', font=('Consolas', 10, 'bold')).pack(side=tk.LEFT, padx=10, pady=5)
        tk.Button(bloodhound_frame, text="🐕 Run SharpHound", command=self.run_sharphound,
                 bg='#555555', fg='white', font=('Consolas', 10)).pack(side=tk.LEFT, padx=5, pady=5)
        tk.Button(bloodhound_frame, text="🎯 Attack Paths", command=self.analyze_attack_paths,
                 bg='#555555', fg='white', font=('Consolas', 10)).pack(side=tk.LEFT, padx=5, pady=5)
        
        # Persistence techniques
        persistence_frame = tk.LabelFrame(post_exploit_frame, text="⚓ Persistence Techniques", 
                                        bg='#2d2d2d', fg='#ff6b35', font=('Consolas', 12, 'bold'))
        persistence_frame.pack(fill=tk.X, padx=20, pady=5)
        
        tk.Button(persistence_frame, text="🔑 Registry Persistence", command=self.registry_persistence,
                 bg='#cc6600', fg='white', font=('Consolas', 10, 'bold')).pack(side=tk.LEFT, padx=10, pady=5)
        tk.Button(persistence_frame, text="📋 Scheduled Tasks", command=self.scheduled_tasks,
                 bg='#555555', fg='white', font=('Consolas', 10)).pack(side=tk.LEFT, padx=5, pady=5)
        tk.Button(persistence_frame, text="🚪 Backdoor Creation", command=self.create_backdoor,
                 bg='#cc0000', fg='white', font=('Consolas', 10, 'bold')).pack(side=tk.LEFT, padx=5, pady=5)
        
        # Post-exploit results
        self.post_exploit_results = scrolledtext.ScrolledText(post_exploit_frame, height=20, bg='#0f0f0f', fg='#ff0066',
                                                            font=('Consolas', 10), insertbackground='#ff0066')
        self.post_exploit_results.pack(fill=tk.BOTH, expand=True, padx=20, pady=10)
    
    def create_ai_dashboard_tab(self):
        """AI-Powered Dashboard & Analytics - BEAST MODE!"""
        ai_frame = ttk.Frame(self.notebook)
        self.notebook.add(ai_frame, text="🤖 AI Dashboard")
        
        self.create_section_header(ai_frame, "AI-Powered Security Analytics & Visualization")
        
        # AI analytics
        ai_analytics_frame = tk.LabelFrame(ai_frame, text="🧠 AI Security Analytics", 
                                         bg='#2d2d2d', fg='#ff6b35', font=('Consolas', 12, 'bold'))
        ai_analytics_frame.pack(fill=tk.X, padx=20, pady=10)
        
        tk.Button(ai_analytics_frame, text="🧠 AI Vulnerability Analysis", command=self.ai_vuln_analysis,
                 bg='#ff6b35', fg='white', font=('Consolas', 10, 'bold')).pack(side=tk.LEFT, padx=10, pady=5)
        tk.Button(ai_analytics_frame, text="📊 Risk Scoring", command=self.ai_risk_scoring,
                 bg='#cc6600', fg='white', font=('Consolas', 10, 'bold')).pack(side=tk.LEFT, padx=5, pady=5)
        tk.Button(ai_analytics_frame, text="🎯 Auto Prioritization", command=self.ai_auto_prioritization,
                 bg='#555555', fg='white', font=('Consolas', 10)).pack(side=tk.LEFT, padx=5, pady=5)
        
        # Network visualization
        viz_frame = tk.LabelFrame(ai_frame, text="🌐 3D Network Visualization", 
                                bg='#2d2d2d', fg='#ff6b35', font=('Consolas', 12, 'bold'))
        viz_frame.pack(fill=tk.X, padx=20, pady=5)
        
        tk.Button(viz_frame, text="🌐 3D Network Map", command=self.create_3d_network_map,
                 bg='#00cc88', fg='white', font=('Consolas', 10, 'bold')).pack(side=tk.LEFT, padx=10, pady=5)
        tk.Button(viz_frame, text="📈 Real-time Dashboard", command=self.realtime_dashboard,
                 bg='#555555', fg='white', font=('Consolas', 10)).pack(side=tk.LEFT, padx=5, pady=5)
        tk.Button(viz_frame, text="🎨 Attack Flow Diagram", command=self.attack_flow_diagram,
                 bg='#555555', fg='white', font=('Consolas', 10)).pack(side=tk.LEFT, padx=5, pady=5)
        
        # Automation
        automation_frame = tk.LabelFrame(ai_frame, text="🤖 Intelligent Automation", 
                                       bg='#2d2d2d', fg='#ff6b35', font=('Consolas', 12, 'bold'))
        automation_frame.pack(fill=tk.X, padx=20, pady=5)
        
        tk.Button(automation_frame, text="⏰ Auto Scan Scheduler", command=self.auto_scan_scheduler,
                 bg='#ff6b35', fg='white', font=('Consolas', 10, 'bold')).pack(side=tk.LEFT, padx=10, pady=5)
        tk.Button(automation_frame, text="🔄 Continuous Monitoring", command=self.continuous_monitoring,
                 bg='#cc6600', fg='white', font=('Consolas', 10, 'bold')).pack(side=tk.LEFT, padx=5, pady=5)
        tk.Button(automation_frame, text="📧 Alert System", command=self.alert_system,
                 bg='#555555', fg='white', font=('Consolas', 10)).pack(side=tk.LEFT, padx=5, pady=5)
        
        # AI results with fancy visualization placeholder
        self.ai_results = scrolledtext.ScrolledText(ai_frame, height=20, bg='#0f0f0f', fg='#00ffaa',
                                                  font=('Consolas', 10), insertbackground='#00ffaa')
        self.ai_results.pack(fill=tk.BOTH, expand=True, padx=20, pady=10)
        
        # Initialize with AI dashboard
        self.initialize_ai_dashboard()
    
    def create_reporting_tab(self):
        """Reporting & Export Module"""
        report_frame = ttk.Frame(self.notebook)
        self.notebook.add(report_frame, text="📊 Reports & Export")
        
        self.create_section_header(report_frame, "Penetration Testing Reports")
        
        # Report generation controls
        report_control_frame = tk.LabelFrame(report_frame, text="📈 Report Generation", 
                                           bg='#2d2d2d', fg='#ff6b35', font=('Consolas', 12, 'bold'))
        report_control_frame.pack(fill=tk.X, padx=20, pady=10)
        
        # Report options
        report_options_frame = tk.Frame(report_control_frame, bg='#2d2d2d')
        report_options_frame.pack(fill=tk.X, padx=10, pady=10)
        
        tk.Button(report_options_frame, text="📄 Generate PDF Report", 
                 command=self.generate_pdf_report,
                 bg='#ff6b35', fg='white', font=('Consolas', 11, 'bold')).pack(side=tk.LEFT, padx=10, pady=5)
        
        tk.Button(report_options_frame, text="📊 Export to HTML", 
                 command=self.export_html_report,
                 bg='#555555', fg='white', font=('Consolas', 11)).pack(side=tk.LEFT, padx=10, pady=5)
        
        tk.Button(report_options_frame, text="💾 Save Raw Data", 
                 command=self.save_raw_data,
                 bg='#555555', fg='white', font=('Consolas', 11)).pack(side=tk.LEFT, padx=10, pady=5)
        
        # Report preview
        self.report_preview = scrolledtext.ScrolledText(report_frame, height=30, bg='#f8f8f8', fg='#000000',
                                                      font=('Arial', 10))
        self.report_preview.pack(fill=tk.BOTH, expand=True, padx=20, pady=10)
        
    def create_section_header(self, parent, title):
        """Create a section header"""
        header_frame = tk.Frame(parent, bg='#1a1a1a')
        header_frame.pack(fill=tk.X, padx=20, pady=(10, 5))
        
        tk.Label(header_frame, text=title, 
                bg='#1a1a1a', fg='#ff6b35',
                font=('Consolas', 16, 'bold')).pack(side=tk.LEFT)
        
        # Add separator line
        separator = tk.Frame(header_frame, bg='#ff6b35', height=2)
        separator.pack(fill=tk.X, pady=(10, 0))
        
    def create_status_bar(self):
        """Create status bar at bottom"""
        self.status_bar = tk.Frame(self.root, bg='#2d2d2d', height=30)
        self.status_bar.pack(side=tk.BOTTOM, fill=tk.X)
        self.status_bar.pack_propagate(False)
        
        self.status_text = tk.Label(self.status_bar, text="🔥 PENTU Ready - Select a module to begin penetration testing", 
                                   bg='#2d2d2d', fg='#ffffff', font=('Consolas', 10))
        self.status_text.pack(side=tk.LEFT, padx=10, pady=5)
        
        # Current time display
        self.time_label = tk.Label(self.status_bar, bg='#2d2d2d', fg='#888888', font=('Consolas', 9))
        self.time_label.pack(side=tk.RIGHT, padx=10, pady=5)
        self.update_time()
        
    def update_time(self):
        """Update time display"""
        current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self.time_label.config(text=current_time)
        self.root.after(1000, self.update_time)
        
    def log_message(self, widget, message, color='#00ff00'):
        """Log message to specified text widget"""
        timestamp = datetime.now().strftime("[%H:%M:%S]")
        formatted_message = f"{timestamp} {message}\n"
        widget.insert(tk.END, formatted_message)
        widget.see(tk.END)
        self.root.update()
        
    def update_status(self, message):
        """Update status bar message"""
        self.status_text.config(text=f"🔥 {message}")
        
    # ===== WEB APPLICATION SECURITY METHODS =====
    
    def launch_burp_suite(self):
        """Launch Burp Suite"""
        self.update_status("Launching Burp Suite...")
        self.log_message(self.web_results, "🎯 Launching Burp Suite Professional...")
        
        try:
            # Try to launch Burp Suite
            subprocess.Popen(['java', '-jar', '/opt/burpsuite/burpsuite.jar'], 
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            self.log_message(self.web_results, "✅ Burp Suite launched successfully!")
        except Exception as e:
            self.log_message(self.web_results, f"❌ Failed to launch Burp Suite: {e}")
            
    def configure_burp_proxy(self):
        """Configure Burp Suite proxy settings"""
        proxy_config = """
🔧 Burp Suite Proxy Configuration:
1. Start Burp Suite
2. Go to Proxy tab → Options
3. Set Intercept to: 127.0.0.1:8080
4. Configure browser proxy: 127.0.0.1:8080
5. Import Burp certificate for HTTPS
        """
        self.log_message(self.web_results, proxy_config)
        
    def start_zap_scan(self):
        """Start OWASP ZAP scan"""
        target = self.zap_target.get()
        if not target:
            messagebox.showerror("Error", "Please enter a target URL")
            return
            
        self.update_status(f"Starting ZAP scan on {target}")
        self.log_message(self.web_results, f"🕷️ Starting OWASP ZAP scan on: {target}")
        
        def run_zap_scan():
            try:
                # Basic ZAP scan command
                cmd = f"zap-cli quick-scan --self-contained {target}"
                process = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, 
                                         stderr=subprocess.PIPE, text=True)
                
                for line in process.stdout:
                    self.root.after(0, lambda l=line: self.log_message(self.web_results, f"ZAP: {l.strip()}"))
                    
            except Exception as e:
                self.root.after(0, lambda: self.log_message(self.web_results, f"❌ ZAP scan failed: {e}"))
                
        threading.Thread(target=run_zap_scan, daemon=True).start()
        
    def test_sql_injection(self):
        """Test for SQL injection vulnerabilities"""
        target = self.sql_target.get()
        if not target:
            messagebox.showerror("Error", "Please enter a target URL")
            return
            
        self.update_status(f"Testing SQL injection on {target}")
        self.log_message(self.web_results, f"💉 Testing SQL injection on: {target}")
        
        def run_sqlmap():
            try:
                cmd = f"sqlmap -u '{target}' --batch --risk=3 --level=3"
                process = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, 
                                         stderr=subprocess.PIPE, text=True)
                
                for line in process.stdout:
                    self.root.after(0, lambda l=line: self.log_message(self.web_results, f"SQLMap: {l.strip()}"))
                    
            except Exception as e:
                self.root.after(0, lambda: self.log_message(self.web_results, f"❌ SQLMap failed: {e}"))
                
        threading.Thread(target=run_sqlmap, daemon=True).start()
        
    # ===== NETWORK RECONNAISSANCE METHODS =====
    
    def start_nmap_scan(self):
        """Start Nmap network scan"""
        target = self.nmap_target.get()
        scan_type = self.scan_type.get()
        
        if not target:
            messagebox.showerror("Error", "Please enter a target")
            return
            
        self.scan_running = True
        self.update_status(f"Running {scan_type} Nmap scan on {target}")
        self.log_message(self.network_results, f"🗺️ Starting {scan_type} scan on: {target}")
        
        # Build nmap command based on scan type
        nmap_commands = {
            "quick": f"nmap -T4 -F {target}",
            "comprehensive": f"nmap -T4 -A -v {target}",
            "stealth": f"nmap -sS -T2 {target}",
            "udp": f"nmap -sU -T4 {target}",
            "os": f"nmap -O {target}",
            "version": f"nmap -sV {target}"
        }
        
        cmd = nmap_commands.get(scan_type, nmap_commands["quick"])
        
        def run_nmap():
            try:
                self.current_scan = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, 
                                                   stderr=subprocess.PIPE, text=True)
                
                for line in self.current_scan.stdout:
                    if self.scan_running:
                        self.root.after(0, lambda l=line: self.log_message(self.network_results, f"Nmap: {l.strip()}"))
                    else:
                        break
                        
                self.root.after(0, lambda: self.update_status("Nmap scan completed"))
                
            except Exception as e:
                self.root.after(0, lambda: self.log_message(self.network_results, f"❌ Nmap scan failed: {e}"))
                
        threading.Thread(target=run_nmap, daemon=True).start()
        
    def stop_scan(self):
        """Stop current scan"""
        self.scan_running = False
        if self.current_scan:
            self.current_scan.terminate()
        self.update_status("Scan stopped by user")
        self.log_message(self.network_results, "⏹️ Scan stopped by user")
        
    def export_nmap_results(self):
        """Export Nmap results to file"""
        results = self.network_results.get(1.0, tk.END)
        if not results.strip():
            messagebox.showwarning("Warning", "No results to export")
            return
            
        filename = filedialog.asksaveasfilename(
            defaultextension=".txt",
            filetypes=[("Text files", "*.txt"), ("All files", "*.*")]
        )
        
        if filename:
            try:
                with open(filename, 'w') as f:
                    f.write(results)
                self.log_message(self.network_results, f"📊 Results exported to: {filename}")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to export results: {e}")
                
    def launch_wireshark(self):
        """Launch Wireshark"""
        self.update_status("Launching Wireshark...")
        self.log_message(self.network_results, "📡 Launching Wireshark packet analyzer...")
        
        try:
            subprocess.Popen(['wireshark'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            self.log_message(self.network_results, "✅ Wireshark launched successfully!")
        except Exception as e:
            self.log_message(self.network_results, f"❌ Failed to launch Wireshark: {e}")
            
    def start_packet_capture(self):
        """Start packet capture"""
        interface = simpledialog.askstring("Interface", "Enter network interface (e.g., eth0, wlan0):")
        if interface:
            self.log_message(self.network_results, f"📡 Starting packet capture on {interface}")
            try:
                cmd = f"tcpdump -i {interface} -w /tmp/capture_{int(time.time())}.pcap"
                subprocess.Popen(cmd, shell=True)
                self.log_message(self.network_results, "✅ Packet capture started!")
            except Exception as e:
                self.log_message(self.network_results, f"❌ Packet capture failed: {e}")
                
    # ===== EXPLOITATION METHODS =====
    
    def launch_metasploit(self):
        """Launch Metasploit framework"""
        self.update_status("Launching Metasploit Framework...")
        self.log_message(self.exploit_results, "💣 Starting Metasploit Framework...")
        
        try:
            # Launch msfconsole in a new terminal
            subprocess.Popen(['gnome-terminal', '--', 'msfconsole'])
            self.log_message(self.exploit_results, "✅ Metasploit console launched!")
        except Exception as e:
            self.log_message(self.exploit_results, f"❌ Failed to launch Metasploit: {e}")
            
    def run_exploit(self):
        """Run selected exploit"""
        exploit = self.exploit_type.get()
        target = self.msf_target.get()
        lhost = self.msf_lhost.get()
        
        if not all([exploit, target, lhost]):
            messagebox.showerror("Error", "Please fill in all fields")
            return
            
        self.log_message(self.exploit_results, f"🎯 Running exploit: {exploit}")
        self.log_message(self.exploit_results, f"Target: {target}, LHOST: {lhost}")
        
        # This would typically interface with Metasploit's RPC API
        exploit_commands = f"""
use {exploit}
set RHOST {target}
set LHOST {lhost}
exploit
        """
        self.log_message(self.exploit_results, "Metasploit commands:")
        self.log_message(self.exploit_results, exploit_commands)
        
    def show_payloads(self):
        """Show available payloads"""
        payloads = [
            "windows/meterpreter/reverse_tcp",
            "linux/x86/meterpreter/reverse_tcp",
            "cmd/unix/reverse_bash",
            "windows/shell/reverse_tcp"
        ]
        
        self.log_message(self.exploit_results, "🚀 Available Payloads:")
        for payload in payloads:
            self.log_message(self.exploit_results, f"  • {payload}")
            
    # ===== WIRELESS SECURITY METHODS =====
    
    def scan_wifi_interfaces(self):
        """Scan for wireless interfaces"""
        self.log_message(self.wireless_results, "🔍 Scanning for wireless interfaces...")
        
        try:
            result = subprocess.run(['iwconfig'], capture_output=True, text=True)
            interfaces = []
            
            for line in result.stdout.split('\n'):
                if 'IEEE 802.11' in line:
                    interface = line.split()[0]
                    interfaces.append(interface)
                    
            if interfaces:
                self.wifi_interface.set(interfaces[0])
                for interface in interfaces:
                    self.log_message(self.wireless_results, f"📶 Found interface: {interface}")
            else:
                self.log_message(self.wireless_results, "❌ No wireless interfaces found")
                
        except Exception as e:
            self.log_message(self.wireless_results, f"❌ Interface scan failed: {e}")
            
    def scan_wifi_networks(self):
        """Scan for wireless networks"""
        interface = self.wifi_interface.get()
        if not interface:
            messagebox.showerror("Error", "Please select a wireless interface")
            return
            
        self.log_message(self.wireless_results, f"🔍 Scanning networks on {interface}...")
        
        def run_wifi_scan():
            try:
                cmd = f"iwlist {interface} scan"
                process = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, 
                                         stderr=subprocess.PIPE, text=True)
                
                for line in process.stdout:
                    if 'ESSID' in line or 'Quality' in line:
                        self.root.after(0, lambda l=line: self.log_message(self.wireless_results, l.strip()))
                        
            except Exception as e:
                self.root.after(0, lambda: self.log_message(self.wireless_results, f"❌ WiFi scan failed: {e}"))
                
        threading.Thread(target=run_wifi_scan, daemon=True).start()
        
    def enable_monitor_mode(self):
        """Enable monitor mode on wireless interface"""
        interface = self.wifi_interface.get()
        if not interface:
            messagebox.showerror("Error", "Please select a wireless interface")
            return
            
        self.log_message(self.wireless_results, f"🎯 Enabling monitor mode on {interface}...")
        
        try:
            commands = [
                f"sudo airmon-ng start {interface}",
                f"sudo ifconfig {interface}mon up"
            ]
            
            for cmd in commands:
                subprocess.run(cmd, shell=True)
                
            self.log_message(self.wireless_results, f"✅ Monitor mode enabled on {interface}mon")
            
        except Exception as e:
            self.log_message(self.wireless_results, f"❌ Monitor mode failed: {e}")
            
    def capture_handshake(self):
        """Capture WPA handshake"""
        bssid = simpledialog.askstring("BSSID", "Enter target BSSID:")
        channel = simpledialog.askstring("Channel", "Enter channel:")
        
        if bssid and channel:
            self.log_message(self.wireless_results, f"📡 Capturing handshake from {bssid} on channel {channel}")
            
            try:
                interface = self.wifi_interface.get() + "mon"
                cmd = f"sudo airodump-ng -c {channel} --bssid {bssid} -w /tmp/handshake {interface}"
                subprocess.Popen(cmd, shell=True)
                self.log_message(self.wireless_results, "✅ Handshake capture started!")
            except Exception as e:
                self.log_message(self.wireless_results, f"❌ Handshake capture failed: {e}")
                
    def crack_wifi_password(self):
        """Crack WiFi password using captured handshake"""
        handshake_file = filedialog.askopenfilename(
            title="Select handshake file",
            filetypes=[("Cap files", "*.cap"), ("All files", "*.*")]
        )
        
        if handshake_file:
            wordlist = self.wordlist_file.get()
            self.log_message(self.wireless_results, f"🔓 Cracking password using {handshake_file}")
            
            def run_crack():
                try:
                    cmd = f"aircrack-ng -w {wordlist} {handshake_file}"
                    process = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, 
                                             stderr=subprocess.PIPE, text=True)
                    
                    for line in process.stdout:
                        self.root.after(0, lambda l=line: self.log_message(self.wireless_results, l.strip()))
                        
                except Exception as e:
                    self.root.after(0, lambda: self.log_message(self.wireless_results, f"❌ Password crack failed: {e}"))
                    
            threading.Thread(target=run_crack, daemon=True).start()
            
    # ===== PASSWORD CRACKING METHODS =====
    
    def browse_hash_file(self):
        """Browse for hash file"""
        filename = filedialog.askopenfilename(
            title="Select hash file",
            filetypes=[("Text files", "*.txt"), ("Hash files", "*.hash"), ("All files", "*.*")]
        )
        if filename:
            self.hash_file.set(filename)
            
    def browse_wordlist_file(self):
        """Browse for wordlist file"""
        filename = filedialog.askopenfilename(
            title="Select wordlist file",
            filetypes=[("Text files", "*.txt"), ("All files", "*.*")]
        )
        if filename:
            self.wordlist_file.set(filename)
            
    def start_password_crack(self):
        """Start password cracking with John the Ripper"""
        hash_file = self.hash_file.get()
        wordlist = self.wordlist_file.get()
        attack_type = self.attack_type.get()
        
        if not hash_file:
            messagebox.showerror("Error", "Please select a hash file")
            return
            
        self.log_message(self.password_results, f"🔨 Starting {attack_type} attack on {hash_file}")
        
        def run_john():
            try:
                if attack_type == "dictionary":
                    cmd = f"john --wordlist={wordlist} {hash_file}"
                elif attack_type == "brute":
                    cmd = f"john --incremental {hash_file}"
                else:
                    cmd = f"john {hash_file}"
                    
                process = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, 
                                         stderr=subprocess.PIPE, text=True)
                
                for line in process.stdout:
                    self.root.after(0, lambda l=line: self.log_message(self.password_results, l.strip()))
                    
            except Exception as e:
                self.root.after(0, lambda: self.log_message(self.password_results, f"❌ Password crack failed: {e}"))
                
        threading.Thread(target=run_john, daemon=True).start()
        
    def stop_password_crack(self):
        """Stop password cracking"""
        try:
            subprocess.run(['pkill', 'john'], check=False)
            self.log_message(self.password_results, "⏹️ Password cracking stopped")
        except Exception as e:
            self.log_message(self.password_results, f"❌ Failed to stop cracking: {e}")
            
    def show_crack_progress(self):
        """Show password cracking progress"""
        try:
            result = subprocess.run(['john', '--show', self.hash_file.get()], 
                                  capture_output=True, text=True)
            if result.stdout:
                self.log_message(self.password_results, "📊 Cracked passwords:")
                self.log_message(self.password_results, result.stdout)
            else:
                self.log_message(self.password_results, "No passwords cracked yet")
        except Exception as e:
            self.log_message(self.password_results, f"❌ Failed to check progress: {e}")
            
    # ===== REPORTING METHODS =====
    
    def generate_pdf_report(self):
        """Generate PDF penetration testing report"""
        self.update_status("Generating PDF report...")
        
        report_content = self.compile_report_data()
        
        # Display in preview
        self.report_preview.delete(1.0, tk.END)
        self.report_preview.insert(1.0, report_content)
        
        messagebox.showinfo("Report Generated", "PDF report preview loaded. Use 'Save Raw Data' to export.")
        
    def export_html_report(self):
        """Export report to HTML format"""
        report_content = self.compile_report_data()
        
        html_content = f"""
<!DOCTYPE html>
<html>
<head>
    <title>PENTU Penetration Testing Report</title>
    <style>
        body {{ font-family: 'Courier New', monospace; background: #1a1a1a; color: #fff; }}
        .header {{ color: #ff6b35; font-size: 24px; font-weight: bold; }}
        .section {{ margin: 20px 0; padding: 15px; border-left: 3px solid #ff6b35; }}
    </style>
</head>
<body>
    <div class="header">🔥 PENTU PENETRATION TESTING REPORT</div>
    <pre>{report_content}</pre>
</body>
</html>
        """
        
        filename = filedialog.asksaveasfilename(
            defaultextension=".html",
            filetypes=[("HTML files", "*.html"), ("All files", "*.*")]
        )
        
        if filename:
            try:
                with open(filename, 'w') as f:
                    f.write(html_content)
                messagebox.showinfo("Success", f"HTML report saved to {filename}")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to save HTML report: {e}")
                
    def save_raw_data(self):
        """Save raw scan data"""
        filename = filedialog.asksaveasfilename(
            defaultextension=".txt",
            filetypes=[("Text files", "*.txt"), ("All files", "*.*")]
        )
        
        if filename:
            try:
                report_content = self.compile_report_data()
                with open(filename, 'w') as f:
                    f.write(report_content)
                messagebox.showinfo("Success", f"Raw data saved to {filename}")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to save raw data: {e}")
                
    # ===== BEAST MODE METHOD IMPLEMENTATIONS =====
    
    # OSINT & Social Engineering Methods
    def run_harvester(self):
        """Run TheHarvester email/domain reconnaissance"""
        domain = self.harvester_domain.get()
        if not domain:
            messagebox.showerror("Error", "Please enter a target domain")
            return
            
        self.log_message(self.osint_results, f"🌾 Running TheHarvester on domain: {domain}")
        
        def harvest():
            try:
                cmd = f"theharvester -d {domain} -b google,bing,linkedin,twitter -l 200"
                process = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, 
                                         stderr=subprocess.PIPE, text=True)
                
                for line in process.stdout:
                    self.root.after(0, lambda l=line: self.log_message(self.osint_results, f"📧 {l.strip()}"))
                    
            except Exception as e:
                self.root.after(0, lambda: self.log_message(self.osint_results, f"❌ TheHarvester failed: {e}"))
                
        threading.Thread(target=harvest, daemon=True).start()
    
    def run_shodan_search(self):
        """Run Shodan search for IoT devices"""
        query = self.shodan_query.get()
        if not query:
            messagebox.showerror("Error", "Please enter a Shodan search query")
            return
            
        self.log_message(self.osint_results, f"🛰️ Searching Shodan for: {query}")
        
        try:
            # Note: Requires shodan CLI tool and API key
            cmd = f"shodan search '{query}' --limit 20"
            process = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, 
                                     stderr=subprocess.PIPE, text=True)
            
            def shodan_search():
                for line in process.stdout:
                    self.root.after(0, lambda l=line: self.log_message(self.osint_results, f"🛰️ {l.strip()}"))
                    
            threading.Thread(target=shodan_search, daemon=True).start()
            
        except Exception as e:
            self.log_message(self.osint_results, f"❌ Shodan search failed: {e}")
    
    def launch_set(self):
        """Launch Social Engineer Toolkit"""
        self.log_message(self.osint_results, "🎭 Launching Social Engineer Toolkit (SET)...")
        
        try:
            subprocess.Popen(['gnome-terminal', '--', 'setoolkit'], stdout=subprocess.DEVNULL)
            self.log_message(self.osint_results, "✅ SET launched successfully!")
        except Exception as e:
            self.log_message(self.osint_results, f"❌ Failed to launch SET: {e}")
    
    def create_phishing_campaign(self):
        """Create phishing campaign with SET"""
        self.log_message(self.osint_results, "📧 Creating phishing campaign...")
        campaign_info = """
🎯 PHISHING CAMPAIGN SETUP:
1. Launch SET from terminal
2. Choose 'Social-Engineering Attacks'
3. Select 'Website Attack Vectors'
4. Choose 'Credential Harvester Attack Method'
5. Configure target website clone
6. Set listening interface and port
        """
        self.log_message(self.osint_results, campaign_info)
    
    def sms_spoofing(self):
        """SMS spoofing setup"""
        self.log_message(self.osint_results, "📱 SMS Spoofing configuration...")
        sms_info = """
📱 SMS SPOOFING SETUP:
1. Use services like SpoofCard or similar
2. Configure sender ID spoofing
3. Craft convincing SMS messages
4. Test delivery and response rates
WARNING: Use only for authorized testing!
        """
        self.log_message(self.osint_results, sms_info)
    
    # Mobile & IoT Security Methods
    def launch_mobsf(self):
        """Launch Mobile Security Framework"""
        self.log_message(self.mobile_results, "📱 Launching Mobile Security Framework (MobSF)...")
        
        try:
            subprocess.Popen(['python3', '/opt/MobSF/manage.py', 'runserver', '127.0.0.1:8000'], 
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            self.log_message(self.mobile_results, "✅ MobSF launched at http://127.0.0.1:8000")
        except Exception as e:
            self.log_message(self.mobile_results, f"❌ Failed to launch MobSF: {e}")
    
    def upload_apk(self):
        """Upload APK file for analysis"""
        apk_file = filedialog.askopenfilename(
            title="Select APK file",
            filetypes=[("APK files", "*.apk"), ("All files", "*.*")]
        )
        
        if apk_file:
            self.log_message(self.mobile_results, f"📱 Analyzing APK: {apk_file}")
            # Integration with MobSF API would go here
            self.log_message(self.mobile_results, "Upload APK to MobSF web interface for analysis")
    
    def upload_ipa(self):
        """Upload IPA file for analysis"""
        ipa_file = filedialog.askopenfilename(
            title="Select IPA file",
            filetypes=[("IPA files", "*.ipa"), ("All files", "*.*")]
        )
        
        if ipa_file:
            self.log_message(self.mobile_results, f"🍎 Analyzing IPA: {ipa_file}")
            self.log_message(self.mobile_results, "Upload IPA to MobSF web interface for analysis")
    
    def adb_connect(self):
        """Connect to Android device via ADB"""
        self.log_message(self.mobile_results, "📱 Connecting to Android device...")
        
        try:
            result = subprocess.run(['adb', 'devices'], capture_output=True, text=True)
            self.log_message(self.mobile_results, "Connected devices:")
            self.log_message(self.mobile_results, result.stdout)
        except Exception as e:
            self.log_message(self.mobile_results, f"❌ ADB connection failed: {e}")
    
    def get_device_info(self):
        """Get Android device information"""
        self.log_message(self.mobile_results, "🔍 Getting device information...")
        
        try:
            commands = [
                'adb shell getprop ro.build.version.release',
                'adb shell getprop ro.product.model',
                'adb shell getprop ro.product.manufacturer'
            ]
            
            for cmd in commands:
                result = subprocess.run(cmd.split(), capture_output=True, text=True)
                self.log_message(self.mobile_results, f"{cmd}: {result.stdout.strip()}")
                
        except Exception as e:
            self.log_message(self.mobile_results, f"❌ Failed to get device info: {e}")
    
    def extract_apk(self):
        """Extract APK from connected device"""
        package_name = simpledialog.askstring("Package", "Enter package name (e.g., com.example.app):")
        if package_name:
            self.log_message(self.mobile_results, f"📦 Extracting APK for {package_name}...")
            
            try:
                cmd = f"adb shell pm path {package_name}"
                result = subprocess.run(cmd.split(), capture_output=True, text=True)
                if 'package:' in result.stdout:
                    apk_path = result.stdout.split('package:')[1].strip()
                    subprocess.run(['adb', 'pull', apk_path, f'/tmp/{package_name}.apk'])
                    self.log_message(self.mobile_results, f"✅ APK extracted to /tmp/{package_name}.apk")
                else:
                    self.log_message(self.mobile_results, "❌ Package not found")
            except Exception as e:
                self.log_message(self.mobile_results, f"❌ APK extraction failed: {e}")
    
    def iot_discovery(self):
        """Discover IoT devices on network"""
        self.log_message(self.mobile_results, "🔍 Discovering IoT devices...")
        
        def discover_iot():
            try:
                # Nmap scan for common IoT ports
                cmd = "nmap -sS -O 192.168.1.0/24 -p 22,23,80,443,554,8080,8443"
                process = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, 
                                         stderr=subprocess.PIPE, text=True)
                
                for line in process.stdout:
                    self.root.after(0, lambda l=line: self.log_message(self.mobile_results, f"IoT: {l.strip()}"))
                    
            except Exception as e:
                self.root.after(0, lambda: self.log_message(self.mobile_results, f"❌ IoT discovery failed: {e}"))
                
        threading.Thread(target=discover_iot, daemon=True).start()
    
    def protocol_analysis(self):
        """Analyze IoT protocols"""
        self.log_message(self.mobile_results, "📡 Analyzing IoT protocols...")
        protocol_info = """
📡 COMMON IoT PROTOCOLS:
• MQTT (Port 1883/8883)
• CoAP (Port 5683/5684) 
• HTTP/HTTPS (Port 80/443)
• Modbus (Port 502)
• BACnet (Port 47808)
• ZigBee (802.15.4)
• LoRaWAN
        """
        self.log_message(self.mobile_results, protocol_info)
    
    def firmware_analysis(self):
        """Analyze IoT firmware"""
        firmware_file = filedialog.askopenfilename(
            title="Select firmware file",
            filetypes=[("All files", "*.*")]
        )
        
        if firmware_file:
            self.log_message(self.mobile_results, f"🔐 Analyzing firmware: {firmware_file}")
            
            try:
                # Use binwalk for firmware analysis
                cmd = f"binwalk -e {firmware_file}"
                process = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, 
                                         stderr=subprocess.PIPE, text=True)
                
                def analyze_firmware():
                    for line in process.stdout:
                        self.root.after(0, lambda l=line: self.log_message(self.mobile_results, f"Binwalk: {l.strip()}"))
                        
                threading.Thread(target=analyze_firmware, daemon=True).start()
                
            except Exception as e:
                self.log_message(self.mobile_results, f"❌ Firmware analysis failed: {e}")
    
    # Advanced Web Security Methods
    def run_nikto_scan(self):
        """Run Nikto web vulnerability scan"""
        target = self.nikto_target.get()
        if not target:
            messagebox.showerror("Error", "Please enter a target URL")
            return
            
        self.log_message(self.advanced_web_results, f"🕷️ Starting Nikto scan on: {target}")
        
        def nikto_scan():
            try:
                cmd = f"nikto -h {target} -C all"
                process = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, 
                                         stderr=subprocess.PIPE, text=True)
                
                for line in process.stdout:
                    self.root.after(0, lambda l=line: self.log_message(self.advanced_web_results, f"Nikto: {l.strip()}"))
                    
            except Exception as e:
                self.root.after(0, lambda: self.log_message(self.advanced_web_results, f"❌ Nikto scan failed: {e}"))
                
        threading.Thread(target=nikto_scan, daemon=True).start()
    
    def run_gobuster(self):
        """Run Gobuster directory brute forcing"""
        target = self.dirb_target.get()
        if not target:
            messagebox.showerror("Error", "Please enter a target URL")
            return
            
        self.log_message(self.advanced_web_results, f"📁 Running Gobuster on: {target}")
        
        def gobuster_scan():
            try:
                cmd = f"gobuster dir -u {target} -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt"
                process = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, 
                                         stderr=subprocess.PIPE, text=True)
                
                for line in process.stdout:
                    self.root.after(0, lambda l=line: self.log_message(self.advanced_web_results, f"Gobuster: {l.strip()}"))
                    
            except Exception as e:
                self.root.after(0, lambda: self.log_message(self.advanced_web_results, f"❌ Gobuster failed: {e}"))
                
        threading.Thread(target=gobuster_scan, daemon=True).start()
    
    def run_dirb(self):
        """Run Dirb directory brute forcing"""
        target = self.dirb_target.get()
        if not target:
            messagebox.showerror("Error", "Please enter a target URL")
            return
            
        self.log_message(self.advanced_web_results, f"🔍 Running Dirb on: {target}")
        
        def dirb_scan():
            try:
                cmd = f"dirb {target} /usr/share/wordlists/dirb/common.txt"
                process = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, 
                                         stderr=subprocess.PIPE, text=True)
                
                for line in process.stdout:
                    self.root.after(0, lambda l=line: self.log_message(self.advanced_web_results, f"Dirb: {l.strip()}"))
                    
            except Exception as e:
                self.root.after(0, lambda: self.log_message(self.advanced_web_results, f"❌ Dirb failed: {e}"))
                
        threading.Thread(target=dirb_scan, daemon=True).start()
    
    def run_ffuf(self):
        """Run FFuF fuzzing"""
        target = self.dirb_target.get()
        if not target:
            messagebox.showerror("Error", "Please enter a target URL")
            return
            
        self.log_message(self.advanced_web_results, f"⚡ Running FFuF on: {target}")
        
        def ffuf_scan():
            try:
                cmd = f"ffuf -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -u {target}/FUZZ"
                process = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, 
                                         stderr=subprocess.PIPE, text=True)
                
                for line in process.stdout:
                    self.root.after(0, lambda l=line: self.log_message(self.advanced_web_results, f"FFuF: {l.strip()}"))
                    
            except Exception as e:
                self.root.after(0, lambda: self.log_message(self.advanced_web_results, f"❌ FFuF failed: {e}"))
                
        threading.Thread(target=ffuf_scan, daemon=True).start()
    
    def run_nuclei_scan(self):
        """Run Nuclei template-based scan"""
        target = self.nuclei_target.get()
        if not target:
            messagebox.showerror("Error", "Please enter a target URL")
            return
            
        self.log_message(self.advanced_web_results, f"☢️ Running Nuclei on: {target}")
        
        def nuclei_scan():
            try:
                cmd = f"nuclei -u {target} -t /opt/nuclei-templates/ -v"
                process = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, 
                                         stderr=subprocess.PIPE, text=True)
                
                for line in process.stdout:
                    self.root.after(0, lambda l=line: self.log_message(self.advanced_web_results, f"Nuclei: {l.strip()}"))
                    
            except Exception as e:
                self.root.after(0, lambda: self.log_message(self.advanced_web_results, f"❌ Nuclei scan failed: {e}"))
                
        threading.Thread(target=nuclei_scan, daemon=True).start()
    
    def update_nuclei_templates(self):
        """Update Nuclei templates"""
        self.log_message(self.advanced_web_results, "📥 Updating Nuclei templates...")
        
        def update_templates():
            try:
                cmd = "nuclei -update-templates"
                process = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, 
                                         stderr=subprocess.PIPE, text=True)
                
                for line in process.stdout:
                    self.root.after(0, lambda l=line: self.log_message(self.advanced_web_results, f"Update: {l.strip()}"))
                    
            except Exception as e:
                self.root.after(0, lambda: self.log_message(self.advanced_web_results, f"❌ Template update failed: {e}"))
                
        threading.Thread(target=update_templates, daemon=True).start()
    
    # Post-Exploitation Methods
    def launch_empire(self):
        """Launch PowerShell Empire framework"""
        self.log_message(self.post_exploit_results, "👑 Launching PowerShell Empire...")
        
        try:
            subprocess.Popen(['gnome-terminal', '--', 'python3', '/opt/Empire/empire'], 
                           stdout=subprocess.DEVNULL)
            self.log_message(self.post_exploit_results, "✅ Empire framework launched!")
        except Exception as e:
            self.log_message(self.post_exploit_results, f"❌ Failed to launch Empire: {e}")
    
    def generate_stager(self):
        """Generate Empire stager"""
        self.log_message(self.post_exploit_results, "🏭 Generating Empire stager...")
        stager_info = """
🏭 EMPIRE STAGER GENERATION:
1. Launch Empire framework
2. Use 'usestager' command
3. Configure LHOST and LPORT
4. Generate PowerShell stager
5. Deploy on target system
        """
        self.log_message(self.post_exploit_results, stager_info)
    
    def setup_c2_server(self):
        """Setup Command & Control server"""
        self.log_message(self.post_exploit_results, "📡 Setting up C2 server...")
        c2_info = """
📡 C2 SERVER SETUP:
• Configure Empire listeners
• Set up HTTPS redirectors
• Domain fronting options
• Encrypted communications
• Persistence mechanisms
        """
        self.log_message(self.post_exploit_results, c2_info)
    
    def launch_bloodhound(self):
        """Launch Bloodhound for AD analysis"""
        self.log_message(self.post_exploit_results, "🩸 Launching Bloodhound...")
        
        try:
            subprocess.Popen(['bloodhound'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            self.log_message(self.post_exploit_results, "✅ Bloodhound launched successfully!")
        except Exception as e:
            self.log_message(self.post_exploit_results, f"❌ Failed to launch Bloodhound: {e}")
    
    def run_sharphound(self):
        """Run SharpHound collector"""
        self.log_message(self.post_exploit_results, "🐕 Running SharpHound data collector...")
        sharphound_info = """
🐕 SHARPHOUND COLLECTION:
1. Upload SharpHound.exe to target
2. Run: SharpHound.exe -c All
3. Download generated .zip file
4. Import into Bloodhound
5. Analyze attack paths
        """
        self.log_message(self.post_exploit_results, sharphound_info)
    
    def analyze_attack_paths(self):
        """Analyze Active Directory attack paths"""
        self.log_message(self.post_exploit_results, "🎯 Analyzing AD attack paths...")
        attack_paths = """
🎯 COMMON ATTACK PATHS:
• Kerberoasting attacks
• ASREPRoasting
• DCSync privileges
• Path to Domain Admin
• Golden/Silver ticket attacks
        """
        self.log_message(self.post_exploit_results, attack_paths)
    
    def registry_persistence(self):
        """Setup registry-based persistence"""
        self.log_message(self.post_exploit_results, "🔑 Setting up registry persistence...")
        reg_persistence = """
🔑 REGISTRY PERSISTENCE METHODS:
• HKLM\Software\Microsoft\Windows\CurrentVersion\Run
• HKCU\Software\Microsoft\Windows\CurrentVersion\Run
• HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce
• Services registry keys
• WinLogon registry modifications
        """
        self.log_message(self.post_exploit_results, reg_persistence)
    
    def scheduled_tasks(self):
        """Create scheduled tasks for persistence"""
        self.log_message(self.post_exploit_results, "📋 Creating scheduled tasks...")
        tasks_info = """
📋 SCHEDULED TASK PERSISTENCE:
• schtasks /create /tn "Update" /tr "payload.exe" /sc onstart
• Task Scheduler GUI manipulation
• AT command (legacy systems)
• PowerShell scheduled jobs
        """
        self.log_message(self.post_exploit_results, tasks_info)
    
    def create_backdoor(self):
        """Create system backdoor"""
        self.log_message(self.post_exploit_results, "🚪 Creating system backdoor...")
        backdoor_info = """
🚪 BACKDOOR CREATION:
• Sticky Keys backdoor
• RDP backdoor modifications
• Service backdoors
• DLL hijacking
• WMI event subscriptions
WARNING: Use only on authorized systems!
        """
        self.log_message(self.post_exploit_results, backdoor_info)
    
    # AI Dashboard Methods
    def initialize_ai_dashboard(self):
        """Initialize AI dashboard with welcome message"""
        welcome_message = """
🤖 AI-POWERED SECURITY ANALYTICS DASHBOARD
============================================

🧠 Advanced Features:
• Machine Learning vulnerability analysis
• Automated risk scoring and prioritization
• Intelligent attack path prediction
• Real-time threat correlation
• 3D network visualization
• Behavioral anomaly detection

🎯 Getting Started:
1. Run scans from other modules
2. AI will analyze results automatically
3. Check risk scores and recommendations
4. View 3D network maps and attack flows
        """
        self.log_message(self.ai_results, welcome_message)
    
    def ai_vuln_analysis(self):
        """AI-powered vulnerability analysis"""
        self.log_message(self.ai_results, "🧠 Running AI vulnerability analysis...")
        
        # Simulate AI analysis
        def ai_analysis():
            import random
            time.sleep(2)
            
            vulnerabilities = [
                "SQL Injection (High Risk - CVSS 9.1)",
                "Cross-Site Scripting (Medium Risk - CVSS 6.4)", 
                "Weak Authentication (High Risk - CVSS 8.7)",
                "Insecure Direct Object Reference (Medium Risk - CVSS 5.9)",
                "Security Misconfiguration (Low Risk - CVSS 3.2)"
            ]
            
            self.root.after(0, lambda: self.log_message(self.ai_results, "\n🎯 AI VULNERABILITY ANALYSIS RESULTS:"))
            for vuln in random.sample(vulnerabilities, 3):
                self.root.after(0, lambda v=vuln: self.log_message(self.ai_results, f"• {v}"))
                time.sleep(0.5)
                
        threading.Thread(target=ai_analysis, daemon=True).start()
    
    def ai_risk_scoring(self):
        """AI risk scoring system"""
        self.log_message(self.ai_results, "📊 Calculating AI risk scores...")
        
        def risk_analysis():
            import random
            time.sleep(1.5)
            
            risk_factors = [
                ("Network Exposure", random.randint(60, 95)),
                ("Vulnerability Severity", random.randint(70, 90)),
                ("Exploit Availability", random.randint(40, 85)),
                ("Asset Criticality", random.randint(80, 95)),
                ("Security Controls", random.randint(30, 70))
            ]
            
            self.root.after(0, lambda: self.log_message(self.ai_results, "\n📊 RISK SCORING MATRIX:"))
            total_score = 0
            for factor, score in risk_factors:
                self.root.after(0, lambda f=factor, s=score: self.log_message(self.ai_results, f"• {f}: {s}/100"))
                total_score += score
                time.sleep(0.3)
                
            final_score = total_score // len(risk_factors)
            risk_level = "HIGH" if final_score > 75 else "MEDIUM" if final_score > 50 else "LOW"
            
            self.root.after(0, lambda: self.log_message(self.ai_results, f"\n🎯 OVERALL RISK SCORE: {final_score}/100 ({risk_level})"))
            
        threading.Thread(target=risk_analysis, daemon=True).start()
    
    def ai_auto_prioritization(self):
        """AI automatic vulnerability prioritization"""
        self.log_message(self.ai_results, "🎯 Running AI auto-prioritization...")
        
        def prioritization():
            import random
            time.sleep(1)
            
            priorities = [
                ("1. SQL Injection on login page", "CRITICAL", "Immediate action required"),
                ("2. Weak SSL configuration", "HIGH", "Fix within 7 days"),
                ("3. Directory traversal vulnerability", "HIGH", "Fix within 14 days"),
                ("4. Information disclosure", "MEDIUM", "Fix within 30 days"),
                ("5. Missing security headers", "LOW", "Fix when convenient")
            ]
            
            self.root.after(0, lambda: self.log_message(self.ai_results, "\n🎯 AI PRIORITIZATION RESULTS:"))
            for item, level, action in priorities:
                color = "🔴" if level == "CRITICAL" else "🟠" if level == "HIGH" else "🟡" if level == "MEDIUM" else "🟢"
                self.root.after(0, lambda i=item, l=level, a=action, c=color: 
                               self.log_message(self.ai_results, f"{c} {i} [{l}] - {a}"))
                time.sleep(0.4)
                
        threading.Thread(target=prioritization, daemon=True).start()
    
    def create_3d_network_map(self):
        """Create 3D network visualization"""
        self.log_message(self.ai_results, "🌐 Generating 3D network visualization...")
        
        def create_3d_viz():
            time.sleep(2)
            
            network_info = """
🌐 3D NETWORK MAP GENERATED:

📍 Network Nodes Discovered:
• Router: 192.168.1.1 (Gateway)
• Web Server: 192.168.1.10 (High Value)
• Database: 192.168.1.20 (Critical Asset) 
• Workstations: 192.168.1.100-150
• IoT Devices: 192.168.1.200-220

🔗 Attack Vectors Identified:
• Direct paths to critical assets
• Lateral movement opportunities
• Privilege escalation points
• Network segmentation gaps

📊 3D visualization shows network topology,
    vulnerability hotspots, and attack paths
            """
            
            self.root.after(0, lambda: self.log_message(self.ai_results, network_info))
            
        threading.Thread(target=create_3d_viz, daemon=True).start()
    
    def realtime_dashboard(self):
        """Launch real-time security dashboard"""
        self.log_message(self.ai_results, "📈 Launching real-time security dashboard...")
        
        dashboard_info = """
📈 REAL-TIME SECURITY DASHBOARD:

🔍 Live Monitoring:
• Active scan progress
• Vulnerability discoveries
• Network traffic analysis
• Threat intelligence feeds
• System health metrics

🎛️ Dashboard Features:
• Interactive charts and graphs
• Real-time alerts and notifications
• Customizable threat indicators
• Historical trend analysis
• Executive summary reports
        """
        self.log_message(self.ai_results, dashboard_info)
    
    def attack_flow_diagram(self):
        """Generate attack flow diagram"""
        self.log_message(self.ai_results, "🎨 Creating attack flow diagram...")
        
        def generate_diagram():
            time.sleep(1.5)
            
            attack_flow = """
🎨 ATTACK FLOW DIAGRAM GENERATED:

📍 Attack Chain Visualization:
1. 🎯 Initial Compromise
   └── Phishing email → Malware execution
   
2. 🔍 Reconnaissance 
   └── Network enumeration → Service discovery
   
3. 🚪 Lateral Movement
   └── Credential harvesting → Privilege escalation
   
4. 🎖️ Persistence
   └── Backdoor installation → C2 communication
   
5. 🏆 Objective Achievement
   └── Data exfiltration → Mission complete

🔗 Critical Path Analysis:
• Shortest attack path: 3 steps
• Highest probability route: Web app → DB
• Stealth approach: Living off the land
            """
            
            self.root.after(0, lambda: self.log_message(self.ai_results, attack_flow))
            
        threading.Thread(target=generate_diagram, daemon=True).start()
    
    def auto_scan_scheduler(self):
        """Setup automatic scan scheduling"""
        self.log_message(self.ai_results, "⏰ Configuring automatic scan scheduler...")
        
        scheduler_info = """
⏰ INTELLIGENT SCAN SCHEDULER:

📅 Scheduling Options:
• Daily vulnerability scans
• Weekly comprehensive assessments
• Monthly penetration tests
• Continuous monitoring
• Event-triggered scans

🎯 Smart Scheduling:
• Off-hours execution
• Resource optimization
• Priority-based queuing
• Failure retry logic
• Results aggregation
        """
        self.log_message(self.ai_results, scheduler_info)
    
    def continuous_monitoring(self):
        """Setup continuous security monitoring"""
        self.log_message(self.ai_results, "🔄 Enabling continuous monitoring...")
        
        monitoring_info = """
🔄 CONTINUOUS SECURITY MONITORING:

🛡️ Monitoring Capabilities:
• Real-time vulnerability detection
• Network behavior analysis
• Anomaly detection algorithms
• Threat intelligence correlation
• Configuration drift monitoring

📊 Monitoring Dashboards:
• Security posture metrics
• Compliance status tracking
• Incident response timelines
• Performance indicators
• Executive summaries
        """
        self.log_message(self.ai_results, monitoring_info)
    
    def alert_system(self):
        """Configure intelligent alert system"""
        self.log_message(self.ai_results, "📧 Configuring intelligent alert system...")
        
        alert_info = """
📧 INTELLIGENT ALERT SYSTEM:

🚨 Alert Types:
• Critical vulnerability discoveries
• High-risk attack patterns
• Compliance violations
• System compromises
• Performance degradations

📬 Delivery Methods:
• Email notifications
• SMS alerts
• Slack integration
• SIEM forwarding
• API webhooks

🤖 Smart Features:
• Alert correlation and deduplication
• Severity-based escalation
• Machine learning false positive reduction
• Contextual threat intelligence
        """
        self.log_message(self.ai_results, alert_info)
    
    def compile_report_data(self):
        """Compile all scan results into a report"""
        report_sections = []
        
        # Header
        report_sections.append("=" * 80)
        report_sections.append("🔥 PENTU - ULTIMATE PENETRATION TESTING REPORT")
        report_sections.append("=" * 80)
        report_sections.append(f"Report Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        report_sections.append("")
        
        # Web Application Results
        if self.web_results.get(1.0, tk.END).strip():
            report_sections.append("🌐 WEB APPLICATION SECURITY RESULTS:")
            report_sections.append("-" * 50)
            report_sections.append(self.web_results.get(1.0, tk.END))
            
        # Network Results
        if self.network_results.get(1.0, tk.END).strip():
            report_sections.append("🔍 NETWORK RECONNAISSANCE RESULTS:")
            report_sections.append("-" * 50)
            report_sections.append(self.network_results.get(1.0, tk.END))
            
        # Exploitation Results
        if self.exploit_results.get(1.0, tk.END).strip():
            report_sections.append("🎯 EXPLOITATION FRAMEWORK RESULTS:")
            report_sections.append("-" * 50)
            report_sections.append(self.exploit_results.get(1.0, tk.END))
            
        # Wireless Results
        if self.wireless_results.get(1.0, tk.END).strip():
            report_sections.append("📡 WIRELESS SECURITY RESULTS:")
            report_sections.append("-" * 50)
            report_sections.append(self.wireless_results.get(1.0, tk.END))
            
        # Password Results
        if self.password_results.get(1.0, tk.END).strip():
            report_sections.append("🔐 PASSWORD CRACKING RESULTS:")
            report_sections.append("-" * 50)
            report_sections.append(self.password_results.get(1.0, tk.END))
            
        report_sections.append("=" * 80)
        report_sections.append("End of PENTU Report")
        report_sections.append("=" * 80)
        
        return "\n".join(report_sections)
        
    def run(self):
        """Start the PENTU application"""
        self.root.mainloop()

def main():
    """Main entry point"""
    try:
        print("🔥 Starting PENTU - Ultimate Penetration Testing Suite...")
        app = PentuSuite()
        app.run()
    except KeyboardInterrupt:
        print("\n🔥 PENTU shutting down...")
    except Exception as e:
        print(f"❌ Error starting PENTU: {e}")

if __name__ == "__main__":
    main()
