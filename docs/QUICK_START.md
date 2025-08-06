# 🚀 PENTU BEAST MODE - Quick Start Guide

Welcome to the ultimate penetration testing arsenal! This guide will get you up and running with PENTU in minutes.

## 📋 Pre-requisites

### System Requirements
- **OS**: Kali Linux (recommended) / Ubuntu 18.04+ / Debian 10+
- **Python**: 3.8 or higher
- **RAM**: 4GB minimum, 8GB recommended
- **Storage**: 2GB free space

### Quick Check
```bash
python3 --version  # Should be 3.8+
which nmap         # Should find nmap
which python3-tk   # GUI toolkit
```

## ⚡ 5-Minute Setup

### 1. Installation
```bash
# Clone or extract PENTU BEAST MODE
cd PENTU-BEAST-MODE

# Run the installer (handles everything automatically)
./install.sh

# OR manual installation:
pip3 install -r requirements.txt
chmod +x pentu.py
```

### 2. First Launch
```bash
# Launch PENTU
python3 pentu.py

# OR double-click the desktop icon
```

### 3. Quick Test
1. Click on **Network Reconnaissance** tab
2. Enter `127.0.0.1` as target
3. Select **Quick Scan**
4. Click **🚀 Start Nmap Scan**
5. Watch the results appear in real-time!

## 🎯 Basic Workflow

### Phase 1: Reconnaissance
**Tab**: 🔍 Network Reconnaissance
```
1. Enter target IP/range (e.g., 192.168.1.0/24)
2. Choose scan type (Quick for beginners)
3. Start scan and analyze open ports
4. Export results for documentation
```

### Phase 2: Web Application Testing
**Tab**: 🌐 Web Application Security
```
1. Enter target URL (e.g., http://example.com)
2. Run OWASP ZAP scan for vulnerabilities
3. Test for SQL injection with SQLMap
4. Launch Burp Suite for manual testing
```

### Phase 3: Advanced Analysis
**Tab**: 🤖 AI Dashboard
```
1. Let AI analyze your scan results
2. Get intelligent risk scoring
3. View 3D network visualization
4. Get prioritized vulnerability list
```

### Phase 4: Reporting
**Tab**: 📊 Reports & Export
```
1. Generate professional PDF report
2. Export to HTML for sharing
3. Save raw data for further analysis
```

## 🛠 Tool Overview

### Core Tools (Tab by Tab)

#### 🌐 Web Application Security
- **Burp Suite**: Professional web security testing
- **OWASP ZAP**: Automated web vulnerability scanning
- **SQLMap**: SQL injection detection and exploitation

#### 🔍 Network Reconnaissance  
- **Nmap**: Network discovery and port scanning
- **Wireshark**: Network traffic analysis
- **Masscan**: High-speed port scanner

#### 🎯 Exploitation Framework
- **Metasploit**: Penetration testing and exploitation
- **Custom Payloads**: Generate and deploy exploits

#### 📡 Wireless Security
- **Aircrack-ng**: WiFi security auditing
- **Monitor Mode**: Wireless packet capture
- **WPA/WPA2 Cracking**: Password recovery

#### 🔐 Password Cracking
- **John the Ripper**: Password hash cracking
- **Multiple Attack Types**: Dictionary, brute force, hybrid
- **Custom Wordlists**: Use your own password lists

#### 🎯 OSINT & Social Engineering
- **TheHarvester**: Email and domain intelligence
- **Shodan**: IoT device discovery
- **Social Engineer Toolkit**: Phishing campaigns

#### 📱 Mobile & IoT Security
- **MobSF**: Mobile app security analysis
- **ADB Integration**: Android device testing
- **IoT Discovery**: Network device enumeration

#### 🕷️ Advanced Web Security
- **Nikto**: Web server vulnerability scanner
- **Directory Brute Forcing**: Gobuster, Dirb, FFuF
- **Nuclei**: Template-based vulnerability detection

#### 💀 Post-Exploitation
- **Empire Framework**: PowerShell post-exploitation
- **Bloodhound**: Active Directory analysis
- **Persistence**: Maintain system access

#### 🤖 AI Dashboard
- **Vulnerability Analysis**: ML-powered threat assessment
- **Risk Scoring**: Intelligent prioritization
- **3D Visualization**: Network topology mapping

## 🔥 Pro Tips

### For Beginners
1. **Start with Network Recon** - always begin with port scanning
2. **Use Quick Scans** - get familiar with the interface first
3. **Read the Results** - understand what each tool tells you
4. **Export Everything** - keep records of all your findings

### For Advanced Users
1. **Combine Tools** - use results from one tool to inform another
2. **Custom Wordlists** - create targeted password lists
3. **AI Analysis** - let machine learning guide your testing
4. **Automation** - set up scheduled scans for continuous monitoring

### Legal and Ethical
⚠️ **CRITICAL**: Only test systems you own or have explicit permission to test!

```
✅ DO:
- Test your own lab environments
- Get written authorization before testing
- Follow responsible disclosure practices
- Use for educational purposes

❌ DON'T:
- Test systems without permission
- Use for malicious purposes
- Ignore local laws and regulations
- Share sensitive findings publicly
```

## 🐛 Common Issues

### "Tool not found" errors
```bash
# Install missing tools on Kali Linux
sudo apt update
sudo apt install nmap metasploit-framework burpsuite

# Check tool paths
which nmap
which msfconsole
```

### GUI not loading
```bash
# Install GUI dependencies
sudo apt install python3-tk

# Check display
echo $DISPLAY  # Should show :0 or similar
```

### Permission errors
```bash
# Some tools need root privileges
sudo python3 pentu.py  # For root-required tools

# Or run specific commands with sudo as needed
```

## 📚 Learning Resources

### Getting Started
- [Penetration Testing Basics](docs/pentest_basics.md)
- [Tool Configuration Guide](docs/tool_config.md)  
- [Sample Targets for Practice](docs/practice_targets.md)

### Advanced Topics
- [Custom Tool Integration](docs/custom_tools.md)
- [AI Feature Deep Dive](docs/ai_features.md)
- [Enterprise Deployment](docs/enterprise.md)

### Video Tutorials
- YouTube: PENTU BEAST MODE Walkthrough
- Udemy: Complete Penetration Testing with PENTU
- Cybrary: Advanced PENTU Techniques

## 🆘 Getting Help

### Documentation
- 📖 [Full Documentation](docs/)
- 🎥 [Video Tutorials](https://youtube.com/pentu-tutorials)
- 📝 [FAQ](docs/FAQ.md)

### Community Support
- 💬 [Discord Server](https://discord.gg/pentu)
- 🐛 [GitHub Issues](https://github.com/your-username/PENTU-BEAST-MODE/issues)
- 📧 [Email Support](mailto:support@pentu.dev)

### Professional Training
- 🎓 [PENTU Certification Program](https://pentu.dev/training)
- 🏢 [Corporate Training](https://pentu.dev/enterprise)
- 👥 [Private Workshops](https://pentu.dev/workshops)

---

## 🚀 Ready to Dominate?

You're now ready to unleash the full power of PENTU BEAST MODE! Remember:

1. **Practice Safely** - use lab environments first
2. **Learn Continuously** - security is always evolving  
3. **Share Knowledge** - help the community grow
4. **Stay Ethical** - with great power comes great responsibility

**Happy Hacking!** 🔥

---

*Need more help? Check out our [full documentation](docs/) or join our [Discord community](https://discord.gg/pentu)*
