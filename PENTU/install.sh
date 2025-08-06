#!/bin/bash
# PENTU Installation Script
# ==========================

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# ASCII Art Banner
echo -e "${RED}"
cat << "EOF"
    ____  ______ _   __ ______ __  __
   / __ \/ ____// | / //_  __// / / /
  / /_/ / __/  /  |/ /  / /  / / / / 
 / ____/ /___ / /|  /  / /  / /_/ /  
/_/   /_____//_/ |_/  /_/   \____/   
                                     
🔥 PENETRATION TESTING ARSENAL 🔥
EOF
echo -e "${NC}"

echo -e "${CYAN}========================================${NC}"
echo -e "${YELLOW}Starting PENTU Installation...${NC}"
echo -e "${CYAN}========================================${NC}\n"

# Check if running as root
if [[ $EUID -eq 0 ]]; then
   echo -e "${RED}❌ This script should NOT be run as root${NC}"
   echo -e "${YELLOW}Please run as regular user. Sudo will be used when needed.${NC}"
   exit 1
fi

# Check OS compatibility
echo -e "${BLUE}🔍 Checking system compatibility...${NC}"
if [[ "$OSTYPE" != "linux-gnu"* ]]; then
    echo -e "${RED}❌ This installer is designed for Linux systems${NC}"
    exit 1
fi

# Check if Kali Linux
if grep -q "kali" /etc/os-release 2>/dev/null; then
    echo -e "${GREEN}✅ Kali Linux detected - optimal compatibility${NC}"
    KALI_LINUX=true
else
    echo -e "${YELLOW}⚠️  Non-Kali system detected - some tools may need manual installation${NC}"
    KALI_LINUX=false
fi

# Check Python version
echo -e "${BLUE}🐍 Checking Python installation...${NC}"
if command -v python3 &> /dev/null; then
    PYTHON_VERSION=$(python3 --version | cut -d " " -f 2)
    echo -e "${GREEN}✅ Python ${PYTHON_VERSION} found${NC}"
else
    echo -e "${RED}❌ Python 3 not found. Please install Python 3.8+${NC}"
    exit 1
fi

# Update system packages
echo -e "${BLUE}📦 Updating system packages...${NC}"
sudo apt update -qq

# Install system dependencies
echo -e "${BLUE}🔧 Installing system dependencies...${NC}"
sudo apt install -y python3 python3-pip python3-tkinter git curl wget

# Install Python dependencies
echo -e "${BLUE}🐍 Installing Python dependencies...${NC}"
pip3 install -r requirements.txt --user

# Make pentu.py executable
echo -e "${BLUE}🔧 Making PENTU executable...${NC}"
chmod +x pentu.py

# Create desktop shortcut
echo -e "${BLUE}🖥️  Creating desktop shortcut...${NC}"
DESKTOP_FILE="$HOME/Desktop/PENTU.desktop"
CURRENT_DIR=$(pwd)

cat > "$DESKTOP_FILE" << EOF
[Desktop Entry]
Version=2.0
Type=Application
Name=PENTU
Comment=Penetration Testing Arsenal
Exec=python3 "$CURRENT_DIR/pentu.py"
Icon=$CURRENT_DIR/assets/pentu-icon.png
Path=$CURRENT_DIR
Terminal=false
StartupWMClass=PENTU
Categories=Security;Network;
Keywords=pentest;security;hacking;kali;
EOF

chmod +x "$DESKTOP_FILE"

# Create menu entry
echo -e "${BLUE}📋 Creating application menu entry...${NC}"
mkdir -p "$HOME/.local/share/applications"
cp "$DESKTOP_FILE" "$HOME/.local/share/applications/"

# Create assets directory and icon
echo -e "${BLUE}🎨 Setting up assets...${NC}"
mkdir -p assets

# Create a simple icon (text-based for now)
cat > assets/pentu-icon.png << 'EOF'
# This would be a proper PNG icon file
# For now, we'll create a placeholder
EOF

# Tool availability check
echo -e "${BLUE}🔍 Checking penetration testing tools...${NC}"

declare -A tools=(
    ["nmap"]="Network scanner"
    ["wireshark"]="Packet analyzer"
    ["aircrack-ng"]="Wireless security"
    ["john"]="Password cracking"
    ["sqlmap"]="SQL injection testing"
    ["nikto"]="Web vulnerability scanner"
    ["gobuster"]="Directory brute forcing"
    ["dirb"]="Web content scanner"
    ["theharvester"]="OSINT gathering"
    ["metasploit-framework"]="Exploitation framework"
)

missing_tools=()

for tool in "${!tools[@]}"; do
    if command -v "$tool" &> /dev/null || dpkg -l | grep -q "$tool" 2>/dev/null; then
        echo -e "${GREEN}✅ $tool - ${tools[$tool]}${NC}"
    else
        echo -e "${RED}❌ $tool - ${tools[$tool]} (missing)${NC}"
        missing_tools+=("$tool")
    fi
done

# Install missing tools on Kali
if [[ ${#missing_tools[@]} -gt 0 ]] && [[ "$KALI_LINUX" == true ]]; then
    echo -e "\n${YELLOW}🔧 Installing missing tools on Kali Linux...${NC}"
    for tool in "${missing_tools[@]}"; do
        echo -e "${BLUE}Installing $tool...${NC}"
        sudo apt install -y "$tool" 2>/dev/null || echo -e "${YELLOW}⚠️  Could not auto-install $tool${NC}"
    done
fi

# Create sample configuration
echo -e "${BLUE}⚙️  Creating configuration files...${NC}"
mkdir -p config
cat > config/pentu.conf << EOF
# PENTU Configuration
[DEFAULT]
theme = dark
auto_update = true
log_level = INFO
max_threads = 10

[TOOLS]
nmap_path = /usr/bin/nmap
burp_jar = /opt/burpsuite/burpsuite.jar
metasploit_path = /usr/bin/msfconsole

[REPORTING]
output_dir = ./reports
template_dir = ./templates
auto_generate = false
EOF

# Set up logging directory
echo -e "${BLUE}📝 Setting up logging...${NC}"
mkdir -p logs
touch logs/pentu.log

# Create documentation structure
echo -e "${BLUE}📚 Setting up documentation...${NC}"
mkdir -p docs
cat > docs/QUICK_START.md << 'EOF'
# PENTU Quick Start Guide

## First Run
1. Launch PENTU: `python3 pentu.py`
2. Select a module from the tabs
3. Configure target parameters
4. Run your first scan

## Basic Workflow
1. **Reconnaissance** - Use Network tab for initial discovery
2. **Enumeration** - Use Web App tab for service enumeration
3. **Exploitation** - Use Exploitation tab for attack vectors
4. **Post-Exploitation** - Use Post-Exploit tab for persistence
5. **Reporting** - Generate professional reports

## Tips
- Always get proper authorization before testing
- Start with passive reconnaissance
- Use the AI Dashboard for intelligent analysis
- Export results regularly
EOF

# Final checks and summary
echo -e "\n${CYAN}========================================${NC}"
echo -e "${GREEN}🎉 PENTU Installation Complete!${NC}"
echo -e "${CYAN}========================================${NC}\n"

echo -e "${PURPLE}📊 Installation Summary:${NC}"
echo -e "✅ PENTU installed to: ${CURRENT_DIR}"
echo -e "✅ Desktop shortcut created"
echo -e "✅ Application menu entry added"
echo -e "✅ Python dependencies installed"
echo -e "✅ Configuration files created"

echo -e "\n${YELLOW}🚀 Quick Start:${NC}"
echo -e "1. Double-click desktop icon, or"
echo -e "2. Run: ${GREEN}python3 pentu.py${NC}"
echo -e "3. Check docs/QUICK_START.md for usage guide"

if [[ ${#missing_tools[@]} -gt 0 ]] && [[ "$KALI_LINUX" != true ]]; then
    echo -e "\n${YELLOW}⚠️  Missing Tools (install manually):${NC}"
    for tool in "${missing_tools[@]}"; do
        echo -e "   - $tool"
    done
fi

echo -e "\n${RED}⚠️  IMPORTANT REMINDER:${NC}"
echo -e "${RED}Only use PENTU for authorized security testing!${NC}"
echo -e "${RED}You are responsible for compliance with all applicable laws.${NC}"

echo -e "\n${GREEN}Happy Hacking! 🔥${NC}"
