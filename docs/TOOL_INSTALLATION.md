# Tool Installation Guide

This guide provides comprehensive instructions for installing all external security tools required by the Security Reconnaissance Platform.

## Table of Contents

1. [Quick Start](#quick-start)
2. [System Requirements](#system-requirements)
3. [Automated Installation](#automated-installation)
4. [Manual Installation](#manual-installation)
5. [Platform-Specific Instructions](#platform-specific-instructions)
6. [Troubleshooting](#troubleshooting)
7. [Tool Reference](#tool-reference)

---

## Quick Start

### Automated Installation (Recommended)

```bash
# Check current tool status
python main.py --check-tools

# Install all tools automatically
python main.py --install-tools

# Download required resources (wordlists, resolvers)
python main.py --download-resources

# Verify installation
python main.py --tool-status
```

### Using Installation Scripts

**Linux/macOS:**
```bash
chmod +x install.sh
./install.sh
```

**Windows (PowerShell):**
```powershell
.\install.ps1
```

---

## System Requirements

### Required Tools

| Tool | Version | Purpose | Installation Link |
|------|---------|---------|-------------------|
| **Python** | 3.9+ | Core platform runtime | [python.org](https://www.python.org/downloads/) |
| **Go** | 1.19+ | Building Go-based tools | [golang.org](https://golang.org/dl/) |
| **Git** | 2.x+ | Cloning tool repositories | [git-scm.com](https://git-scm.com/downloads) |

### Optional Tools (for building from source)

| Tool | Purpose | Linux | macOS | Windows |
|------|---------|-------|-------|---------|
| **GCC/Make** | Compiling C programs | `build-essential` | Xcode Command Line Tools | MinGW or Visual Studio |
| **C Compiler** | Building MassDNS | apt/yum | clang | MSVC |
| **libpcap-dev** | Packet capture (for naabu) | `libpcap-dev` (Debian) or `libpcap-devel` (RHEL) | Included with Xcode | WinPcap or Npcap |

### Disk Space

- **Minimum:** 500 MB for all tools
- **Recommended:** 1 GB (includes tools, wordlists, and build artifacts)

### Network

- Internet connection required for:
  - Downloading Go packages
  - Cloning Git repositories
  - Downloading wordlists and resolvers

---

## Automated Installation

The platform provides an automated installation system that handles all tool setup.

### Step 1: Activate Virtual Environment

```bash
# Linux/macOS
source recon_env/bin/activate

# Windows
recon_env\Scripts\activate
```

### Step 2: Run Installation

```bash
# Install all tools at once
python main.py --install-tools

# Or install components separately
python main.py --install-tool subfinder    # Install specific tool
python main.py --download-resources        # Download wordlists
```

### Step 3: Verify Installation

```bash
python main.py --tool-status
```

### What Gets Installed

The automated installer will:

1. ✅ Check system requirements (Go, Git, Python)
2. ✅ Install 15+ Go-based security tools
3. ✅ Clone and build Git-based tools (MassDNS, PureDNS)
4. ✅ Clone Python-based tools
5. ✅ Download DNS wordlists (~2-5 MB)
6. ✅ Download DNS resolver lists
7. ✅ Verify all installations

---

## Manual Installation

If automated installation fails or you prefer manual control, follow these steps.

### 1. Install System Dependencies

#### Ubuntu/Debian

```bash
# Install Go
wget https://go.dev/dl/go1.21.0.linux-amd64.tar.gz
sudo rm -rf /usr/local/go
sudo tar -C /usr/local -xzf go1.21.0.linux-amd64.tar.gz
export PATH=$PATH:/usr/local/go/bin
export GOPATH=$HOME/go
export PATH=$PATH:$GOPATH/bin

# Install build tools
sudo apt update
sudo apt install -y git build-essential python3 python3-pip
```

#### macOS

```bash
# Install Homebrew (if not installed)
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"

# Install dependencies
brew install go git python3
```

#### Windows

1. Install Go: [Download from golang.org](https://golang.org/dl/)
2. Install Git: [Download from git-scm.com](https://git-scm.com/download/win)
3. Install Python: [Download from python.org](https://www.python.org/downloads/)
4. Add to PATH: `C:\Go\bin` and `%USERPROFILE%\go\bin`

### 2. Install Go Tools

```bash
# Project Discovery Tools (Essential)
go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install github.com/projectdiscovery/httpx/cmd/httpx@latest
go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest
go install github.com/projectdiscovery/naabu/v2/cmd/naabu@latest
go install github.com/projectdiscovery/mapcidr/cmd/mapcidr@latest

# Community Tools
go install github.com/tomnomnom/assetfinder@latest
go install github.com/lc/gau/v2/cmd/gau@latest
go install github.com/tomnomnom/waybackurls@latest
go install github.com/Josue87/gotator@latest
go install github.com/jaeles-project/gospider@latest
go install github.com/OJ/gobuster/v3@latest
go install github.com/tomnomnom/unfurl@latest
go install github.com/tomnomnom/anew@latest

# GitHub/GitLab Tools
go install github.com/gwen001/github-subdomains@latest
go install github.com/gwen001/gitlab-subdomains@latest
```

### 3. Install Git-Based Tools

```bash
cd tools/

# MassDNS (DNS resolver)
git clone https://github.com/blechschmidt/massdns.git
cd massdns && make
cd ..

# PureDNS (DNS bruteforcer)
git clone https://github.com/d3mondev/puredns
cd puredns && go install
cd ..
```

### 4. Install Python Tools

```bash
cd tools/

# Fav-up (Favicon hash tool)
git clone https://github.com/pielco11/fav-up.git
cd fav-up && pip install -r requirements.txt
cd ..

# CTF-FR (Certificate Transparency)
git clone https://github.com/UnaPibaGeek/ctfr.git
cd ctfr && pip install -r requirements.txt
cd ..

# SecretFinder (Find secrets in JavaScript)
git clone https://github.com/m4ll0k/SecretFinder.git
cd SecretFinder && pip install -r requirements.txt
cd ..

# HostHunter (VHOST discovery)
git clone https://github.com/SpiderLabs/HostHunter.git
cd HostHunter && pip install -r requirements.txt
cd ..
```

### 5. Download Resources

```bash
cd tools/

# DNS wordlist (huge subdomain list)
curl -o n0kovo_subdomains_huge.txt \
  https://raw.githubusercontent.com/n0kovo/n0kovo_subdomains/main/n0kovo_subdomains_huge.txt

# DNS resolvers (trusted resolver list)
curl -o resolvers.txt \
  https://raw.githubusercontent.com/trickest/resolvers/main/resolvers.txt

cd ..
```

### 6. Verify Installation

```bash
# Check each tool
subfinder -version
httpx -version
naabu -version
dnsx -version
mapcidr -version

# Check resources
ls -lh tools/n0kovo_subdomains_huge.txt
ls -lh tools/resolvers.txt

# Use platform's verification
python main.py --tool-status
```

---

## Platform-Specific Instructions

### Linux

#### Debian/Ubuntu

```bash
# 1. Install system dependencies
sudo apt update
sudo apt install -y wget git build-essential python3 python3-pip python3-venv

# 2. Install Go
wget https://go.dev/dl/go1.21.0.linux-amd64.tar.gz
sudo tar -C /usr/local -xzf go1.21.0.linux-amd64.tar.gz

# 3. Configure environment
echo 'export PATH=$PATH:/usr/local/go/bin' >> ~/.bashrc
echo 'export GOPATH=$HOME/go' >> ~/.bashrc
echo 'export PATH=$PATH:$GOPATH/bin' >> ~/.bashrc
source ~/.bashrc

# 4. Run automated installer
python3 main.py --install-tools
```

#### CentOS/RHEL/Fedora

```bash
# 1. Install system dependencies
sudo yum groupinstall -y "Development Tools"
sudo yum install -y wget git python3 python3-pip libpcap-devel

# 2. Install Go (same as above)
# 3. Configure environment (same as above)
# 4. Run automated installer
```

#### Arch Linux

```bash
# 1. Install dependencies
sudo pacman -S go git base-devel python python-pip

# 2. Run automated installer
python main.py --install-tools
```

### macOS

```bash
# 1. Install Homebrew
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"

# 2. Install dependencies
brew install go git python@3.11

# 3. Run automated installer
python3 main.py --install-tools
```

### Windows

#### Using PowerShell (Recommended)

```powershell
# 1. Install Chocolatey (package manager)
Set-ExecutionPolicy Bypass -Scope Process -Force
[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072
iex ((New-Object System.Net.WebClient).DownloadString('https://community.chocolatey.org/install.ps1'))

# 2. Install dependencies
choco install -y golang git python

# 3. Refresh environment
refreshenv

# 4. Run automated installer
python main.py --install-tools
```

#### Manual Windows Installation

1. **Install Go:**
   - Download: https://go.dev/dl/go1.21.0.windows-amd64.msi
   - Run installer, use default settings
   - Verify: `go version`

2. **Install Git:**
   - Download: https://git-scm.com/download/win
   - Run installer, use default settings
   - Verify: `git --version`

3. **Install Python:**
   - Download: https://www.python.org/ftp/python/3.11.5/python-3.11.5-amd64.exe
   - ✅ Check "Add Python to PATH"
   - Verify: `python --version`

4. **Configure Go Environment:**
   ```powershell
   # Add to user PATH
   [Environment]::SetEnvironmentVariable("GOPATH", "$env:USERPROFILE\go", "User")
   $path = [Environment]::GetEnvironmentVariable("Path", "User")
   $path += ";$env:USERPROFILE\go\bin"
   [Environment]::SetEnvironmentVariable("Path", $path, "User")
   ```

5. **Run Installer:**
   ```powershell
   python main.py --install-tools
   ```

#### Windows Subsystem for Linux (WSL)

If you're using WSL, follow the Linux instructions above.

---

## Troubleshooting

### Common Issues

#### Go Tools Not in PATH

**Problem:** Installed Go tools not found (command not found)

**Solution:**

```bash
# Linux/macOS
echo 'export PATH=$PATH:$HOME/go/bin' >> ~/.bashrc
source ~/.bashrc

# Windows (PowerShell)
$env:Path += ";$env:USERPROFILE\go\bin"
# Add permanently via System Properties > Environment Variables
```

#### Permission Denied

**Problem:** Permission errors during installation

**Solution:**

```bash
# Linux/macOS - Don't use sudo for Go tools
# Instead, ensure proper ownership
chown -R $USER:$USER ~/go

# Windows - Run PowerShell as Administrator
```

#### Network Issues

**Problem:** Timeout or connection errors during download

**Solution:**

```bash
# Use proxy if needed
export HTTP_PROXY=http://proxy:port
export HTTPS_PROXY=http://proxy:port

# Or increase timeout
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
```

#### Build Failures

**Problem:** Compilation errors for C-based tools (MassDNS, naabu)

**Solution:**

```bash
# Install C compiler and dependencies
# Ubuntu/Debian
sudo apt install build-essential libpcap-dev

# macOS
xcode-select --install
brew install libpcap

# Fedora/RHEL/CentOS
sudo yum groupinstall "Development Tools"
sudo yum install libpcap-devel

# Windows (WSL)
sudo apt install build-essential libpcap-dev
```

#### Naabu Compilation Error (pcap.h not found)

**Problem:** `fatal error: pcap.h: No such file or directory`

**Solution:**

This means libpcap development headers are missing:

```bash
# Ubuntu/Debian/WSL
sudo apt-get install -y libpcap-dev

# Fedora/RHEL/CentOS  
sudo yum install -y libpcap-devel

# macOS
brew install libpcap
```

Then retry:
```bash
python main.py --install-tools
```

#### Tool Version Conflicts

**Problem:** Tool not working after installation

**Solution:**

```bash
# Update to latest version
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest

# Or specify version
go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@v2.6.3
```

### Getting Help

If you encounter issues:

1. **Check tool status:** `python main.py --tool-status`
2. **View logs:** Check `logs/tool_install.log`
3. **Manual verification:** Try running tools directly (e.g., `subfinder -version`)
4. **Check PATH:** Ensure Go bin directory is in PATH
5. **Report issues:** Include OS, Go version, and error messages

---

## Tool Reference

### Go-Based Tools (15 tools)

| Tool | Purpose | Installation Command |
|------|---------|---------------------|
| **subfinder** | Subdomain discovery | `go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest` |
| **httpx** | HTTP probing | `go install github.com/projectdiscovery/httpx/cmd/httpx@latest` |
| **dnsx** | DNS toolkit | `go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest` |
| **naabu** | Port scanner | `go install github.com/projectdiscovery/naabu/v2/cmd/naabu@latest` |
| **mapcidr** | CIDR manipulation | `go install github.com/projectdiscovery/mapcidr/cmd/mapcidr@latest` |
| **assetfinder** | Domain finder | `go install github.com/tomnomnom/assetfinder@latest` |
| **gau** | URL fetcher | `go install github.com/lc/gau/v2/cmd/gau@latest` |
| **waybackurls** | Wayback URLs | `go install github.com/tomnomnom/waybackurls@latest` |
| **gotator** | Permutation generator | `go install github.com/Josue87/gotator@latest` |
| **gospider** | Web crawler | `go install github.com/jaeles-project/gospider@latest` |
| **gobuster** | Directory bruteforcer | `go install github.com/OJ/gobuster/v3@latest` |
| **unfurl** | URL parser | `go install github.com/tomnomnom/unfurl@latest` |
| **anew** | Unique line appender | `go install github.com/tomnomnom/anew@latest` |
| **github-subdomains** | GitHub scraper | `go install github.com/gwen001/github-subdomains@latest` |
| **gitlab-subdomains** | GitLab scraper | `go install github.com/gwen001/gitlab-subdomains@latest` |

### Git-Based Tools

| Tool | Purpose | Installation |
|------|---------|-------------|
| **massdns** | Fast DNS resolver | Clone + Make |
| **puredns** | DNS bruteforcer | Clone + go install |

### Python Tools

| Tool | Purpose | Installation |
|------|---------|-------------|
| **fav-up** | Favicon hasher | Clone + pip install |
| **ctfr** | CT log scanner | Clone + pip install |
| **secretfinder** | JS secret finder | Clone + pip install |
| **hosthunter** | VHOST discovery | Clone + pip install |

### Resources

| Resource | Purpose | Size | URL |
|----------|---------|------|-----|
| **n0kovo_subdomains_huge.txt** | DNS wordlist | ~2-5 MB | [GitHub](https://github.com/n0kovo/n0kovo_subdomains) |
| **resolvers.txt** | Trusted DNS resolvers | ~100 KB | [GitHub](https://github.com/trickest/resolvers) |

---

## Post-Installation

After successful installation:

1. **Verify all tools:** `python main.py --tool-status`
2. **Test basic scan:** Run a small test scan to ensure everything works
3. **Configure API keys:** See `docs/API_KEYS.md` for optional API key setup
4. **Read architecture docs:** See `.cursor/rules/architecture.mdc` for system overview

### Next Steps

- Configure API keys for enhanced features (optional)
- Review scan profiles (passive, normal, aggressive)
- Start your first reconnaissance scan
- Monitor logs for any tool execution errors

---

## Updates and Maintenance

### Updating Tools

Tools are updated frequently. To update:

```bash
# Update all Go tools
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
# ... repeat for other tools

# Update Git tools
cd tools/massdns && git pull && make
cd tools/puredns && git pull && go install

# Update resources
python main.py --download-resources
```

### Recommended Update Schedule

- **Go tools:** Monthly (breaking changes are rare)
- **Git tools:** Quarterly
- **Wordlists:** Every 6 months
- **Resolvers:** Monthly (DNS resolvers change)

---

**Need more help?** Check our [FAQ](../README.md#faq) or open an issue on GitHub.

