#!/bin/bash

# Security Reconnaissance Platform - Tool Installation Script
# For Linux and macOS
# This script automates the installation of all required security tools

set -e  # Exit on error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Print functions
print_banner() {
    echo -e "${BLUE}"
    echo "╔══════════════════════════════════════════════════════════════╗"
    echo "║    Security Reconnaissance Platform - Tool Installer        ║"
    echo "║    Automated installation of 15+ security tools             ║"
    echo "╚══════════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
}

print_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

print_step() {
    echo -e "\n${GREEN}==>${NC} ${BLUE}$1${NC}"
}

# Check if command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Check system requirements
check_system_requirements() {
    print_step "Checking system requirements..."
    
    local all_present=true
    
    # Check Go
    if command_exists go; then
        local go_version=$(go version | awk '{print $3}')
        print_success "Go is installed ($go_version)"
    else
        print_warning "Go is not installed (required for Go-based tools)"
        all_present=false
    fi
    
    # Check Git
    if command_exists git; then
        local git_version=$(git --version | awk '{print $3}')
        print_success "Git is installed (version $git_version)"
    else
        print_error "Git is not installed (required)"
        all_present=false
    fi
    
    # Check Python3
    if command_exists python3; then
        local python_version=$(python3 --version | awk '{print $2}')
        print_success "Python3 is installed (version $python_version)"
    else
        print_error "Python3 is not installed (required)"
        all_present=false
    fi
    
    # Check Make
    if command_exists make; then
        print_success "Make is installed"
    else
        print_warning "Make is not installed (needed for building some tools)"
    fi
    
    # Check libpcap (required for naabu)
    if [ -f "/usr/include/pcap.h" ] || [ -f "/usr/local/include/pcap.h" ]; then
        print_success "libpcap-dev is installed"
    else
        print_warning "libpcap-dev is not installed (required for naabu port scanner)"
        all_present=false
    fi
    
    if [ "$all_present" = false ]; then
        echo ""
        print_error "Missing required dependencies!"
        print_info "Please install missing tools before continuing."
        print_info ""
        print_info "Quick fix for Ubuntu/Debian:"
        print_info "  sudo apt-get install -y git build-essential libpcap-dev"
        print_info ""
        print_info "See docs/TOOL_INSTALLATION.md for other platforms."
        echo ""
        read -p "Continue anyway? (y/N): " -n 1 -r
        echo
        if [[ ! $REPLY =~ ^[Yy]$ ]]; then
            exit 1
        fi
    fi
}

# Install Go if not present (Linux only)
install_go() {
    if ! command_exists go; then
        print_step "Installing Go..."
        
        local GO_VERSION="1.21.0"
        local ARCH=$(uname -m)
        
        if [ "$ARCH" = "x86_64" ]; then
            ARCH="amd64"
        elif [ "$ARCH" = "aarch64" ]; then
            ARCH="arm64"
        fi
        
        local GO_TAR="go${GO_VERSION}.linux-${ARCH}.tar.gz"
        local GO_URL="https://go.dev/dl/${GO_TAR}"
        
        print_info "Downloading Go ${GO_VERSION}..."
        wget -q --show-progress "$GO_URL" || {
            print_error "Failed to download Go"
            return 1
        }
        
        print_info "Installing Go to /usr/local/go..."
        sudo rm -rf /usr/local/go
        sudo tar -C /usr/local -xzf "$GO_TAR"
        rm "$GO_TAR"
        
        # Add to PATH
        if ! grep -q "/usr/local/go/bin" ~/.bashrc; then
            echo 'export PATH=$PATH:/usr/local/go/bin' >> ~/.bashrc
            echo 'export GOPATH=$HOME/go' >> ~/.bashrc
            echo 'export PATH=$PATH:$GOPATH/bin' >> ~/.bashrc
        fi
        
        export PATH=$PATH:/usr/local/go/bin
        export GOPATH=$HOME/go
        export PATH=$PATH:$GOPATH/bin
        
        print_success "Go installed successfully"
    fi
}

# Setup Python virtual environment
setup_venv() {
    print_step "Setting up Python virtual environment..."
    
    if [ ! -d "recon_env" ]; then
        python3 -m venv recon_env
        print_success "Virtual environment created"
    else
        print_info "Virtual environment already exists"
    fi
    
    # Activate venv
    source recon_env/bin/activate
    
    # Install requirements
    print_info "Installing Python dependencies..."
    pip install --quiet --upgrade pip
    pip install --quiet -r requirements.txt
    
    print_success "Python dependencies installed"
}

# Use platform's tool installer
install_all_tools() {
    print_step "Installing security tools..."
    
    # Activate venv if not already active
    if [ -z "$VIRTUAL_ENV" ]; then
        source recon_env/bin/activate
    fi
    
    # Run the platform's installer
    python main.py --install-tools
    
    return $?
}

# Download resources
download_resources() {
    print_step "Downloading resources (wordlists, resolvers)..."
    
    # Activate venv if not already active
    if [ -z "$VIRTUAL_ENV" ]; then
        source recon_env/bin/activate
    fi
    
    python main.py --download-resources
    
    return $?
}

# Verify installation
verify_installation() {
    print_step "Verifying installation..."
    
    # Activate venv if not already active
    if [ -z "$VIRTUAL_ENV" ]; then
        source recon_env/bin/activate
    fi
    
    python main.py --tool-status
}

# Show post-installation instructions
show_next_steps() {
    echo ""
    echo -e "${GREEN}╔══════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${GREEN}║              Installation Complete!                          ║${NC}"
    echo -e "${GREEN}╚══════════════════════════════════════════════════════════════╝${NC}"
    echo ""
    print_info "Next steps:"
    echo ""
    echo "  1. Activate virtual environment:"
    echo "     ${BLUE}source recon_env/bin/activate${NC}"
    echo ""
    echo "  2. (Optional) Configure API keys:"
    echo "     ${BLUE}python main.py --set-api-key <service> <key>${NC}"
    echo "     See docs/API_KEYS.md for details"
    echo ""
    echo "  3. Start the platform:"
    echo "     ${BLUE}python main.py${NC}"
    echo ""
    echo "  4. Access web interface:"
    echo "     ${BLUE}http://localhost:8000${NC}"
    echo ""
    echo "For more information, see:"
    echo "  • docs/TOOL_INSTALLATION.md - Tool documentation"
    echo "  • docs/API_KEYS.md - API key configuration"
    echo "  • README.md - Platform usage guide"
    echo ""
}

# Main installation flow
main() {
    print_banner
    
    # Check requirements
    check_system_requirements
    
    # Offer to install Go on Linux
    if [ "$(uname)" = "Linux" ]; then
        if ! command_exists go; then
            echo ""
            read -p "Install Go automatically? (y/N): " -n 1 -r
            echo
            if [[ $REPLY =~ ^[Yy]$ ]]; then
                install_go
            fi
        fi
    fi
    
    # Setup Python environment
    setup_venv
    
    # Install tools
    install_all_tools
    local tools_status=$?
    
    # Download resources
    download_resources
    
    # Verify
    echo ""
    verify_installation
    
    # Show next steps
    show_next_steps
    
    # Exit with appropriate code
    if [ $tools_status -eq 0 ]; then
        exit 0
    else
        print_warning "Some tools failed to install. Check output above."
        exit 1
    fi
}

# Run main function
main "$@"

