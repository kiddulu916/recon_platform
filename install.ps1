# Security Reconnaissance Platform - Tool Installation Script
# For Windows PowerShell
# This script automates the installation of all required security tools

# Requires PowerShell 5.1 or later
#Requires -Version 5.1

# Colors for output
$ESC = [char]27
$ColorReset = "$ESC[0m"
$ColorRed = "$ESC[31m"
$ColorGreen = "$ESC[32m"
$ColorYellow = "$ESC[33m"
$ColorBlue = "$ESC[34m"

function Print-Banner {
    Write-Host "$ColorBlue╔══════════════════════════════════════════════════════════════╗$ColorReset"
    Write-Host "$ColorBlue║    Security Reconnaissance Platform - Tool Installer        ║$ColorReset"
    Write-Host "$ColorBlue║    Automated installation of 15+ security tools             ║$ColorReset"
    Write-Host "$ColorBlue╚══════════════════════════════════════════════════════════════╝$ColorReset`n"
}

function Print-Info {
    param([string]$Message)
    Write-Host "${ColorBlue}[INFO]${ColorReset} $Message"
}

function Print-Success {
    param([string]$Message)
    Write-Host "${ColorGreen}[SUCCESS]${ColorReset} $Message"
}

function Print-Warning {
    param([string]$Message)
    Write-Host "${ColorYellow}[WARNING]${ColorReset} $Message"
}

function Print-Error {
    param([string]$Message)
    Write-Host "${ColorRed}[ERROR]${ColorReset} $Message"
}

function Print-Step {
    param([string]$Message)
    Write-Host "`n${ColorGreen}==>${ColorReset} ${ColorBlue}$Message${ColorReset}"
}

function Test-CommandExists {
    param([string]$Command)
    $null -ne (Get-Command $Command -ErrorAction SilentlyContinue)
}

function Test-Administrator {
    $currentUser = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    return $currentUser.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Check-SystemRequirements {
    Print-Step "Checking system requirements..."
    
    $allPresent = $true
    
    # Check Go
    if (Test-CommandExists "go") {
        $goVersion = (go version) -replace "go version ", ""
        Print-Success "Go is installed ($goVersion)"
    } else {
        Print-Warning "Go is not installed (required for Go-based tools)"
        $allPresent = $false
    }
    
    # Check Git
    if (Test-CommandExists "git") {
        $gitVersion = (git --version) -replace "git version ", ""
        Print-Success "Git is installed ($gitVersion)"
    } else {
        Print-Error "Git is not installed (required)"
        $allPresent = $false
    }
    
    # Check Python
    if (Test-CommandExists "python") {
        $pythonVersion = (python --version) -replace "Python ", ""
        Print-Success "Python is installed ($pythonVersion)"
    } else {
        Print-Error "Python is not installed (required)"
        $allPresent = $false
    }
    
    if (-not $allPresent) {
        Write-Host ""
        Print-Error "Missing required dependencies!"
        Print-Info "Please install missing tools before continuing."
        Print-Info "See docs/TOOL_INSTALLATION.md for instructions."
        Write-Host ""
        Print-Info "Installation options:"
        Write-Host "  1. Manual installation (see docs)"
        Write-Host "  2. Use Chocolatey: choco install golang git python"
        Write-Host "  3. Use Scoop: scoop install go git python"
        Write-Host ""
        
        $continue = Read-Host "Continue anyway? (y/N)"
        if ($continue -ne "y" -and $continue -ne "Y") {
            exit 1
        }
    }
}

function Install-Chocolatey {
    if (-not (Test-CommandExists "choco")) {
        Print-Step "Installing Chocolatey package manager..."
        
        Set-ExecutionPolicy Bypass -Scope Process -Force
        [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072
        
        try {
            Invoke-Expression ((New-Object System.Net.WebClient).DownloadString('https://community.chocolatey.org/install.ps1'))
            Print-Success "Chocolatey installed successfully"
            
            # Refresh environment
            $env:Path = [System.Environment]::GetEnvironmentVariable("Path","Machine") + ";" + [System.Environment]::GetEnvironmentVariable("Path","User")
            
            return $true
        } catch {
            Print-Error "Failed to install Chocolatey: $_"
            return $false
        }
    } else {
        Print-Info "Chocolatey is already installed"
        return $true
    }
}

function Install-MissingDependencies {
    Print-Step "Installing missing dependencies..."
    
    # Check if admin
    if (-not (Test-Administrator)) {
        Print-Warning "Not running as administrator. Cannot install system dependencies."
        Print-Info "Please run this script as administrator or install dependencies manually."
        return
    }
    
    # Install Chocolatey if needed
    $chocoInstalled = Install-Chocolatey
    
    if (-not $chocoInstalled) {
        Print-Warning "Cannot install dependencies without Chocolatey"
        return
    }
    
    # Install missing tools
    if (-not (Test-CommandExists "go")) {
        Print-Info "Installing Go..."
        choco install golang -y
    }
    
    if (-not (Test-CommandExists "git")) {
        Print-Info "Installing Git..."
        choco install git -y
    }
    
    if (-not (Test-CommandExists "python")) {
        Print-Info "Installing Python..."
        choco install python -y
    }
    
    # Refresh environment
    Print-Info "Refreshing environment variables..."
    $env:Path = [System.Environment]::GetEnvironmentVariable("Path","Machine") + ";" + [System.Environment]::GetEnvironmentVariable("Path","User")
    
    Print-Success "Dependencies installed"
}

function Setup-PythonVenv {
    Print-Step "Setting up Python virtual environment..."
    
    if (-not (Test-Path "recon_env")) {
        python -m venv recon_env
        Print-Success "Virtual environment created"
    } else {
        Print-Info "Virtual environment already exists"
    }
    
    # Activate venv
    & .\recon_env\Scripts\Activate.ps1
    
    # Install requirements
    Print-Info "Installing Python dependencies..."
    python -m pip install --quiet --upgrade pip
    python -m pip install --quiet -r requirements.txt
    
    Print-Success "Python dependencies installed"
}

function Install-SecurityTools {
    Print-Step "Installing security tools..."
    
    # Activate venv if not already active
    if (-not $env:VIRTUAL_ENV) {
        & .\recon_env\Scripts\Activate.ps1
    }
    
    # Run the platform's installer
    python main.py --install-tools
    
    return $LASTEXITCODE
}

function Download-Resources {
    Print-Step "Downloading resources (wordlists, resolvers)..."
    
    # Activate venv if not already active
    if (-not $env:VIRTUAL_ENV) {
        & .\recon_env\Scripts\Activate.ps1
    }
    
    python main.py --download-resources
    
    return $LASTEXITCODE
}

function Verify-Installation {
    Print-Step "Verifying installation..."
    
    # Activate venv if not already active
    if (-not $env:VIRTUAL_ENV) {
        & .\recon_env\Scripts\Activate.ps1
    }
    
    python main.py --tool-status
}

function Show-NextSteps {
    Write-Host ""
    Write-Host "${ColorGreen}╔══════════════════════════════════════════════════════════════╗${ColorReset}"
    Write-Host "${ColorGreen}║              Installation Complete!                          ║${ColorReset}"
    Write-Host "${ColorGreen}╚══════════════════════════════════════════════════════════════╝${ColorReset}"
    Write-Host ""
    Print-Info "Next steps:"
    Write-Host ""
    Write-Host "  1. Activate virtual environment:"
    Write-Host "     ${ColorBlue}.\recon_env\Scripts\Activate.ps1${ColorReset}"
    Write-Host ""
    Write-Host "  2. (Optional) Configure API keys:"
    Write-Host "     ${ColorBlue}python main.py --set-api-key <service> <key>${ColorReset}"
    Write-Host "     See docs/API_KEYS.md for details"
    Write-Host ""
    Write-Host "  3. Start the platform:"
    Write-Host "     ${ColorBlue}python main.py${ColorReset}"
    Write-Host ""
    Write-Host "  4. Access web interface:"
    Write-Host "     ${ColorBlue}http://localhost:8000${ColorReset}"
    Write-Host ""
    Write-Host "For more information, see:"
    Write-Host "  • docs/TOOL_INSTALLATION.md - Tool documentation"
    Write-Host "  • docs/API_KEYS.md - API key configuration"
    Write-Host "  • README.md - Platform usage guide"
    Write-Host ""
}

# Main installation flow
function Main {
    Print-Banner
    
    # Check if running as admin
    if (Test-Administrator) {
        Print-Success "Running as administrator"
    } else {
        Print-Warning "Not running as administrator - some features may be limited"
    }
    
    # Check requirements
    Check-SystemRequirements
    
    # Offer to install missing dependencies
    $installDeps = Read-Host "`nInstall missing dependencies automatically? (y/N)"
    if ($installDeps -eq "y" -or $installDeps -eq "Y") {
        if (Test-Administrator) {
            Install-MissingDependencies
        } else {
            Print-Error "Administrator privileges required to install dependencies"
            Print-Info "Please restart PowerShell as Administrator or install manually"
            exit 1
        }
    }
    
    # Setup Python environment
    Setup-PythonVenv
    
    # Install tools
    $toolsStatus = Install-SecurityTools
    
    # Download resources
    Download-Resources
    
    # Verify
    Write-Host ""
    Verify-Installation
    
    # Show next steps
    Show-NextSteps
    
    # Exit with appropriate code
    if ($toolsStatus -eq 0) {
        exit 0
    } else {
        Print-Warning "Some tools failed to install. Check output above."
        exit 1
    }
}

# Run main function
Main

