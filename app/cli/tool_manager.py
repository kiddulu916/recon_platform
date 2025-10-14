"""
Tool Installation and Management CLI
Provides user-friendly commands for installing and managing external security tools
"""

import asyncio
import sys
from pathlib import Path
from typing import Dict, Optional
import structlog
from rich.console import Console
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.panel import Panel
from rich import print as rprint

from app.scanner.tools.installer import ToolInstaller
from app.scanner.tools.base import get_gopath

logger = structlog.get_logger()
console = Console()


def check_path_configuration() -> Dict:
    """
    Check if Go bin directories are in PATH
    Returns status and recommendations
    """
    import os
    
    path_env = os.getenv("PATH", "")
    gopath = get_gopath()
    home = os.path.expanduser("~")
    
    gopath_bin = os.path.join(gopath, "bin")
    home_go_bin = os.path.join(home, "go", "bin")
    
    return {
        "gopath": gopath,
        "gopath_bin": gopath_bin,
        "gopath_in_path": gopath_bin in path_env,
        "home_go_bin": home_go_bin,
        "home_go_in_path": home_go_bin in path_env,
        "any_go_in_path": gopath_bin in path_env or home_go_bin in path_env,
    }


class ToolManager:
    """
    CLI interface for tool installation and management
    """
    
    def __init__(self, tools_dir: Path = Path("tools")):
        self.tools_dir = tools_dir
        self.installer = ToolInstaller(tools_dir)
        
    async def install_all_tools(self) -> bool:
        """
        Install all required security tools
        Returns True if at least critical tools were installed
        """
        console.print("\n[bold blue]🔧 Starting Tool Installation[/bold blue]\n")
        
        # Check system requirements first
        console.print("[yellow]Checking system requirements...[/yellow]")
        system_check = await self._check_system_requirements()
        
        if not system_check["all_present"]:
            self._display_system_requirements_warning(system_check)
            if not self._confirm_continue():
                return False
        
        # Check PATH configuration
        path_config = check_path_configuration()
        if not path_config["any_go_in_path"]:
            self._display_path_warning(path_config)
        
        # Install tools with progress tracking
        console.print("\n[yellow]Installing external security tools...[/yellow]")
        
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console
        ) as progress:
            task = progress.add_task("Installing tools...", total=None)
            
            results = await self.installer.install_all()
            
            progress.update(task, completed=True)
        
        # Display results
        self._display_installation_results(results)
        
        # Show PATH setup instructions if needed
        if not path_config["any_go_in_path"]:
            self._display_path_setup_instructions(path_config)
        
        # Check if critical tools are available
        critical_tools = ["go", "git"]
        critical_available = all(results.get(tool, False) for tool in critical_tools)
        
        return critical_available
    
    async def check_tool_status(self) -> Dict[str, Dict]:
        """
        Check status of all tools and resources
        """
        console.print("\n[bold blue]🔍 Checking Tool Status[/bold blue]\n")
        
        status = self.installer.get_tool_status()
        self._display_tool_status(status)
        
        return status
    
    async def install_individual_tool(self, tool_name: str) -> bool:
        """
        Install a specific tool
        """
        console.print(f"\n[bold blue]🔧 Installing {tool_name}[/bold blue]\n")
        
        # Determine tool type and install
        if tool_name in self.installer.go_tools:
            package = self.installer.go_tools[tool_name]
            success = await self.installer._install_go_tool(tool_name, package)
        elif tool_name in self.installer.git_tools:
            repo_url = self.installer.git_tools[tool_name]
            success = await self.installer._install_git_tool(tool_name, repo_url)
        elif tool_name in self.installer.python_tools:
            repo_url = self.installer.python_tools[tool_name]
            if repo_url:
                success = await self.installer._install_python_tool(tool_name, repo_url)
            else:
                console.print(f"[red]❌ {tool_name} requires manual installation[/red]")
                success = False
        else:
            console.print(f"[red]❌ Unknown tool: {tool_name}[/red]")
            return False
        
        if success:
            console.print(f"[green]✅ Successfully installed {tool_name}[/green]")
        else:
            console.print(f"[red]❌ Failed to install {tool_name}[/red]")
        
        return success
    
    async def download_resources(self) -> bool:
        """
        Download required resources (wordlists, resolvers)
        """
        console.print("\n[bold blue]📥 Downloading Resources[/bold blue]\n")
        
        results = {}
        
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console
        ) as progress:
            # Download wordlist
            task1 = progress.add_task("Downloading DNS wordlist...", total=None)
            results["wordlist"] = await self.installer._download_resource(
                "n0kovo_subdomains_huge.txt",
                self.installer.resources["wordlist"]
            )
            progress.update(task1, completed=True)
            
            # Download resolvers
            task2 = progress.add_task("Downloading DNS resolvers...", total=None)
            results["resolvers"] = await self.installer._download_resource(
                "resolvers.txt",
                self.installer.resources["resolvers"]
            )
            progress.update(task2, completed=True)
        
        # Display results
        console.print()
        if results["wordlist"]:
            console.print("[green]✅ DNS wordlist downloaded[/green]")
        else:
            console.print("[red]❌ Failed to download DNS wordlist[/red]")
        
        if results["resolvers"]:
            console.print("[green]✅ DNS resolvers downloaded[/green]")
        else:
            console.print("[red]❌ Failed to download DNS resolvers[/red]")
        
        return all(results.values())
    
    async def _check_system_requirements(self) -> Dict:
        """
        Check if required system tools are available
        """
        requirements = {
            "go": await self.installer._check_system_tool("go"),
            "git": await self.installer._check_system_tool("git"),
            "python3": await self.installer._check_system_tool("python3"),
            "make": await self.installer._check_system_tool("make"),
        }
        
        requirements["all_present"] = all(requirements.values())
        return requirements
    
    def _display_system_requirements_warning(self, system_check: Dict):
        """
        Display warning about missing system requirements
        """
        console.print("\n[yellow]⚠️  Missing System Requirements:[/yellow]\n")
        
        missing = [tool for tool, present in system_check.items() 
                  if tool != "all_present" and not present]
        
        for tool in missing:
            console.print(f"  [red]✗[/red] {tool}")
        
        console.print("\n[yellow]Please install missing requirements:[/yellow]")
        console.print("  • Go: https://golang.org/dl/")
        console.print("  • Git: https://git-scm.com/downloads")
        console.print("  • Python3: https://www.python.org/downloads/")
        console.print("  • Make: Install build-essential (Linux) or build tools (Windows)")
        console.print()
    
    def _display_path_warning(self, path_config: Dict):
        """
        Display warning about Go bin not in PATH
        """
        console.print("\n[yellow]⚠️  PATH Configuration Notice:[/yellow]\n")
        console.print(f"  Go bin directory not found in PATH")
        console.print(f"  Tools will be installed to: {path_config['gopath_bin']}")
        console.print(f"  [dim]Don't worry - tools will still work via absolute paths[/dim]\n")
    
    def _display_path_setup_instructions(self, path_config: Dict):
        """
        Display instructions for setting up PATH
        """
        console.print("\n[bold cyan]💡 Optional: Add Go bin to PATH[/bold cyan]\n")
        console.print("[dim]Tools are working via absolute paths, but adding to PATH is recommended:[/dim]\n")
        
        # Detect shell
        import os
        shell = os.getenv("SHELL", "")
        
        if "bash" in shell:
            console.print("[yellow]For Bash:[/yellow]")
            console.print(f"  echo 'export PATH=\"{path_config['gopath_bin']}:$PATH\"' >> ~/.bashrc")
            console.print("  source ~/.bashrc\n")
        elif "zsh" in shell:
            console.print("[yellow]For Zsh:[/yellow]")
            console.print(f"  echo 'export PATH=\"{path_config['gopath_bin']}:$PATH\"' >> ~/.zshrc")
            console.print("  source ~/.zshrc\n")
        else:
            console.print("[yellow]Add to your shell config:[/yellow]")
            console.print(f"  export PATH=\"{path_config['gopath_bin']}:$PATH\"\n")
        
        console.print("[dim]Note: This is optional - the platform detects tools automatically![/dim]\n")
    
    def _display_installation_results(self, results: Dict[str, bool]):
        """
        Display installation results in a formatted table
        """
        console.print("\n[bold]Installation Results:[/bold]\n")
        
        table = Table(show_header=True, header_style="bold magenta")
        table.add_column("Tool", style="cyan", width=25)
        table.add_column("Status", width=15)
        table.add_column("Type", width=15)
        
        # Categorize tools
        categories = {
            "System Tools": self.installer.system_tools,
            "Go Tools": list(self.installer.go_tools.keys()),
            "Git Tools": list(self.installer.git_tools.keys()),
            "Python Tools": list(self.installer.python_tools.keys()),
            "Resources": ["resolvers", "wordlist"]
        }
        
        for category, tools in categories.items():
            table.add_row(f"[bold]{category}[/bold]", "", "")
            for tool in tools:
                status = results.get(tool, False)
                status_text = "[green]✅ Installed[/green]" if status else "[red]❌ Failed[/red]"
                table.add_row(f"  {tool}", status_text, category.split()[0])
        
        console.print(table)
        
        # Summary
        total = len(results)
        installed = sum(1 for v in results.values() if v)
        
        if installed == total:
            console.print(f"\n[green]✅ All tools installed successfully! ({installed}/{total})[/green]")
        elif installed > total // 2:
            console.print(f"\n[yellow]⚠️  Partial installation: {installed}/{total} tools available[/yellow]")
        else:
            console.print(f"\n[red]❌ Installation mostly failed: {installed}/{total} tools available[/red]")
    
    def _display_tool_status(self, status: Dict[str, Dict]):
        """
        Display current tool status in a formatted table
        """
        table = Table(show_header=True, header_style="bold magenta")
        table.add_column("Tool", style="cyan", width=25)
        table.add_column("Available", width=12)
        table.add_column("In PATH", width=10)
        table.add_column("Location", style="dim")
        
        tools_not_in_path = []
        
        for tool, info in sorted(status.items()):
            available = info.get("available", False)
            in_path = info.get("in_path", False)
            
            status_icon = "[green]✅[/green]" if available else "[red]❌[/red]"
            path_icon = "[green]✅[/green]" if in_path else "[yellow]⚠️[/yellow]"
            
            # Show path or version
            location = info.get("path") or info.get("version") or "N/A"
            if location and len(location) > 60:
                location = location[:57] + "..."
            
            table.add_row(tool, status_icon, path_icon, location)
            
            # Track tools not in PATH
            if available and not in_path:
                tools_not_in_path.append(tool)
        
        console.print(table)
        
        # Summary statistics
        total = len(status)
        available = sum(1 for info in status.values() if info.get("available", False))
        in_path_count = sum(1 for info in status.values() if info.get("in_path", False))
        
        console.print(f"\n[bold]Summary:[/bold] {available}/{total} tools available, {in_path_count}/{total} in PATH")
        
        if tools_not_in_path:
            console.print(f"\n[yellow]⚠️  {len(tools_not_in_path)} tool(s) available but not in PATH[/yellow]")
            console.print("[dim]These tools will work via absolute paths (no action needed)[/dim]")
        
        if available < total:
            console.print(f"\n[yellow]💡 Tip: Run with --install-tools to install missing tools[/yellow]")
    
    def _confirm_continue(self) -> bool:
        """
        Ask user to confirm continuation
        """
        try:
            response = console.input("\n[yellow]Continue anyway? (y/N): [/yellow]")
            return response.lower() in ['y', 'yes']
        except (KeyboardInterrupt, EOFError):
            return False
    
    def display_tool_installation_guide(self):
        """
        Display comprehensive tool installation guide
        """
        guide = """
[bold blue]🔧 Tool Installation Guide[/bold blue]

[bold]Quick Start:[/bold]
  python main.py --install-tools    Install all tools automatically
  python main.py --check-tools      Check tool availability
  python main.py --tool-status      Detailed tool status report

[bold]System Requirements:[/bold]
  • Go 1.19+ (for Go-based tools)
  • Git (for cloning repositories)
  • Python 3.9+ (for Python tools)
  • Make/GCC (for building from source)

[bold]Manual Installation:[/bold]

1. [cyan]Go Tools[/cyan] (install individually):
   go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
   go install github.com/projectdiscovery/httpx/cmd/httpx@latest
   go install github.com/projectdiscovery/naabu/v2/cmd/naabu@latest
   go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest
   go install github.com/projectdiscovery/mapcidr/cmd/mapcidr@latest

2. [cyan]Resources[/cyan] (manual download):
   Wordlist: https://github.com/n0kovo/n0kovo_subdomains
   Resolvers: https://github.com/trickest/resolvers

[bold]Troubleshooting:[/bold]
  • Ensure GOPATH/bin is in PATH
  • Run with administrator/sudo if permission errors occur
  • Check network connectivity for downloads
  • Verify disk space (need ~500MB)

[bold]Documentation:[/bold]
  See docs/TOOL_INSTALLATION.md for detailed instructions
"""
        console.print(Panel(guide, border_style="blue"))


# CLI command functions
async def install_tools_command():
    """CLI command to install all tools"""
    manager = ToolManager()
    success = await manager.install_all_tools()
    return 0 if success else 1


async def check_tools_command():
    """CLI command to check tool status"""
    manager = ToolManager()
    await manager.check_tool_status()
    return 0


async def install_tool_command(tool_name: str):
    """CLI command to install a specific tool"""
    manager = ToolManager()
    success = await manager.install_individual_tool(tool_name)
    return 0 if success else 1


async def download_resources_command():
    """CLI command to download resources"""
    manager = ToolManager()
    success = await manager.download_resources()
    return 0 if success else 1


def show_tool_guide():
    """CLI command to show installation guide"""
    manager = ToolManager()
    manager.display_tool_installation_guide()
    return 0

