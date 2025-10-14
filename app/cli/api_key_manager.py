"""
API Key Management CLI
Provides secure command-line interface for managing API keys
"""

import sys
import getpass
from typing import Optional
import structlog
from rich.console import Console
from rich.table import Table
from rich import print as rprint

from app.core.config import ApplicationConfig

logger = structlog.get_logger()
console = Console()


class APIKeyManager:
    """
    CLI interface for API key management
    """
    
    def __init__(self):
        try:
            self.config = ApplicationConfig()
        except Exception as e:
            console.print(f"[red]Failed to load configuration: {e}[/red]")
            self.config = None
    
    def set_api_key(self, service: str, api_key: Optional[str] = None) -> bool:
        """
        Set an API key for a service
        If api_key is None, prompt user for input (hidden)
        """
        if not self.config:
            console.print("[red]Configuration not available[/red]")
            return False
        
        # Validate service name
        supported_services = [
            "whoisxml", "censys", "shodan", "securitytrails",
            "virustotal", "github", "gitlab", "bufferover"
        ]
        
        if service not in supported_services:
            console.print(f"[yellow]Warning:[/yellow] '{service}' is not a recognized service")
            console.print(f"Supported services: {', '.join(supported_services)}")
            console.print("Continuing anyway...")
        
        # Get API key
        if api_key is None:
            console.print(f"\n[blue]Setting API key for:[/blue] {service}")
            console.print("[dim]Enter the API key (input will be hidden):[/dim]")
            api_key = getpass.getpass("API Key: ")
            
            if not api_key:
                console.print("[red]Error: API key cannot be empty[/red]")
                return False
        
        # Store the key
        try:
            self.config.api_keys.save_key(service, api_key)
            console.print(f"[green]✅ API key for '{service}' stored successfully[/green]")
            console.print(f"[dim]Key is encrypted and stored in config/api_keys.enc[/dim]")
            return True
        except Exception as e:
            console.print(f"[red]Failed to store API key: {e}[/red]")
            return False
    
    def list_api_keys(self) -> bool:
        """
        List all configured API key services (not the actual keys)
        """
        if not self.config:
            console.print("[red]Configuration not available[/red]")
            return False
        
        console.print("\n[bold blue]📋 Configured API Keys[/bold blue]\n")
        
        try:
            services = self.config.api_keys.list_services()
            
            if not services:
                console.print("[yellow]No API keys configured[/yellow]")
                console.print("\n[dim]To add an API key:[/dim]")
                console.print("  python main.py --set-api-key <service> <key>")
                console.print("\n[dim]See docs/API_KEYS.md for more information[/dim]")
                return True
            
            table = Table(show_header=True, header_style="bold magenta")
            table.add_column("Service", style="cyan", width=20)
            table.add_column("Status", width=15)
            table.add_column("Description", style="dim")
            
            service_descriptions = {
                "whoisxml": "Company acquisition discovery",
                "censys": "Certificate transparency & scanning",
                "shodan": "Internet-wide device discovery",
                "securitytrails": "Historical DNS data",
                "virustotal": "Subdomain discovery & reputation",
                "github": "Code search (Personal Access Token)",
                "gitlab": "Repository search (PAT)",
                "bufferover": "Passive DNS data"
            }
            
            for service in sorted(services):
                description = service_descriptions.get(service, "")
                table.add_row(service, "[green]✅ Configured[/green]", description)
            
            console.print(table)
            console.print(f"\n[green]Total configured services: {len(services)}[/green]")
            console.print("\n[dim]Note: Actual API keys are encrypted and not displayed[/dim]")
            
            return True
        except Exception as e:
            console.print(f"[red]Failed to list API keys: {e}[/red]")
            return False
    
    def remove_api_key(self, service: str) -> bool:
        """
        Remove an API key for a service
        """
        if not self.config:
            console.print("[red]Configuration not available[/red]")
            return False
        
        try:
            # Check if key exists
            services = self.config.api_keys.list_services()
            if service not in services:
                console.print(f"[yellow]No API key found for '{service}'[/yellow]")
                return False
            
            # Confirm removal
            console.print(f"\n[yellow]⚠️  Remove API key for '{service}'?[/yellow]")
            confirm = input("Type 'yes' to confirm: ")
            
            if confirm.lower() != 'yes':
                console.print("[dim]Cancelled[/dim]")
                return False
            
            # Remove the key
            self.config.api_keys.remove_key(service)
            console.print(f"[green]✅ API key for '{service}' removed[/green]")
            return True
        except Exception as e:
            console.print(f"[red]Failed to remove API key: {e}[/red]")
            return False
    
    def test_api_key(self, service: str) -> bool:
        """
        Test if an API key is configured and valid
        """
        if not self.config:
            console.print("[red]Configuration not available[/red]")
            return False
        
        console.print(f"\n[blue]Testing API key for:[/blue] {service}\n")
        
        try:
            # Check if key exists
            services = self.config.api_keys.list_services()
            if service not in services:
                console.print(f"[red]❌ No API key configured for '{service}'[/red]")
                console.print(f"\n[dim]To add an API key:[/dim]")
                console.print(f"  python main.py --set-api-key {service} YOUR_KEY")
                return False
            
            # Get the key (decrypted)
            api_key = self.config.api_keys.get_key(service)
            
            if not api_key:
                console.print(f"[red]❌ API key for '{service}' is empty or invalid[/red]")
                return False
            
            # Basic validation
            console.print("[green]✅ API key is configured[/green]")
            console.print(f"[dim]Key length: {len(api_key)} characters[/dim]")
            
            # Service-specific validation
            if service == "censys" and ":" in api_key:
                console.print("[green]✅ Format looks correct (ID:SECRET)[/green]")
            elif service == "github" and api_key.startswith("ghp_"):
                console.print("[green]✅ Format looks correct (GitHub PAT)[/green]")
            elif service == "gitlab" and api_key.startswith("glpat-"):
                console.print("[green]✅ Format looks correct (GitLab PAT)[/green]")
            
            console.print("\n[yellow]Note:[/yellow] This only checks if the key is configured.")
            console.print("To verify it works with the service, run a scan or check the service dashboard.")
            
            return True
        except Exception as e:
            console.print(f"[red]Failed to test API key: {e}[/red]")
            return False
    
    def show_api_key_guide(self):
        """
        Display API key configuration guide
        """
        guide = """
[bold blue]🔑 API Key Configuration Guide[/bold blue]

[bold]Quick Commands:[/bold]
  python main.py --set-api-key <service> <key>    Set an API key
  python main.py --list-api-keys                  List configured services
  python main.py --test-api-key <service>         Test if key works
  python main.py --remove-api-key <service>       Remove a key

[bold]Supported Services:[/bold]

1. [cyan]whoisxml[/cyan] - Company acquisition discovery
   • Free tier: 500 requests/month
   • Get key: https://whoisxmlapi.com/

2. [cyan]censys[/cyan] - Certificate transparency & scanning
   • Free tier: 250 queries/month
   • Format: API_ID:API_SECRET
   • Get key: https://censys.io/

3. [cyan]shodan[/cyan] - Internet-wide device discovery
   • Membership: $59 (one-time, lifetime)
   • Get key: https://www.shodan.io/

4. [cyan]securitytrails[/cyan] - Historical DNS data
   • Free tier: 50 queries/month
   • Get key: https://securitytrails.com/

5. [cyan]virustotal[/cyan] - Subdomain discovery
   • Free tier: 500 requests/day
   • Get key: https://www.virustotal.com/

6. [cyan]github[/cyan] - Code search (Personal Access Token)
   • Free with rate limits
   • Scopes: public_repo or repo
   • Get token: https://github.com/settings/tokens

7. [cyan]gitlab[/cyan] - Repository search
   • Free with rate limits
   • Scopes: read_api, read_repository
   • Get token: https://gitlab.com/-/profile/personal_access_tokens

[bold]Important Notes:[/bold]
• API keys are [green]optional[/green] - the platform works without them
• Keys are encrypted at rest using Fernet encryption
• Keys are stored in config/api_keys.enc (0600 permissions)
• Never commit API keys to version control

[bold]For detailed information:[/bold]
  See docs/API_KEYS.md
"""
        console.print(guide)


# CLI command functions
def set_api_key_command(service: str, api_key: Optional[str] = None):
    """CLI command to set an API key"""
    manager = APIKeyManager()
    success = manager.set_api_key(service, api_key)
    return 0 if success else 1


def list_api_keys_command():
    """CLI command to list API keys"""
    manager = APIKeyManager()
    success = manager.list_api_keys()
    return 0 if success else 1


def remove_api_key_command(service: str):
    """CLI command to remove an API key"""
    manager = APIKeyManager()
    success = manager.remove_api_key(service)
    return 0 if success else 1


def test_api_key_command(service: str):
    """CLI command to test an API key"""
    manager = APIKeyManager()
    success = manager.test_api_key(service)
    return 0 if success else 1


def show_api_key_guide():
    """CLI command to show API key guide"""
    manager = APIKeyManager()
    manager.show_api_key_guide()
    return 0

