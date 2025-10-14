"""
Tool installation and verification manager
Handles installation of external security tools
"""

import os
import asyncio
import subprocess
import shutil
from pathlib import Path
from typing import Dict, List, Optional, Tuple
import structlog
import aiohttp

# Import path resolution utilities from base
from .base import get_tool_path, get_gopath, clear_tool_cache

logger = structlog.get_logger()


class ToolInstaller:
    """
    Manages installation and verification of external security tools
    Supports Go tools, Python tools, and git repositories
    """
    
    def __init__(self, tools_dir: Path = Path("tools")):
        self.tools_dir = tools_dir
        self.tools_dir.mkdir(exist_ok=True, parents=True)
        
        # Define tool installation methods
        self.go_tools = {
            "subfinder": "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest",
            "assetfinder": "github.com/tomnomnom/assetfinder@latest",
            "gau": "github.com/lc/gau/v2/cmd/gau@latest",
            "waybackurls": "github.com/tomnomnom/waybackurls@latest",
            "github-subdomains": "github.com/gwen001/github-subdomains@latest",
            "gitlab-subdomains": "github.com/gwen001/gitlab-subdomains@latest",
            "gotator": "github.com/Josue87/gotator@latest",
            "gospider": "github.com/jaeles-project/gospider@latest",
            "unfurl": "github.com/tomnomnom/unfurl@latest",
            "gobuster": "github.com/OJ/gobuster/v3@latest",
            "anew": "github.com/tomnomnom/anew@latest",
            "dnsx": "github.com/projectdiscovery/dnsx/cmd/dnsx@latest",
            "mapcidr": "github.com/projectdiscovery/mapcidr/cmd/mapcidr@latest",
            "naabu": "github.com/projectdiscovery/naabu/v2/cmd/naabu@latest",
            "httpx": "github.com/projectdiscovery/httpx/cmd/httpx@latest",
        }
        
        self.git_tools = {
            "massdns": "https://github.com/blechschmidt/massdns.git",
            "puredns": "https://github.com/d3mondev/puredns",
        }
        
        self.python_tools = {
            "amass": None,  # Install via snap or download binary
            "ctfr": "https://github.com/UnaPibaGeek/ctfr.git",
            "favup": "https://github.com/pielco11/fav-up.git",
            "secretfinder": "https://github.com/m4ll0k/SecretFinder.git",
            "hosthunter": "https://github.com/SpiderLabs/HostHunter.git",
        }
        
        self.system_tools = ["nmap", "git", "go"]
        
        # Resources to download
        self.resources = {
            "resolvers": "https://raw.githubusercontent.com/trickest/resolvers/main/resolvers.txt",
            "wordlist": "https://raw.githubusercontent.com/n0kovo/n0kovo_subdomains/main/n0kovo_subdomains_huge.txt",
        }
    
    async def install_all(self) -> Dict[str, bool]:
        """
        Install all required tools
        Returns dict of tool_name: success
        """
        logger.info("Starting tool installation")
        results = {}
        
        # Check and install system tools first
        for tool in self.system_tools:
            results[tool] = await self._check_system_tool(tool)
        
        # Install Go tools
        if results.get("go", False):
            for tool_name, package in self.go_tools.items():
                results[tool_name] = await self._install_go_tool(tool_name, package)
        else:
            logger.warning("Go not available, skipping Go tools")
            for tool_name in self.go_tools:
                results[tool_name] = False
        
        # Install Git-based tools
        if results.get("git", False):
            for tool_name, repo_url in self.git_tools.items():
                results[tool_name] = await self._install_git_tool(tool_name, repo_url)
        
        # Install Python tools
        for tool_name, repo_url in self.python_tools.items():
            if repo_url:
                results[tool_name] = await self._install_python_tool(tool_name, repo_url)
            else:
                results[tool_name] = await self._check_tool_availability(tool_name)
        
        # Download resources
        results["resolvers"] = await self._download_resource(
            "resolvers.txt",
            self.resources["resolvers"]
        )
        results["wordlist"] = await self._download_resource(
            "n0kovo_subdomains_huge.txt",
            self.resources["wordlist"]
        )
        
        # Summary
        logger.info(
            "Tool installation completed",
            available=sum(1 for v in results.values() if v),
            total=len(results)
        )
        
        return results
    
    async def _check_system_tool(self, tool_name: str) -> bool:
        """Check if system tool is available"""
        available = shutil.which(tool_name) is not None
        logger.info(f"System tool {tool_name}", available=available)
        return available
    
    async def _check_tool_availability(self, tool_name: str) -> bool:
        """
        Check if tool is available using enhanced path resolution
        Checks PATH, GOPATH/bin, and common locations
        """
        tool_path = get_tool_path(tool_name, self.tools_dir)
        if tool_path:
            logger.debug("Tool found", tool=tool_name, path=tool_path)
            return True
        return False
    
    async def _install_go_tool(self, tool_name: str, package: str) -> bool:
        """Install a Go-based tool"""
        logger.info(f"Installing Go tool: {tool_name}")
        
        # Check if already installed
        if await self._check_tool_availability(tool_name):
            tool_path = get_tool_path(tool_name, self.tools_dir)
            logger.info(f"{tool_name} already installed", path=tool_path)
            return True
        
        try:
            process = await asyncio.create_subprocess_exec(
                "go", "install", "-v", package,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=300)
            
            if process.returncode == 0:
                # Clear cache to force re-detection
                clear_tool_cache()
                
                # Verify installation with enhanced path resolution
                tool_path = get_tool_path(tool_name, self.tools_dir)
                if tool_path:
                    logger.info(f"Successfully installed {tool_name}", path=tool_path)
                    
                    # Check if tool is in PATH
                    if shutil.which(tool_name) is None:
                        gopath = get_gopath()
                        logger.warning(
                            f"{tool_name} installed but not in PATH",
                            tool_path=tool_path,
                            gopath_bin=os.path.join(gopath, "bin"),
                            hint="Add $GOPATH/bin or $HOME/go/bin to your PATH"
                        )
                    return True
                else:
                    logger.error(f"Installation reported success but {tool_name} not found")
                    return False
            else:
                logger.error(
                    f"Failed to install {tool_name}",
                    stderr=stderr.decode('utf-8', errors='ignore')
                )
                return False
                
        except asyncio.TimeoutError:
            logger.error(f"Timeout installing {tool_name}")
            return False
        except Exception as e:
            logger.error(f"Error installing {tool_name}", error=str(e))
            return False
    
    async def _install_git_tool(self, tool_name: str, repo_url: str) -> bool:
        """Install a tool from git repository"""
        logger.info(f"Installing git tool: {tool_name}")
        
        tool_path = self.tools_dir / tool_name
        
        # Clone if not exists
        if not tool_path.exists():
            try:
                process = await asyncio.create_subprocess_exec(
                    "git", "clone", repo_url, str(tool_path),
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE
                )
                await asyncio.wait_for(process.communicate(), timeout=300)
                
                if process.returncode != 0:
                    logger.error(f"Failed to clone {tool_name}")
                    return False
                    
            except Exception as e:
                logger.error(f"Error cloning {tool_name}", error=str(e))
                return False
        
        # Build based on tool
        if tool_name == "massdns":
            return await self._build_massdns(tool_path)
        elif tool_name == "puredns":
            return await self._install_puredns_go(tool_path)
        
        return True
    
    async def _build_massdns(self, tool_path: Path) -> bool:
        """Build MassDNS from source"""
        try:
            process = await asyncio.create_subprocess_exec(
                "make",
                cwd=str(tool_path),
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=120)
            
            if process.returncode == 0:
                # Create symlink to bin
                binary = tool_path / "bin" / "massdns"
                if binary.exists():
                    logger.info("MassDNS built successfully")
                    return True
            
            logger.error("Failed to build MassDNS")
            return False
            
        except Exception as e:
            logger.error("Error building MassDNS", error=str(e))
            return False
    
    async def _install_puredns_go(self, tool_path: Path) -> bool:
        """Install PureDNS using go install"""
        try:
            process = await asyncio.create_subprocess_exec(
                "go", "install",
                cwd=str(tool_path),
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            await asyncio.wait_for(process.communicate(), timeout=120)
            
            # Check if puredns is now available
            if await self._check_tool_availability("puredns"):
                logger.info("PureDNS installed successfully")
                return True
            
            return False
            
        except Exception as e:
            logger.error("Error installing PureDNS", error=str(e))
            return False
    
    async def _install_python_tool(self, tool_name: str, repo_url: str) -> bool:
        """Install a Python-based tool from git"""
        logger.info(f"Installing Python tool: {tool_name}")
        
        tool_path = self.tools_dir / tool_name
        
        # Clone if not exists
        if not tool_path.exists():
            try:
                process = await asyncio.create_subprocess_exec(
                    "git", "clone", repo_url, str(tool_path),
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE
                )
                await asyncio.wait_for(process.communicate(), timeout=300)
                
                if process.returncode != 0:
                    logger.error(f"Failed to clone {tool_name}")
                    return False
                    
            except Exception as e:
                logger.error(f"Error cloning {tool_name}", error=str(e))
                return False
        
        # Install requirements if requirements.txt exists
        requirements_file = tool_path / "requirements.txt"
        if requirements_file.exists():
            try:
                process = await asyncio.create_subprocess_exec(
                    "pip", "install", "-r", str(requirements_file),
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE
                )
                await asyncio.wait_for(process.communicate(), timeout=300)
            except Exception as e:
                logger.warning(f"Could not install requirements for {tool_name}", error=str(e))
        
        return True
    
    async def _download_resource(self, filename: str, url: str) -> bool:
        """Download a resource file"""
        logger.info(f"Downloading resource: {filename}")
        
        file_path = self.tools_dir / filename
        
        # Skip if already exists
        if file_path.exists():
            logger.info(f"{filename} already exists")
            return True
        
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(url, timeout=aiohttp.ClientTimeout(total=300)) as response:
                    if response.status == 200:
                        content = await response.text()
                        file_path.write_text(content)
                        logger.info(f"Successfully downloaded {filename}")
                        return True
                    else:
                        logger.error(f"Failed to download {filename}", status=response.status)
                        return False
                        
        except Exception as e:
            logger.error(f"Error downloading {filename}", error=str(e))
            return False
    
    def get_tool_status(self) -> Dict[str, Dict[str, any]]:
        """Get status of all tools using enhanced path resolution"""
        status = {}
        
        all_tools = (
            list(self.system_tools) +
            list(self.go_tools.keys()) +
            list(self.git_tools.keys()) +
            list(self.python_tools.keys())
        )
        
        for tool in all_tools:
            # Use enhanced path resolution
            tool_path = get_tool_path(tool, self.tools_dir)
            available = tool_path is not None
            version = None
            in_path = shutil.which(tool) is not None
            
            if available and tool_path:
                try:
                    result = subprocess.run(
                        [tool_path, "--version"],
                        capture_output=True,
                        text=True,
                        timeout=5
                    )
                    version = result.stdout.strip() or result.stderr.strip()
                except:
                    pass
            
            status[tool] = {
                "available": available,
                "path": tool_path,
                "in_path": in_path,
                "version": version
            }
        
        # Check resources
        for resource, url in self.resources.items():
            filename = resource + (".txt" if resource != "wordlist" else "_huge.txt")
            file_path = self.tools_dir / filename.replace("resolvers", "resolvers.txt").replace("wordlist_huge", "n0kovo_subdomains_huge")
            status[resource] = {
                "available": file_path.exists(),
                "path": str(file_path) if file_path.exists() else None,
                "in_path": True  # Resources are files, not executables
            }
        
        return status

