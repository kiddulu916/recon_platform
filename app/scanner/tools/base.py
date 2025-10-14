"""
Base class for external tool wrappers
Provides standardized interface for running security tools
"""

import asyncio
import subprocess
import shutil
import os
from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import List, Optional, Dict, Any
from pathlib import Path
import structlog

logger = structlog.get_logger()

# Module-level cache for environment variables and tool paths
_ENV_CACHE = {
    "gopath": None,
    "home": None,
    "tool_paths": {}
}


def get_gopath() -> Optional[str]:
    """
    Get GOPATH from environment or go command
    Cached for performance
    """
    if _ENV_CACHE["gopath"] is not None:
        return _ENV_CACHE["gopath"]
    
    # Try environment variable first
    gopath = os.getenv("GOPATH")
    if gopath:
        _ENV_CACHE["gopath"] = gopath
        return gopath
    
    # Try running 'go env GOPATH'
    try:
        result = subprocess.run(
            ["go", "env", "GOPATH"],
            capture_output=True,
            text=True,
            timeout=5
        )
        if result.returncode == 0:
            gopath = result.stdout.strip()
            if gopath:
                _ENV_CACHE["gopath"] = gopath
                return gopath
    except (subprocess.TimeoutExpired, FileNotFoundError):
        pass
    
    # Fall back to default
    home = os.path.expanduser("~")
    default_gopath = os.path.join(home, "go")
    _ENV_CACHE["gopath"] = default_gopath
    return default_gopath


def get_tool_path(tool_name: str, tools_dir: Optional[Path] = None) -> Optional[str]:
    """
    Find tool in common locations, even if not in PATH
    Searches: PATH, GOPATH/bin, $HOME/go/bin, /usr/local/bin, tools/ directory
    
    Args:
        tool_name: Name of the tool to find
        tools_dir: Optional tools directory to search
        
    Returns:
        Absolute path to tool if found, None otherwise
    """
    # Check cache first
    cache_key = f"{tool_name}:{tools_dir}"
    if cache_key in _ENV_CACHE["tool_paths"]:
        return _ENV_CACHE["tool_paths"][cache_key]
    
    # Search locations in priority order
    search_locations = []
    
    # 1. Check PATH first (fastest)
    path_result = shutil.which(tool_name)
    if path_result:
        _ENV_CACHE["tool_paths"][cache_key] = path_result
        return path_result
    
    # 2. Check GOPATH/bin
    gopath = get_gopath()
    if gopath:
        search_locations.append(os.path.join(gopath, "bin", tool_name))
    
    # 3. Check $HOME/go/bin (common default)
    home = os.path.expanduser("~")
    search_locations.append(os.path.join(home, "go", "bin", tool_name))
    
    # 4. Check /usr/local/bin (system install)
    search_locations.append(os.path.join("/usr", "local", "bin", tool_name))
    
    # 5. Check local tools directory
    if tools_dir:
        search_locations.append(os.path.join(str(tools_dir), tool_name, tool_name))
        search_locations.append(os.path.join(str(tools_dir), tool_name, "bin", tool_name))
    
    # Search each location
    for location in search_locations:
        if os.path.isfile(location) and os.access(location, os.X_OK):
            _ENV_CACHE["tool_paths"][cache_key] = location
            logger.debug("Tool found", tool=tool_name, path=location)
            return location
    
    # Not found
    _ENV_CACHE["tool_paths"][cache_key] = None
    return None


def clear_tool_cache():
    """Clear the tool path cache - useful after installing new tools"""
    _ENV_CACHE["tool_paths"].clear()
    logger.debug("Tool path cache cleared")


@dataclass
class ToolResult:
    """Standardized result from tool execution"""
    success: bool
    output: str
    error: str
    return_code: int
    results: List[str]  # Parsed results
    metadata: Dict[str, Any]  # Additional metadata


class ToolWrapper(ABC):
    """
    Abstract base class for all external tool wrappers
    Provides standardized interface and common functionality
    """
    
    def __init__(self, tool_name: str, timeout: int = 300, tools_dir: Optional[Path] = None):
        self.tool_name = tool_name
        self.timeout = timeout
        self.tools_dir = tools_dir or Path("tools")
        self.logger = logger.bind(tool=tool_name)
        self._resolved_path = None
    
    @abstractmethod
    def get_command(self, *args, **kwargs) -> List[str]:
        """
        Build the command to execute
        Returns list of command arguments
        
        Note: Subclasses should use self.get_tool_executable() to get
        the tool path instead of hardcoding the tool name
        """
        pass
    
    @abstractmethod
    def parse_output(self, output: str) -> List[str]:
        """
        Parse tool output into normalized results
        Returns list of discovered items (subdomains, IPs, etc.)
        """
        pass
    
    def get_tool_executable(self) -> str:
        """
        Get the executable path for this tool
        Returns absolute path if found, or tool name as fallback
        """
        if self._resolved_path is None:
            self._resolved_path = get_tool_path(self.tool_name, self.tools_dir)
        
        return self._resolved_path if self._resolved_path else self.tool_name
    
    def check_available(self) -> bool:
        """
        Check if the tool is available
        Searches PATH, GOPATH/bin, and common locations
        """
        tool_path = get_tool_path(self.tool_name, self.tools_dir)
        if tool_path:
            self.logger.debug("Tool available", path=tool_path)
            return True
        return False
    
    def get_install_command(self) -> str:
        """
        Get installation command for this tool
        Override in subclasses for tool-specific instructions
        """
        # Try to determine tool type
        if self.tool_name in ["subfinder", "httpx", "dnsx", "naabu", "mapcidr"]:
            return f"go install github.com/projectdiscovery/{self.tool_name}/cmd/{self.tool_name}@latest"
        elif self.tool_name in ["assetfinder", "waybackurls", "unfurl", "anew"]:
            return f"go install github.com/tomnomnom/{self.tool_name}@latest"
        elif self.tool_name == "gotator":
            return "go install github.com/Josue87/gotator@latest"
        elif self.tool_name == "gau":
            return "go install github.com/lc/gau/v2/cmd/gau@latest"
        elif self.tool_name == "gospider":
            return "go install github.com/jaeles-project/gospider@latest"
        else:
            return f"python main.py --install-tool {self.tool_name}"
    
    async def run(self, *args, **kwargs) -> ToolResult:
        """
        Execute the tool with given arguments
        Returns ToolResult with parsed output
        """
        # Check tool availability and resolve path
        tool_path = get_tool_path(self.tool_name, self.tools_dir)
        
        if not tool_path:
            install_cmd = self.get_install_command()
            error_msg = (
                f"Tool '{self.tool_name}' not found.\n"
                f"Searched: PATH, $GOPATH/bin, $HOME/go/bin, /usr/local/bin\n"
                f"Install it with: {install_cmd}\n"
                f"Or run: python main.py --install-tools"
            )
            self.logger.warning(
                "Tool not available",
                tool=self.tool_name,
                install_command=install_cmd
            )
            return ToolResult(
                success=False,
                output="",
                error=error_msg,
                return_code=-1,
                results=[],
                metadata={
                    "error": "tool_not_found",
                    "install_command": install_cmd
                }
            )
        
        # Store resolved path for get_tool_executable()
        self._resolved_path = tool_path
        
        # Build command
        try:
            command = self.get_command(*args, **kwargs)
            # Ensure first element is the resolved tool path
            if command and command[0] == self.tool_name:
                command[0] = tool_path
            
            self.logger.info("Executing tool", command=" ".join(command), tool_path=tool_path)
        except Exception as e:
            self.logger.error("Failed to build command", error=str(e))
            return ToolResult(
                success=False,
                output="",
                error=str(e),
                return_code=-1,
                results=[],
                metadata={"error": "command_build_failed"}
            )
        
        # Execute command
        try:
            process = await asyncio.create_subprocess_exec(
                *command,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            # Wait for completion with timeout
            stdout, stderr = await asyncio.wait_for(
                process.communicate(),
                timeout=self.timeout
            )
            
            output = stdout.decode('utf-8', errors='ignore')
            error = stderr.decode('utf-8', errors='ignore')
            return_code = process.returncode
            
            self.logger.info(
                "Tool execution completed",
                return_code=return_code,
                output_lines=len(output.splitlines())
            )
            
            # Parse output
            try:
                results = self.parse_output(output)
                self.logger.info("Parsed results", count=len(results))
            except Exception as e:
                self.logger.error("Failed to parse output", error=str(e))
                results = []
            
            return ToolResult(
                success=return_code == 0,
                output=output,
                error=error,
                return_code=return_code,
                results=results,
                metadata={}
            )
            
        except asyncio.TimeoutError:
            self.logger.error("Tool execution timed out", timeout=self.timeout)
            try:
                process.kill()
            except:
                pass
            return ToolResult(
                success=False,
                output="",
                error=f"Timeout after {self.timeout} seconds",
                return_code=-1,
                results=[],
                metadata={"error": "timeout"}
            )
        
        except Exception as e:
            self.logger.error("Tool execution failed", error=str(e))
            return ToolResult(
                success=False,
                output="",
                error=str(e),
                return_code=-1,
                results=[],
                metadata={"error": "execution_failed"}
            )
    
    def get_version(self) -> Optional[str]:
        """Get tool version if available"""
        try:
            result = subprocess.run(
                [self.tool_name, "--version"],
                capture_output=True,
                text=True,
                timeout=5
            )
            return result.stdout.strip() or result.stderr.strip()
        except:
            return None

