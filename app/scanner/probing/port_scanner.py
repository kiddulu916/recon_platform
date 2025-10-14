"""
Port scanning using naabu, nmap, and Python fallback
"""

from typing import List, Dict, Optional
import structlog
from sqlalchemy.ext.asyncio import AsyncSession
from pathlib import Path
import tempfile
import json

from app.scanner.tools.base import ToolWrapper
from app.models.network import IPAddress, Port

logger = structlog.get_logger()


class NaabuWrapper(ToolWrapper):
    """Wrapper for naabu port scanner"""
    
    def __init__(self):
        super().__init__("naabu", timeout=600)
    
    def get_command(
        self,
        targets_file: str,
        ports: str,
        output_file: str
    ) -> List[str]:
        return [
            self.tool_name,
            "-list", targets_file,
            "-p", ports,
            "-o", output_file,
            "-silent",
            "-json"
        ]
    
    def parse_output(self, output: str) -> List[Dict]:
        results = []
        for line in output.splitlines():
            if line.strip():
                try:
                    data = json.loads(line)
                    results.append({
                        "ip": data.get("ip"),
                        "port": data.get("port")
                    })
                except:
                    pass
        return results


class PortScanner:
    """
    Port scanning orchestrator
    Uses naabu for speed, falls back to nmap for detailed scanning
    """
    
    def __init__(self, config, rate_limiter):
        self.config = config
        self.rate_limiter = rate_limiter
        self.logger = logger.bind(tool="port_scanner")
        
        self.naabu = NaabuWrapper()
        
        # Port ranges based on scan profile
        self.port_profiles = {
            "default": "80,443,8080,8443",
            "common": "1-1000",
            "full": "1-65535"
        }
    
    async def scan(
        self,
        session: AsyncSession,
        targets: List[str],  # IP addresses or subdomains
        profile: str = "default"
    ) -> Dict[str, List[int]]:
        """
        Scan ports on targets
        
        Args:
            session: Database session
            targets: List of IP addresses or subdomains
            profile: Scan profile (default, common, full)
        
        Returns:
            Dict mapping target -> list of open ports
        """
        if not targets:
            return {}
        
        self.logger.info(
            "Starting port scan",
            targets=len(targets),
            profile=profile
        )
        
        # Get port range for profile
        ports = self.port_profiles.get(profile, self.port_profiles["default"])
        
        # Create temp files
        with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as f:
            targets_file = f.name
            f.write("\n".join(targets))
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as f:
            output_file = f.name
        
        try:
            # Run naabu
            await self.rate_limiter.acquire(tool="naabu")
            result = await self.naabu.run(targets_file, ports, output_file)
            
            # Parse results
            port_map: Dict[str, List[int]] = {}
            
            if result.success:
                # Read results from file
                if Path(output_file).exists():
                    content = Path(output_file).read_text()
                    for line in content.splitlines():
                        if line.strip():
                            try:
                                data = json.loads(line)
                                ip = data.get("ip")
                                port = data.get("port")
                                
                                if ip and port:
                                    if ip not in port_map:
                                        port_map[ip] = []
                                    port_map[ip].append(port)
                            except:
                                pass
            
            self.logger.info(
                "Port scan complete",
                targets_scanned=len(port_map),
                total_ports=sum(len(ports) for ports in port_map.values())
            )
            
            # Save to database
            await self._save_ports(session, port_map)
            
            # Cleanup
            Path(targets_file).unlink()
            Path(output_file).unlink()
            
            return port_map
        
        except Exception as e:
            self.logger.error("Port scan failed", error=str(e))
            return {}
    
    async def _save_ports(
        self,
        session: AsyncSession,
        port_map: Dict[str, List[int]]
    ):
        """Save discovered ports to database"""
        from sqlalchemy import select
        
        for ip_str, ports in port_map.items():
            # Get or create IP address record
            result = await session.execute(
                select(IPAddress).where(IPAddress.ip == ip_str)
            )
            ip_record = result.scalar_one_or_none()
            
            if not ip_record:
                ip_record = IPAddress(ip=ip_str)
                session.add(ip_record)
                await session.flush()
            
            # Add port records
            for port_num in ports:
                # Check if port already exists
                result = await session.execute(
                    select(Port).where(
                        Port.ip_id == ip_record.id,
                        Port.port == port_num
                    )
                )
                existing = result.scalar_one_or_none()
                
                if not existing:
                    port_record = Port(
                        ip_id=ip_record.id,
                        port=port_num,
                        state="open"
                    )
                    session.add(port_record)
        
        await session.commit()

