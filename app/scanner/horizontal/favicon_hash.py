"""
Favicon hashing using favUp.py
Technology fingerprinting via favicon hashes
"""

from typing import List, Dict, Optional
import structlog
from sqlalchemy.ext.asyncio import AsyncSession
from pathlib import Path
import tempfile
import json
import hashlib
import mmh3
import base64

from app.scanner.tools.base import ToolWrapper
from app.models.domain import FaviconHash, Subdomain
import aiohttp

logger = structlog.get_logger()


class FavUpWrapper(ToolWrapper):
    """Wrapper for favUp.py tool"""
    
    def __init__(self, tools_dir: Path):
        super().__init__("python3", timeout=120)
        self.favup_script = tools_dir / "fav-up" / "favUp.py"
    
    def get_command(self, input_file: str, output_file: str) -> List[str]:
        return [
            self.tool_name,
            str(self.favup_script),
            "-l", input_file,
            "-o", output_file
        ]
    
    def parse_output(self, output: str) -> List[Dict]:
        results = []
        for line in output.splitlines():
            if '|' in line:
                parts = line.split('|')
                if len(parts) >= 3:
                    results.append({
                        "url": parts[0].strip(),
                        "hash": parts[1].strip(),
                        "technology": parts[2].strip() if len(parts) > 2 else None
                    })
        return results


class FaviconHasher:
    """
    Generates favicon hashes for technology fingerprinting
    Uses mmh3 hashing algorithm (Shodan-compatible)
    """
    
    def __init__(self, config, rate_limiter):
        self.config = config
        self.rate_limiter = rate_limiter
        self.logger = logger.bind(tool="favicon_hash")
        tools_dir = Path(config.tools.tools_directory if hasattr(config, 'tools') else "tools")
        self.favup = FavUpWrapper(tools_dir)
        
        # Technology fingerprint database (hash -> technology)
        self.fingerprints = self._load_fingerprints()
    
    def _load_fingerprints(self) -> Dict[str, str]:
        """Load known favicon hash fingerprints"""
        # This would load from a database or file
        # For now, return a few common ones
        return {
            "116323821": "Apache",
            "-235478387": "Nginx",
            "-1426968821": "Microsoft IIS",
            "81586312": "Tomcat",
            "1708240621": "WordPress",
        }
    
    async def hash_subdomains(
        self,
        session: AsyncSession,
        subdomain_ids: List[int]
    ) -> List[Dict]:
        """
        Generate favicon hashes for subdomains
        
        Args:
            session: Database session
            subdomain_ids: List of subdomain IDs to process
        
        Returns:
            List of favicon hash results
        """
        if not subdomain_ids:
            return []
        
        self.logger.info("Starting favicon hashing", count=len(subdomain_ids))
        
        results = []
        
        for subdomain_id in subdomain_ids:
            try:
                # Get subdomain record
                subdomain = await session.get(Subdomain, subdomain_id)
                if not subdomain:
                    continue
                
                # Try HTTPS first, then HTTP
                for protocol in ["https", "http"]:
                    favicon_url = f"{protocol}://{subdomain.subdomain}/favicon.ico"
                    
                    hash_result = await self._hash_favicon(favicon_url)
                    if hash_result:
                        # Save to database
                        favicon_hash = FaviconHash(
                            subdomain_id=subdomain_id,
                            hash=hash_result["hash"],
                            hash_type="mmh3",
                            technology=hash_result.get("technology"),
                            confidence=hash_result.get("confidence", 50),
                            favicon_url=favicon_url
                        )
                        session.add(favicon_hash)
                        results.append(hash_result)
                        break  # Stop after first successful hash
                
            except Exception as e:
                self.logger.error("Failed to hash subdomain", subdomain_id=subdomain_id, error=str(e))
        
        await session.commit()
        
        self.logger.info("Favicon hashing complete", hashes=len(results))
        return results
    
    async def _hash_favicon(self, url: str) -> Optional[Dict]:
        """
        Download and hash a favicon
        
        Args:
            url: Favicon URL
        
        Returns:
            Dict with hash and identified technology
        """
        await self.rate_limiter.acquire(tool="favicon_hash")
        
        try:
            async with aiohttp.ClientSession() as http_session:
                async with http_session.get(
                    url,
                    timeout=aiohttp.ClientTimeout(total=10),
                    allow_redirects=True
                ) as response:
                    if response.status == 200:
                        favicon_data = await response.read()
                        
                        # Calculate mmh3 hash (Shodan-compatible)
                        favicon_b64 = base64.encodebytes(favicon_data)
                        hash_value = str(mmh3.hash(favicon_b64))
                        
                        # Check if hash matches known technology
                        technology = self.fingerprints.get(hash_value, "Unknown")
                        confidence = 90 if technology != "Unknown" else 30
                        
                        self.logger.info(
                            "Favicon hashed",
                            url=url,
                            hash=hash_value,
                            technology=technology
                        )
                        
                        return {
                            "hash": hash_value,
                            "technology": technology,
                            "confidence": confidence,
                            "url": url
                        }
            
        except Exception as e:
            self.logger.warning("Failed to hash favicon", url=url, error=str(e))
        
        return None

