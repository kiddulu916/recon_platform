"""
Context-Aware Directory and File Enumeration

Goes beyond simple brute forcing with intelligent, adaptive wordlists:
- Technology-specific wordlists (WordPress, Spring Boot, Django, etc.)
- Learning from successful discoveries (find /admin → try related paths)
- Context adaptation based on detected frameworks
- Smart path generation based on discovered patterns
- Recursive discovery on successful finds
"""

import re
import asyncio
from typing import List, Set, Dict, Optional, Any
from pathlib import Path
from dataclasses import dataclass, field
from urllib.parse import urljoin
import structlog
from sqlalchemy.ext.asyncio import AsyncSession
import aiohttp
import json

from app.models.http_traffic import HTTPTraffic

logger = structlog.get_logger()


@dataclass
class TechnologyProfile:
    """Technology-specific paths and patterns"""
    name: str
    indicators: List[str]  # How to detect this technology
    paths: List[str]  # Technology-specific paths to check
    extensions: List[str] = field(default_factory=list)
    interesting_files: List[str] = field(default_factory=list)


# Technology profiles
TECH_PROFILES = {
    "wordpress": TechnologyProfile(
        name="WordPress",
        indicators=["wp-content", "wp-includes", "wp-admin", "wordpress"],
        paths=[
            "/wp-admin/",
            "/wp-login.php",
            "/wp-content/",
            "/wp-includes/",
            "/wp-content/plugins/",
            "/wp-content/themes/",
            "/wp-content/uploads/",
            "/wp-json/",
            "/wp-json/wp/v2/users",
            "/xmlrpc.php",
            "/readme.html",
            "/license.txt",
            "/wp-config.php.bak",
            "/wp-config.php.old",
            "/.wp-config.php.swp",
        ],
        extensions=[".php"],
        interesting_files=["wp-config.php", "debug.log"]
    ),
    "spring_boot": TechnologyProfile(
        name="Spring Boot",
        indicators=["spring", "actuator", "Whitelabel Error Page"],
        paths=[
            "/actuator",
            "/actuator/health",
            "/actuator/env",
            "/actuator/metrics",
            "/actuator/mappings",
            "/actuator/configprops",
            "/actuator/beans",
            "/actuator/heapdump",
            "/actuator/threaddump",
            "/actuator/trace",
            "/actuator/logfile",
            "/api-docs",
            "/swagger-ui.html",
            "/swagger-ui/",
            "/v2/api-docs",
            "/v3/api-docs",
        ],
        extensions=[".json"],
    ),
    "django": TechnologyProfile(
        name="Django",
        indicators=["django", "csrftoken", "__debug__"],
        paths=[
            "/admin/",
            "/admin/login/",
            "/api/",
            "/api/v1/",
            "/api/v2/",
            "/static/",
            "/media/",
            "/graphql",
            "/.git/",
            "/debug/",
            "/__debug__/",
        ],
        extensions=[".py"],
    ),
    "laravel": TechnologyProfile(
        name="Laravel",
        indicators=["laravel", "laravel_session"],
        paths=[
            "/api/",
            "/storage/",
            "/storage/logs/",
            "/public/",
            "/.env",
            "/.env.backup",
            "/phpinfo.php",
            "/server-status",
            "/telescope",
            "/horizon",
            "/log-viewer",
        ],
        extensions=[".php"],
        interesting_files=[".env", "composer.json", "composer.lock"]
    ),
    "asp_net": TechnologyProfile(
        name="ASP.NET",
        indicators=["aspnet", "asp.net", "ViewState"],
        paths=[
            "/api/",
            "/admin/",
            "/login.aspx",
            "/admin.aspx",
            "/web.config",
            "/Web.config",
            "/bin/",
            "/App_Data/",
            "/elmah.axd",
            "/trace.axd",
        ],
        extensions=[".aspx", ".ashx", ".asmx"],
    ),
    "nodejs": TechnologyProfile(
        name="Node.js",
        indicators=["express", "node", "npm"],
        paths=[
            "/api/",
            "/graphql",
            "/admin/",
            "/dashboard/",
            "/.env",
            "/package.json",
            "/package-lock.json",
            "/node_modules/",
            "/dist/",
            "/build/",
        ],
        extensions=[".js", ".json"],
        interesting_files=["package.json", ".env", "config.json"]
    ),
    "react": TechnologyProfile(
        name="React",
        indicators=["react", "reactdom"],
        paths=[
            "/static/js/",
            "/static/css/",
            "/api/",
            "/manifest.json",
            "/asset-manifest.json",
            "/service-worker.js",
        ],
        extensions=[".js", ".map"],
    ),
}

# Common paths that work across technologies
COMMON_PATHS = [
    # Admin/Management
    "/admin", "/administrator", "/admin-console", "/admin-panel",
    "/dashboard", "/panel", "/manage", "/management",
    "/admin/login", "/admin/index", "/admin/dashboard",

    # API
    "/api", "/api/v1", "/api/v2", "/api/v3",
    "/rest", "/rest/v1", "/rest/v2",
    "/graphql", "/graphiql",

    # Documentation
    "/docs", "/documentation", "/api-docs", "/swagger",
    "/swagger-ui", "/swagger-ui.html", "/swagger.json",
    "/openapi.json", "/openapi.yaml", "/redoc",

    # Configuration
    "/config", "/configuration", "/settings",
    "/.env", "/.env.local", "/.env.production",
    "/web.config", "/app.config", "/config.json",
    "/config.php", "/config.yml", "/config.yaml",

    # Development/Debug
    "/debug", "/test", "/dev", "/development",
    "/.git", "/.git/config", "/.git/HEAD",
    "/.svn", "/.hg",
    "/phpinfo.php", "/info.php", "/test.php",

    # Backup files
    "/backup", "/backups", "/backup.zip",
    "/db_backup", "/database.sql",
    "/site.zip", "/www.zip",

    # Logs
    "/logs", "/log", "/error_log", "/access_log",
    "/debug.log", "/app.log", "/error.log",

    # Upload directories
    "/upload", "/uploads", "/files", "/media",
    "/images", "/attachments", "/downloads",

    # Common files
    "/robots.txt", "/sitemap.xml", "/security.txt",
    "/.well-known/security.txt",
    "/crossdomain.xml", "/clientaccesspolicy.xml",
    "/humans.txt", "/ads.txt",
]


class ContextAwareDirectoryEnumerator:
    """
    Intelligent directory and file enumeration

    Features:
    - Technology detection and context-aware wordlists
    - Learning from successful discoveries
    - Smart path generation
    - Recursive enumeration on interesting finds
    - Status code analysis
    """

    def __init__(self, config, rate_limiter, session: aiohttp.ClientSession):
        self.config = config
        self.rate_limiter = rate_limiter
        self.http_session = session
        self.logger = logger.bind(component="directory_enum")

        # State
        self.discovered_paths: Set[str] = set()
        self.tested_paths: Set[str] = set()
        self.detected_technologies: Set[str] = set()

        # Learning engine
        self.successful_patterns: Dict[str, int] = {}  # Pattern -> frequency
        self.path_relationships: Dict[str, Set[str]] = {}  # Found path -> related paths to try

        # Statistics
        self.stats = {
            "paths_tested": 0,
            "paths_found": 0,
            "technologies_detected": 0,
            "patterns_learned": 0,
        }

    async def enumerate(
        self,
        db_session: AsyncSession,
        base_url: str,
        subdomain_id: int,
        initial_paths: Optional[List[str]] = None
    ) -> Dict[str, Any]:
        """
        Enumerate directories and files

        Args:
            db_session: Database session
            base_url: Base URL to enumerate
            subdomain_id: Subdomain ID for logging
            initial_paths: Optional initial paths discovered elsewhere

        Returns:
            Enumeration results
        """
        self.logger.info("Starting directory enumeration", base_url=base_url)

        # Step 1: Detect technologies
        await self._detect_technologies(base_url, subdomain_id, db_session)

        # Step 2: Build adaptive wordlist
        wordlist = self._build_wordlist(initial_paths or [])

        # Step 3: Test paths
        tasks = []
        for path in wordlist:
            task = self._test_path(db_session, base_url, path, subdomain_id)
            tasks.append(task)

            # Process in batches to avoid overwhelming target
            if len(tasks) >= 20:
                await asyncio.gather(*tasks)
                tasks = []

        # Process remaining
        if tasks:
            await asyncio.gather(*tasks)

        # Step 4: Learn from discoveries and try related paths
        await self._learn_and_expand(db_session, base_url, subdomain_id)

        self.logger.info("Directory enumeration complete", **self.stats)

        return {
            "discovered_paths": list(self.discovered_paths),
            "detected_technologies": list(self.detected_technologies),
            "stats": self.stats,
        }

    async def _detect_technologies(
        self,
        base_url: str,
        subdomain_id: int,
        db_session: AsyncSession
    ):
        """Detect what technologies are being used"""
        try:
            await self.rate_limiter.acquire(tool="directory_enum")

            async with self.http_session.get(base_url, timeout=10) as response:
                body = await response.text()
                headers = dict(response.headers)

                # Check headers
                server = headers.get('Server', '').lower()
                x_powered_by = headers.get('X-Powered-By', '').lower()
                set_cookie = headers.get('Set-Cookie', '').lower()

                # Check each technology profile
                for tech_name, profile in TECH_PROFILES.items():
                    for indicator in profile.indicators:
                        indicator_lower = indicator.lower()

                        if (indicator_lower in body.lower() or
                            indicator_lower in server or
                            indicator_lower in x_powered_by or
                            indicator_lower in set_cookie):

                            self.detected_technologies.add(tech_name)
                            self.stats["technologies_detected"] += 1
                            self.logger.info("Detected technology", technology=profile.name)

        except Exception as e:
            self.logger.debug("Technology detection failed", error=str(e))

    def _build_wordlist(self, initial_paths: List[str]) -> List[str]:
        """Build context-aware wordlist"""
        wordlist = set()

        # Add common paths
        wordlist.update(COMMON_PATHS)

        # Add initial paths
        wordlist.update(initial_paths)

        # Add technology-specific paths
        for tech_name in self.detected_technologies:
            if tech_name in TECH_PROFILES:
                profile = TECH_PROFILES[tech_name]
                wordlist.update(profile.paths)

                self.logger.info(
                    "Added technology-specific paths",
                    technology=profile.name,
                    paths=len(profile.paths)
                )

        return list(wordlist)

    async def _test_path(
        self,
        db_session: AsyncSession,
        base_url: str,
        path: str,
        subdomain_id: int
    ):
        """Test a single path"""
        if path in self.tested_paths:
            return

        full_url = urljoin(base_url, path)
        self.tested_paths.add(path)
        self.stats["paths_tested"] += 1

        try:
            await self.rate_limiter.acquire(tool="directory_enum")

            async with self.http_session.get(
                full_url,
                timeout=10,
                allow_redirects=False
            ) as response:
                status_code = response.status
                headers = dict(response.headers)
                body = await response.read()

                # Interesting status codes
                if status_code in [200, 201, 204, 301, 302, 303, 307, 308, 401, 403]:
                    self.discovered_paths.add(path)
                    self.stats["paths_found"] += 1

                    self.logger.info(
                        "Found path",
                        path=path,
                        status_code=status_code
                    )

                    # Log to database
                    await self._log_discovery(
                        db_session,
                        subdomain_id,
                        full_url,
                        path,
                        status_code,
                        headers,
                        body
                    )

                    # Learn from this discovery
                    self._learn_from_discovery(path, status_code)

        except Exception as e:
            self.logger.debug("Path test failed", path=path, error=str(e))

    def _learn_from_discovery(self, path: str, status_code: int):
        """
        Learn from successful discovery to generate related paths

        Examples:
        - Found /admin → try /administrator, /admin-console, /admin-panel
        - Found /api/v1 → try /api/v2, /api/v3
        - Found /config.json → try /config.yaml, /config.xml
        """
        # Extract pattern
        pattern = self._extract_pattern(path)
        if pattern:
            self.successful_patterns[pattern] = self.successful_patterns.get(pattern, 0) + 1
            self.stats["patterns_learned"] += 1

        # Generate related paths
        related = set()

        # Version variations
        if re.search(r'v\d+', path):
            for version in ['v1', 'v2', 'v3', 'v4', 'v5']:
                related.add(re.sub(r'v\d+', version, path))

        # Extension variations
        base_path = path.rsplit('.', 1)[0] if '.' in path else path
        if '.' in path:
            for ext in ['.json', '.xml', '.yaml', '.yml', '.txt', '.bak', '.old', '.conf']:
                related.add(base_path + ext)

        # Common substitutions
        substitutions = {
            'admin': ['administrator', 'admin-console', 'admin-panel', 'adminpanel'],
            'api': ['rest', 'service', 'services'],
            'config': ['configuration', 'settings', 'conf'],
            'backup': ['backups', 'bak', 'old'],
            'upload': ['uploads', 'files', 'media'],
        }

        path_lower = path.lower()
        for key, alternatives in substitutions.items():
            if key in path_lower:
                for alt in alternatives:
                    related.add(path.replace(key, alt))
                    related.add(path.replace(key.capitalize(), alt.capitalize()))

        # Store relationships
        if path not in self.path_relationships:
            self.path_relationships[path] = set()
        self.path_relationships[path].update(related)

    def _extract_pattern(self, path: str) -> Optional[str]:
        """Extract pattern from path"""
        # Replace numbers with {N}
        pattern = re.sub(r'\d+', '{N}', path)

        # Replace UUIDs with {UUID}
        pattern = re.sub(
            r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}',
            '{UUID}',
            pattern,
            flags=re.IGNORECASE
        )

        return pattern if pattern != path else None

    async def _learn_and_expand(
        self,
        db_session: AsyncSession,
        base_url: str,
        subdomain_id: int
    ):
        """Learn from discoveries and test related paths"""
        # Test related paths for successful discoveries
        tasks = []
        for discovered_path in list(self.discovered_paths)[:20]:  # Limit to prevent explosion
            related_paths = self.path_relationships.get(discovered_path, set())

            for related_path in related_paths:
                if related_path not in self.tested_paths:
                    task = self._test_path(db_session, base_url, related_path, subdomain_id)
                    tasks.append(task)

                    if len(tasks) >= 10:
                        await asyncio.gather(*tasks)
                        tasks = []

        if tasks:
            await asyncio.gather(*tasks)

    async def _log_discovery(
        self,
        db_session: AsyncSession,
        subdomain_id: int,
        url: str,
        path: str,
        status_code: int,
        headers: Dict,
        body: bytes
    ):
        """Log discovered path to database"""
        try:
            from urllib.parse import urlparse

            parsed = urlparse(url)

            traffic = HTTPTraffic(
                subdomain_id=subdomain_id,
                method="GET",
                url=url,
                path=path,
                status_code=status_code,
                response_headers=json.dumps(headers),
                response_body=body[:10000],  # Limit size
                response_content_type=headers.get('Content-Type', ''),
                scanner_module="directory_enumeration",
                scan_purpose="path_discovery"
            )

            db_session.add(traffic)
            await db_session.commit()

        except Exception as e:
            self.logger.debug("Failed to log discovery", error=str(e))
