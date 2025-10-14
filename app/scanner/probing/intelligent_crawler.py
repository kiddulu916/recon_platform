"""
Intelligent Web Crawler with Stateful Application Modeling

Goes beyond simple link following to understand web application structure:
- Learns URL patterns and parameter structures
- Identifies routing schemes (e.g., /api/v1/users/123 → try other IDs/versions)
- Maintains stateful model tracking authentication requirements
- Understands which parameters affect application behavior
- Smart exploration strategy based on discovered patterns
"""

import re
import asyncio
from typing import Dict, List, Set, Optional, Any, Tuple
from dataclasses import dataclass, field
from urllib.parse import urlparse, parse_qs, urljoin, urlunparse
from collections import defaultdict, Counter
import structlog
from sqlalchemy.ext.asyncio import AsyncSession
import aiohttp
from bs4 import BeautifulSoup
import json

from app.models.http_traffic import HTTPTraffic, APIEndpoint
from app.models.domain import Subdomain

logger = structlog.get_logger()


@dataclass
class URLPattern:
    """Represents a discovered URL pattern"""
    pattern: str  # Regex pattern
    examples: List[str] = field(default_factory=list)
    parameter_positions: List[int] = field(default_factory=list)  # Which segments are parameters
    parameter_types: Dict[int, str] = field(default_factory=dict)  # int, uuid, string, etc.
    requires_auth: bool = False
    http_methods: Set[str] = field(default_factory=set)
    frequency: int = 0


@dataclass
class ApplicationState:
    """Stateful model of the application"""
    url_patterns: Dict[str, URLPattern] = field(default_factory=dict)
    auth_required_paths: Set[str] = field(default_factory=set)
    auth_tokens: Dict[str, str] = field(default_factory=dict)  # type -> token
    routing_scheme: Dict[str, str] = field(default_factory=dict)  # prefix -> type (REST, MVC, etc.)
    parameter_effects: Dict[str, Set[str]] = field(default_factory=dict)  # param -> observed effects
    api_versions: Set[str] = field(default_factory=set)
    discovered_resources: Set[str] = field(default_factory=set)  # User-like resources
    technology_stack: Set[str] = field(default_factory=set)


class IntelligentCrawler:
    """
    Intelligent web crawler that learns application structure

    Features:
    - Pattern recognition for URLs and parameters
    - Stateful application modeling
    - Smart parameter fuzzing based on discovered patterns
    - Authentication state tracking
    - Resource relationship mapping
    """

    def __init__(self, config, rate_limiter, session: aiohttp.ClientSession):
        self.config = config
        self.rate_limiter = rate_limiter
        self.http_session = session
        self.logger = logger.bind(component="intelligent_crawler")

        # Application state model
        self.app_state = ApplicationState()

        # Crawl state
        self.visited_urls: Set[str] = set()
        self.url_queue: asyncio.Queue = asyncio.Queue()
        self.depth_map: Dict[str, int] = {}

        # Pattern recognition
        self.id_patterns = {
            "numeric_id": re.compile(r'^\d+$'),
            "uuid": re.compile(r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$', re.IGNORECASE),
            "hash": re.compile(r'^[0-9a-f]{32,64}$', re.IGNORECASE),
            "slug": re.compile(r'^[a-z0-9\-]+$', re.IGNORECASE),
        }

        # Resource indicators (REST-like patterns)
        self.resource_indicators = [
            'users', 'accounts', 'profiles', 'posts', 'articles', 'comments',
            'products', 'items', 'orders', 'invoices', 'payments',
            'files', 'documents', 'images', 'uploads',
            'teams', 'organizations', 'groups', 'projects'
        ]

        # Statistics
        self.stats = {
            "urls_crawled": 0,
            "patterns_discovered": 0,
            "api_endpoints_found": 0,
            "auth_endpoints_found": 0,
            "parameters_fuzzed": 0,
        }

    async def crawl(
        self,
        db_session: AsyncSession,
        base_url: str,
        subdomain_id: int,
        max_depth: int = 5,
        max_pages: int = 1000
    ) -> Dict[str, Any]:
        """
        Crawl web application with intelligent exploration

        Args:
            db_session: Database session
            base_url: Starting URL
            subdomain_id: Subdomain ID for logging
            max_depth: Maximum crawl depth
            max_pages: Maximum pages to crawl

        Returns:
            Crawl results with discovered patterns and endpoints
        """
        self.logger.info("Starting intelligent crawl", base_url=base_url)

        # Initialize queue with base URL
        await self.url_queue.put(base_url)
        self.depth_map[base_url] = 0

        try:
            while not self.url_queue.empty() and self.stats["urls_crawled"] < max_pages:
                url = await self.url_queue.get()

                # Skip if already visited
                if url in self.visited_urls:
                    continue

                # Check depth limit
                if self.depth_map.get(url, 0) > max_depth:
                    continue

                # Crawl this URL
                await self._crawl_url(db_session, url, subdomain_id)
                self.visited_urls.add(url)
                self.stats["urls_crawled"] += 1

                # Adaptive crawling: analyze patterns and generate new URLs to test
                if self.stats["urls_crawled"] % 10 == 0:
                    generated_urls = await self._generate_smart_urls(base_url)
                    for generated_url in generated_urls:
                        if generated_url not in self.visited_urls:
                            await self.url_queue.put(generated_url)
                            self.depth_map[generated_url] = self.depth_map[url] + 1

            self.logger.info("Crawl complete", **self.stats)

            return {
                "stats": self.stats,
                "url_patterns": self.app_state.url_patterns,
                "routing_scheme": self.app_state.routing_scheme,
                "api_versions": list(self.app_state.api_versions),
                "discovered_resources": list(self.app_state.discovered_resources),
                "auth_required_paths": list(self.app_state.auth_required_paths),
            }

        except Exception as e:
            self.logger.error("Crawl failed", error=str(e))
            return {"stats": self.stats, "error": str(e)}

    async def _crawl_url(
        self,
        db_session: AsyncSession,
        url: str,
        subdomain_id: int
    ):
        """Crawl a single URL and extract information"""
        try:
            await self.rate_limiter.acquire(tool="crawler")

            # Make request
            async with self.http_session.get(url, timeout=10, allow_redirects=True) as response:
                content_type = response.headers.get('Content-Type', '')
                status_code = response.status
                body = await response.read()

                # Log to database
                await self._log_traffic(
                    db_session,
                    subdomain_id,
                    "GET",
                    url,
                    status_code,
                    dict(response.headers),
                    body,
                    content_type
                )

                # Analyze response
                await self._analyze_response(url, status_code, content_type, body)

                # Extract links if HTML
                if 'html' in content_type.lower():
                    links = await self._extract_links(url, body)
                    current_depth = self.depth_map.get(url, 0)

                    for link in links:
                        if link not in self.visited_urls:
                            await self.url_queue.put(link)
                            self.depth_map[link] = current_depth + 1

        except aiohttp.ClientError as e:
            self.logger.debug("Request failed", url=url, error=str(e))
        except Exception as e:
            self.logger.warning("URL crawl error", url=url, error=str(e))

    async def _analyze_response(
        self,
        url: str,
        status_code: int,
        content_type: str,
        body: bytes
    ):
        """Analyze response to learn application patterns"""
        parsed_url = urlparse(url)
        path = parsed_url.path

        # Learn URL patterns
        pattern = self._extract_url_pattern(path)
        if pattern:
            if pattern not in self.app_state.url_patterns:
                self.app_state.url_patterns[pattern] = URLPattern(pattern=pattern)
                self.stats["patterns_discovered"] += 1

            url_pattern = self.app_state.url_patterns[pattern]
            url_pattern.examples.append(url)
            url_pattern.frequency += 1
            url_pattern.http_methods.add("GET")

        # Detect authentication requirements
        if status_code in [401, 403]:
            self.app_state.auth_required_paths.add(path)
            self.stats["auth_endpoints_found"] += 1

            if pattern and pattern in self.app_state.url_patterns:
                self.app_state.url_patterns[pattern].requires_auth = True

        # Detect API endpoints
        if self._is_api_response(url, content_type, body):
            self.stats["api_endpoints_found"] += 1

            # Extract API version
            api_version = self._extract_api_version(path)
            if api_version:
                self.app_state.api_versions.add(api_version)

        # Identify routing scheme
        routing_type = self._identify_routing_type(path, content_type)
        if routing_type:
            path_prefix = self._get_path_prefix(path)
            self.app_state.routing_scheme[path_prefix] = routing_type

        # Extract resources from path
        resources = self._extract_resources(path)
        self.app_state.discovered_resources.update(resources)

    def _extract_url_pattern(self, path: str) -> Optional[str]:
        """
        Extract URL pattern from path

        Examples:
        /api/v1/users/123 -> /api/v1/users/{id}
        /posts/abc-def-123/comments -> /posts/{slug}/comments
        /files/550e8400-e29b-41d4-a716-446655440000 -> /files/{uuid}
        """
        parts = [p for p in path.split('/') if p]
        if not parts:
            return None

        pattern_parts = []
        for i, part in enumerate(parts):
            # Check if this part is a parameter
            param_type = self._detect_parameter_type(part)
            if param_type:
                pattern_parts.append(f"{{{param_type}}}")
            else:
                pattern_parts.append(part)

        return '/' + '/'.join(pattern_parts)

    def _detect_parameter_type(self, segment: str) -> Optional[str]:
        """Detect what type of parameter this segment is"""
        for param_type, pattern in self.id_patterns.items():
            if pattern.match(segment):
                return param_type
        return None

    def _extract_api_version(self, path: str) -> Optional[str]:
        """Extract API version from path"""
        version_pattern = re.compile(r'/v(\d+)/', re.IGNORECASE)
        match = version_pattern.search(path)
        if match:
            return f"v{match.group(1)}"
        return None

    def _identify_routing_type(self, path: str, content_type: str) -> Optional[str]:
        """Identify the routing/framework type"""
        if '/api/' in path.lower():
            if '/graphql' in path.lower():
                return "GraphQL"
            elif re.search(r'/v\d+/', path):
                return "REST_versioned"
            else:
                return "REST"

        if 'json' in content_type.lower() and '/api' not in path:
            return "JSON_API"

        # Detect MVC patterns
        if re.match(r'/[a-z]+/[a-z]+/\d+', path, re.IGNORECASE):
            return "MVC"

        return None

    def _get_path_prefix(self, path: str, levels: int = 2) -> str:
        """Get path prefix for categorization"""
        parts = [p for p in path.split('/') if p]
        return '/' + '/'.join(parts[:levels]) if parts else '/'

    def _extract_resources(self, path: str) -> Set[str]:
        """Extract resource names from path"""
        resources = set()
        parts = [p.lower() for p in path.split('/') if p]

        for part in parts:
            # Check if this looks like a resource
            if part in self.resource_indicators:
                resources.add(part)
            # Check plural forms
            elif part.endswith('s') and part[:-1] in self.resource_indicators:
                resources.add(part)

        return resources

    def _is_api_response(self, url: str, content_type: str, body: bytes) -> bool:
        """Determine if this is an API response"""
        # Check URL
        if '/api/' in url.lower():
            return True

        # Check content type
        if 'json' in content_type.lower() or 'xml' in content_type.lower():
            # Try to parse as JSON
            try:
                json.loads(body.decode('utf-8', errors='ignore'))
                return True
            except:
                pass

        return False

    async def _extract_links(self, base_url: str, html: bytes) -> List[str]:
        """Extract links from HTML"""
        links = []

        try:
            soup = BeautifulSoup(html, 'lxml')
            base_domain = urlparse(base_url).netloc

            # Extract from <a> tags
            for tag in soup.find_all('a', href=True):
                href = tag['href']
                full_url = urljoin(base_url, href)

                # Only follow links on same domain
                if urlparse(full_url).netloc == base_domain:
                    # Skip certain extensions
                    if not self._is_static_resource(full_url):
                        links.append(full_url)

            # Extract from JavaScript (simple patterns)
            for script in soup.find_all('script'):
                if script.string:
                    # Look for URL patterns in JS
                    js_urls = re.findall(r'["\']([/a-z0-9\-._~:/?#\[\]@!$&\'()*+,;=%]+)["\']', script.string, re.IGNORECASE)
                    for url in js_urls:
                        if url.startswith('/'):
                            full_url = urljoin(base_url, url)
                            if not self._is_static_resource(full_url):
                                links.append(full_url)

        except Exception as e:
            self.logger.debug("Link extraction failed", error=str(e))

        return list(set(links))  # Deduplicate

    def _is_static_resource(self, url: str) -> bool:
        """Check if URL is a static resource"""
        static_extensions = [
            '.css', '.js', '.jpg', '.jpeg', '.png', '.gif', '.svg', '.ico',
            '.woff', '.woff2', '.ttf', '.eot', '.mp4', '.mp3', '.pdf',
            '.zip', '.tar', '.gz'
        ]
        url_lower = url.lower()
        return any(url_lower.endswith(ext) for ext in static_extensions)

    async def _generate_smart_urls(self, base_url: str) -> List[str]:
        """
        Generate smart URLs based on discovered patterns

        This is where the intelligence happens:
        - Found /api/v1/users/123? Try v2, v3, other IDs
        - Found /admin? Try /administrator, /admin-console
        - Found pattern with numeric IDs? Try sequential IDs
        """
        generated = []

        # Try different API versions
        for pattern_str, pattern_obj in self.app_state.url_patterns.items():
            if '/v' in pattern_str and pattern_obj.examples:
                example = pattern_obj.examples[0]

                # Try other API versions
                for version in ['v1', 'v2', 'v3', 'v4']:
                    if version not in example:
                        new_url = re.sub(r'/v\d+/', f'/{version}/', example)
                        generated.append(new_url)

        # Try parameter variations for discovered resources
        for resource in self.app_state.discovered_resources:
            if resource in self.resource_indicators:
                # Generate some test IDs
                for test_id in [1, 2, 100, 999, 1000]:
                    test_url = urljoin(base_url, f"/api/v1/{resource}/{test_id}")
                    generated.append(test_url)

                # Try common CRUD endpoints
                for action in ['create', 'update', 'delete', 'list']:
                    test_url = urljoin(base_url, f"/api/v1/{resource}/{action}")
                    generated.append(test_url)

        # Try related paths for auth endpoints
        if self.app_state.auth_required_paths:
            for auth_path in list(self.app_state.auth_required_paths)[:5]:
                # Generate variations
                base_path = auth_path.rstrip('/')

                variations = [
                    base_path + '/login',
                    base_path + '/auth',
                    base_path + '/signin',
                    base_path.replace('admin', 'administrator'),
                    base_path.replace('admin', 'admin-console'),
                ]

                for variation in variations:
                    generated.append(urljoin(base_url, variation))

        self.stats["parameters_fuzzed"] += len(generated)
        return generated[:100]  # Limit to prevent explosion

    async def _log_traffic(
        self,
        db_session: AsyncSession,
        subdomain_id: int,
        method: str,
        url: str,
        status_code: int,
        headers: Dict,
        body: bytes,
        content_type: str
    ):
        """Log HTTP traffic to database"""
        try:
            parsed = urlparse(url)

            traffic = HTTPTraffic(
                subdomain_id=subdomain_id,
                method=method,
                url=url,
                path=parsed.path,
                query_params=parsed.query,
                status_code=status_code,
                response_headers=json.dumps(headers),
                response_body=body[:10000],  # Limit size
                response_content_type=content_type,
                scanner_module="intelligent_crawler",
                scan_purpose="intelligent_crawl"
            )

            db_session.add(traffic)
            await db_session.commit()

        except Exception as e:
            self.logger.debug("Failed to log traffic", error=str(e))
