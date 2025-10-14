"""
Advanced API Endpoint Discovery System

Multi-approach API discovery combining:
1. Static Analysis - Examine JavaScript for API calls (fetch, XMLHttpRequest, axios, etc.)
2. Dynamic Analysis - Observe API calls during crawling
3. Documentation Discovery - Find Swagger, OpenAPI, GraphQL introspection
4. Pattern Recognition - Learn API structures and generate variations
5. Parameter Mapping - Understand required/optional parameters and auth methods
"""

import re
import asyncio
import json as json_lib
from typing import List, Dict, Set, Optional, Any, Tuple
from dataclasses import dataclass, field
from urllib.parse import urlparse, urljoin, parse_qs
from collections import defaultdict
import structlog
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
import aiohttp
from bs4 import BeautifulSoup

from app.models.http_traffic import HTTPTraffic, APIEndpoint
from app.models.domain import Subdomain

logger = structlog.get_logger()


@dataclass
class DiscoveredAPI:
    """Represents a discovered API endpoint"""
    url: str
    method: str
    api_type: str  # REST, GraphQL, SOAP, etc.
    version: Optional[str] = None
    parameters: Dict[str, Any] = field(default_factory=dict)
    headers: Dict[str, str] = field(default_factory=dict)
    body_schema: Optional[Dict] = None
    response_schema: Optional[Dict] = None
    requires_auth: bool = False
    auth_type: Optional[str] = None
    discovery_method: str = "unknown"
    confidence: float = 0.0
    documentation_url: Optional[str] = None


class APIDiscoveryEngine:
    """
    Advanced API discovery using multiple approaches

    Features:
    - Static analysis of JavaScript files
    - Dynamic observation during crawling
    - Documentation endpoint discovery
    - GraphQL introspection
    - OpenAPI/Swagger parsing
    - Parameter structure learning
    """

    def __init__(self, config, rate_limiter, session: aiohttp.ClientSession):
        self.config = config
        self.rate_limiter = rate_limiter
        self.http_session = session
        self.logger = logger.bind(component="api_discovery")

        # Discovered APIs
        self.apis: List[DiscoveredAPI] = []
        self.tested_endpoints: Set[str] = set()

        # JS API call patterns
        self.js_api_patterns = [
            # fetch()
            re.compile(r'fetch\s*\(\s*[\'"`]([^\'"`]+)[\'"`]', re.IGNORECASE),
            re.compile(r'fetch\s*\(\s*`([^`]+)`', re.IGNORECASE),

            # axios
            re.compile(r'axios\.(?:get|post|put|delete|patch)\s*\(\s*[\'"`]([^\'"`]+)[\'"`]', re.IGNORECASE),
            re.compile(r'axios\s*\(\s*\{\s*url\s*:\s*[\'"`]([^\'"`]+)[\'"`]', re.IGNORECASE),

            # XMLHttpRequest
            re.compile(r'\.open\s*\(\s*[\'"`](?:GET|POST|PUT|DELETE|PATCH)[\'"`]\s*,\s*[\'"`]([^\'"`]+)[\'"`]', re.IGNORECASE),

            # jQuery ajax
            re.compile(r'\$\.ajax\s*\(\s*\{\s*url\s*:\s*[\'"`]([^\'"`]+)[\'"`]', re.IGNORECASE),
            re.compile(r'\$\.(?:get|post)\s*\(\s*[\'"`]([^\'"`]+)[\'"`]', re.IGNORECASE),

            # General URL patterns in JS
            re.compile(r'[\'"`](/api/[^\'"`\s]+)[\'"`]', re.IGNORECASE),
            re.compile(r'[\'"`](/rest/[^\'"`\s]+)[\'"`]', re.IGNORECASE),
            re.compile(r'[\'"`](/graphql[^\'"`\s]*)[\'"`]', re.IGNORECASE),
        ]

        # Documentation paths
        self.doc_paths = [
            "/swagger", "/swagger.json", "/swagger.yaml",
            "/swagger-ui", "/swagger-ui.html", "/swagger-ui/",
            "/api-docs", "/api-docs.json", "/api/docs",
            "/openapi.json", "/openapi.yaml", "/openapi/v3",
            "/v2/api-docs", "/v3/api-docs",
            "/redoc", "/rapidoc",
            "/graphql", "/graphiql", "/graphql/schema",
            "/api/schema", "/api/spec",
            "/__schema", "/schema.json",
        ]

        # Statistics
        self.stats = {
            "js_files_analyzed": 0,
            "apis_discovered": 0,
            "docs_found": 0,
            "graphql_endpoints": 0,
            "rest_endpoints": 0,
            "parameters_mapped": 0,
        }

    async def discover(
        self,
        db_session: AsyncSession,
        base_url: str,
        subdomain_id: int,
        observed_traffic: Optional[List[HTTPTraffic]] = None
    ) -> Dict[str, Any]:
        """
        Discover API endpoints using multiple approaches

        Args:
            db_session: Database session
            base_url: Base URL to scan
            subdomain_id: Subdomain ID
            observed_traffic: Optional HTTP traffic observed during crawling

        Returns:
            Discovery results
        """
        self.logger.info("Starting API discovery", base_url=base_url)

        # Approach 1: Find API documentation
        await self._discover_documentation(db_session, base_url, subdomain_id)

        # Approach 2: Static analysis of JavaScript
        await self._analyze_javascript(db_session, base_url, subdomain_id)

        # Approach 3: Dynamic analysis from observed traffic
        if observed_traffic:
            await self._analyze_traffic(observed_traffic)

        # Approach 4: Try GraphQL introspection
        await self._graphql_introspection(db_session, base_url, subdomain_id)

        # Approach 5: Generate API variations based on discovered patterns
        await self._generate_api_variations(db_session, base_url, subdomain_id)

        # Save discovered APIs to database
        await self._save_apis(db_session, subdomain_id)

        self.logger.info("API discovery complete", **self.stats)

        return {
            "apis": [self._api_to_dict(api) for api in self.apis],
            "stats": self.stats,
        }

    async def _discover_documentation(
        self,
        db_session: AsyncSession,
        base_url: str,
        subdomain_id: int
    ):
        """Discover API documentation endpoints"""
        self.logger.info("Searching for API documentation")

        tasks = []
        for doc_path in self.doc_paths:
            task = self._check_doc_path(db_session, base_url, doc_path, subdomain_id)
            tasks.append(task)

        await asyncio.gather(*tasks)

    async def _check_doc_path(
        self,
        db_session: AsyncSession,
        base_url: str,
        path: str,
        subdomain_id: int
    ):
        """Check if a documentation path exists"""
        url = urljoin(base_url, path)

        if url in self.tested_endpoints:
            return

        self.tested_endpoints.add(url)

        try:
            await self.rate_limiter.acquire(tool="api_discovery")

            async with self.http_session.get(url, timeout=10) as response:
                if response.status == 200:
                    content_type = response.headers.get('Content-Type', '')
                    body = await response.text()

                    self.logger.info("Found API documentation", url=url)
                    self.stats["docs_found"] += 1

                    # Parse documentation
                    if 'json' in content_type or path.endswith('.json'):
                        await self._parse_openapi_json(body, base_url, url)
                    elif 'yaml' in content_type or path.endswith(('.yaml', '.yml')):
                        await self._parse_openapi_yaml(body, base_url, url)
                    elif 'graphql' in path.lower():
                        # GraphQL endpoint found
                        api = DiscoveredAPI(
                            url=url,
                            method="POST",
                            api_type="GraphQL",
                            discovery_method="documentation",
                            confidence=0.9,
                            documentation_url=url
                        )
                        self.apis.append(api)
                        self.stats["graphql_endpoints"] += 1

        except Exception as e:
            self.logger.debug("Doc path check failed", path=path, error=str(e))

    async def _parse_openapi_json(self, content: str, base_url: str, doc_url: str):
        """Parse OpenAPI/Swagger JSON specification"""
        try:
            spec = json_lib.loads(content)

            # Get base path
            servers = spec.get('servers', [])
            base_path = servers[0].get('url', '') if servers else spec.get('basePath', '')

            # Extract paths
            paths = spec.get('paths', {})

            for path, path_spec in paths.items():
                for method, operation in path_spec.items():
                    if method.upper() in ['GET', 'POST', 'PUT', 'DELETE', 'PATCH']:
                        full_path = urljoin(base_url, base_path + path)

                        # Extract parameters
                        parameters = {}
                        for param in operation.get('parameters', []):
                            param_name = param.get('name')
                            param_in = param.get('in')  # query, path, header, body
                            param_required = param.get('required', False)
                            param_type = param.get('type', param.get('schema', {}).get('type'))

                            parameters[param_name] = {
                                "in": param_in,
                                "required": param_required,
                                "type": param_type
                            }

                        # Check if auth required
                        security = operation.get('security') or spec.get('security')
                        requires_auth = bool(security)

                        # Determine auth type
                        auth_type = None
                        if security and spec.get('securityDefinitions'):
                            sec_defs = spec.get('securityDefinitions', {})
                            auth_type = list(sec_defs.values())[0].get('type') if sec_defs else None

                        api = DiscoveredAPI(
                            url=full_path,
                            method=method.upper(),
                            api_type="REST",
                            version=self._extract_version(path),
                            parameters=parameters,
                            requires_auth=requires_auth,
                            auth_type=auth_type,
                            discovery_method="openapi_spec",
                            confidence=1.0,
                            documentation_url=doc_url
                        )

                        self.apis.append(api)
                        self.stats["rest_endpoints"] += 1
                        self.stats["parameters_mapped"] += len(parameters)

            self.logger.info("Parsed OpenAPI spec", endpoints=len(paths))

        except Exception as e:
            self.logger.warning("Failed to parse OpenAPI spec", error=str(e))

    async def _parse_openapi_yaml(self, content: str, base_url: str, doc_url: str):
        """Parse OpenAPI YAML specification"""
        try:
            import yaml
            spec = yaml.safe_load(content)
            # Convert to same format as JSON and reuse parser
            json_content = json_lib.dumps(spec)
            await self._parse_openapi_json(json_content, base_url, doc_url)
        except Exception as e:
            self.logger.warning("Failed to parse OpenAPI YAML", error=str(e))

    async def _analyze_javascript(
        self,
        db_session: AsyncSession,
        base_url: str,
        subdomain_id: int
    ):
        """Static analysis of JavaScript files for API calls"""
        self.logger.info("Analyzing JavaScript files")

        # Find JavaScript files (from previous crawl data or discover them)
        js_urls = await self._find_javascript_files(db_session, subdomain_id, base_url)

        for js_url in js_urls[:50]:  # Limit to prevent overwhelming
            await self._analyze_js_file(js_url, base_url)

    async def _find_javascript_files(
        self,
        db_session: AsyncSession,
        subdomain_id: int,
        base_url: str
    ) -> List[str]:
        """Find JavaScript files to analyze"""
        js_urls = []

        # Check database for previously discovered JS files
        result = await db_session.execute(
            select(HTTPTraffic).where(
                HTTPTraffic.subdomain_id == subdomain_id,
                HTTPTraffic.response_content_type.like('%javascript%')
            ).limit(50)
        )
        traffic_records = result.scalars().all()

        for record in traffic_records:
            js_urls.append(record.url)

        # Also try common JS file locations
        common_js_paths = [
            "/static/js/main.js",
            "/static/js/app.js",
            "/js/main.js",
            "/js/app.js",
            "/assets/js/main.js",
            "/dist/js/main.js",
            "/build/main.js",
        ]

        for path in common_js_paths:
            js_urls.append(urljoin(base_url, path))

        return js_urls

    async def _analyze_js_file(self, js_url: str, base_url: str):
        """Analyze a JavaScript file for API endpoints"""
        try:
            await self.rate_limiter.acquire(tool="api_discovery")

            async with self.http_session.get(js_url, timeout=10) as response:
                if response.status == 200:
                    js_content = await response.text()
                    self.stats["js_files_analyzed"] += 1

                    # Apply patterns to find API calls
                    for pattern in self.js_api_patterns:
                        matches = pattern.findall(js_content)

                        for match in matches:
                            # Clean up match
                            api_path = match.strip()

                            # Skip if not a valid path
                            if not api_path.startswith('/'):
                                continue

                            full_url = urljoin(base_url, api_path)

                            if full_url not in self.tested_endpoints:
                                self.tested_endpoints.add(full_url)

                                # Test if endpoint exists
                                await self._test_api_endpoint(full_url, base_url)

        except Exception as e:
            self.logger.debug("JS analysis failed", url=js_url, error=str(e))

    async def _test_api_endpoint(self, url: str, base_url: str):
        """Test if an API endpoint exists"""
        try:
            await self.rate_limiter.acquire(tool="api_discovery")

            # Try GET first
            async with self.http_session.get(url, timeout=10) as response:
                status_code = response.status
                content_type = response.headers.get('Content-Type', '')

                # Interesting responses
                if status_code in [200, 201, 400, 401, 403, 404, 405]:
                    # Determine if this is likely an API
                    is_api = (
                        'json' in content_type.lower() or
                        'xml' in content_type.lower() or
                        '/api/' in url.lower() or
                        status_code == 405  # Method not allowed suggests endpoint exists
                    )

                    if is_api:
                        api = DiscoveredAPI(
                            url=url,
                            method="GET" if status_code != 405 else "UNKNOWN",
                            api_type="REST",
                            version=self._extract_version(url),
                            requires_auth=(status_code in [401, 403]),
                            discovery_method="javascript_analysis",
                            confidence=0.7
                        )

                        self.apis.append(api)
                        self.stats["apis_discovered"] += 1

                        # Try other methods if 405
                        if status_code == 405:
                            await self._probe_http_methods(url, base_url)

        except Exception as e:
            self.logger.debug("API endpoint test failed", url=url, error=str(e))

    async def _probe_http_methods(self, url: str, base_url: str):
        """Probe different HTTP methods for an endpoint"""
        methods = ['POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS']

        for method in methods:
            try:
                await self.rate_limiter.acquire(tool="api_discovery")

                async with self.http_session.request(method, url, timeout=10) as response:
                    if response.status not in [404, 405]:
                        # This method is accepted
                        api = DiscoveredAPI(
                            url=url,
                            method=method,
                            api_type="REST",
                            version=self._extract_version(url),
                            requires_auth=(response.status in [401, 403]),
                            discovery_method="http_method_probing",
                            confidence=0.8
                        )
                        self.apis.append(api)

            except Exception as e:
                self.logger.debug(f"{method} probe failed", url=url, error=str(e))

    async def _analyze_traffic(self, traffic: List[HTTPTraffic]):
        """Analyze observed HTTP traffic for API patterns"""
        self.logger.info("Analyzing observed traffic", records=len(traffic))

        for record in traffic:
            # Check if this looks like an API call
            content_type = record.response_content_type or ''

            if ('json' in content_type.lower() or
                'xml' in content_type.lower() or
                '/api/' in record.url.lower()):

                api = DiscoveredAPI(
                    url=record.url,
                    method=record.method,
                    api_type=self._determine_api_type(record),
                    version=self._extract_version(record.path),
                    requires_auth=(record.status_code in [401, 403]),
                    discovery_method="traffic_observation",
                    confidence=0.9
                )

                self.apis.append(api)
                self.stats["apis_discovered"] += 1

    async def _graphql_introspection(
        self,
        db_session: AsyncSession,
        base_url: str,
        subdomain_id: int
    ):
        """Try GraphQL introspection query"""
        graphql_paths = ['/graphql', '/api/graphql', '/v1/graphql']

        introspection_query = """
        query IntrospectionQuery {
            __schema {
                types {
                    name
                    kind
                    fields {
                        name
                        type {
                            name
                            kind
                        }
                    }
                }
            }
        }
        """

        for path in graphql_paths:
            url = urljoin(base_url, path)

            try:
                await self.rate_limiter.acquire(tool="api_discovery")

                async with self.http_session.post(
                    url,
                    json={"query": introspection_query},
                    timeout=10
                ) as response:
                    if response.status == 200:
                        result = await response.json()

                        if 'data' in result and '__schema' in result['data']:
                            self.logger.info("GraphQL introspection successful", url=url)

                            # Parse schema
                            schema = result['data']['__schema']
                            types = schema.get('types', [])

                            # Create API entry for GraphQL endpoint
                            api = DiscoveredAPI(
                                url=url,
                                method="POST",
                                api_type="GraphQL",
                                response_schema={"types": types},
                                discovery_method="graphql_introspection",
                                confidence=1.0
                            )

                            self.apis.append(api)
                            self.stats["graphql_endpoints"] += 1

            except Exception as e:
                self.logger.debug("GraphQL introspection failed", url=url, error=str(e))

    async def _generate_api_variations(
        self,
        db_session: AsyncSession,
        base_url: str,
        subdomain_id: int
    ):
        """Generate API variations based on discovered patterns"""
        # Find common patterns in discovered APIs
        patterns = defaultdict(list)

        for api in self.apis:
            pattern = self._extract_pattern(api.url)
            if pattern:
                patterns[pattern].append(api)

        # Generate variations
        for pattern, apis in patterns.items():
            if '/v' in pattern and '{N}' in pattern:
                # Try other versions
                for version in ['v1', 'v2', 'v3', 'v4']:
                    test_url = pattern.replace('{N}', version.replace('v', ''))
                    if test_url not in self.tested_endpoints:
                        await self._test_api_endpoint(test_url, base_url)

    def _extract_version(self, path: str) -> Optional[str]:
        """Extract API version from path"""
        match = re.search(r'/v(\d+)/', path, re.IGNORECASE)
        if match:
            return f"v{match.group(1)}"
        return None

    def _extract_pattern(self, url: str) -> str:
        """Extract URL pattern"""
        parsed = urlparse(url)
        path = parsed.path

        # Replace numbers
        pattern = re.sub(r'\d+', '{N}', path)

        # Replace UUIDs
        pattern = re.sub(
            r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}',
            '{UUID}',
            pattern,
            flags=re.IGNORECASE
        )

        return pattern

    def _determine_api_type(self, traffic: HTTPTraffic) -> str:
        """Determine API type from traffic"""
        if 'graphql' in traffic.url.lower():
            return "GraphQL"
        elif 'soap' in (traffic.response_content_type or '').lower():
            return "SOAP"
        else:
            return "REST"

    async def _save_apis(self, db_session: AsyncSession, subdomain_id: int):
        """Save discovered APIs to database"""
        for api in self.apis:
            try:
                # Check if already exists
                result = await db_session.execute(
                    select(APIEndpoint).where(
                        APIEndpoint.subdomain_id == subdomain_id,
                        APIEndpoint.path == urlparse(api.url).path,
                        APIEndpoint.method == api.method
                    )
                )
                existing = result.scalar_one_or_none()

                if not existing:
                    endpoint = APIEndpoint(
                        subdomain_id=subdomain_id,
                        path=urlparse(api.url).path,
                        method=api.method,
                        api_type=api.api_type,
                        version=api.version,
                        parameters=json_lib.dumps(api.parameters),
                        response_schema=json_lib.dumps(api.response_schema) if api.response_schema else None,
                        requires_auth=api.requires_auth,
                        auth_methods=json_lib.dumps([api.auth_type]) if api.auth_type else None,
                        documented=bool(api.documentation_url),
                        documentation_url=api.documentation_url,
                        discovery_method=api.discovery_method
                    )

                    db_session.add(endpoint)

            except Exception as e:
                self.logger.warning("Failed to save API", url=api.url, error=str(e))

        await db_session.commit()

    def _api_to_dict(self, api: DiscoveredAPI) -> Dict:
        """Convert API to dictionary"""
        return {
            "url": api.url,
            "method": api.method,
            "api_type": api.api_type,
            "version": api.version,
            "requires_auth": api.requires_auth,
            "auth_type": api.auth_type,
            "discovery_method": api.discovery_method,
            "confidence": api.confidence,
            "parameters": api.parameters,
        }
