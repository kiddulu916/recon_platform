"""
URL Extractor for HTTP Response Bodies

Extracts URLs from various content types:
- HTML (href, src, action, data attributes)
- JavaScript (strings, API calls, imports)
- JSON (any string that looks like a URL)
- XML/SOAP (href attributes, text content)
"""

import re
from typing import List, Set, Dict, Any, Optional
from urllib.parse import urljoin, urlparse, parse_qs
from bs4 import BeautifulSoup
import json as json_lib
import structlog

logger = structlog.get_logger()


class URLExtractor:
    """
    Extracts and categorizes URLs from HTTP response bodies
    
    Handles multiple content types and normalizes extracted URLs.
    """
    
    def __init__(self):
        self.logger = logger.bind(component="url_extractor")
        
        # URL patterns for different contexts
        self.url_patterns = [
            # Absolute URLs
            re.compile(r'https?://[^\s<>"{}|\\^`\[\]]+', re.IGNORECASE),
            # Protocol-relative URLs
            re.compile(r'//[^\s<>"{}|\\^`\[\]]+', re.IGNORECASE),
            # Absolute paths
            re.compile(r'(/[^\s<>"{}|\\^`\[\]]*)', re.IGNORECASE),
        ]
        
        # JavaScript URL patterns
        self.js_url_patterns = [
            # API calls
            re.compile(r'["\']([/a-z0-9\-._~:/?#\[\]@!$&\'()*+,;=%]+)["\']', re.IGNORECASE),
            # fetch/axios/ajax
            re.compile(r'(?:fetch|axios|ajax)\s*\(\s*["\']([^"\']+)["\']', re.IGNORECASE),
            # import/require
            re.compile(r'(?:import|require)\s*\(["\']([^"\']+)["\']', re.IGNORECASE),
        ]
    
    def extract(
        self,
        content: bytes,
        content_type: Optional[str],
        base_url: str
    ) -> Dict[str, Any]:
        """
        Extract URLs from content
        
        Args:
            content: Response body content
            content_type: Content-Type header
            base_url: Base URL for relative URL resolution
        
        Returns:
            Dictionary with extracted URLs and metadata
        """
        if not content:
            return {"urls": [], "by_type": {}, "total": 0}
        
        try:
            # Decode content
            try:
                text = content.decode('utf-8', errors='ignore')
            except:
                text = str(content)
            
            # Determine content type
            urls_by_type = {}
            
            if self._is_html(content_type):
                urls_by_type["html"] = self._extract_from_html(text, base_url)
            
            if self._is_javascript(content_type):
                urls_by_type["javascript"] = self._extract_from_javascript(text, base_url)
            
            if self._is_json(content_type):
                urls_by_type["json"] = self._extract_from_json(text, base_url)
            
            if self._is_xml(content_type):
                urls_by_type["xml"] = self._extract_from_xml(text, base_url)
            
            # Fallback: extract from plain text
            if not urls_by_type:
                urls_by_type["text"] = self._extract_from_text(text, base_url)
            
            # Combine and deduplicate
            all_urls = []
            for url_list in urls_by_type.values():
                all_urls.extend(url_list)
            
            unique_urls = list(set(all_urls))
            
            # Categorize URLs
            categorized = self._categorize_urls(unique_urls, base_url)
            
            return {
                "urls": unique_urls,
                "by_type": urls_by_type,
                "categorized": categorized,
                "total": len(unique_urls)
            }
        
        except Exception as e:
            self.logger.error("URL extraction failed", error=str(e))
            return {"urls": [], "by_type": {}, "total": 0}
    
    def _extract_from_html(self, html: str, base_url: str) -> List[str]:
        """Extract URLs from HTML content"""
        urls = set()
        
        try:
            soup = BeautifulSoup(html, 'lxml')
            
            # Extract from common attributes
            for tag in soup.find_all(True):
                # href attributes (a, link)
                if tag.has_attr('href'):
                    urls.add(tag['href'])
                
                # src attributes (img, script, iframe, etc.)
                if tag.has_attr('src'):
                    urls.add(tag['src'])
                
                # action attributes (form)
                if tag.has_attr('action'):
                    urls.add(tag['action'])
                
                # data attributes
                for attr in tag.attrs:
                    if attr.startswith('data-') and isinstance(tag[attr], str):
                        if self._looks_like_url(tag[attr]):
                            urls.add(tag[attr])
            
            # Normalize URLs
            normalized = []
            for url in urls:
                if url:
                    normalized_url = self._normalize_url(url, base_url)
                    if normalized_url:
                        normalized.append(normalized_url)
            
            return normalized
        
        except Exception as e:
            self.logger.warning("HTML parsing failed", error=str(e))
            return []
    
    def _extract_from_javascript(self, js: str, base_url: str) -> List[str]:
        """Extract URLs from JavaScript content"""
        urls = set()
        
        # Apply JavaScript-specific patterns
        for pattern in self.js_url_patterns:
            matches = pattern.findall(js)
            urls.update(matches)
        
        # General URL extraction
        for pattern in self.url_patterns:
            matches = pattern.findall(js)
            urls.update(matches)
        
        # Normalize
        normalized = []
        for url in urls:
            if url and self._looks_like_url(url):
                normalized_url = self._normalize_url(url, base_url)
                if normalized_url:
                    normalized.append(normalized_url)
        
        return normalized
    
    def _extract_from_json(self, json_str: str, base_url: str) -> List[str]:
        """Extract URLs from JSON content"""
        urls = set()
        
        try:
            data = json_lib.loads(json_str)
            self._extract_urls_from_json_obj(data, urls)
        
        except json_lib.JSONDecodeError:
            # Fallback to regex if not valid JSON
            for pattern in self.url_patterns:
                matches = pattern.findall(json_str)
                urls.update(matches)
        
        # Normalize
        normalized = []
        for url in urls:
            if url and self._looks_like_url(url):
                normalized_url = self._normalize_url(url, base_url)
                if normalized_url:
                    normalized.append(normalized_url)
        
        return normalized
    
    def _extract_urls_from_json_obj(self, obj: Any, urls: Set[str]):
        """Recursively extract URLs from JSON object"""
        if isinstance(obj, dict):
            for value in obj.values():
                self._extract_urls_from_json_obj(value, urls)
        
        elif isinstance(obj, list):
            for item in obj:
                self._extract_urls_from_json_obj(item, urls)
        
        elif isinstance(obj, str):
            if self._looks_like_url(obj):
                urls.add(obj)
    
    def _extract_from_xml(self, xml: str, base_url: str) -> List[str]:
        """Extract URLs from XML content"""
        urls = set()
        
        try:
            soup = BeautifulSoup(xml, 'xml')
            
            # Extract from href attributes
            for tag in soup.find_all(True):
                if tag.has_attr('href'):
                    urls.add(tag['href'])
                
                # Extract from text content
                if tag.string and self._looks_like_url(tag.string):
                    urls.add(tag.string)
        
        except:
            # Fallback to regex
            for pattern in self.url_patterns:
                matches = pattern.findall(xml)
                urls.update(matches)
        
        # Normalize
        normalized = []
        for url in urls:
            if url:
                normalized_url = self._normalize_url(url, base_url)
                if normalized_url:
                    normalized.append(normalized_url)
        
        return normalized
    
    def _extract_from_text(self, text: str, base_url: str) -> List[str]:
        """Extract URLs from plain text"""
        urls = set()
        
        for pattern in self.url_patterns:
            matches = pattern.findall(text)
            urls.update(matches)
        
        # Normalize
        normalized = []
        for url in urls:
            if url and self._looks_like_url(url):
                normalized_url = self._normalize_url(url, base_url)
                if normalized_url:
                    normalized.append(normalized_url)
        
        return normalized
    
    def _normalize_url(self, url: str, base_url: str) -> Optional[str]:
        """Normalize and resolve URL"""
        try:
            # Strip whitespace
            url = url.strip()
            
            # Skip certain patterns
            if url.startswith(('javascript:', 'mailto:', 'tel:', 'data:', '#')):
                return None
            
            # Resolve relative URLs
            full_url = urljoin(base_url, url)
            
            # Parse to validate
            parsed = urlparse(full_url)
            
            # Must have at least scheme and netloc, or a path
            if not (parsed.scheme and parsed.netloc) and not parsed.path:
                return None
            
            return full_url
        
        except:
            return None
    
    def _categorize_urls(self, urls: List[str], base_url: str) -> Dict[str, List[str]]:
        """Categorize URLs by type"""
        base_domain = urlparse(base_url).netloc
        
        categorized = {
            "internal": [],
            "external": [],
            "api": [],
            "static": [],
            "parameters": []
        }
        
        for url in urls:
            parsed = urlparse(url)
            
            # Internal vs External
            if parsed.netloc == base_domain or not parsed.netloc:
                categorized["internal"].append(url)
            else:
                categorized["external"].append(url)
            
            # API endpoints
            if self._is_api_url(url):
                categorized["api"].append(url)
            
            # Static resources
            if self._is_static_url(url):
                categorized["static"].append(url)
            
            # URLs with parameters
            if parsed.query:
                categorized["parameters"].append(url)
        
        return categorized
    
    def _is_html(self, content_type: Optional[str]) -> bool:
        """Check if content type is HTML"""
        if not content_type:
            return False
        return 'html' in content_type.lower()
    
    def _is_javascript(self, content_type: Optional[str]) -> bool:
        """Check if content type is JavaScript"""
        if not content_type:
            return False
        ct = content_type.lower()
        return 'javascript' in ct or 'ecmascript' in ct
    
    def _is_json(self, content_type: Optional[str]) -> bool:
        """Check if content type is JSON"""
        if not content_type:
            return False
        return 'json' in content_type.lower()
    
    def _is_xml(self, content_type: Optional[str]) -> bool:
        """Check if content type is XML"""
        if not content_type:
            return False
        ct = content_type.lower()
        return 'xml' in ct or 'soap' in ct
    
    def _looks_like_url(self, string: str) -> bool:
        """Check if string looks like a URL"""
        if not isinstance(string, str):
            return False
        
        string = string.strip()
        
        # Must have reasonable length
        if len(string) < 1 or len(string) > 2048:
            return False
        
        # Check for URL-like patterns
        if string.startswith(('http://', 'https://', '//', '/')):
            return True
        
        # Check for domain-like patterns
        if re.match(r'^[a-z0-9\-]+\.[a-z]{2,}', string, re.IGNORECASE):
            return True
        
        return False
    
    def _is_api_url(self, url: str) -> bool:
        """Check if URL looks like an API endpoint"""
        api_indicators = ['/api/', '/v1/', '/v2/', '/v3/', '/rest/', '/graphql', '/json']
        url_lower = url.lower()
        return any(indicator in url_lower for indicator in api_indicators)
    
    def _is_static_url(self, url: str) -> bool:
        """Check if URL is a static resource"""
        static_extensions = [
            '.css', '.js', '.jpg', '.jpeg', '.png', '.gif', '.svg', '.ico',
            '.woff', '.woff2', '.ttf', '.eot', '.mp4', '.mp3', '.pdf'
        ]
        url_lower = url.lower()
        return any(url_lower.endswith(ext) for ext in static_extensions)
