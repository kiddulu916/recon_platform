"""
Proxy Client Helper

Configures HTTP clients to route through the interception proxy
with proper context tagging.
"""

from typing import Dict, Any, Optional
import structlog

from .context_manager import context_manager

logger = structlog.get_logger()


class ProxyClient:
    """
    Helper for configuring HTTP clients to use the proxy
    
    Provides methods to:
    - Configure proxies for various HTTP clients
    - Inject context headers
    - Handle proxy errors gracefully
    """
    
    def __init__(self, config):
        """
        Initialize proxy client helper
        
        Args:
            config: Application configuration
        """
        self.config = config
        self.logger = logger.bind(component="proxy_client")
        
        # Proxy URL
        self.proxy_url = f"http://{config.proxy.proxy_host}:{config.proxy.proxy_port}"
        self.enabled = config.proxy.proxy_enabled
    
    def get_proxy_settings(self) -> Optional[Dict[str, str]]:
        """
        Get proxy settings for HTTP clients
        
        Returns:
            Dictionary with http/https proxy URLs or None if disabled
        """
        if not self.enabled:
            return None
        
        return {
            "http": self.proxy_url,
            "https": self.proxy_url
        }
    
    def inject_context_headers(self, headers: Dict[str, str]) -> Dict[str, str]:
        """
        Inject context information into request headers
        
        Args:
            headers: Original headers
        
        Returns:
            Headers with context information added
        """
        if not self.enabled:
            return headers
        
        return context_manager.inject_headers(headers)
    
    def configure_aiohttp_session(self, **kwargs) -> Dict[str, Any]:
        """
        Configure aiohttp ClientSession for proxy
        
        Args:
            **kwargs: Additional session kwargs
        
        Returns:
            Dictionary of session configuration
        """
        config = dict(kwargs)
        
        if self.enabled:
            config["proxy"] = self.proxy_url
            config["trust_env"] = True
        
        return config
    
    def configure_requests(self, **kwargs) -> Dict[str, Any]:
        """
        Configure requests library for proxy
        
        Args:
            **kwargs: Additional request kwargs
        
        Returns:
            Dictionary of request configuration
        """
        config = dict(kwargs)
        
        if self.enabled:
            config["proxies"] = self.get_proxy_settings()
            config["verify"] = False  # Disable cert verification when using proxy
        
        return config
    
    def configure_httpx_args(self) -> list:
        """
        Get httpx command-line arguments for proxy
        
        Returns:
            List of command-line arguments
        """
        if not self.enabled:
            return []
        
        return [
            "-http-proxy", self.proxy_url,
            "-https-proxy", self.proxy_url
        ]
