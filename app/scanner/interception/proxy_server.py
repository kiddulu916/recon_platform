"""
Proxy Server for mitmproxy Lifecycle Management

Manages starting, stopping, and monitoring the mitmproxy server.
"""

import asyncio
import threading
from pathlib import Path
from typing import Optional
import structlog

from mitmproxy import options
from mitmproxy.tools import dump

logger = structlog.get_logger()


class ProxyServer:
    """
    Manages mitmproxy proxy server lifecycle
    
    Provides methods to start, stop, and monitor the proxy server,
    with proper integration of our custom interceptor addon.
    """
    
    def __init__(self, config, wal_writer=None, stream_analyzer=None):
        """
        Initialize the proxy server
        
        Args:
            config: Application configuration
            wal_writer: WAL writer for traffic persistence
            stream_analyzer: Stream analyzer for real-time analysis
        """
        self.config = config
        self.wal_writer = wal_writer
        self.stream_analyzer = stream_analyzer
        self.logger = logger.bind(component="proxy_server")
        
        self._server_thread: Optional[threading.Thread] = None
        self._master: Optional[dump.DumpMaster] = None
        self._running = False
        self._interceptor = None
    
    def start(self):
        """
        Start the proxy server
        
        Starts mitmproxy in a separate thread with our custom addon.
        """
        if self._running:
            self.logger.warning("Proxy server already running")
            return
        
        try:
            # Import here to avoid issues if mitmproxy not installed
            from .interceptor import ReconInterceptor
            
            # Create interceptor addon
            self._interceptor = ReconInterceptor(
                self.config,
                self.wal_writer,
                self.stream_analyzer
            )
            
            # Configure mitmproxy options
            opts = options.Options(
                listen_host=self.config.proxy.proxy_host,
                listen_port=self.config.proxy.proxy_port,
                # Certificate directory
                confdir=str(self.config.proxy.ca_cert_dir),
                # SSL/TLS options
                ssl_insecure=False,  # Validate upstream certs
                # Performance options
                stream_large_bodies="10m",  # Stream bodies > 10MB
                # Behavior options
                upstream_cert=True,  # Use upstream's certificate
                # Logging
                termlog_verbosity="info"
            )
            
            # Create master with our addon
            self._master = dump.DumpMaster(
                opts,
                with_termlog=False,
                with_dumper=False
            )
            
            # Add our interceptor addon
            self._master.addons.add(self._interceptor)
            
            # Start server in separate thread
            self._running = True
            self._server_thread = threading.Thread(
                target=self._run_proxy,
                daemon=True,
                name="mitmproxy-server"
            )
            self._server_thread.start()
            
            self.logger.info(
                "Proxy server started",
                host=self.config.proxy.proxy_host,
                port=self.config.proxy.proxy_port,
                ca_cert=str(self.config.proxy.ca_cert_dir)
            )
        
        except Exception as e:
            self.logger.error("Failed to start proxy server", error=str(e))
            self._running = False
            raise
    
    def stop(self):
        """
        Stop the proxy server
        
        Gracefully shuts down the proxy and waits for the thread to finish.
        """
        if not self._running:
            self.logger.warning("Proxy server not running")
            return
        
        try:
            self.logger.info("Stopping proxy server...")
            
            # Signal shutdown
            if self._master:
                self._master.shutdown()
            
            # Wait for thread to finish
            if self._server_thread and self._server_thread.is_alive():
                self._server_thread.join(timeout=5)
            
            self._running = False
            self._master = None
            self._server_thread = None
            
            self.logger.info("Proxy server stopped")
        
        except Exception as e:
            self.logger.error("Error stopping proxy server", error=str(e))
            raise
    
    def is_running(self) -> bool:
        """Check if proxy server is running"""
        return self._running and self._server_thread and self._server_thread.is_alive()
    
    def get_status(self) -> dict:
        """
        Get proxy server status
        
        Returns:
            Dictionary with status information
        """
        status = {
            "running": self.is_running(),
            "host": self.config.proxy.proxy_host,
            "port": self.config.proxy.proxy_port,
            "ca_cert_dir": str(self.config.proxy.ca_cert_dir),
            "wal_directory": str(self.config.proxy.wal_directory),
            "realtime_analysis": self.config.proxy.realtime_analysis_enabled
        }
        
        # Add statistics if available
        if self._interceptor:
            status["statistics"] = self._interceptor.get_stats()
        
        return status
    
    def _run_proxy(self):
        """
        Run the proxy server
        
        This runs in a separate thread and blocks until shutdown.
        """
        try:
            self.logger.debug("Proxy thread starting...")
            self._master.run()
            self.logger.debug("Proxy thread stopped")
        except Exception as e:
            self.logger.error("Proxy thread error", error=str(e))
            self._running = False
    
    async def start_async(self):
        """
        Start proxy server asynchronously
        
        Wrapper for async contexts.
        """
        loop = asyncio.get_event_loop()
        await loop.run_in_executor(None, self.start)
    
    async def stop_async(self):
        """
        Stop proxy server asynchronously
        
        Wrapper for async contexts.
        """
        loop = asyncio.get_event_loop()
        await loop.run_in_executor(None, self.stop)
    
    def __enter__(self):
        """Context manager entry"""
        self.start()
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit"""
        self.stop()
        return False
