"""
HTTP Traffic Interception and Analysis System

This module provides comprehensive HTTP/HTTPS traffic interception using mitmproxy,
with real-time analysis, pattern matching, and vulnerability detection capabilities.

Components:
- Interceptor: mitmproxy addon for traffic capture
- Context Manager: Request tagging and correlation
- Certificate Manager: SSL/TLS certificate handling
- Proxy Server: mitmproxy lifecycle management
- WAL: Write-ahead log for immediate persistence
- Processor: Background processing pipeline
- Analyzers: Content analysis and extraction
- Stream Analyzer: Real-time pattern matching
- Alerting: Alert generation and management
"""

from .proxy_server import ProxyServer
from .context_manager import ContextManager, context_manager
from .proxy_client import ProxyClient
from .wal import WALWriter, WALReader
from .processor import TrafficProcessor
from .storage_manager import StorageManager
from .stream_analyzer import StreamAnalyzer
from .alerting import AlertManager

__all__ = [
    "ProxyServer",
    "ContextManager",
    "context_manager",
    "ProxyClient",
    "WALWriter",
    "WALReader",
    "TrafficProcessor",
    "StorageManager",
    "StreamAnalyzer",
    "AlertManager"
]
