"""
Configuration Management System
Handles all application settings with security and flexibility
"""

import yaml
from pathlib import Path
from typing import Dict, Any, Optional, List
from pydantic import Field, field_validator
from pydantic_settings import BaseSettings  # Pydantic v2 import
from cryptography.fernet import Fernet
import json
import structlog

logger = structlog.get_logger()


class SecurityConfig(BaseSettings):
    """Security-related configuration settings"""
    
    # Encryption settings for sensitive data storage
    master_key: Optional[str] = Field(None, env="RECON_MASTER_KEY")
    encryption_enabled: bool = Field(True, env="ENCRYPTION_ENABLED")
    
    # Rate limiting to avoid overwhelming targets
    global_rate_limit: int = Field(10, env="GLOBAL_RATE_LIMIT")  # requests per second
    per_domain_rate_limit: int = Field(5, env="DOMAIN_RATE_LIMIT")
    
    # Authentication for the web interface
    jwt_secret_key: str = Field(..., env="JWT_SECRET_KEY")
    jwt_algorithm: str = Field("HS256")
    access_token_expire_minutes: int = Field(60 * 24)  # 24 hours
    
    @field_validator("master_key", mode='before')
    @classmethod
    def generate_master_key_if_missing(cls, v):
        """Generate a master key if not provided - critical for first run"""
        if not v:
            # Generate a secure random key
            key = Fernet.generate_key()
            key_str = key.decode()
            
            # Save it securely for future use
            key_file = Path("config/.master_key")
            key_file.parent.mkdir(exist_ok=True)
            key_file.write_text(key_str)
            key_file.chmod(0o600)  # Read/write for owner only
            
            logger.warning("Generated new master key", key_file=str(key_file))
            return key_str
        return v
    
    model_config = {
        "env_file": ".env",
        "env_file_encoding": "utf-8",
        "extra": "ignore"
    }


class DatabaseConfig(BaseSettings):
    """Database configuration with support for different environments"""
    
    # Default to SQLite for development, can switch to PostgreSQL for production
    database_url: str = Field(
        "sqlite+aiosqlite:///./data/recon.db",
        env="DATABASE_URL"
    )
    
    # Connection pool settings for production databases
    pool_size: int = Field(10, env="DB_POOL_SIZE")
    max_overflow: int = Field(20, env="DB_MAX_OVERFLOW")
    pool_timeout: int = Field(30, env="DB_POOL_TIMEOUT")
    echo_sql: bool = Field(False, env="DB_ECHO")  # SQL logging for debugging
    
    # Performance tuning
    enable_connection_pooling: bool = Field(True)
    use_batch_inserts: bool = Field(True)  # Critical for HTTP traffic logs
    
    @field_validator("database_url", mode='after')
    @classmethod
    def ensure_async_driver(cls, v):
        """Ensure we're using async database drivers for performance"""
        if "sqlite" in v and "aiosqlite" not in v:
            return v.replace("sqlite:", "sqlite+aiosqlite:")
        elif "postgresql" in v and "asyncpg" not in v:
            return v.replace("postgresql:", "postgresql+asyncpg:")
        return v
    
    model_config = {
        "env_file": ".env",
        "extra": "ignore"
    }


class ScannerConfig(BaseSettings):
    """Scanner-specific configuration for reconnaissance operations"""
    
    # Scanning profiles for different authorization levels
    scan_profile: str = Field("passive", env="SCAN_PROFILE")  # passive, normal, aggressive
    
    # Concurrent operation limits to manage resource usage
    max_concurrent_subdomains: int = Field(20)
    max_concurrent_ports: int = Field(100)
    max_concurrent_http_requests: int = Field(50)
    
    # Timeout settings for different operations
    dns_timeout: int = Field(5)  # seconds
    port_scan_timeout: int = Field(2)
    http_timeout: int = Field(10)
    
    # Port scanning ranges
    quick_ports: List[int] = Field(
        default=[21, 22, 23, 25, 53, 80, 443, 445, 3306, 3389, 8080, 8443]
    )
    full_ports: str = Field("1-65535")
    
    # Web enumeration settings
    max_crawl_depth: int = Field(5)
    max_pages_per_domain: int = Field(1000)
    follow_redirects: bool = Field(True)
    respect_robots_txt: bool = Field(True)  # Important for ethical scanning
    
    # API discovery patterns
    api_endpoints_patterns: List[str] = Field(
        default=[
            "/api", "/v1", "/v2", "/graphql", "/rest",
            "/swagger", "/openapi", "/docs", "/.well-known"
        ]
    )
    
    @field_validator("scan_profile", mode='after')
    @classmethod
    def validate_scan_profile(cls, v):
        """Ensure scan profile is valid and set appropriate limits"""
        profiles = {
            "passive": {"description": "No direct target interaction"},
            "normal": {"description": "Balanced scanning with rate limits"},
            "aggressive": {"description": "Fast scanning for authorized tests"}
        }
        if v not in profiles:
            raise ValueError(f"Invalid scan profile. Choose from: {list(profiles.keys())}")
        return v
    
    model_config = {
        "env_file": ".env",
        "extra": "ignore"
    }


class APIKeyManager:
    """
    Secure storage and retrieval of third-party API keys
    Uses encryption to protect keys at rest
    """
    
    def __init__(self, master_key: str):
        self.cipher = Fernet(master_key.encode() if isinstance(master_key, str) else master_key)
        self.key_file = Path("config/api_keys.enc")
        self.keys = self._load_keys()
    
    def _load_keys(self) -> Dict[str, str]:
        """Load and decrypt API keys from secure storage"""
        if not self.key_file.exists():
            self.key_file.parent.mkdir(exist_ok=True)
            return {}
        
        try:
            encrypted_data = self.key_file.read_bytes()
            decrypted_data = self.cipher.decrypt(encrypted_data)
            return json.loads(decrypted_data)
        except Exception as e:
            logger.error("Failed to load API keys", error=str(e))
            return {}
    
    def _save_keys(self):
        """Encrypt and save all API keys"""
        encrypted_data = self.cipher.encrypt(json.dumps(self.keys).encode())
        self.key_file.write_bytes(encrypted_data)
        self.key_file.chmod(0o600)
    
    def save_key(self, service: str, api_key: str):
        """Encrypt and save an API key"""
        self.keys[service] = api_key
        self._save_keys()
        logger.info("API key saved", service=service)
    
    def get_key(self, service: str) -> Optional[str]:
        """Retrieve a decrypted API key"""
        return self.keys.get(service)
    
    def list_services(self) -> List[str]:
        """List all services with stored API keys"""
        return list(self.keys.keys())
    
    def remove_key(self, service: str):
        """Remove an API key from storage"""
        if service in self.keys:
            del self.keys[service]
            self._save_keys()
            logger.info("API key removed", service=service)


class ToolsConfig(BaseSettings):
    """Tools and resources configuration"""
    
    # Directory where tools are installed
    tools_directory: Path = Field(Path("tools"), env="TOOLS_DIRECTORY")
    
    # Resolver file for DNS operations
    resolvers_file: Path = Field(Path("tools/resolvers.txt"))
    
    # Wordlist paths
    wordlist_huge: Path = Field(Path("tools/n0kovo_subdomains_huge.txt"))
    
    # Recursion settings
    recursion_depth: int = Field(2, env="RECURSION_DEPTH")
    
    # Phase toggles
    enable_horizontal: bool = Field(True, env="ENABLE_HORIZONTAL")
    enable_passive: bool = Field(True, env="ENABLE_PASSIVE")
    enable_active: bool = Field(True, env="ENABLE_ACTIVE")
    enable_web_probing: bool = Field(True, env="ENABLE_WEB_PROBING")
    enable_recursion: bool = Field(False, env="ENABLE_RECURSION")
    
    model_config = {
        "env_file": ".env",
        "extra": "ignore"
    }


class ProxyConfig(BaseSettings):
    """HTTP interception proxy configuration"""
    
    # Proxy server settings
    proxy_enabled: bool = Field(False, env="PROXY_ENABLED")
    proxy_host: str = Field("0.0.0.0", env="PROXY_HOST")
    proxy_port: int = Field(8080, env="PROXY_PORT")
    
    # SSL/TLS certificate settings
    ca_cert_dir: Path = Field(Path("data/certs"), env="CA_CERT_DIR")
    ca_cert_name: str = Field("mitmproxy-ca", env="CA_CERT_NAME")
    
    # Write-Ahead Log (WAL) settings
    wal_directory: Path = Field(Path("data/http_wal"), env="WAL_DIRECTORY")
    wal_max_size_mb: int = Field(100, env="WAL_MAX_SIZE_MB")
    wal_max_age_hours: int = Field(1, env="WAL_MAX_AGE_HOURS")
    wal_buffer_size: int = Field(1000, env="WAL_BUFFER_SIZE")  # Entries before flush
    
    # Background processing settings
    processing_enabled: bool = Field(True, env="PROCESSING_ENABLED")
    processing_interval_seconds: int = Field(10, env="PROCESSING_INTERVAL")
    processing_batch_size: int = Field(100, env="PROCESSING_BATCH_SIZE")
    processing_workers: int = Field(2, env="PROCESSING_WORKERS")
    
    # Real-time analysis settings
    realtime_analysis_enabled: bool = Field(True, env="REALTIME_ANALYSIS")
    analysis_timeout_seconds: int = Field(5, env="ANALYSIS_TIMEOUT")
    
    # Pattern matching settings
    patterns_directory: Path = Field(Path("config/patterns"), env="PATTERNS_DIR")
    enable_sensitive_data_scanning: bool = Field(True, env="ENABLE_SENSITIVE_SCAN")
    enable_vulnerability_patterns: bool = Field(True, env="ENABLE_VULN_PATTERNS")
    enable_error_detection: bool = Field(True, env="ENABLE_ERROR_DETECT")
    
    # Storage and compression
    compress_response_bodies: bool = Field(True, env="COMPRESS_RESPONSES")
    compression_min_size_bytes: int = Field(1024, env="COMPRESSION_MIN_SIZE")  # 1KB
    max_body_size_mb: int = Field(10, env="MAX_BODY_SIZE_MB")
    
    # Traffic filtering
    capture_only_subdomains: bool = Field(True, env="CAPTURE_ONLY_SUBDOMAINS")
    ignored_content_types: List[str] = Field(
        default=["image/", "video/", "audio/", "font/"],
        env="IGNORED_CONTENT_TYPES"
    )
    
    # Alert settings
    enable_alerts: bool = Field(True, env="ENABLE_ALERTS")
    alert_webhook_url: Optional[str] = Field(None, env="ALERT_WEBHOOK_URL")
    
    model_config = {
        "env_file": ".env",
        "extra": "ignore"
    }


class ApplicationConfig:
    """
    Main configuration class that combines all config sections
    This is what the rest of the application will use
    """
    
    def __init__(self):
        self.security = SecurityConfig()
        self.database = DatabaseConfig()
        self.scanner = ScannerConfig()
        self.tools = ToolsConfig()
        self.proxy = ProxyConfig()
        self.api_keys = APIKeyManager(self.security.master_key)
        
        # Load custom configuration from YAML if it exists
        self.custom_config = self._load_custom_config()
        
        # Set up structured logging
        self._configure_logging()
        
        # Ensure required directories exist
        self._ensure_directories()
    
    def _load_custom_config(self) -> Dict[str, Any]:
        """Load user-defined configuration from YAML files"""
        config_file = Path("config/default.yaml")
        if config_file.exists():
            with open(config_file, 'r') as f:
                return yaml.safe_load(f) or {}
        return {}
    
    def _configure_logging(self):
        """Set up structured logging for better debugging and monitoring"""
        structlog.configure(
            processors=[
                structlog.stdlib.filter_by_level,
                structlog.stdlib.add_logger_name,
                structlog.stdlib.add_log_level,
                structlog.stdlib.PositionalArgumentsFormatter(),
                structlog.processors.TimeStamper(fmt="iso"),
                structlog.processors.StackInfoRenderer(),
                structlog.processors.format_exc_info,
                structlog.dev.ConsoleRenderer(colors=True)
            ],
            context_class=dict,
            logger_factory=structlog.stdlib.LoggerFactory(),
            cache_logger_on_first_use=True,
        )
    
    def get_scan_profile_config(self) -> Dict[str, Any]:
        """Get configuration based on current scan profile"""
        profiles = {
            "passive": {
                "rate_limit": 1,  # 1 request per second
                "ports": [],  # No port scanning
                "crawl_depth": 0,  # No crawling
                "dns_enumeration": False
            },
            "normal": {
                "rate_limit": self.security.per_domain_rate_limit,
                "ports": self.scanner.quick_ports,
                "crawl_depth": 3,
                "dns_enumeration": True
            },
            "aggressive": {
                "rate_limit": 50,  # Much faster for authorized tests
                "ports": self.scanner.full_ports,
                "crawl_depth": self.scanner.max_crawl_depth,
                "dns_enumeration": True
            }
        }
        return profiles.get(self.scanner.scan_profile, profiles["normal"])
    
    def _ensure_directories(self):
        """Ensure required directories exist for proxy and storage"""
        directories = [
            self.proxy.wal_directory,
            self.proxy.ca_cert_dir,
            self.proxy.patterns_directory,
            Path("data"),
            Path("config"),
            Path("logs")
        ]
        
        for directory in directories:
            directory.mkdir(parents=True, exist_ok=True)
        
        logger.debug("Ensured required directories exist")
